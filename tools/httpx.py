"""
Tool wrapper for httpx — live host probing and tech detection.

httpx probes a list of hosts/URLs for HTTP(S) responses, extracts:
- Status codes
- Titles
- Technologies (via Wappalyzer fingerprints)
- Response sizes
- Redirect chains
- TLS info
- CDN detection
- Web servers

Input: file of hosts (one per line), typically output from subfinder/amass.

Flags used:
  -l <file>             input list of hosts
  -o <file>             JSON output
  -json                 JSON output format
  -silent               suppress banner
  -nc                   no color
  -title                extract page title
  -tech-detect          technology detection
  -status-code          show status code
  -content-length       show content length
  -location             follow/show redirects
  -favicon              fetch favicon and hash it
  -jarm                 JARM fingerprint (TLS)
  -pipeline             pipelined HTTP requests
  -follow-redirects     follow HTTP redirects
  -threads <n>          concurrent threads
  -rate-limit <n>       max requests per second
  -timeout <secs>       HTTP timeout
  -retries <n>          number of retries
  -ports <ports>        additional ports to probe (standard + extras)
  -probe                probe for http/https both
  -cdn                  check if behind CDN
  -websocket            detect websocket support
  -ip                   show IPs
  -cname                show CNAME
  -asn                  show ASN info
"""

from __future__ import annotations

import json
import logging
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.base import ToolWrapper

log = logging.getLogger(__name__)


class HttpxWrapper(ToolWrapper):
    name = "httpx"
    version_flag = "-version"

    _DEPTH_CONFIG = {
        "quick": {
            "threads": 50,
            "rate_limit": 150,
            "timeout": 10,
            "retries": 1,
            "ports": "80,443",
            "follow_redirects": True,
            "tech_detect": True,
            "jarm": False,
            "favicon": False,
            "websocket": False,
        },
        "standard": {
            "threads": 50,
            "rate_limit": 150,
            "timeout": 15,
            "retries": 2,
            "ports": "80,443,8080,8443,8000,8888",
            "follow_redirects": True,
            "tech_detect": True,
            "jarm": True,
            "favicon": True,
            "websocket": True,
        },
        "exhaustive": {
            "threads": 50,
            "rate_limit": 100,  # slower to be thorough on all ports
            "timeout": 20,
            "retries": 3,
            "ports": "80,443,8080,8443,8000,8888,3000,4000,5000,9000,9090,9200,9300,7080,7443",
            "follow_redirects": True,
            "tech_detect": True,
            "jarm": True,
            "favicon": True,
            "websocket": True,
        },
    }

    def run(
        self,
        target: str,
        depth: str,
        run_id: str,
        raw_output_dir: Path,
        program: dict,
        hosts: list[str] | None = None,
        hosts_file: Path | None = None,
        extra_headers: dict | None = None,
        cookies: str | None = None,
        **kwargs: Any,
    ) -> dict:
        """
        Args:
            target:       Primary domain / context (for output naming).
            hosts:        List of hosts to probe. If None, uses hosts_file.
            hosts_file:   Path to a file of hosts. Preferred over hosts list.
        """
        self.require()
        cfg = self._DEPTH_CONFIG[depth]
        started_at = _now()
        t0 = time.monotonic()

        findings: list[dict] = []
        errors: list[dict] = []

        # Build hosts input file
        _tmp_input = None
        if hosts_file and hosts_file.exists():
            input_path = hosts_file
        elif hosts:
            _tmp_input = tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False
            )
            for h in hosts:
                _tmp_input.write(h + "\n")
            _tmp_input.flush()
            input_path = Path(_tmp_input.name)
        else:
            errors.append({"message": "httpx: no hosts or hosts_file provided"})
            return self._write_empty(run_id, raw_output_dir, target, started_at, errors)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            out_path_tmp = Path(tmp.name)

        cmd = [
            "httpx",
            "-l", str(input_path),
            "-o", str(out_path_tmp),
            "-json",
            "-silent",
            "-nc",
            "-title",
            "-status-code",
            "-content-length",
            "-location",
            "-ip",
            "-cname",
            "-asn",
            "-probe",
            "-follow-redirects",
            "-threads", str(cfg["threads"]),
            "-rate-limit", str(cfg["rate_limit"]),
            "-timeout", str(cfg["timeout"]),
            "-retries", str(cfg["retries"]),
            "-ports", cfg["ports"],
        ]
        if cfg["tech_detect"]:
            cmd.append("-tech-detect")
        if cfg["jarm"]:
            cmd.append("-jarm")
        if cfg["favicon"]:
            cmd.append("-favicon")
        if cfg["websocket"]:
            cmd.append("-websocket")
        if cfg.get("cdn"):
            cmd.append("-cdn")
        if extra_headers:
            for k, v in extra_headers.items():
                if k.lower() != "cookie":
                    cmd.extend(["-H", f"{k}: {v}"])
        if cookies:
            cmd.extend(["-H", f"Cookie: {cookies}"])
        elif extra_headers and "Cookie" in extra_headers:
            cmd.extend(["-H", f"Cookie: {extra_headers['Cookie']}"])

        result = self._exec(cmd)

        if result.returncode not in (0, 1):
            errors.append({
                "message": f"httpx exited with code {result.returncode}",
                "stderr_excerpt": result.stderr[:500],
                "exit_code": result.returncode,
            })

        # Parse JSON lines output
        if out_path_tmp.exists():
            for line in out_path_tmp.read_text().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue

                url = entry.get("url", "")
                host = entry.get("host", "")
                # httpx uses status_code (underscore) in its JSON output
                status = entry.get("status_code") or entry.get("status-code", 0)

                # Only include live hosts (status code present)
                if not status:
                    continue

                # Scope check — host field in httpx output is the hostname
                check_host = host or url.split("//")[-1].split("/")[0].split(":")[0]
                if not self._is_in_scope(check_host, program):
                    continue

                technologies = entry.get("tech", [])
                title = entry.get("title", "")
                content_length = entry.get("content_length") or entry.get("content-length", -1)

                evidence_parts = [f"HTTP {status}"]
                if title:
                    evidence_parts.append(f"Title: {title}")
                if technologies:
                    evidence_parts.append(f"Tech: {', '.join(technologies)}")
                evidence = " | ".join(evidence_parts)

                finding = {
                    "type": "tech_detection",
                    "url": url,
                    "host": host,
                    "evidence": evidence,
                    "raw_output": {
                        "status_code": status,
                        "title": title,
                        "content_length": content_length,
                        "technologies": technologies,
                        "ip": entry.get("host_ip", ""),
                        "asn": entry.get("asn", {}),
                        "location": entry.get("location", ""),
                        "jarm": entry.get("jarm", ""),
                        "favicon_hash": entry.get("favicon", ""),
                        "webserver": entry.get("webserver", ""),
                        "tls": entry.get("tls", {}),
                        "cdn_name": entry.get("cdn_name", ""),
                    },
                }
                findings.append(finding)

            out_path_tmp.unlink(missing_ok=True)

        if _tmp_input:
            Path(_tmp_input.name).unlink(missing_ok=True)

        finished_at = _now()
        duration = time.monotonic() - t0
        status_str = "success" if not errors else ("partial" if findings else "failed")

        out_path = self._write_raw_output(
            run_id=run_id,
            raw_output_dir=raw_output_dir,
            target=target,
            invocation_command=" ".join(str(c) for c in cmd),
            started_at=started_at,
            finished_at=finished_at,
            duration_seconds=duration,
            status=status_str,
            findings=findings,
            errors=errors,
        )

        return {"raw_output_path": out_path, "findings_count": len(findings)}

    def _write_empty(self, run_id, raw_output_dir, target, started_at, errors):
        out_path = self._write_raw_output(
            run_id=run_id,
            raw_output_dir=raw_output_dir,
            target=target,
            invocation_command="httpx (not run — no input)",
            started_at=started_at,
            finished_at=_now(),
            duration_seconds=0,
            status="failed",
            findings=[],
            errors=errors,
        )
        return {"raw_output_path": out_path, "findings_count": 0}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
