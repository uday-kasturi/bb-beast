"""
Tool wrapper for dnsx — DNS resolution and validation.

dnsx resolves a list of hostnames, filters out dead ones,
and returns only those with valid A/AAAA/CNAME records.
In exhaustive mode it also does MX, NS, TXT, SOA lookups.

Flags:
  -l <file>         input list of hosts
  -o <file>         output file
  -json             JSON output
  -a                resolve A records
  -aaaa             resolve AAAA records
  -cname            resolve CNAME records
  -mx               resolve MX records (standard+exhaustive)
  -ns               resolve NS records (standard+exhaustive)
  -txt              resolve TXT records (exhaustive)
  -soa              resolve SOA records (exhaustive)
  -resp             show response body
  -resp-only        only show IP/response (no host prefix)
  -retry <n>        retry count
  -t <n>            threads
  -rl <n>           rate limit
  -silent           suppress banner
  -nc               no color
  -cdn              check CDN membership
  -asn              show ASN
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


class DnsxWrapper(ToolWrapper):
    name = "dnsx"
    version_flag = "-version"

    _DEPTH_CONFIG = {
        "quick": {
            "threads": 50,
            "rate_limit": 500,
            "retry": 2,
            "record_types": ["-a", "-cname"],
            "cdn": False,
            "asn": False,
        },
        "standard": {
            "threads": 50,
            "rate_limit": 300,
            "retry": 3,
            "record_types": ["-a", "-aaaa", "-cname", "-mx", "-ns"],
            "cdn": True,
            "asn": True,
        },
        "exhaustive": {
            "threads": 50,
            "rate_limit": 200,
            "retry": 5,
            "record_types": ["-a", "-aaaa", "-cname", "-mx", "-ns", "-txt", "-soa"],
            "cdn": True,
            "asn": True,
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
        **kwargs: Any,
    ) -> dict:
        self.require()
        cfg = self._DEPTH_CONFIG[depth]
        started_at = _now()
        t0 = time.monotonic()

        findings: list[dict] = []
        errors: list[dict] = []

        _tmp_input = None
        if hosts_file and hosts_file.exists():
            input_path = hosts_file
        elif hosts:
            _tmp_input = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
            for h in hosts:
                _tmp_input.write(h + "\n")
            _tmp_input.flush()
            input_path = Path(_tmp_input.name)
        else:
            errors.append({"message": "dnsx: no hosts provided"})
            return self._write_empty(run_id, raw_output_dir, target, started_at, errors)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            out_path_tmp = Path(tmp.name)

        cmd = [
            "dnsx",
            "-l", str(input_path),
            "-o", str(out_path_tmp),
            "-json",
            "-silent",
            "-nc",
            "-resp",
            "-t", str(cfg["threads"]),
            "-rl", str(cfg["rate_limit"]),
            "-retry", str(cfg["retry"]),
        ]
        cmd.extend(cfg["record_types"])
        if cfg["cdn"]:
            cmd.append("-cdn")
        if cfg["asn"]:
            cmd.append("-asn")

        result = self._exec(cmd, timeout=1800)

        if result.returncode not in (0, 1):
            errors.append({
                "message": f"dnsx exited with code {result.returncode}",
                "stderr_excerpt": result.stderr[:500],
                "exit_code": result.returncode,
            })

        if out_path_tmp.exists():
            for line in out_path_tmp.read_text().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue

                host = entry.get("host", "")
                if not host:
                    continue
                if not self._is_in_scope(host, program):
                    continue

                ips = entry.get("a", [])
                cname = entry.get("cname", [])
                mx = entry.get("mx", [])
                ns = entry.get("ns", [])
                txt = entry.get("txt", [])

                evidence_parts = [f"Resolved: {host}"]
                if ips:
                    evidence_parts.append(f"A: {', '.join(ips[:5])}")
                if cname:
                    evidence_parts.append(f"CNAME: {', '.join(cname)}")

                finding = {
                    "type": "dns_record",
                    "host": host,
                    "evidence": " | ".join(evidence_parts),
                    "raw_output": {
                        "host": host,
                        "a": ips,
                        "aaaa": entry.get("aaaa", []),
                        "cname": cname,
                        "mx": mx,
                        "ns": ns,
                        "txt": txt,
                        "soa": entry.get("soa", []),
                        "cdn": entry.get("cdn", ""),
                        "asn": entry.get("asn", {}),
                        "status_code": entry.get("status_code", ""),
                    },
                }
                findings.append(finding)

            out_path_tmp.unlink(missing_ok=True)

        if _tmp_input:
            Path(_tmp_input.name).unlink(missing_ok=True)

        finished_at = _now()
        duration = time.monotonic() - t0
        status = "success" if not errors else ("partial" if findings else "failed")

        out_path = self._write_raw_output(
            run_id=run_id,
            raw_output_dir=raw_output_dir,
            target=target,
            invocation_command=" ".join(str(c) for c in cmd),
            started_at=started_at,
            finished_at=finished_at,
            duration_seconds=duration,
            status=status,
            findings=findings,
            errors=errors,
        )
        return {"raw_output_path": out_path, "findings_count": len(findings)}

    def _write_empty(self, run_id, raw_output_dir, target, started_at, errors):
        out_path = self._write_raw_output(
            run_id=run_id, raw_output_dir=raw_output_dir, target=target,
            invocation_command="dnsx (not run)", started_at=started_at,
            finished_at=_now(), duration_seconds=0, status="failed",
            findings=[], errors=errors,
        )
        return {"raw_output_path": out_path, "findings_count": 0}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
