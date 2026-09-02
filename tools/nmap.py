"""
Tool wrapper for nmap — port scanning and service detection.

Used for:
- Port discovery (TCP SYN scan)
- Service/version detection
- OS fingerprinting (exhaustive)
- NSE script execution for vulnerability detection

NSE script categories used:
  quick:      default
  standard:   default, safe, vuln
  exhaustive: default, safe, vuln, discovery, auth

CRITICAL: Always check "port_scan" is in allowed_test_types.

Flags:
  -sS              TCP SYN scan (stealth, requires root; falls back to -sT)
  -sV              service/version detection
  -sC              default scripts (same as --script=default)
  -O               OS detection
  -oJ <file>       JSON output
  -p <ports>       port range
  --top-ports <n>  scan top N ports
  -T<0-5>          timing template (3=normal, 4=aggressive)
  --open           only show open ports
  --version-intensity <0-9>  version detection intensity
  --script <cats>  script categories
  --script-args    script arguments
  -n               no DNS resolution (we already did this)
  -Pn              skip host discovery (assume up, we verified with httpx)
  --min-rate <n>   minimum packet rate
  --max-rate <n>   maximum packet rate
  --max-retries <n> max retries
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


class NmapWrapper(ToolWrapper):
    name = "nmap"
    version_flag = "--version"

    _DEPTH_CONFIG = {
        "quick": {
            "timing": 4,
            "top_ports": 100,
            "version_intensity": 5,
            "scripts": "default",
            "os_detect": False,
            "min_rate": 300,
            "max_rate": 1000,
            "max_retries": 2,
        },
        "standard": {
            "timing": 3,
            "top_ports": 1000,
            "version_intensity": 7,
            "scripts": "default,safe,vuln",
            "os_detect": False,
            "min_rate": 100,
            "max_rate": 500,
            "max_retries": 3,
        },
        "exhaustive": {
            "timing": 3,
            "top_ports": None,  # all ports
            "port_range": "1-65535",
            "version_intensity": 9,
            "scripts": "default,safe,vuln,discovery,auth",
            "os_detect": True,
            "min_rate": 50,
            "max_rate": 200,
            "max_retries": 6,
        },
    }

    _SERVICE_SEVERITY = {
        "ftp":      "medium",
        "telnet":   "high",
        "smtp":     "low",
        "http":     "info",
        "https":    "info",
        "ssh":      "info",
        "rdp":      "medium",
        "vnc":      "high",
        "mongodb":  "high",
        "redis":    "high",
        "elasticsearch": "high",
        "mysql":    "high",
        "postgres": "high",
        "mssql":    "high",
        "oracle":   "high",
        "memcached": "high",
        "cassandra": "high",
        "zookeeper": "medium",
        "docker":   "high",
        "kubernetes": "high",
        "etcd":     "high",
    }

    def run(
        self,
        target: str,
        depth: str,
        run_id: str,
        raw_output_dir: Path,
        program: dict,
        hosts: list[str] | None = None,
        **kwargs: Any,
    ) -> dict:
        if "port_scan" not in program.get("allowed_test_types", []):
            log.info("[nmap] port_scan not in allowed_test_types — skipping")
            return self._write_skipped(run_id, raw_output_dir, target)

        self.require()
        cfg = self._DEPTH_CONFIG[depth]
        started_at = _now()
        t0 = time.monotonic()

        findings: list[dict] = []
        errors: list[dict] = []

        targets = hosts or [target]

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            out_path_tmp = Path(tmp.name)

        cmd = [
            "nmap",
            "-sV",
            "--open",
            "-oJ", str(out_path_tmp),
            "-n",
            "-Pn",
            f"-T{cfg['timing']}",
            "--version-intensity", str(cfg["version_intensity"]),
            "--script", cfg["scripts"],
            "--min-rate", str(cfg["min_rate"]),
            "--max-rate", str(cfg["max_rate"]),
            "--max-retries", str(cfg["max_retries"]),
        ]
        if cfg.get("top_ports"):
            cmd.extend(["--top-ports", str(cfg["top_ports"])])
        elif cfg.get("port_range"):
            cmd.extend(["-p", cfg["port_range"]])
        if cfg.get("os_detect"):
            cmd.append("-O")
        cmd.extend(targets)

        result = self._exec(cmd, timeout=7200)

        if result.returncode not in (0, 1):
            errors.append({
                "message": f"nmap exited with code {result.returncode}",
                "stderr_excerpt": result.stderr[:500],
                "exit_code": result.returncode,
            })

        if out_path_tmp.exists():
            try:
                data = json.loads(out_path_tmp.read_text())
                for host_entry in data.get("hosts", []):
                    ip = ""
                    hostname = ""
                    for addr in host_entry.get("addresses", []):
                        if addr.get("addrtype") == "ipv4":
                            ip = addr["addr"]
                    for hn in host_entry.get("hostnames", []):
                        if hn.get("name"):
                            hostname = hn["name"]
                            break

                    check_host = hostname or ip
                    if check_host and not self._is_in_scope(check_host, program):
                        continue

                    for port_entry in host_entry.get("ports", []):
                        port_id = port_entry.get("portid", "")
                        protocol = port_entry.get("protocol", "tcp")
                        state = port_entry.get("state", {}).get("state", "")
                        if state != "open":
                            continue

                        service = port_entry.get("service", {})
                        svc_name = service.get("name", "")
                        svc_product = service.get("product", "")
                        svc_version = service.get("version", "")
                        svc_extra = service.get("extrainfo", "")

                        severity = self._SERVICE_SEVERITY.get(svc_name.lower(), "info")

                        evidence = f"Open port {port_id}/{protocol}: {svc_name}"
                        if svc_product:
                            evidence += f" ({svc_product} {svc_version})".rstrip()

                        script_outputs = []
                        for script in port_entry.get("scripts", []):
                            script_outputs.append({
                                "id": script.get("id", ""),
                                "output": script.get("output", ""),
                            })

                        findings.append({
                            "type": "open_port",
                            "host": hostname or ip,
                            "ip": ip,
                            "port": int(port_id) if str(port_id).isdigit() else 0,
                            "protocol": protocol,
                            "evidence": evidence,
                            "raw_output": {
                                "port": port_id,
                                "protocol": protocol,
                                "state": state,
                                "service": svc_name,
                                "product": svc_product,
                                "version": svc_version,
                                "extra_info": svc_extra,
                                "scripts": script_outputs,
                                "ip": ip,
                                "hostname": hostname,
                            },
                            "metadata": {"severity": severity},
                        })
            except (json.JSONDecodeError, KeyError) as exc:
                errors.append({"message": f"nmap output parse error: {exc}"})
            out_path_tmp.unlink(missing_ok=True)

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

    def _write_skipped(self, run_id, raw_output_dir, target):
        out_path = self._write_raw_output(
            run_id=run_id, raw_output_dir=raw_output_dir, target=target,
            invocation_command="nmap (skipped)", started_at=_now(),
            finished_at=_now(), duration_seconds=0, status="success",
            findings=[], errors=[],
        )
        return {"raw_output_path": out_path, "findings_count": 0}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
