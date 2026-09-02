"""
Tool wrapper for masscan — ultra-fast port scanner.

masscan is used for initial fast port sweep across large IP ranges.
Output feeds into nmap for service detection. NEVER used alone for findings.

IMPORTANT: masscan requires root/sudo on most systems for raw packet sending.
The wrapper detects this and warns if not running as root.

Flags:
  <targets>         CIDR ranges or IPs
  -p <ports>        port range
  --rate <n>        packets per second
  --wait <secs>     wait after scan
  -oJ <file>        JSON output
  --banners         grab banners (slower)
  --exclude <range> exclude IP ranges (always exclude RFC1918)
  --source-ip <ip>  source IP for raw packets
  --router-mac <m>  router MAC (for raw packets)
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.base import ToolWrapper

log = logging.getLogger(__name__)

# Always exclude these from masscan (RFC1918 + loopback)
_ALWAYS_EXCLUDE = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8,0.0.0.0/8,240.0.0.0/4,255.255.255.255/32"


class MasscanWrapper(ToolWrapper):
    name = "masscan"
    version_flag = "--version"

    _DEPTH_CONFIG = {
        "quick":      {"rate": 10000, "ports": "80,443,8080,8443"},
        "standard":   {"rate": 5000,  "ports": "0-1023,8080,8443,8888,9090,9200"},
        "exhaustive": {"rate": 1000,  "ports": "0-65535"},
    }

    def run(
        self,
        target: str,
        depth: str,
        run_id: str,
        raw_output_dir: Path,
        program: dict,
        targets: list[str] | None = None,
        **kwargs: Any,
    ) -> dict:
        if "port_scan" not in program.get("allowed_test_types", []):
            log.info("[masscan] port_scan not in allowed_test_types — skipping")
            return self._write_skipped(run_id, raw_output_dir, target)

        if os.geteuid() != 0:
            log.warning("[masscan] not running as root — masscan requires root for raw packets. Skipping.")
            return self._write_skipped(run_id, raw_output_dir, target)

        self.require()
        cfg = self._DEPTH_CONFIG[depth]
        started_at = _now()
        t0 = time.monotonic()

        findings: list[dict] = []
        errors: list[dict] = []

        scan_targets = targets or [target]

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            out_path_tmp = Path(tmp.name)

        # Build out-of-scope exclusions from program
        out_ranges = program.get("out_of_scope", {}).get("ip_ranges", [])
        exclude_str = _ALWAYS_EXCLUDE
        if out_ranges:
            exclude_str += "," + ",".join(out_ranges)

        cmd = [
            "masscan",
            *scan_targets,
            "-p", cfg["ports"],
            "--rate", str(cfg["rate"]),
            "--wait", "5",
            "-oJ", str(out_path_tmp),
            "--exclude", exclude_str,
        ]

        result = self._exec(cmd, timeout=7200)

        if result.returncode not in (0, 1):
            errors.append({
                "message": f"masscan exited with code {result.returncode}",
                "stderr_excerpt": result.stderr[:300],
                "exit_code": result.returncode,
            })

        if out_path_tmp.exists():
            try:
                # masscan JSON is almost-valid JSON but wrapped weirdly — parse line by line
                content = out_path_tmp.read_text().strip()
                # Strip masscan's wrapper if present
                if content.startswith("[") and content.endswith(","):
                    content = content[:-1] + "]"
                data = json.loads(content)
                for entry in (data if isinstance(data, list) else []):
                    ip = entry.get("ip", "")
                    for port_info in entry.get("ports", []):
                        port = port_info.get("port", 0)
                        proto = port_info.get("proto", "tcp")
                        status = port_info.get("status", "")
                        if status != "open":
                            continue

                        findings.append({
                            "type": "open_port",
                            "ip": ip,
                            "port": int(port),
                            "protocol": proto,
                            "evidence": f"masscan: open port {port}/{proto} on {ip}",
                            "raw_output": {
                                "ip": ip,
                                "port": port,
                                "proto": proto,
                                "status": status,
                                "timestamp": entry.get("timestamp", ""),
                            },
                            "metadata": {"severity": "info"},
                        })
            except (json.JSONDecodeError, Exception) as exc:
                errors.append({"message": f"masscan output parse error: {exc}"})
            out_path_tmp.unlink(missing_ok=True)

        finished_at = _now()
        duration = time.monotonic() - t0
        status = "success" if not errors else ("partial" if findings else "failed")

        out_path = self._write_raw_output(
            run_id=run_id, raw_output_dir=raw_output_dir, target=target,
            invocation_command=" ".join(str(c) for c in cmd),
            started_at=started_at, finished_at=finished_at,
            duration_seconds=duration, status=status,
            findings=findings, errors=errors,
        )
        return {"raw_output_path": out_path, "findings_count": len(findings)}

    def _write_skipped(self, run_id, raw_output_dir, target):
        out_path = self._write_raw_output(
            run_id=run_id, raw_output_dir=raw_output_dir, target=target,
            invocation_command="masscan (skipped)", started_at=_now(),
            finished_at=_now(), duration_seconds=0, status="success",
            findings=[], errors=[],
        )
        return {"raw_output_path": out_path, "findings_count": 0}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
