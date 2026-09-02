"""
Tool wrapper for naabu — fast port scanner optimized for bug bounty.

naabu is faster than nmap for initial port discovery. Used to:
1. Quick-discover open ports across many hosts
2. Feed confirmed open ports back to nmap for service detection

Flags:
  -l <file>         input list of hosts
  -host <h>         single host
  -o <file>         output file
  -json             JSON output
  -silent           suppress banner
  -nc               no color
  -p <ports>        specific ports
  -top-ports <n>    top N ports
  -exclude-ports <> exclude ports
  -c <n>            concurrency
  -rate <n>         packet rate
  -timeout <ms>     timeout per port
  -retries <n>      retries
  -ping             ping before scanning
  -Pn               skip ping (assume up)
  -s <syn/connect>  scan type (syn requires root)
  -interface-list   list interfaces
  -exclude-cdn      exclude CDN IPs (they rate-limit aggressively)
  -service-discovery run nmap service detection on open ports
  -nmap-cli <cmd>   custom nmap command for service detection
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


class NaabuWrapper(ToolWrapper):
    name = "naabu"
    version_flag = "-version"

    _DEPTH_CONFIG = {
        "quick": {
            "top_ports": 100,
            "concurrency": 1000,
            "rate": 1000,
            "timeout": 1000,
            "retries": 1,
            "exclude_cdn": True,
        },
        "standard": {
            "top_ports": 1000,
            "concurrency": 500,
            "rate": 500,
            "timeout": 1500,
            "retries": 2,
            "exclude_cdn": True,
        },
        "exhaustive": {
            "ports": "1-65535",
            "concurrency": 250,
            "rate": 250,
            "timeout": 2000,
            "retries": 3,
            "exclude_cdn": False,
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
        if "port_scan" not in program.get("allowed_test_types", []):
            log.info("[naabu] port_scan not in allowed_test_types — skipping")
            return self._write_skipped(run_id, raw_output_dir, target)

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
            errors.append({"message": "naabu: no hosts provided"})
            return self._write_empty(run_id, raw_output_dir, target, started_at, errors)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            out_path_tmp = Path(tmp.name)

        cmd = [
            "naabu",
            "-l", str(input_path),
            "-o", str(out_path_tmp),
            "-json",
            "-silent",
            "-nc",
            "-Pn",
            "-c", str(cfg["concurrency"]),
            "-rate", str(cfg["rate"]),
            "-timeout", str(cfg["timeout"]),
            "-retries", str(cfg["retries"]),
        ]
        if cfg.get("top_ports"):
            cmd.extend(["-top-ports", str(cfg["top_ports"])])
        elif cfg.get("ports"):
            cmd.extend(["-p", cfg["ports"]])
        if cfg.get("exclude_cdn"):
            cmd.append("-exclude-cdn")

        result = self._exec(cmd, timeout=7200)

        if result.returncode not in (0, 1):
            errors.append({
                "message": f"naabu exited with code {result.returncode}",
                "stderr_excerpt": result.stderr[:300],
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
                port = entry.get("port", 0)
                ip = entry.get("ip", "")

                if host and not self._is_in_scope(host, program):
                    continue

                findings.append({
                    "type": "open_port",
                    "host": host,
                    "ip": ip,
                    "port": int(port),
                    "protocol": "tcp",
                    "evidence": f"Open port {port}/tcp on {host or ip}",
                    "raw_output": {
                        "host": host,
                        "ip": ip,
                        "port": port,
                    },
                    "metadata": {"severity": "info"},
                })
            out_path_tmp.unlink(missing_ok=True)

        if _tmp_input:
            Path(_tmp_input.name).unlink(missing_ok=True)

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
            invocation_command="naabu (skipped)", started_at=_now(),
            finished_at=_now(), duration_seconds=0, status="success",
            findings=[], errors=[],
        )
        return {"raw_output_path": out_path, "findings_count": 0}

    def _write_empty(self, run_id, raw_output_dir, target, started_at, errors):
        out_path = self._write_raw_output(
            run_id=run_id, raw_output_dir=raw_output_dir, target=target,
            invocation_command="naabu (not run)", started_at=started_at,
            finished_at=_now(), duration_seconds=0, status="failed",
            findings=[], errors=errors,
        )
        return {"raw_output_path": out_path, "findings_count": 0}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
