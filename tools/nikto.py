"""
Tool wrapper for nikto — web server misconfiguration scanner.

nikto checks for:
- Outdated server software
- Default files and CGI vulnerabilities
- Dangerous HTTP methods
- Misconfigured headers
- Known vulnerabilities

Note: nikto is noisy and produces many false positives.
Confidence weights are lower for nikto findings (handled in confidence.py).

Flags:
  -h <host>         target host
  -p <port>         port
  -o <file>         output file
  -Format json      output format
  -Tuning <t>       test categories (0-9, x)
  -timeout <secs>   timeout
  -maxtime <secs>   max scan time
  -useragent <ua>   user agent
  -nointeractive    batch mode
  -ask no           never ask
  -ssl              force SSL
  -Plugins <list>   specific plugins to run
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


class NiktoWrapper(ToolWrapper):
    name = "nikto"
    version_flag = "-Version"

    # Tuning codes:
    # 0 = File Upload, 1 = Interesting File / Seen in logs
    # 2 = Misconfiguration / Default File, 3 = Info Disclosure
    # 4 = Injection (XSS/Script/HTML), 5 = Remote File Retrieval (Inside Web Root)
    # 6 = Denial of Service, 7 = Remote File Retrieval (Server Wide)
    # 8 = Command Execution / Remote Shell, 9 = SQL Injection
    # a = Authentication Bypass, b = Software Identification
    # c = Remote Source Inclusion, x = Reverse Tuning (exclude)
    _DEPTH_CONFIG = {
        "quick":      {"tuning": "1234ab",   "maxtime": "300s",  "timeout": 10},
        "standard":   {"tuning": "123457ab", "maxtime": "600s",  "timeout": 15},
        "exhaustive": {"tuning": "012345789abcx6", "maxtime": "1800s", "timeout": 20},
    }

    def run(
        self,
        target: str,
        depth: str,
        run_id: str,
        raw_output_dir: Path,
        program: dict,
        url: str | None = None,
        ssl: bool = True,
        port: int | None = None,
        **kwargs: Any,
    ) -> dict:
        self.require()
        cfg = self._DEPTH_CONFIG[depth]
        started_at = _now()
        t0 = time.monotonic()

        findings: list[dict] = []
        errors: list[dict] = []

        host = url or target

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            out_path_tmp = Path(tmp.name)

        cmd = [
            "nikto",
            "-h", host,
            "-o", str(out_path_tmp),
            "-Format", "json",
            "-nointeractive",
            "-ask", "no",
            "-Tuning", cfg["tuning"],
            "-maxtime", cfg["maxtime"],
            "-timeout", str(cfg["timeout"]),
            "-useragent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        ]
        if ssl:
            cmd.append("-ssl")
        if port:
            cmd.extend(["-p", str(port)])

        result = self._exec(cmd, timeout=7200)

        if result.returncode not in (0, 1):
            errors.append({
                "message": f"nikto exited with code {result.returncode}",
                "stderr_excerpt": result.stderr[:500],
                "exit_code": result.returncode,
            })

        if out_path_tmp.exists():
            try:
                data = json.loads(out_path_tmp.read_text())
                vulnerabilities = data.get("vulnerabilities", [])
                for vuln in vulnerabilities:
                    url_found = vuln.get("url", host)
                    msg = vuln.get("msg", "")
                    method = vuln.get("method", "GET")
                    osvdb = vuln.get("OSVDBID", "")
                    osvdb_link = vuln.get("OSVDBLINK", "")

                    if not self._is_in_scope(target, program):
                        continue

                    findings.append({
                        "type": "misconfiguration",
                        "url": url_found,
                        "host": target,
                        "evidence": msg,
                        "raw_output": {
                            "url": url_found,
                            "method": method,
                            "message": msg,
                            "osvdb_id": osvdb,
                            "osvdb_link": osvdb_link,
                        },
                        "metadata": {"severity": "low"},
                    })
            except (json.JSONDecodeError, Exception) as exc:
                errors.append({"message": f"nikto output parse error: {exc}"})
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


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
