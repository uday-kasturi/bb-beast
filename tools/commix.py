"""
Tool wrapper for commix — command injection scanner.

commix automatically detects and exploits command injection vulnerabilities.
We use detection-only mode (--level controls test depth, not exploitation).

CRITICAL: Only runs if "command_injection" is in allowed_test_types.

Flags:
  --url <url>           target URL
  --data <data>         POST data
  --level <1-3>         test level
  --timeout <secs>      timeout
  --retries <n>         retries
  --delay <secs>        delay between requests
  --random-agent        randomize user agent
  --batch               never ask for input
  --flush-session       fresh session
  --output-dir <dir>    output directory
  --technique <T>       injection techniques: C(lassic), T(imeBased), F(ileBased), S(emiBlind)
  --all-techniques      use all techniques
  -s <file>             load session from file
  --header <h>          custom header
  --cookie <c>          cookie
  --tamper <script>     tamper script for WAF evasion
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.base import ToolWrapper

log = logging.getLogger(__name__)


class CommixWrapper(ToolWrapper):
    name = "commix"
    version_flag = "--version"

    _DEPTH_CONFIG = {
        "quick": {
            "level": 1,
            "technique": "CT",   # Classic + TimeBased (fast)
            "delay": 0,
            "timeout": 30,
            "retries": 1,
            "tamper": "",
        },
        "standard": {
            "level": 2,
            "technique": "CTS",  # + SemiBlind
            "delay": 1,
            "timeout": 45,
            "retries": 2,
            "tamper": "",
        },
        "exhaustive": {
            "level": 3,
            "technique": "CTSF",  # All
            "delay": 2,
            "timeout": 60,
            "retries": 3,
            "tamper": "space2ifs",
        },
    }

    def run(
        self,
        target: str,
        depth: str,
        run_id: str,
        raw_output_dir: Path,
        program: dict,
        url: str | None = None,
        post_data: str | None = None,
        cookies: str | None = None,
        extra_headers: dict | None = None,
        **kwargs: Any,
    ) -> dict:
        if "command_injection" not in program.get("allowed_test_types", []):
            log.info("[commix] command_injection not in allowed_test_types — skipping")
            return self._write_skipped(run_id, raw_output_dir, target)

        self.require()
        cfg = self._DEPTH_CONFIG[depth]
        started_at = _now()
        t0 = time.monotonic()

        findings: list[dict] = []
        errors: list[dict] = []

        scan_url = url or f"https://{target}"
        output_dir = raw_output_dir / "commix_sessions"
        output_dir.mkdir(exist_ok=True)

        cmd = [
            "commix",
            "--url", scan_url,
            "--batch",
            "--random-agent",
            "--flush-session",
            "--output-dir", str(output_dir),
            "--level", str(cfg["level"]),
            "--technique", cfg["technique"],
            "--delay", str(cfg["delay"]),
            "--timeout", str(cfg["timeout"]),
            "--retries", str(cfg["retries"]),
        ]
        if post_data:
            cmd.extend(["--data", post_data])
        if cookies:
            cmd.extend(["--cookie", cookies])
        if extra_headers:
            for k, v in extra_headers.items():
                cmd.extend(["--header", f"{k}: {v}"])
        if cfg.get("tamper"):
            cmd.extend(["--tamper", cfg["tamper"]])

        result = self._exec(cmd, timeout=3600)

        if result.returncode not in (0, 1):
            errors.append({
                "message": f"commix exited with code {result.returncode}",
                "stderr_excerpt": result.stderr[:500],
                "exit_code": result.returncode,
            })

        stdout = result.stdout
        for line in stdout.splitlines():
            lower = line.lower()
            if any(kw in lower for kw in [
                "is vulnerable", "command injection", "backdoor",
                "shell prompt", "exploit"
            ]):
                findings.append({
                    "type": "command_injection",
                    "url": scan_url,
                    "evidence": line.strip(),
                    "raw_output": {
                        "url": scan_url,
                        "stdout_line": line.strip(),
                        "technique": cfg["technique"],
                        "level": cfg["level"],
                        "matched_at": scan_url,
                    },
                    "metadata": {"severity": "critical"},
                })

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
            invocation_command="commix (skipped)", started_at=_now(),
            finished_at=_now(), duration_seconds=0, status="success",
            findings=[], errors=[],
        )
        return {"raw_output_path": out_path, "findings_count": 0}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
