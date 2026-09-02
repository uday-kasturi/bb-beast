"""
Tool wrapper for gowitness — web screenshot tool.

gowitness takes screenshots of URLs using a headless browser.
Used in exhaustive recon to visually surface interesting targets
(login pages, admin panels, unusual apps).

Flags:
  file                  subcommand: screenshot list of URLs from file
  -f <file>             input file of URLs
  --screenshot-path     output directory for screenshots
  --db-path             SQLite DB path
  --threads <n>         concurrent workers
  --timeout <secs>      browser timeout per URL
  --resolution <WxH>    screenshot resolution
  --user-agent <ua>     custom user agent
  --no-http             skip non-HTTPS (disabled — we want both)
  --fullpage            take full-page screenshot
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


class GoWitnessWrapper(ToolWrapper):
    name = "gowitness"
    version_flag = "version"

    _DEPTH_CONFIG = {
        "quick":      {"threads": 4, "timeout": 10, "resolution": "1440,900"},
        "standard":   {"threads": 4, "timeout": 15, "resolution": "1440,900"},
        "exhaustive": {"threads": 6, "timeout": 20, "resolution": "1440,900"},
    }

    def run(
        self,
        target: str,
        depth: str,
        run_id: str,
        raw_output_dir: Path,
        program: dict,
        urls: list[str] | None = None,
        urls_file: Path | None = None,
        output_dir: Path | None = None,
        **kwargs: Any,
    ) -> dict:
        self.require()
        cfg = self._DEPTH_CONFIG[depth]
        started_at = _now()
        t0 = time.monotonic()

        findings: list[dict] = []
        errors: list[dict] = []

        _tmp_input = None
        if urls_file and urls_file.exists():
            input_path = urls_file
        elif urls:
            _tmp_input = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
            for u in urls:
                _tmp_input.write(u + "\n")
            _tmp_input.flush()
            input_path = Path(_tmp_input.name)
        else:
            errors.append({"message": "gowitness: no urls provided"})
            return self._write_empty(run_id, raw_output_dir, target, started_at, errors)

        screenshots_dir = output_dir or (raw_output_dir.parent / "screenshots")
        screenshots_dir.mkdir(parents=True, exist_ok=True)
        db_path = screenshots_dir / "gowitness.db"

        cmd = [
            "gowitness", "file",
            "-f", str(input_path),
            "--screenshot-path", str(screenshots_dir),
            "--db-path", str(db_path),
            "--threads", str(cfg["threads"]),
            "--timeout", str(cfg["timeout"]),
            "--resolution", cfg["resolution"],
            "--fullpage",
            "--user-agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        ]

        result = self._exec(cmd, timeout=3600)

        if result.returncode not in (0, 1):
            errors.append({
                "message": f"gowitness exited with code {result.returncode}",
                "stderr_excerpt": result.stderr[:300],
                "exit_code": result.returncode,
            })

        # Report the screenshots taken
        for screenshot in screenshots_dir.glob("*.png"):
            # gowitness names files after the URL (encoded)
            findings.append({
                "type": "tech_detection",
                "url": _decode_gowitness_filename(screenshot.stem),
                "evidence": f"Screenshot taken: {screenshot.name}",
                "raw_output": {
                    "screenshot_path": str(screenshot),
                    "filename": screenshot.name,
                },
            })

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
            invocation_command="gowitness (not run)", started_at=started_at,
            finished_at=_now(), duration_seconds=0, status="failed",
            findings=[], errors=errors,
        )
        return {"raw_output_path": out_path, "findings_count": 0}


def _decode_gowitness_filename(stem: str) -> str:
    """Best-effort decode of gowitness screenshot filename back to URL."""
    return stem.replace("_", "/").replace("http/", "http://").replace("https/", "https://")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
