"""
Tool wrapper for subfinder — passive subdomain discovery.

subfinder uses passive sources (VirusTotal, Shodan, cert transparency, etc.)
to enumerate subdomains without touching the target directly.

Flags used:
  -d <domain>           target domain
  -o <file>             output file
  -oJ                   output as JSON lines
  -all                  use all sources (slower, exhaustive)
  -recursive            recursive subdomain discovery
  -t <threads>          number of threads (default: 10)
  -timeout <secs>       DNS resolution timeout
  -silent               suppress banner, only print results
  -v                    verbose (for standard/exhaustive)
  -cs                   show source in output
  -duc                  disable update check
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


class SubfinderWrapper(ToolWrapper):
    name = "subfinder"
    version_flag = "-version"

    # Depth → flag sets
    _DEPTH_CONFIG = {
        "quick": {
            "threads": 10,
            "timeout": 30,
            "all_sources": False,
            "recursive": False,
        },
        "standard": {
            "threads": 20,
            "timeout": 60,
            "all_sources": False,
            "recursive": True,
        },
        "exhaustive": {
            "threads": 30,
            "timeout": 120,
            "all_sources": True,
            "recursive": True,
        },
    }

    def run(
        self,
        target: str,
        depth: str,
        run_id: str,
        raw_output_dir: Path,
        program: dict,
        **kwargs: Any,
    ) -> dict:
        self.require()

        cfg = self._DEPTH_CONFIG[depth]
        started_at = _now()
        t0 = time.monotonic()

        findings: list[dict] = []
        errors: list[dict] = []

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            tmp_path = Path(tmp.name)

        cmd = [
            "subfinder",
            "-d", target,
            "-o", str(tmp_path),
            "-oJ",
            "-silent",
            "-duc",
            "-cs",
            "-t", str(cfg["threads"]),
            "-timeout", str(cfg["timeout"]),
        ]
        if cfg["all_sources"]:
            cmd.append("-all")
        if cfg["recursive"]:
            cmd.append("-recursive")

        result = self._exec(cmd)

        if result.returncode not in (0, 1):
            errors.append({
                "message": f"subfinder exited with code {result.returncode}",
                "stderr_excerpt": result.stderr[:500],
                "exit_code": result.returncode,
            })

        # Parse JSON lines output
        if tmp_path.exists():
            for line in tmp_path.read_text().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    subdomain = entry.get("host", "")
                    if not subdomain:
                        continue
                    if not self._is_in_scope(subdomain, program):
                        continue
                    findings.append({
                        "type": "subdomain",
                        "host": subdomain,
                        "evidence": f"Discovered via {entry.get('sources', ['unknown'])}",
                        "raw_output": entry,
                    })
                except json.JSONDecodeError:
                    # Some lines may not be JSON, skip
                    pass
            tmp_path.unlink(missing_ok=True)

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


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
