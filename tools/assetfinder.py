"""
Tool wrapper for assetfinder — lightweight passive subdomain discovery.

assetfinder queries a small set of sources (crt.sh, certspotter, hackertarget,
reddit, etc.) quickly. Used as a fast complement to subfinder and amass.

Flags:
  --subs-only    only print subdomains (not root domain matches)
  <domain>       positional argument
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.base import ToolWrapper

log = logging.getLogger(__name__)


class AssetfinderWrapper(ToolWrapper):
    name = "assetfinder"
    version_flag = "--help"

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
        started_at = _now()
        t0 = time.monotonic()

        findings: list[dict] = []
        errors: list[dict] = []

        cmd = ["assetfinder", "--subs-only", target]
        result = self._exec(cmd, timeout=120)

        if result.returncode not in (0, 1):
            errors.append({
                "message": f"assetfinder exited with code {result.returncode}",
                "stderr_excerpt": result.stderr[:500],
                "exit_code": result.returncode,
            })

        for line in result.stdout.splitlines():
            host = line.strip().lower()
            if not host or "." not in host:
                continue
            if not self._is_in_scope(host, program):
                continue
            findings.append({
                "type": "subdomain",
                "host": host,
                "evidence": f"assetfinder passive discovery",
                "raw_output": {"host": host, "source": "assetfinder"},
            })

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
