"""
Tool wrapper for gau (getallurls) — URL collection from multiple sources.

Sources: AlienVault OTX, Wayback Machine, Common Crawl, URLScan.io

gau complements waybackurls by pulling from sources waybackurls doesn't hit.

Flags:
  --subs            include subdomains
  --providers       comma-separated list of providers to use
  --retries <n>     retry failed requests
  --threads <n>     concurrent workers
  --timeout <secs>  request timeout
  --from <YYYYMM>   earliest date to fetch (optional)
  --blacklist <ext> comma-separated extensions to exclude
  --json            JSON output
  --o <file>        output file
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


class GauWrapper(ToolWrapper):
    name = "gau"
    version_flag = "--version"

    _DEPTH_CONFIG = {
        "quick": {
            "providers": "wayback,otx",
            "threads": 5,
            "retries": 2,
            "timeout": 30,
            "subs": False,
        },
        "standard": {
            "providers": "wayback,otx,commoncrawl",
            "threads": 10,
            "retries": 3,
            "timeout": 45,
            "subs": True,
        },
        "exhaustive": {
            "providers": "wayback,otx,commoncrawl,urlscan",
            "threads": 15,
            "retries": 5,
            "timeout": 60,
            "subs": True,
        },
    }

    # Extensions to skip — binary/media files are not useful
    _BLACKLIST = "png,jpg,gif,jpeg,webp,svg,ico,css,woff,woff2,ttf,eot,mp4,mp3,m4a,avi"

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
            out_path_tmp = Path(tmp.name)

        cmd = [
            "gau",
            target,
            "--json",
            "--o", str(out_path_tmp),
            "--providers", cfg["providers"],
            "--threads", str(cfg["threads"]),
            "--retries", str(cfg["retries"]),
            "--timeout", str(cfg["timeout"]),
            "--blacklist", self._BLACKLIST,
        ]
        if cfg["subs"]:
            cmd.append("--subs")

        result = self._exec(cmd, timeout=600)

        if result.returncode not in (0, 1):
            errors.append({
                "message": f"gau exited with code {result.returncode}",
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
                    url = entry.get("url", "")
                except (json.JSONDecodeError, AttributeError):
                    url = line

                if not url:
                    continue

                try:
                    from urllib.parse import urlparse
                    host = urlparse(url).hostname or ""
                except Exception:
                    host = ""

                if host and not self._is_in_scope(host, program):
                    continue

                findings.append({
                    "type": "historical_url",
                    "url": url,
                    "host": host,
                    "evidence": f"URL from gau ({cfg['providers']}): {url}",
                    "raw_output": {"url": url, "source": "gau"},
                })
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


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
