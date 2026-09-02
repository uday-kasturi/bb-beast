"""
Tool wrapper for waybackurls — historical URL retrieval from Wayback Machine.

Fetches all URLs ever captured for a domain from archive.org.
Useful for finding:
- Forgotten endpoints
- Old API versions
- Backup files (.bak, .old, .zip)
- Config files accidentally committed

Flags:
  <domain>      positional — domain to fetch URLs for
  -no-subs      don't include subdomains (we handle this at chain level)
  -dates        show date of capture
"""

from __future__ import annotations

import logging
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.base import ToolWrapper

log = logging.getLogger(__name__)

# Extensions and patterns worth keeping from historical URLs
_INTERESTING_EXTENSIONS = {
    ".php", ".asp", ".aspx", ".jsp", ".do", ".action",
    ".json", ".xml", ".yaml", ".yml", ".toml", ".env",
    ".bak", ".backup", ".old", ".orig", ".tmp", ".swp",
    ".sql", ".db", ".sqlite", ".gz", ".zip", ".tar",
    ".log", ".txt", ".cfg", ".conf", ".config", ".ini",
    ".pem", ".key", ".crt", ".p12", ".pfx",
}

_INTERESTING_PATTERNS = re.compile(
    r"(admin|api|v[0-9]+|debug|test|dev|staging|internal|"
    r"backup|config|secret|token|auth|oauth|login|upload|"
    r"shell|cmd|exec|eval|include|require|redirect|callback|"
    r"webhook|graphql|swagger|openapi)",
    re.IGNORECASE,
)


class WaybackurlsWrapper(ToolWrapper):
    name = "waybackurls"
    version_flag = "-h"

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

        # waybackurls reads from stdin or takes domain as arg depending on version
        # Most versions: echo domain | waybackurls
        import subprocess
        cmd_str = f"echo {target} | waybackurls"
        log.info("[waybackurls] $ %s", cmd_str)

        try:
            proc = subprocess.run(
                ["waybackurls", target],
                capture_output=True, text=True, timeout=300,
            )
            output = proc.stdout
            if proc.returncode not in (0, 1):
                errors.append({
                    "message": f"waybackurls exited with code {proc.returncode}",
                    "stderr_excerpt": proc.stderr[:300],
                    "exit_code": proc.returncode,
                })
        except subprocess.TimeoutExpired:
            output = ""
            errors.append({"message": "waybackurls timed out after 300s"})

        all_urls = [u.strip() for u in output.splitlines() if u.strip()]
        log.info("[waybackurls] %d raw URLs for %s", len(all_urls), target)

        for url in all_urls:
            # Scope check — extract host from URL
            try:
                from urllib.parse import urlparse
                host = urlparse(url).hostname or ""
            except Exception:
                host = ""

            if host and not self._is_in_scope(host, program):
                continue

            # Classify interestingness
            is_interesting = False
            lower = url.lower()
            for ext in _INTERESTING_EXTENSIONS:
                if lower.endswith(ext) or (ext + "?") in lower:
                    is_interesting = True
                    break
            if not is_interesting and _INTERESTING_PATTERNS.search(url):
                is_interesting = True

            if not is_interesting and depth != "exhaustive":
                continue  # in non-exhaustive mode, only keep interesting URLs

            findings.append({
                "type": "historical_url",
                "url": url,
                "host": host,
                "evidence": f"Historical URL from Wayback Machine: {url}",
                "raw_output": {
                    "url": url,
                    "source": "waybackurls",
                    "interesting": is_interesting,
                },
            })

        finished_at = _now()
        duration = time.monotonic() - t0
        status = "success" if not errors else ("partial" if findings else "failed")

        out_path = self._write_raw_output(
            run_id=run_id,
            raw_output_dir=raw_output_dir,
            target=target,
            invocation_command=f"waybackurls {target}",
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
