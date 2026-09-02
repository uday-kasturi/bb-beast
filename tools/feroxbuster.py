"""
Tool wrapper for feroxbuster — recursive content discovery.

feroxbuster is a Rust-based content discovery tool that excels at recursive
scanning. Unlike ffuf (which needs -recursion flag), feroxbuster recursively
crawls discovered directories automatically.

Flags:
  -u <url>          target URL
  --stdin           read URLs from stdin
  -w <wordlist>     wordlist
  -o <file>         output file
  --json            JSON output
  --silent          suppress banner
  --no-state        don't save state
  -t <n>            threads
  -L <n>            limit requests per second
  --timeout <secs>  HTTP timeout
  --depth <n>       max recursion depth
  -x <extensions>   file extensions
  --filter-status   filter by status codes (exclude)
  --status-codes    filter by status codes (include)
  --auto-bail       stop scanning directories returning same response
  --auto-tune       automatically tune filters
  --redirects       follow redirects
  --insecure        ignore TLS errors
  -H <header>       custom header
  --cookies <c>     cookies
  --extract-links   extract links from response body
  --collect-words   collect words from response for wordlist expansion
  --collect-backups scan found paths with backup extensions added
  --smart           auto-bail + auto-tune
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

WORDLIST_DIR = Path(__file__).parent.parent / "config" / "wordlists"


def _wl(name: str) -> str:
    p = WORDLIST_DIR / name
    if not p.exists():
        log.warning("Wordlist not found: %s", p)
        return "/dev/null"
    return str(p)


class FeroxbusterWrapper(ToolWrapper):
    name = "feroxbuster"
    version_flag = "--version"

    _DEPTH_CONFIG = {
        "quick": {
            "wordlist": "common.txt",
            "threads": 50,
            "rate_limit": 200,
            "timeout": 7,
            "depth": 2,
            "extensions": "php,html,txt,js",
            "collect_backups": False,
            "collect_words": False,
            "smart": True,
            "time_limit": "120s",
        },
        "standard": {
            "wordlist": "raft-medium-directories.txt",
            "threads": 50,
            "rate_limit": 150,
            "timeout": 10,
            "depth": 3,
            "extensions": "php,html,htm,txt,js,json,xml,bak,backup,old,zip,sql,log,cfg,conf,env,yml",
            "collect_backups": True,
            "collect_words": True,
            "smart": True,
            "time_limit": "300s",
        },
        "exhaustive": {
            "wordlist": "raft-large-directories.txt",
            "threads": 40,
            "rate_limit": 100,
            "timeout": 15,
            "depth": 5,
            "extensions": (
                "php,html,htm,txt,js,json,xml,bak,backup,old,orig,zip,gz,tar,"
                "sql,db,sqlite,log,cfg,conf,config,env,yml,yaml,asp,aspx,jsp,"
                "do,action,cgi,pl,py,rb,sh,pem,key,crt"
            ),
            "collect_backups": True,
            "collect_words": True,
            "smart": False,  # exhaustive: don't auto-bail
            "time_limit": "600s",
        },
    }

    _FILTER_STATUS = "404,400,503"
    _INCLUDE_STATUS = "200,201,204,301,302,307,308,401,403,405"

    def run(
        self,
        target: str,
        depth: str,
        run_id: str,
        raw_output_dir: Path,
        program: dict,
        base_url: str | None = None,
        extra_headers: dict | None = None,
        cookies: str | None = None,
        **kwargs: Any,
    ) -> dict:
        self.require()
        cfg = self._DEPTH_CONFIG[depth]
        started_at = _now()
        t0 = time.monotonic()

        findings: list[dict] = []
        errors: list[dict] = []

        if not base_url:
            base_url = f"https://{target}"

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            out_path_tmp = Path(tmp.name)

        cmd = [
            "feroxbuster",
            "-u", base_url,
            "-w", _wl(cfg["wordlist"]),
            "-o", str(out_path_tmp),
            "--json",
            "--silent",
            "--no-state",
            "--redirects",
            "--insecure",
            "--extract-links",
            "-t", str(cfg["threads"]),
            "-L", str(cfg["rate_limit"]),
            "--timeout", str(cfg["timeout"]),
            "--depth", str(cfg["depth"]),
            "-x", cfg["extensions"],
            "--filter-status", self._FILTER_STATUS,
        ]
        if cfg.get("time_limit"):
            cmd.extend(["--time-limit", cfg["time_limit"]])
        if cfg["smart"]:
            cmd.append("--smart")
        else:
            cmd.append("--auto-tune")
        if cfg["collect_backups"]:
            cmd.append("--collect-backups")
        if cfg["collect_words"]:
            cmd.append("--collect-words")
        if extra_headers:
            for k, v in extra_headers.items():
                cmd.extend(["-H", f"{k}: {v}"])
        if cookies:
            cmd.extend(["--cookies", cookies])

        # Hard timeout = time_limit + 60s grace for startup/shutdown
        time_limit_secs = int(cfg.get("time_limit", "600s").rstrip("s"))
        result = self._exec(cmd, timeout=time_limit_secs + 60)

        if result.returncode not in (0, 1):
            errors.append({
                "message": f"feroxbuster exited with code {result.returncode}",
                "stderr_excerpt": result.stderr[:500],
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

                if entry.get("type") != "response":
                    continue

                url = entry.get("url", "")
                status = entry.get("status", 0)
                length = entry.get("content_length", 0)

                try:
                    from urllib.parse import urlparse
                    host = urlparse(url).hostname or ""
                except Exception:
                    host = ""

                if host and not self._is_in_scope(host, program):
                    continue

                findings.append({
                    "type": "exposure",
                    "url": url,
                    "host": host,
                    "evidence": f"feroxbuster: {status} {url} (len={length})",
                    "raw_output": {
                        "url": url,
                        "status": status,
                        "content_length": length,
                        "words": entry.get("word_count", 0),
                        "lines": entry.get("line_count", 0),
                        "method": entry.get("method", "GET"),
                    },
                    "metadata": {"severity": "info"},
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
