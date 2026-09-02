"""
Tool wrapper for ffuf — fast web fuzzer for directory and parameter discovery.

ffuf is used to:
1. Directory/file brute-force — find hidden endpoints
2. Parameter fuzzing — discover hidden GET/POST parameters
3. Virtual host fuzzing — discover hidden vhosts
4. Extension fuzzing — find backup/config files

Wordlists (expected in /config/wordlists/):
  - directories: common.txt, raft-medium-directories.txt, raft-large-directories.txt
  - params: burp-parameter-names.txt, raft-medium-words.txt
  - extensions: web-extensions.txt

Flags:
  -u <url>          target URL with FUZZ placeholder
  -w <wordlist>     wordlist (use FUZZ as keyword)
  -o <file>         output file
  -of json          output format
  -c                colorize output
  -t <n>            threads
  -rate <n>         rate limit (requests/sec)
  -timeout <secs>   HTTP timeout
  -recursion        recursive fuzzing
  -recursion-depth  max recursion depth
  -fc <codes>       filter HTTP status codes (exclude)
  -mc <codes>       match HTTP status codes (include)
  -fl <lines>       filter by response line count
  -fs <size>        filter by response size
  -fw <words>       filter by response word count
  -ac               auto-calibrate filters
  -e <extensions>   comma-separated extensions to append
  -H <header>       add custom header
  -X <method>       HTTP method
  -b <cookies>      cookies
  -maxtime <secs>   max total run time
  -silent           suppress progress
  -v                verbose output
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
    """Return wordlist path, fall back to /dev/null if not found."""
    p = WORDLIST_DIR / name
    if not p.exists():
        log.warning("Wordlist not found: %s", p)
        return "/dev/null"
    return str(p)


class FfufWrapper(ToolWrapper):
    name = "ffuf"
    version_flag = "-V"

    _DEPTH_CONFIG = {
        "quick": {
            "dir_wordlist": "common.txt",
            "threads": 40,
            "rate": 150,
            "timeout": 10,
            "recursion": False,
            "extensions": ".php,.html,.txt",
            "maxtime": 60,   # 1 min — quick means quick
        },
        "standard": {
            "dir_wordlist": "raft-medium-directories.txt",
            "threads": 40,
            "rate": 100,
            "timeout": 8,
            "recursion": True,
            "recursion_depth": 2,
            "extensions": ".php,.html,.txt,.js,.json,.xml,.bak,.backup,.old,.zip,.gz",
            "maxtime": 90,  # 90s hard cap per host
        },
        "exhaustive": {
            "dir_wordlist": "raft-large-directories.txt",
            "threads": 30,
            "rate": 75,
            "timeout": 15,
            "recursion": True,
            "recursion_depth": 3,
            "extensions": (
                ".php,.html,.htm,.txt,.js,.json,.xml,.bak,.backup,.old,.orig,"
                ".zip,.gz,.tar,.sql,.db,.log,.cfg,.conf,.config,.env,.yml,.yaml,"
                ".asp,.aspx,.jsp,.do,.action,.cgi,.pl,.py,.rb,.sh"
            ),
            "maxtime": 600,
        },
    }

    # Status codes to always filter out (not interesting)
    _FILTER_CODES = "404,400,500,503"
    # Status codes to always include
    _MATCH_CODES = "200,201,202,204,301,302,307,308,401,403,405"

    def run(
        self,
        target: str,
        depth: str,
        run_id: str,
        raw_output_dir: Path,
        program: dict,
        base_url: str | None = None,
        mode: str = "directory",  # directory | params | vhost
        extra_headers: dict | None = None,
        cookies: str | None = None,
        **kwargs: Any,
    ) -> dict:
        """
        Args:
            base_url:  URL to fuzz. If None, uses https://<target>/FUZZ
            mode:      directory, params, or vhost
            extra_headers: Dict of headers to add
            cookies:   Cookie string
        """
        self.require()
        cfg = self._DEPTH_CONFIG[depth]
        started_at = _now()
        t0 = time.monotonic()

        findings: list[dict] = []
        errors: list[dict] = []

        if not base_url:
            base_url = f"https://{target}/FUZZ"

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            out_path_tmp = Path(tmp.name)

        wordlist = _wl(cfg["dir_wordlist"])

        cmd = [
            "ffuf",
            "-u", base_url,
            "-w", f"{wordlist}:FUZZ",
            "-o", str(out_path_tmp),
            "-of", "json",
            "-t", str(cfg["threads"]),
            "-rate", str(cfg["rate"]),
            "-timeout", str(cfg["timeout"]),
            "-fc", self._FILTER_CODES,
            "-mc", self._MATCH_CODES,
            "-maxtime", str(cfg["maxtime"]),
            "-ac",
            "-s",          # silent mode (ffuf v2+; was -silent in older versions)
            "-noninteractive",
        ]
        if cfg.get("extensions"):
            cmd.extend(["-e", cfg["extensions"]])
        if cfg.get("recursion"):
            # Only enable recursion when FUZZ is in the URL path.
            # -recursion with FUZZ in the query string (e.g. ?q=FUZZ) exits code 1 immediately.
            from urllib.parse import urlparse as _urlparse
            _parsed = _urlparse(base_url)
            if "FUZZ" in _parsed.path:
                cmd.append("-recursion")
                cmd.extend(["-recursion-depth", str(cfg.get("recursion_depth", 2))])
        if extra_headers:
            for k, v in extra_headers.items():
                cmd.extend(["-H", f"{k}: {v}"])
        if cookies:
            cmd.extend(["-b", cookies])

        result = self._exec(cmd, timeout=cfg["maxtime"] + 30)

        if result.returncode not in (0, 1, 2):
            errors.append({
                "message": f"ffuf exited with code {result.returncode}",
                "stderr_excerpt": result.stderr[:500],
                "exit_code": result.returncode,
            })

        if out_path_tmp.exists():
            try:
                data = json.loads(out_path_tmp.read_text())
                for item in data.get("results", []):
                    url = item.get("url", "")
                    status = item.get("status", 0)
                    length = item.get("length", 0)
                    words = item.get("words", 0)
                    lines = item.get("lines", 0)

                    try:
                        from urllib.parse import urlparse
                        host = urlparse(url).hostname or ""
                    except Exception:
                        host = ""

                    if host and not self._is_in_scope(host, program):
                        continue

                    finding_type = "exposure" if status in (200, 201, 202) else "misconfiguration"
                    evidence = f"ffuf: {status} {url} (len={length}, words={words})"

                    findings.append({
                        "type": finding_type,
                        "url": url,
                        "host": host,
                        "evidence": evidence,
                        "raw_output": {
                            "url": url,
                            "status": status,
                            "length": length,
                            "words": words,
                            "lines": lines,
                            "redirectlocation": item.get("redirectlocation", ""),
                            "input": item.get("input", {}),
                        },
                        "metadata": {"severity": _severity_from_status(status)},
                    })
            except json.JSONDecodeError as exc:
                errors.append({"message": f"ffuf output parse error: {exc}"})
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


def _severity_from_status(status: int) -> str:
    if status in (200, 201, 202, 204):
        return "info"
    if status in (401, 403):
        return "low"
    if status in (301, 302, 307, 308):
        return "info"
    return "info"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
