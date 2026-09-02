"""
Tool wrapper for katana — deep web crawler.

katana crawls live URLs and discovers endpoints, forms, parameters, and
JavaScript files. It parses JS to find hidden endpoints.

Flags:
  -u <url>          single URL to crawl
  -list <file>      list of URLs to crawl
  -o <file>         output file
  -json             JSON output format
  -silent           suppress banner
  -nc               no color
  -d <depth>        crawl depth (pages deep)
  -jc               crawl JavaScript files and extract endpoints
  -ct <secs>        crawl timeout per URL
  -timeout <secs>   overall request timeout
  -c <n>            concurrency
  -rl <n>           rate limit
  -ef <extensions>  exclude file extensions (media/fonts)
  -aff              allow form fields (fill forms to crawl deeper)
  -field-scope      scope field: rdn (root domain), fqdn, dn
  -headless         headless browser crawling (exhaustive only)
  -xhr              capture XHR/fetch requests
  -fx               form extraction
  -kf               known files (robots.txt, sitemap.xml, etc.)
  -mrs <n>          max response size bytes
  -retry <n>        retry count
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


class KatanaWrapper(ToolWrapper):
    name = "katana"
    version_flag = "-version"

    _DEPTH_CONFIG = {
        "quick": {
            "depth": 2,
            "concurrency": 10,
            "rate_limit": 150,
            "timeout": 10,
            "crawl_timeout": 120,
            "jc": True,
            "headless": False,
            "xhr": False,
            "aff": False,
            "max_response_size": 2000000,  # 2MB
        },
        "standard": {
            "depth": 3,
            "concurrency": 10,
            "rate_limit": 100,
            "timeout": 15,
            "crawl_timeout": 300,
            "jc": True,
            "headless": False,
            "xhr": True,
            "aff": True,
            "max_response_size": 4000000,
        },
        "exhaustive": {
            "depth": 5,
            "concurrency": 5,
            "rate_limit": 50,
            "timeout": 20,
            "crawl_timeout": 600,
            "jc": True,
            "headless": True,
            "xhr": True,
            "aff": True,
            "max_response_size": 8000000,
        },
    }

    _EXCLUDE_EXTENSIONS = (
        "png,jpg,gif,jpeg,webp,svg,ico,css,woff,woff2,ttf,"
        "eot,mp4,mp3,m4a,avi,mov,pdf,zip,gz,tar,bz2"
    )

    def run(
        self,
        target: str,
        depth: str,
        run_id: str,
        raw_output_dir: Path,
        program: dict,
        urls: list[str] | None = None,
        urls_file: Path | None = None,
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

        _tmp_input = None
        if urls_file and urls_file.exists():
            input_path = urls_file
            use_list = True
        elif urls:
            _tmp_input = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
            for u in urls:
                _tmp_input.write(u + "\n")
            _tmp_input.flush()
            input_path = Path(_tmp_input.name)
            use_list = True
        else:
            errors.append({"message": "katana: no urls provided"})
            return self._write_empty(run_id, raw_output_dir, target, started_at, errors)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            out_path_tmp = Path(tmp.name)

        cmd = [
            "katana",
            "-list", str(input_path),
            "-o", str(out_path_tmp),
            "-json",
            "-silent",
            "-nc",
            "-d", str(cfg["depth"]),
            "-c", str(cfg["concurrency"]),
            "-rl", str(cfg["rate_limit"]),
            "-timeout", str(cfg["timeout"]),
            "-ct", str(cfg["crawl_timeout"]),
            "-ef", self._EXCLUDE_EXTENSIONS,
            "-mrs", str(cfg["max_response_size"]),
            "-fs", "rdn",
            "-kf", "all",
            "-retry", "2",
        ]
        if cfg["jc"]:
            cmd.append("-jc")
        if cfg["headless"]:
            cmd.append("-headless")
        if cfg["xhr"]:
            cmd.append("-xhr")
        if cfg["aff"]:
            cmd.append("-aff")
            cmd.append("-fx")
        if extra_headers:
            for k, v in extra_headers.items():
                if k.lower() != "cookie":
                    cmd.extend(["-H", f"{k}: {v}"])
        if cookies:
            cmd.extend(["-H", f"Cookie: {cookies}"])
        elif extra_headers and "Cookie" in extra_headers:
            cmd.extend(["-H", f"Cookie: {extra_headers['Cookie']}"])

        result = self._exec(cmd, timeout=cfg["crawl_timeout"] + 300)

        if result.returncode not in (0, 1):
            errors.append({
                "message": f"katana exited with code {result.returncode}",
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

                url = entry.get("endpoint", entry.get("url", ""))
                if not url:
                    continue

                try:
                    from urllib.parse import urlparse
                    host = urlparse(url).hostname or ""
                except Exception:
                    host = ""

                if host and not self._is_in_scope(host, program):
                    continue

                source = entry.get("source", "")
                method = entry.get("method", "GET")
                tag = entry.get("tag", "")

                finding = {
                    "type": "historical_url",
                    "url": url,
                    "host": host,
                    "evidence": f"Crawled endpoint [{method}]: {url}",
                    "raw_output": {
                        "url": url,
                        "source": source,
                        "method": method,
                        "tag": tag,
                        "source_type": entry.get("source_type", ""),
                    },
                }
                findings.append(finding)

            out_path_tmp.unlink(missing_ok=True)

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
            invocation_command="katana (not run)", started_at=started_at,
            finished_at=_now(), duration_seconds=0, status="failed",
            findings=[], errors=errors,
        )
        return {"raw_output_path": out_path, "findings_count": 0}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
