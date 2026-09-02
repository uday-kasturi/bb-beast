"""
Tool wrapper for dalfox — XSS parameter scanner.

dalfox is purpose-built for XSS discovery. It:
- Tests parameters for reflected/stored/DOM XSS
- Parses HTML to find injection points
- Handles WAF bypass with encoding
- Verifies XSS with actual DOM execution (headless)

Flags:
  url <url>         single URL scan
  file <file>       file of URLs
  pipe              read URLs from stdin
  --output <file>   output file
  --format json     JSON output
  --silent          suppress banner
  --no-color        no colors
  --timeout <secs>  timeout
  --delay <ms>      delay between requests
  --worker <n>      parallel workers
  --skip-bav        skip basic-auth verification (faster)
  --skip-grepping   skip grep mode
  --skip-mining-dom skip DOM mining
  --skip-mining-dict skip dictionary mining
  --only-discovery  only discover XSS, don't verify
  --waf-evasion     enable WAF evasion
  --remote-payloads  use remote payload list
  --remote-wordlists use remote wordlist
  --follow-redirects follow redirects
  --ignore-return   comma-separated status codes to ignore
  --header <h>      custom header
  --cookie <c>      cookie
  --data <d>        POST body
  --method <m>      HTTP method
  --mining-dom      enable DOM XSS mining
  --deep-domxss     deep DOM XSS analysis (slow)
  --trigger <url>   callback URL for blind XSS
  --custom-payload <f> custom payload file
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


class DalfoxWrapper(ToolWrapper):
    name = "dalfox"
    version_flag = "version"

    _DEPTH_CONFIG = {
        "quick": {
            "workers": 10,
            "timeout": 10,
            "delay": 0,
            "waf_evasion": False,
            "mining_dom": False,
            "deep_domxss": False,
            "only_discovery": True,
            "skip_bav": True,
        },
        "standard": {
            "workers": 10,
            "timeout": 15,
            "delay": 100,
            "waf_evasion": True,
            "mining_dom": True,
            "deep_domxss": False,
            "only_discovery": False,
            "skip_bav": False,
        },
        "exhaustive": {
            "workers": 5,
            "timeout": 20,
            "delay": 200,
            "waf_evasion": True,
            "mining_dom": True,
            "deep_domxss": True,
            "only_discovery": False,
            "skip_bav": False,
        },
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
        cookies: str | None = None,
        extra_headers: dict | None = None,
        blind_xss_callback: str | None = None,
        **kwargs: Any,
    ) -> dict:
        if "xss" not in program.get("allowed_test_types", []):
            log.info("[dalfox] xss not in allowed_test_types — skipping")
            return self._write_skipped(run_id, raw_output_dir, target)

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
            errors.append({"message": "dalfox: no urls provided"})
            return self._write_empty(run_id, raw_output_dir, target, started_at, errors)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            out_path_tmp = Path(tmp.name)

        cmd = [
            "dalfox", "file", str(input_path),
            "--output", str(out_path_tmp),
            "--format", "json",
            "--silent",
            "--no-color",
            "--follow-redirects",
            "--worker", str(cfg["workers"]),
            "--timeout", str(cfg["timeout"]),
            "--delay", str(cfg["delay"]),
        ]
        if cfg["waf_evasion"]:
            cmd.append("--waf-evasion")
        if cfg["mining_dom"]:
            cmd.append("--mining-dom")
        if cfg["deep_domxss"]:
            cmd.append("--deep-domxss")
        if cfg["only_discovery"]:
            cmd.append("--only-discovery")
        if cfg["skip_bav"]:
            cmd.append("--skip-bav")
        if cookies:
            cmd.extend(["--cookie", cookies])
        if extra_headers:
            for k, v in extra_headers.items():
                cmd.extend(["--header", f"{k}: {v}"])
        if blind_xss_callback:
            cmd.extend(["--trigger", blind_xss_callback])

        result = self._exec(cmd, timeout=3600)

        if result.returncode not in (0, 1):
            errors.append({
                "message": f"dalfox exited with code {result.returncode}",
                "stderr_excerpt": result.stderr[:500],
                "exit_code": result.returncode,
            })

        if out_path_tmp.exists():
            try:
                data = json.loads(out_path_tmp.read_text())
                if isinstance(data, list):
                    items = data
                elif isinstance(data, dict):
                    items = data.get("results", [data])
                else:
                    items = []

                for item in items:
                    url = item.get("poc", item.get("param", ""))
                    param = item.get("param", "")
                    inject_type = item.get("type", "")
                    evidence = f"XSS {inject_type} in param '{param}': {url}"

                    try:
                        from urllib.parse import urlparse
                        host = urlparse(url).hostname or ""
                    except Exception:
                        host = ""

                    if host and not self._is_in_scope(host, program):
                        continue

                    findings.append({
                        "type": "xss",
                        "url": url,
                        "host": host,
                        "evidence": evidence,
                        "raw_output": item,
                        "metadata": {"severity": "medium"},
                    })
            except (json.JSONDecodeError, Exception) as exc:
                errors.append({"message": f"dalfox output parse error: {exc}"})
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

    def _write_skipped(self, run_id, raw_output_dir, target):
        out_path = self._write_raw_output(
            run_id=run_id, raw_output_dir=raw_output_dir, target=target,
            invocation_command="dalfox (skipped)", started_at=_now(),
            finished_at=_now(), duration_seconds=0, status="success",
            findings=[], errors=[],
        )
        return {"raw_output_path": out_path, "findings_count": 0}

    def _write_empty(self, run_id, raw_output_dir, target, started_at, errors):
        out_path = self._write_raw_output(
            run_id=run_id, raw_output_dir=raw_output_dir, target=target,
            invocation_command="dalfox (not run)", started_at=started_at,
            finished_at=_now(), duration_seconds=0, status="failed",
            findings=[], errors=errors,
        )
        return {"raw_output_path": out_path, "findings_count": 0}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
