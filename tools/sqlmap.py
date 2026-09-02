"""
Tool wrapper for sqlmap — SQL injection detection and exploitation.

sqlmap is used ONLY for detection, not full exploitation.
We use --level and --risk to control aggression, and --technique to limit
to detection-only methods (no blind time-based by default in quick mode).

CRITICAL: Always check program.allowed_test_types includes "sqli" before running.
The chain is responsible for this check, but we enforce it here too.

Flags:
  -u <url>          target URL
  --data <data>     POST data
  --level <1-5>     test level (1=default, 5=most thorough)
  --risk <1-3>      risk level (1=safe, 3=heavy)
  --technique <T>   injection techniques: B(oolean), E(rror), U(nion), S(tacked), T(ime), Q(query)
  --forms           parse and test forms
  --crawl <depth>   crawl depth
  --batch           never ask user input
  --random-agent    random user agent
  --threads <n>     concurrent requests
  --timeout <secs>  connection timeout
  --retries <n>     retries
  --output-dir <d>  output directory
  --format json     output format (sqlmap doesn't have --json, use --dump-format=CSV)
  --flush-session   fresh session each run
  --no-cast         no payload casting
  --no-escape       no payload escaping
  --dbms <dbms>     hint the DBMS to speed up detection
  --tamper <script> tamper scripts for WAF bypass (standard+exhaustive)
  --smart           only pursue promising injections
"""

from __future__ import annotations

import json
import logging
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.base import ToolWrapper

log = logging.getLogger(__name__)


class SqlmapWrapper(ToolWrapper):
    name = "sqlmap"
    version_flag = "--version"

    _DEPTH_CONFIG = {
        "quick": {
            "level": 1,
            "risk": 1,
            "technique": "BEU",   # Boolean, Error, Union — no time-based (too slow/risky)
            "threads": 4,
            "timeout": 30,
            "retries": 2,
            "crawl": 0,
            "forms": False,
            "tamper": [],
            "smart": True,
        },
        "standard": {
            "level": 3,
            "risk": 2,
            "technique": "BEUST", # All except Stacked (too destructive)
            "threads": 4,
            "timeout": 30,
            "retries": 3,
            "crawl": 1,
            "forms": True,
            "tamper": ["space2comment", "between"],
            "smart": True,
        },
        "exhaustive": {
            "level": 5,
            "risk": 2,   # Never 3 — risk 3 can modify data
            "technique": "BEUST",
            "threads": 4,
            "timeout": 60,
            "retries": 5,
            "crawl": 2,
            "forms": True,
            "tamper": ["space2comment", "between", "randomcase", "charencode"],
            "smart": False,
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
        dbms_hint: str | None = None,
        **kwargs: Any,
    ) -> dict:
        # Scope / authorization check
        if "sqli" not in program.get("allowed_test_types", []):
            log.info("[sqlmap] sqli not in allowed_test_types — skipping")
            return self._write_skipped(run_id, raw_output_dir, target)

        self.require()
        cfg = self._DEPTH_CONFIG[depth]
        started_at = _now()
        t0 = time.monotonic()

        findings: list[dict] = []
        errors: list[dict] = []

        scan_url = url or f"https://{target}"

        output_dir = raw_output_dir / "sqlmap_sessions"
        output_dir.mkdir(exist_ok=True)

        cmd = [
            "sqlmap",
            "-u", scan_url,
            "--batch",
            "--random-agent",
            "--flush-session",
            "--output-dir", str(output_dir),
            "--level", str(cfg["level"]),
            "--risk", str(cfg["risk"]),
            "--technique", cfg["technique"],
            "--threads", str(cfg["threads"]),
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
        if cfg.get("forms"):
            cmd.append("--forms")
        if cfg.get("crawl", 0) > 0:
            cmd.extend(["--crawl", str(cfg["crawl"])])
        if cfg.get("smart"):
            cmd.append("--smart")
        if cfg.get("tamper"):
            cmd.extend(["--tamper", ",".join(cfg["tamper"])])
        if dbms_hint:
            cmd.extend(["--dbms", dbms_hint])

        result = self._exec(cmd, timeout=3600)

        if result.returncode not in (0, 1):
            errors.append({
                "message": f"sqlmap exited with code {result.returncode}",
                "stderr_excerpt": result.stderr[:500],
                "exit_code": result.returncode,
            })

        # sqlmap doesn't have clean JSON output by default — parse stdout
        stdout = result.stdout
        vuln_detected = False

        for line in stdout.splitlines():
            lower = line.lower()
            if "is vulnerable" in lower or "parameter" in lower and "injectable" in lower:
                vuln_detected = True
                findings.append({
                    "type": "sqli",
                    "url": scan_url,
                    "evidence": line.strip(),
                    "raw_output": {
                        "url": scan_url,
                        "stdout_line": line.strip(),
                        "technique": cfg["technique"],
                        "level": cfg["level"],
                        "risk": cfg["risk"],
                        "matched_at": scan_url,
                    },
                    "metadata": {"severity": "high"},
                })

        if not vuln_detected and "sqlmap identified" in stdout.lower():
            # Sometimes sqlmap reports without "is vulnerable" wording
            findings.append({
                "type": "sqli",
                "url": scan_url,
                "evidence": "sqlmap identified injection point (see raw output)",
                "raw_output": {
                    "url": scan_url,
                    "stdout_excerpt": stdout[:2000],
                },
                "metadata": {"severity": "high"},
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

    def run_multi(
        self,
        urls: list[str],
        target: str,
        depth: str,
        run_id: str,
        raw_output_dir: Path,
        program: dict,
        max_workers: int = 3,
        **kwargs: Any,
    ) -> dict:
        """
        Run sqlmap against multiple URLs in parallel and write findings once.

        Uses ThreadPoolExecutor so that N URLs are scanned concurrently
        (each in its own sqlmap subprocess), then all findings are merged
        into a single raw_output file. Avoids the per-URL sequential bottleneck.

        Args:
            urls:        URLs to scan (already deduped by endpoint).
            max_workers: Concurrent sqlmap processes (default 3).
        """
        if not urls:
            return self._write_skipped(run_id, raw_output_dir, target)
        if "sqli" not in program.get("allowed_test_types", []):
            log.info("[sqlmap] sqli not in allowed_test_types — skipping")
            return self._write_skipped(run_id, raw_output_dir, target)

        self.require()
        cfg = self._DEPTH_CONFIG[depth]
        started_at = _now()
        t0 = time.monotonic()

        all_findings: list[dict] = []
        all_errors: list[dict] = []
        invocation_cmds: list[str] = []

        output_dir = raw_output_dir / "sqlmap_sessions"
        output_dir.mkdir(exist_ok=True)

        def _scan_one(url: str) -> tuple[str, list[dict], list[dict]]:
            """Scan a single URL; return (cmd_str, findings, errors)."""
            cmd = [
                "sqlmap",
                "-u", url,
                "--batch",
                "--random-agent",
                "--flush-session",
                "--output-dir", str(output_dir),
                "--level", str(cfg["level"]),
                "--risk", str(cfg["risk"]),
                "--technique", cfg["technique"],
                "--threads", str(cfg["threads"]),
                "--timeout", str(cfg["timeout"]),
                "--retries", str(cfg["retries"]),
            ]
            if cfg.get("forms"):
                cmd.append("--forms")
            if cfg.get("crawl", 0) > 0:
                cmd.extend(["--crawl", str(cfg["crawl"])])
            if cfg.get("smart"):
                cmd.append("--smart")
            if cfg.get("tamper"):
                cmd.extend(["--tamper", ",".join(cfg["tamper"])])
            if kwargs.get("cookies"):
                cmd.extend(["--cookie", kwargs["cookies"]])
            if kwargs.get("extra_headers"):
                for k, v in kwargs["extra_headers"].items():
                    cmd.extend(["--header", f"{k}: {v}"])

            result = self._exec(cmd, timeout=3600)
            cmd_str = " ".join(str(c) for c in cmd)

            findings: list[dict] = []
            errors: list[dict] = []

            if result.returncode not in (0, 1):
                errors.append({
                    "message": f"sqlmap exited with code {result.returncode}",
                    "stderr_excerpt": result.stderr[:500],
                    "exit_code": result.returncode,
                })

            stdout = result.stdout
            for line in stdout.splitlines():
                lower = line.lower()
                if "is vulnerable" in lower or ("parameter" in lower and "injectable" in lower):
                    findings.append({
                        "type": "sqli",
                        "url": url,
                        "evidence": line.strip(),
                        "raw_output": {
                            "url": url,
                            "stdout_line": line.strip(),
                            "technique": cfg["technique"],
                            "level": cfg["level"],
                            "risk": cfg["risk"],
                        },
                        "metadata": {"severity": "high"},
                    })
            if not findings and "sqlmap identified" in stdout.lower():
                findings.append({
                    "type": "sqli",
                    "url": url,
                    "evidence": "sqlmap identified injection point (see raw output)",
                    "raw_output": {"url": url, "stdout_excerpt": stdout[:2000]},
                    "metadata": {"severity": "high"},
                })

            return cmd_str, findings, errors

        log.info("[sqlmap] Scanning %d URLs in parallel (max_workers=%d)", len(urls), max_workers)
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_url = {executor.submit(_scan_one, u): u for u in urls}
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    cmd_str, findings, errors = future.result()
                    all_findings.extend(findings)
                    all_errors.extend(errors)
                    invocation_cmds.append(cmd_str)
                except Exception as exc:
                    log.warning("[sqlmap] Exception scanning %s: %s", url, exc)
                    all_errors.append({"message": f"exception for {url}: {exc}"})

        finished_at = _now()
        duration = time.monotonic() - t0
        status = "success" if not all_errors else ("partial" if all_findings else "failed")

        # Summarize invocation command (first + count)
        invocation_summary = invocation_cmds[0] if invocation_cmds else "sqlmap (parallel)"
        if len(invocation_cmds) > 1:
            invocation_summary += f" [+{len(invocation_cmds) - 1} more URLs]"

        out_path = self._write_raw_output(
            run_id=run_id,
            raw_output_dir=raw_output_dir,
            target=target,
            invocation_command=invocation_summary,
            started_at=started_at,
            finished_at=finished_at,
            duration_seconds=duration,
            status=status,
            findings=all_findings,
            errors=all_errors,
        )
        log.info(
            "[sqlmap] Parallel scan complete: %d findings from %d URLs in %.1fs",
            len(all_findings), len(urls), duration,
        )
        return {"raw_output_path": out_path, "findings_count": len(all_findings)}

    def _write_skipped(self, run_id, raw_output_dir, target):
        out_path = self._write_raw_output(
            run_id=run_id, raw_output_dir=raw_output_dir, target=target,
            invocation_command="sqlmap (skipped — not in allowed_test_types)",
            started_at=_now(), finished_at=_now(), duration_seconds=0,
            status="success", findings=[], errors=[],
        )
        return {"raw_output_path": out_path, "findings_count": 0}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
