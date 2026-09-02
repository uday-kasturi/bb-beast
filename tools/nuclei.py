"""
Tool wrapper for nuclei — vulnerability template scanner.

nuclei runs a curated set of YAML templates against targets to detect:
- CVEs (thousands of templates)
- Misconfigurations (exposed panels, default creds, open dirs)
- Exposures (git repos, backup files, env files, debug endpoints)
- Technologies (server headers, frameworks)
- DNS misconfigurations
- Network vulnerabilities
- Subdomain takeover indicators
- Supply chain issues

Input: file of URLs (typically httpx output).

Flags used:
  -l <file>             input list of URLs
  -o <file>             output file
  -json                 JSON output
  -silent               suppress banner
  -nc                   no color
  -ni                   no interactivity
  -duc                  disable update check
  -nh                   no httpx (we already probed)
  -severity <levels>    filter by severity
  -tags <tags>          filter by template tags
  -etags <tags>         exclude tags (e.g. dos, intrusive)
  -t <templates>        specific template paths or dirs
  -rl <n>               rate limit (requests/sec)
  -c <n>                concurrency (parallel goroutines)
  -timeout <secs>       per-request timeout
  -retries <n>          retries per template
  -mhe <n>              max host errors before skip
  -headless             run headless browser templates
  -ss                   enable screenshot (headless)
  -stats                show scan stats
  -metrics              expose metrics endpoint
  -follow-redirects     follow HTTP redirects
  -follow-host-redirects  follow same-host redirects only

Template selection strategy:
  quick:       critical + high, exclude dos/intrusive, no headless
  standard:    critical + high + medium, exclude dos, no headless
  exhaustive:  all severities, exclude dos only, headless enabled
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


class NucleiWrapper(ToolWrapper):
    name = "nuclei"
    version_flag = "-version"

    _DEPTH_CONFIG = {
        "quick": {
            "severity": "critical,high",
            "exclude_tags": "dos,intrusive,fuzz,bruteforce",
            "rate_limit": 150,
            "concurrency": 25,
            "timeout": 10,
            "retries": 1,
            "max_host_errors": 30,
            "headless": False,
            "follow_redirects": True,
        },
        "standard": {
            "severity": "critical,high,medium",
            "exclude_tags": "dos,intrusive,bruteforce",
            "rate_limit": 100,
            "concurrency": 20,
            "timeout": 15,
            "retries": 2,
            "max_host_errors": 20,
            "headless": False,
            "follow_redirects": True,
        },
        "exhaustive": {
            "severity": "critical,high,medium,low,info",
            "exclude_tags": "dos",
            "rate_limit": 75,
            "concurrency": 15,
            "timeout": 20,
            "retries": 3,
            "max_host_errors": 10,
            "headless": True,
            "follow_redirects": True,
        },
    }

    # Nuclei severity → our normalized severity
    _SEVERITY_MAP = {
        "critical": "critical",
        "high":     "high",
        "medium":   "medium",
        "low":      "low",
        "info":     "info",
        "unknown":  "unknown",
    }

    # Nuclei template type → our finding type
    _TYPE_MAP = {
        "http":        "misconfiguration",
        "dns":         "dns_record",
        "ssl":         "misconfiguration",
        "tcp":         "open_port",
        "headless":    "misconfiguration",
        "network":     "open_port",
    }

    # Tags that map to specific finding types
    _TAG_TYPE_MAP = {
        "sqli":               "sqli",
        "xss":                "xss",
        "rce":                "rce",
        "ssrf":               "ssrf",
        "ssti":               "ssti",
        "lfi":                "lfi",
        "xxe":                "xxe",
        "redirect":           "open_redirect",
        "takeover":           "subdomain_takeover",
        "exposure":           "secret_exposure",
        "secrets":            "secret_exposure",
        "cve":                "cve",
        "misconfig":          "misconfiguration",
        "default-login":      "misconfiguration",
        "panel":              "exposure",
        "exposed-panels":     "exposure",
        "backup":             "exposure",
        "config":             "exposure",
        "auth-bypass":        "auth_bypass",
        "idor":               "idor",
        "jwt":                "jwt_weakness",
        "cors":               "misconfiguration",
        "csrf":               "csrf",
        "s3":                 "exposed_s3",
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
        extra_templates: list[str] | None = None,
        extra_tags: list[str] | None = None,
        extra_headers: dict | None = None,
        cookies: str | None = None,
        **kwargs: Any,
    ) -> dict:
        """
        Args:
            target:           Primary domain context.
            urls:             List of URLs to scan. If None, uses urls_file.
            urls_file:        Path to a file of URLs from httpx output.
            extra_templates:  Additional template paths or IDs to include.
            extra_tags:       Additional tags to include (beyond depth defaults).
        """
        self.require()
        cfg = self._DEPTH_CONFIG[depth]
        started_at = _now()
        t0 = time.monotonic()

        findings: list[dict] = []
        errors: list[dict] = []

        # Build input file
        _tmp_input = None
        if urls_file and urls_file.exists():
            input_path = urls_file
        elif urls:
            _tmp_input = tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False
            )
            for u in urls:
                _tmp_input.write(u + "\n")
            _tmp_input.flush()
            input_path = Path(_tmp_input.name)
        else:
            errors.append({"message": "nuclei: no urls or urls_file provided"})
            return self._write_empty(run_id, raw_output_dir, target, started_at, errors)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            out_path_tmp = Path(tmp.name)

        cmd = [
            "nuclei",
            "-l", str(input_path),
            "-o", str(out_path_tmp),
            "-jsonl",
            "-silent",
            "-nc",
            "-ni",
            "-duc",
            "-nh",
            "-stats",
            "-follow-redirects",
            "-severity", cfg["severity"],
            "-etags", cfg["exclude_tags"],
            "-rl", str(cfg["rate_limit"]),
            "-c", str(cfg["concurrency"]),
            "-timeout", str(cfg["timeout"]),
            "-retries", str(cfg["retries"]),
            "-mhe", str(cfg["max_host_errors"]),
        ]
        if cfg["headless"]:
            cmd.append("-headless")
        if extra_templates:
            for tmpl in extra_templates:
                cmd.extend(["-t", tmpl])
        if extra_tags:
            cmd.extend(["-tags", ",".join(extra_tags)])
        if extra_headers:
            for k, v in extra_headers.items():
                if k.lower() != "cookie":
                    cmd.extend(["-H", f"{k}: {v}"])
        if cookies:
            cmd.extend(["-H", f"Cookie: {cookies}"])
        elif extra_headers and "Cookie" in extra_headers:
            cmd.extend(["-H", f"Cookie: {extra_headers['Cookie']}"])

        result = self._exec(cmd, timeout=7200)  # nuclei can be slow

        if result.returncode not in (0, 1):
            errors.append({
                "message": f"nuclei exited with code {result.returncode}",
                "stderr_excerpt": result.stderr[:500],
                "exit_code": result.returncode,
            })

        # Parse JSON lines output
        if out_path_tmp.exists():
            for line in out_path_tmp.read_text().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue

                url = entry.get("matched-at", entry.get("host", ""))
                host = url.split("//")[-1].split("/")[0].split(":")[0] if url else ""

                if host and not self._is_in_scope(host, program):
                    continue

                # Resolve finding type from tags first, then template type
                tags = entry.get("info", {}).get("tags", [])
                finding_type = "misconfiguration"
                for tag in (tags or []):
                    if tag in self._TAG_TYPE_MAP:
                        finding_type = self._TAG_TYPE_MAP[tag]
                        break

                # Override with CVE type if template name starts with CVE
                template_id = entry.get("template-id", "")
                if template_id.lower().startswith("cve"):
                    finding_type = "cve"

                info = entry.get("info", {})
                severity = self._SEVERITY_MAP.get(
                    info.get("severity", "unknown"), "unknown"
                )
                name = info.get("name", template_id)
                description = info.get("description", "")
                reference = info.get("reference", [])

                evidence_parts = [f"[{severity.upper()}] {name}"]
                if description:
                    evidence_parts.append(description[:200])
                if entry.get("extracted-results"):
                    evidence_parts.append(f"Extracted: {entry['extracted-results'][:200]}")
                evidence = " | ".join(evidence_parts)

                finding = {
                    "type": finding_type,
                    "url": url,
                    "host": host,
                    "evidence": evidence,
                    "raw_output": {
                        "template_id": template_id,
                        "name": name,
                        "severity": severity,
                        "description": description,
                        "tags": tags,
                        "matched_at": entry.get("matched-at", ""),
                        "extracted_results": entry.get("extracted-results", []),
                        "curl_command": entry.get("curl-command", ""),
                        "reference": reference,
                        "matcher_name": entry.get("matcher-name", ""),
                        "type": entry.get("type", ""),
                    },
                    "metadata": {
                        "severity": severity,
                    },
                }
                findings.append(finding)

            out_path_tmp.unlink(missing_ok=True)

        if _tmp_input:
            Path(_tmp_input.name).unlink(missing_ok=True)

        finished_at = _now()
        duration = time.monotonic() - t0
        status_str = "success" if not errors else ("partial" if findings else "failed")

        out_path = self._write_raw_output(
            run_id=run_id,
            raw_output_dir=raw_output_dir,
            target=target,
            invocation_command=" ".join(str(c) for c in cmd),
            started_at=started_at,
            finished_at=finished_at,
            duration_seconds=duration,
            status=status_str,
            findings=findings,
            errors=errors,
        )

        return {"raw_output_path": out_path, "findings_count": len(findings)}

    def _write_empty(self, run_id, raw_output_dir, target, started_at, errors):
        out_path = self._write_raw_output(
            run_id=run_id,
            raw_output_dir=raw_output_dir,
            target=target,
            invocation_command="nuclei (not run — no input)",
            started_at=started_at,
            finished_at=_now(),
            duration_seconds=0,
            status="failed",
            findings=[],
            errors=errors,
        )
        return {"raw_output_path": out_path, "findings_count": 0}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
