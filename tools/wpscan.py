"""
Tool wrapper for wpscan — WordPress vulnerability scanner.

wpscan detects:
- WordPress version and known CVEs
- Plugin/theme vulnerabilities
- User enumeration
- Weak credentials
- Configuration issues (debug mode, XML-RPC, etc.)

Only runs if the target is detected as WordPress (from httpx tech_detection).

Flags:
  --url <url>           target URL
  --output <file>       output file
  --format json         JSON output
  --no-banner           suppress banner
  --disable-tls-checks  ignore TLS errors
  --enumerate <opts>    what to enumerate:
      vp = vulnerable plugins
      ap = all plugins (exhaustive)
      vt = vulnerable themes
      at = all themes (exhaustive)
      u  = users
      tt = timthumbs
      cb = config backups
      dbe = DB exports
      m  = media
  --plugins-detection <mode>  passive | aggressive | mixed
  --themes-detection <mode>   passive | aggressive | mixed
  --api-token <token>         WPScan API token (for vuln DB lookups)
  --throttle <ms>             delay between requests
  --max-threads <n>           max threads
  --request-timeout <secs>    timeout
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


class WpscanWrapper(ToolWrapper):
    name = "wpscan"
    version_flag = "--version"

    _DEPTH_CONFIG = {
        "quick": {
            "enumerate": "vp,vt,u,cb",
            "plugins_detection": "passive",
            "themes_detection": "passive",
            "max_threads": 5,
            "throttle": 200,
            "timeout": 30,
        },
        "standard": {
            "enumerate": "vp,vt,u,cb,tt,dbe",
            "plugins_detection": "mixed",
            "themes_detection": "passive",
            "max_threads": 5,
            "throttle": 300,
            "timeout": 30,
        },
        "exhaustive": {
            "enumerate": "ap,at,u,tt,cb,dbe,m",
            "plugins_detection": "aggressive",
            "themes_detection": "aggressive",
            "max_threads": 3,
            "throttle": 500,
            "timeout": 60,
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
        api_token: str | None = None,
        cookies: str | None = None,
        extra_headers: dict | None = None,
        **kwargs: Any,
    ) -> dict:
        self.require()
        cfg = self._DEPTH_CONFIG[depth]
        started_at = _now()
        t0 = time.monotonic()

        findings: list[dict] = []
        errors: list[dict] = []

        scan_url = url or f"https://{target}"

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            out_path_tmp = Path(tmp.name)

        cmd = [
            "wpscan",
            "--url", scan_url,
            "--output", str(out_path_tmp),
            "--format", "json",
            "--no-banner",
            "--disable-tls-checks",
            "--enumerate", cfg["enumerate"],
            "--plugins-detection", cfg["plugins_detection"],
            "--themes-detection", cfg["themes_detection"],
            "--max-threads", str(cfg["max_threads"]),
            "--throttle", str(cfg["throttle"]),
            "--request-timeout", str(cfg["timeout"]),
        ]
        if api_token:
            cmd.extend(["--api-token", api_token])
        if cookies:
            cmd.extend(["--cookie", cookies])
        if extra_headers:
            for k, v in extra_headers.items():
                cmd.extend(["--headers", f"{k}: {v}"])

        result = self._exec(cmd, timeout=3600)

        if result.returncode not in (0, 1, 5):
            errors.append({
                "message": f"wpscan exited with code {result.returncode}",
                "stderr_excerpt": result.stderr[:300],
                "exit_code": result.returncode,
            })

        if out_path_tmp.exists():
            try:
                data = json.loads(out_path_tmp.read_text())
                wp_version = data.get("version", {})
                plugins = data.get("plugins", {})
                themes = data.get("themes", {})
                users = data.get("users", {})

                # WordPress version vulnerabilities
                for vuln in wp_version.get("vulnerabilities", []):
                    findings.append({
                        "type": "cve",
                        "url": scan_url,
                        "host": target,
                        "evidence": f"WordPress {wp_version.get('number', 'unknown')}: {vuln.get('title', '')}",
                        "raw_output": {
                            "component": "wordpress_core",
                            "version": wp_version.get("number", ""),
                            "vuln_title": vuln.get("title", ""),
                            "references": vuln.get("references", {}),
                            "cvss": vuln.get("cvss", {}),
                        },
                        "metadata": {"severity": _cvss_to_severity(vuln.get("cvss", {}).get("score", 0))},
                    })

                # Plugin vulnerabilities
                for plugin_name, plugin_data in plugins.items():
                    for vuln in plugin_data.get("vulnerabilities", []):
                        findings.append({
                            "type": "cve",
                            "url": scan_url,
                            "host": target,
                            "evidence": f"WP Plugin {plugin_name} v{plugin_data.get('version', {}).get('number', '?')}: {vuln.get('title', '')}",
                            "raw_output": {
                                "component": f"plugin:{plugin_name}",
                                "version": plugin_data.get("version", {}).get("number", ""),
                                "vuln_title": vuln.get("title", ""),
                                "references": vuln.get("references", {}),
                            },
                            "metadata": {"severity": "high"},
                        })

                # User enumeration
                for username, user_data in users.items():
                    findings.append({
                        "type": "misconfiguration",
                        "url": scan_url,
                        "host": target,
                        "evidence": f"WordPress user enumerated: {username}",
                        "raw_output": {
                            "username": username,
                            "id": user_data.get("id", ""),
                        },
                        "metadata": {"severity": "info"},
                    })

            except (json.JSONDecodeError, Exception) as exc:
                errors.append({"message": f"wpscan output parse error: {exc}"})
            out_path_tmp.unlink(missing_ok=True)

        finished_at = _now()
        duration = time.monotonic() - t0
        status = "success" if not errors else ("partial" if findings else "failed")

        out_path = self._write_raw_output(
            run_id=run_id, raw_output_dir=raw_output_dir, target=target,
            invocation_command=" ".join(str(c) for c in cmd),
            started_at=started_at, finished_at=finished_at,
            duration_seconds=duration, status=status,
            findings=findings, errors=errors,
        )
        return {"raw_output_path": out_path, "findings_count": len(findings)}


def _cvss_to_severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
