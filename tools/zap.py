"""
Tool wrapper for OWASP ZAP — active web application scanner.

ZAP runs as a daemon and exposes a REST API. This wrapper:
- Checks if ZAP daemon is reachable (and auto-starts if installed)
- Spider + active scans the target at the configured depth
- Normalizes alerts into the standard raw_output finding format
- Writes raw_output/zap.json using the shared ToolWrapper infrastructure

ZAP daemon setup (one-time):
  /Applications/ZAP.app/Contents/Java/zap.sh \\
    -daemon -port 8090 \\
    -config api.key=bb-beast-zap \\
    -config api.addrs.addr.name=.* \\
    -config api.addrs.addr.regex=true

Or let this wrapper auto-start it by installing ZAP at the default path.

Configuration via env:
  ZAP_API_URL   — default: http://localhost:8090
  ZAP_API_KEY   — default: bb-beast-zap

Depth behaviour:
  quick:       Spider (traditional) + passive scan only. No active attacks.
  standard:    Spider + active scan, default scan policy.
  exhaustive:  Ajax spider + traditional spider + full active scan.
               Runs all enabled rules including authentication and logic checks.
"""

from __future__ import annotations

import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

from tools.base import ToolWrapper

log = logging.getLogger(__name__)

_DEFAULT_ZAP_URL = os.environ.get("ZAP_API_URL", "http://localhost:8090")
_DEFAULT_ZAP_KEY = os.environ.get("ZAP_API_KEY", "bb-beast-zap")
_ZAP_INSTALL_PATH = "/Applications/ZAP.app/Contents/Java/zap.sh"

_SPIDER_TIMEOUT = 600       # 10 min max for traditional spider
_AJAX_SPIDER_TIMEOUT = 300  # 5 min max for ajax spider
_ACTIVE_SCAN_TIMEOUT = 3600 # 1 hr max for active scan
_POLL_INTERVAL = 10

# ZAP risk/confidence → our severity/confidence
_RISK_MAP = {"High": "high", "Medium": "medium", "Low": "low", "Informational": "info"}
_CONFIDENCE_MAP = {"High": 0.90, "Medium": 0.70, "Low": 0.40, "False Positive": 0.05}

# Alert name fragments → our finding type
_ALERT_TYPE_MAP: list[tuple[str, str]] = [
    ("sql injection",        "sqli"),
    ("sql",                  "sqli"),
    ("xss",                  "xss"),
    ("cross-site scripting", "xss"),
    ("ssrf",                 "ssrf"),
    ("csrf",                 "csrf"),
    ("cross-site request",   "csrf"),
    ("path traversal",       "path_traversal"),
    ("directory traversal",  "path_traversal"),
    ("open redirect",        "open_redirect"),
    ("redirect",             "open_redirect"),
    ("command injection",    "command_injection"),
    ("remote code",          "rce"),
    ("code execution",       "rce"),
    ("xxe",                  "xxe"),
    ("xml external",         "xxe"),
    ("ssti",                 "ssti"),
    ("template injection",   "ssti"),
    ("lfi",                  "lfi"),
    ("local file",           "lfi"),
    ("idor",                 "idor"),
    ("insecure direct",      "idor"),
    ("broken auth",          "auth_bypass"),
    ("authentication",       "auth_bypass"),
    ("jwt",                  "jwt_weakness"),
    ("secret",               "secret_exposure"),
    ("password",             "secret_exposure"),
    ("information disclosure", "info_disclosure"),
    ("disclosure",           "info_disclosure"),
    ("takeover",             "subdomain_takeover"),
    ("cors",                 "misconfiguration"),
    ("clickjack",            "misconfiguration"),
    ("content security",     "misconfiguration"),
    ("x-frame",              "misconfiguration"),
]


class ZapWrapper(ToolWrapper):
    """
    ToolWrapper adapter for OWASP ZAP.

    Unlike CLI tools, ZAP is a daemon — `available()` checks the REST API
    rather than PATH, and `tool_version()` queries the API directly.
    """

    name = "zap"

    def __init__(
        self,
        api_url: str = _DEFAULT_ZAP_URL,
        api_key: str = _DEFAULT_ZAP_KEY,
    ) -> None:
        # ToolWrapper.__init__ checks self.name — must set before super()
        super().__init__()
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self._session = requests.Session()
        self._session.headers["X-ZAP-API-Key"] = api_key

    # ------------------------------------------------------------------
    # ToolWrapper overrides
    # ------------------------------------------------------------------

    def available(self) -> bool:
        """True if ZAP daemon is reachable OR ZAP is installed (can be started)."""
        if self._api_reachable():
            return True
        return Path(_ZAP_INSTALL_PATH).exists()

    def tool_version(self) -> str:
        if self._version_cache:
            return self._version_cache
        try:
            resp = self._session.get(
                f"{self.api_url}/JSON/core/view/version/", timeout=5
            )
            ver = resp.json().get("version", "unknown")
        except Exception:
            ver = "unknown"
        self._version_cache = f"zap-{ver}"
        return self._version_cache

    def run(
        self,
        target: str,
        depth: str,
        run_id: str,
        raw_output_dir: Path,
        program: dict,
        **kwargs: Any,
    ) -> dict:
        """
        Spider + active scan *target* at *depth* and write raw_output/zap.json.

        Args:
            target:        Base URL to scan (e.g. https://example.com).
            depth:         quick | standard | exhaustive
            run_id:        Run UUID.
            raw_output_dir: Directory for raw_output/zap.json.
            program:       program.json dict — used for scope enforcement.
        """
        import uuid as _uuid

        if not self._is_in_scope(target, program):
            log.error("[zap] %s is out of scope — refusing scan", target)
            return self._write_empty(
                run_id, raw_output_dir, target,
                [{"message": f"out of scope: {target}"}],
            )

        if not self._ensure_running():
            return self._write_empty(
                run_id, raw_output_dir, target,
                [{"message": "ZAP daemon unreachable and could not be started"}],
            )

        started_at = _now()
        t0 = time.monotonic()
        findings: list[dict] = []
        errors: list[dict] = []

        try:
            self._set_scope(target)

            if depth in ("standard", "exhaustive"):
                log.info("[zap] traditional spider: %s", target)
                spider_id = self._spider(target)
                self._wait_spider(spider_id, _SPIDER_TIMEOUT)

            if depth == "exhaustive":
                log.info("[zap] ajax spider: %s", target)
                self._ajax_spider(target)
                self._wait_ajax_spider(_AJAX_SPIDER_TIMEOUT)

            if depth == "quick":
                log.info("[zap] passive scan only: %s", target)
                self._passively_fetch(target)
            else:
                log.info("[zap] active scan: %s", target)
                scan_id = self._active_scan(target)
                self._wait_active_scan(scan_id, _ACTIVE_SCAN_TIMEOUT)

            raw_alerts = self._get_alerts(target)
            log.info("[zap] %d alerts collected for %s", len(raw_alerts), target)

            for alert in raw_alerts:
                finding = _normalize_alert(alert)
                host = finding.get("host", "")
                if host and not self._is_in_scope(host, program):
                    continue
                findings.append(finding)

        except Exception as exc:
            log.error("[zap] scan error: %s", exc)
            errors.append({"message": str(exc)})

        finished_at = _now()
        duration = time.monotonic() - t0
        status_str = "success" if not errors else ("partial" if findings else "failed")

        cmd = f"zap active-scan depth={depth} target={target}"
        out_path = self._write_raw_output(
            run_id=run_id,
            raw_output_dir=raw_output_dir,
            target=target,
            invocation_command=cmd,
            started_at=started_at,
            finished_at=finished_at,
            duration_seconds=duration,
            status=status_str,
            findings=findings,
            errors=errors,
        )
        return {"raw_output_path": out_path, "findings_count": len(findings)}

    # ------------------------------------------------------------------
    # ZAP REST API — internal
    # ------------------------------------------------------------------

    def _api_reachable(self) -> bool:
        try:
            resp = self._session.get(
                f"{self.api_url}/JSON/core/view/version/", timeout=4
            )
            return resp.status_code == 200
        except Exception:
            return False

    def _ensure_running(self) -> bool:
        if self._api_reachable():
            return True
        if not Path(_ZAP_INSTALL_PATH).exists():
            log.error("[zap] not installed at %s and daemon not reachable", _ZAP_INSTALL_PATH)
            return False

        import subprocess
        log.info("[zap] starting daemon automatically...")
        port = self._port()
        subprocess.Popen(
            [
                _ZAP_INSTALL_PATH, "-daemon",
                "-port", str(port),
                "-config", f"api.key={self.api_key}",
                "-config", "api.addrs.addr.name=.*",
                "-config", "api.addrs.addr.regex=true",
                "-config", "connection.timeoutInSecs=30",
                "-config", "scanner.threadPerHost=5",
            ],
            stdout=open("/tmp/zap-daemon.log", "w"),  # noqa: SIM115
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            time.sleep(3)
            if self._api_reachable():
                log.info("[zap] daemon ready on %s", self.api_url)
                return True
        log.error("[zap] daemon failed to start within 90s — see /tmp/zap-daemon.log")
        return False

    def _port(self) -> int:
        try:
            return int(self.api_url.rsplit(":", 1)[-1])
        except Exception:
            return 8090

    def _set_scope(self, target_url: str) -> None:
        try:
            self._session.get(
                f"{self.api_url}/JSON/context/action/includeInContext/",
                params={"contextName": "Default Context", "regex": f"{target_url}.*"},
                timeout=10,
            )
        except Exception:
            pass

    def _spider(self, target_url: str, recurse: bool = True) -> str:
        resp = self._session.get(
            f"{self.api_url}/JSON/spider/action/scan/",
            params={"url": target_url, "recurse": str(recurse).lower()},
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json().get("scan", "0")

    def _wait_spider(self, spider_id: str, timeout: int) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                resp = self._session.get(
                    f"{self.api_url}/JSON/spider/view/status/",
                    params={"scanId": spider_id},
                    timeout=10,
                )
                progress = int(resp.json().get("status", 0))
                log.debug("[zap] spider %s: %d%%", spider_id, progress)
                if progress >= 100:
                    return
            except Exception:
                pass
            time.sleep(_POLL_INTERVAL)
        log.warning("[zap] spider %s timed out after %ds", spider_id, timeout)

    def _ajax_spider(self, target_url: str) -> None:
        try:
            self._session.get(
                f"{self.api_url}/JSON/ajaxSpider/action/scan/",
                params={"url": target_url},
                timeout=30,
            )
        except Exception as exc:
            log.warning("[zap] ajax spider start failed: %s", exc)

    def _wait_ajax_spider(self, timeout: int) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                resp = self._session.get(
                    f"{self.api_url}/JSON/ajaxSpider/view/status/",
                    timeout=10,
                )
                status = resp.json().get("status", "")
                log.debug("[zap] ajax spider: %s", status)
                if status == "stopped":
                    return
            except Exception:
                pass
            time.sleep(_POLL_INTERVAL)
        log.warning("[zap] ajax spider timed out after %ds", timeout)
        try:
            self._session.get(
                f"{self.api_url}/JSON/ajaxSpider/action/stop/", timeout=10
            )
        except Exception:
            pass

    def _active_scan(self, target_url: str, recurse: bool = True) -> str:
        resp = self._session.get(
            f"{self.api_url}/JSON/ascan/action/scan/",
            params={"url": target_url, "recurse": str(recurse).lower()},
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json().get("scan", "0")

    def _wait_active_scan(self, scan_id: str, timeout: int) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                resp = self._session.get(
                    f"{self.api_url}/JSON/ascan/view/status/",
                    params={"scanId": scan_id},
                    timeout=10,
                )
                progress = int(resp.json().get("status", 0))
                log.info("[zap] active scan %s: %d%%", scan_id, progress)
                if progress >= 100:
                    return
            except Exception:
                pass
            time.sleep(_POLL_INTERVAL)
        log.warning("[zap] active scan %s timed out after %ds", scan_id, timeout)

    def _passively_fetch(self, target_url: str) -> None:
        """Fetch target through ZAP proxy so passive rules fire."""
        try:
            import urllib3
            urllib3.disable_warnings()
            proxied = requests.Session()
            port = self._port()
            proxied.proxies = {
                "http": f"http://127.0.0.1:{port}",
                "https": f"http://127.0.0.1:{port}",
            }
            proxied.verify = False
            proxied.get(target_url, timeout=15)
            time.sleep(3)
        except Exception as exc:
            log.warning("[zap] passive fetch failed: %s", exc)

    def _get_alerts(self, base_url: str = "") -> list[dict]:
        try:
            params: dict = {}
            if base_url:
                params["baseurl"] = base_url
            resp = self._session.get(
                f"{self.api_url}/JSON/alert/view/alerts/",
                params=params,
                timeout=30,
            )
            resp.raise_for_status()
            return resp.json().get("alerts", [])
        except Exception as exc:
            log.error("[zap] failed to get alerts: %s", exc)
            return []

    def _write_empty(
        self,
        run_id: str,
        raw_output_dir: Path,
        target: str,
        errors: list[dict],
    ) -> dict:
        out_path = self._write_raw_output(
            run_id=run_id,
            raw_output_dir=raw_output_dir,
            target=target,
            invocation_command="zap (not run)",
            started_at=_now(),
            finished_at=_now(),
            duration_seconds=0,
            status="failed",
            findings=[],
            errors=errors,
        )
        return {"raw_output_path": out_path, "findings_count": 0}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _normalize_alert(alert: dict) -> dict:
    name = alert.get("name", "")
    risk = alert.get("risk", "Informational")
    confidence = alert.get("confidence", "Low")
    url = alert.get("url", "")

    return {
        "type": _alert_name_to_type(name),
        "url": url,
        "host": _url_host(url),
        "evidence": f"[ZAP] {name}: {alert.get('description', '')[:200]}",
        "raw_output": {
            "alert_id": alert.get("id"),
            "name": name,
            "risk": risk,
            "confidence": confidence,
            "description": alert.get("description", "")[:500],
            "solution": alert.get("solution", "")[:300],
            "reference": alert.get("reference", "")[:200],
            "param": alert.get("param", ""),
            "attack": alert.get("attack", ""),
            "evidence": alert.get("evidence", ""),
            "cweid": alert.get("cweid", ""),
            "wascid": alert.get("wascid", ""),
        },
        "metadata": {
            "severity": _RISK_MAP.get(risk, "info"),
            "confidence_score": _CONFIDENCE_MAP.get(confidence, 0.4),
            "cwe": alert.get("cweid", ""),
            "source": "zap",
        },
    }


def _alert_name_to_type(name: str) -> str:
    n = name.lower()
    for fragment, vuln_type in _ALERT_TYPE_MAP:
        if fragment in n:
            return vuln_type
    return "misconfiguration"


def _url_host(url: str) -> str:
    from urllib.parse import urlparse
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
