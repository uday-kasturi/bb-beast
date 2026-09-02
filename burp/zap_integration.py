"""
OWASP ZAP REST API integration.

Free alternative to Burp Suite Pro. Reads burp_tasks from actions.json,
submits them to a locally-running ZAP daemon, and normalizes results back
into the pipeline format.

ZAP Daemon Setup:
  Run scripts/start_zap.sh to start ZAP in headless daemon mode.
  Or manually:
    /Applications/OWASP\ ZAP.app/Contents/Java/zap.sh \
      -daemon -port 8090 \
      -config api.key=bb-beast-zap \
      -config api.addrs.addr.name=.* \
      -config api.addrs.addr.regex=true

Configuration:
  ZAP_API_URL   — base URL (default: http://localhost:8090)
  ZAP_API_KEY   — API key (default: bb-beast-zap)

Proxy (optional — route tool requests through ZAP for passive scan):
  Set HTTP_PROXY=http://127.0.0.1:8090 before running tools
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

log = logging.getLogger(__name__)

ZAP_DEFAULT_URL = "http://localhost:8090"
ZAP_DEFAULT_KEY = "bb-beast-zap"
_POLL_INTERVAL = 15
_MAX_WAIT = 3600  # 1 hour max per scan


class ZapIntegration:
    def __init__(
        self,
        api_url: str = ZAP_DEFAULT_URL,
        api_key: str = ZAP_DEFAULT_KEY,
    ) -> None:
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers["X-ZAP-API-Key"] = api_key

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    def ensure_running(self) -> bool:
        """Start ZAP daemon if not already running. Returns True when ready."""
        if self.health_check():
            return True

        import subprocess, os
        log.info("ZAP not running — starting daemon automatically...")
        zap_sh = "/Applications/ZAP.app/Contents/Java/zap.sh"
        if not os.path.exists(zap_sh):
            log.error("ZAP not installed at %s", zap_sh)
            return False

        subprocess.Popen(
            [
                zap_sh, "-daemon",
                "-port", str(self._port()),
                "-config", f"api.key={self.api_key}",
                "-config", "api.addrs.addr.name=.*",
                "-config", "api.addrs.addr.regex=true",
                "-config", "connection.timeoutInSecs=30",
                "-config", "scanner.threadPerHost=5",
            ],
            stdout=open("/tmp/zap-daemon.log", "w"),
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )

        # Wait up to 90s for ZAP to be ready
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            time.sleep(3)
            if self.health_check():
                log.info("ZAP daemon ready on %s", self.api_url)
                return True
        log.error("ZAP failed to start within 90s — check /tmp/zap-daemon.log")
        return False

    def health_check(self) -> bool:
        """Return True if ZAP daemon is reachable."""
        try:
            resp = self.session.get(
                f"{self.api_url}/JSON/core/view/version/",
                timeout=5,
            )
            return resp.status_code == 200
        except requests.RequestException:
            return False

    def _port(self) -> int:
        try:
            return int(self.api_url.rsplit(":", 1)[-1])
        except Exception:
            return 8090

    def version(self) -> str:
        try:
            resp = self.session.get(
                f"{self.api_url}/JSON/core/view/version/",
                timeout=5,
            )
            return resp.json().get("version", "unknown")
        except Exception:
            return "unknown"

    # ------------------------------------------------------------------
    # Active scan (main entry point — mirrors BurpIntegration API)
    # ------------------------------------------------------------------

    def submit_tasks(
        self,
        actions_path: Path,
        run_dir: Path,
        program: dict,
        wait_for_completion: bool = True,
    ) -> dict:
        """
        Submit all pending burp_tasks from actions.json to ZAP.
        ZAP is the free drop-in replacement for Burp Pro scans.

        Returns dict of {task_id: zap_scan_id}.
        """
        if not self.ensure_running():
            return {}

        log.info("ZAP version: %s", self.version())

        with open(actions_path) as f:
            actions_doc = json.load(f)

        burp_tasks = [
            t for t in actions_doc.get("burp_tasks", [])
            if t.get("status") == "pending"
        ]

        if not burp_tasks:
            log.info("No pending scan tasks for ZAP")
            return {}

        log.info("Submitting %d tasks to ZAP", len(burp_tasks))
        task_map: dict[str, str] = {}

        for task in burp_tasks:
            task_id = task.get("task_id", str(uuid.uuid4()))
            target_url = task.get("target_url", "")
            scan_type = task.get("scan_type", "audit_only")

            if not _is_in_scope(target_url, program):
                log.warning("ZAP task %s: out of scope — skipping", task_id[:8])
                task["status"] = "failed"
                continue

            try:
                zap_id = self._run_scan(target_url, scan_type)
                task["status"] = "submitted"
                task_map[task_id] = zap_id
                log.info("ZAP scan started for %s → scan ID %s", target_url, zap_id)
            except Exception as exc:
                log.error("Failed to start ZAP scan for %s: %s", task_id[:8], exc)
                task["status"] = "failed"

        actions_doc["burp_tasks"] = burp_tasks
        with open(actions_path, "w") as f:
            json.dump(actions_doc, f, indent=2)

        if wait_for_completion and task_map:
            self._wait_and_collect(task_map, run_dir)

        return task_map

    # ------------------------------------------------------------------
    # Direct scanning (called manually, not via actions.json)
    # ------------------------------------------------------------------

    def quick_scan(
        self,
        target_url: str,
        run_dir: Path,
        program: dict,
        recurse: bool = True,
    ) -> list[dict]:
        """
        Spider + active scan a single URL. Returns normalized findings.
        Useful for targeted follow-up after recon identifies a live endpoint.
        """
        if not self.ensure_running():
            return []

        if not _is_in_scope(target_url, program):
            log.error("Target %s is out of scope — refusing scan", target_url)
            return []

        log.info("ZAP quick scan: %s", target_url)

        # 1. Set context / include target in scope
        self._set_scope(target_url)

        # 2. Spider
        log.info("ZAP: spidering %s", target_url)
        spider_id = self._spider(target_url, recurse)
        self._wait_spider(spider_id)

        # 3. Active scan
        log.info("ZAP: active scanning %s", target_url)
        scan_id = self._active_scan(target_url, recurse)
        self._wait_active_scan(scan_id)

        # 4. Collect alerts
        findings = self.get_alerts(target_url)
        if run_dir:
            _write_zap_results(findings, target_url, run_dir)

        log.info("ZAP quick scan complete: %d alerts for %s", len(findings), target_url)
        return findings

    def passive_scan_url(self, url: str) -> list[dict]:
        """
        Fetch a URL through ZAP proxy (passive scan only — no active attacks).
        Use when you want ZAP to analyze traffic without active probing.
        """
        try:
            proxied = requests.Session()
            proxied.proxies = {
                "http": f"http://127.0.0.1:{self._proxy_port()}",
                "https": f"http://127.0.0.1:{self._proxy_port()}",
            }
            proxied.verify = False
            proxied.get(url, timeout=15)
            time.sleep(2)  # let ZAP process
            return self.get_alerts(url)
        except Exception as exc:
            log.warning("Passive scan failed for %s: %s", url, exc)
            return []

    def get_alerts(self, base_url: str = "") -> list[dict]:
        """Pull all alerts from ZAP, optionally filtered by base URL."""
        try:
            params = {"baseurl": base_url} if base_url else {}
            resp = self.session.get(
                f"{self.api_url}/JSON/alert/view/alerts/",
                params=params,
                timeout=30,
            )
            resp.raise_for_status()
            alerts = resp.json().get("alerts", [])
        except Exception as exc:
            log.error("Failed to get ZAP alerts: %s", exc)
            return []

        return [_normalize_alert(a) for a in alerts]

    def pull_results(self, zap_scan_id: str) -> list[dict]:
        """Pull results for a specific scan ID."""
        return self.get_alerts()

    # ------------------------------------------------------------------
    # Internal ZAP API calls
    # ------------------------------------------------------------------

    def _set_scope(self, target_url: str) -> None:
        try:
            self.session.get(
                f"{self.api_url}/JSON/context/action/includeInContext/",
                params={"contextName": "Default Context", "regex": f"{target_url}.*"},
                timeout=10,
            )
        except Exception:
            pass

    def _spider(self, target_url: str, recurse: bool = True) -> str:
        resp = self.session.get(
            f"{self.api_url}/JSON/spider/action/scan/",
            params={"url": target_url, "recurse": str(recurse).lower()},
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json().get("scan", "0")

    def _wait_spider(self, spider_id: str) -> None:
        deadline = time.monotonic() + 600  # 10 min max for spider
        while time.monotonic() < deadline:
            try:
                resp = self.session.get(
                    f"{self.api_url}/JSON/spider/view/status/",
                    params={"scanId": spider_id},
                    timeout=10,
                )
                progress = int(resp.json().get("status", 0))
                log.debug("ZAP spider %s: %d%%", spider_id, progress)
                if progress >= 100:
                    return
            except Exception:
                pass
            time.sleep(5)

    def _active_scan(self, target_url: str, recurse: bool = True) -> str:
        resp = self.session.get(
            f"{self.api_url}/JSON/ascan/action/scan/",
            params={"url": target_url, "recurse": str(recurse).lower()},
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json().get("scan", "0")

    def _wait_active_scan(self, scan_id: str) -> None:
        deadline = time.monotonic() + _MAX_WAIT
        while time.monotonic() < deadline:
            try:
                resp = self.session.get(
                    f"{self.api_url}/JSON/ascan/view/status/",
                    params={"scanId": scan_id},
                    timeout=10,
                )
                progress = int(resp.json().get("status", 0))
                log.info("ZAP active scan %s: %d%%", scan_id, progress)
                if progress >= 100:
                    return
            except Exception:
                pass
            time.sleep(_POLL_INTERVAL)

    def _run_scan(self, target_url: str, scan_type: str) -> str:
        """Spider + active scan. Returns active scan ID."""
        self._set_scope(target_url)
        spider_id = self._spider(target_url)
        self._wait_spider(spider_id)
        if scan_type == "crawl_only":
            return spider_id
        return self._active_scan(target_url)

    def _wait_and_collect(self, task_map: dict[str, str], run_dir: Path) -> None:
        for task_id, scan_id in task_map.items():
            self._wait_active_scan(scan_id)
            findings = self.get_alerts()
            if findings:
                _write_zap_results(findings, scan_id, run_dir)

    def _proxy_port(self) -> int:
        try:
            resp = self.session.get(
                f"{self.api_url}/JSON/core/view/proxyChainExcludedDomains/",
                timeout=5,
            )
            # ZAP default proxy port is same as API port
            return int(self.api_url.split(":")[-1])
        except Exception:
            return 8090


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _normalize_alert(alert: dict) -> dict:
    severity_map = {"High": "high", "Medium": "medium", "Low": "low", "Informational": "info"}
    confidence_map = {"High": 0.9, "Medium": 0.7, "Low": 0.4, "False Positive": 0.1}

    return {
        "type": _zap_name_to_type(alert.get("name", "")),
        "url": alert.get("url", ""),
        "host": _url_host(alert.get("url", "")),
        "evidence": f"[ZAP] {alert.get('name', '')}: {alert.get('description', '')[:200]}",
        "raw_output": {
            "alert_id": alert.get("id"),
            "name": alert.get("name"),
            "risk": alert.get("risk"),
            "confidence": alert.get("confidence"),
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
            "severity": severity_map.get(alert.get("risk", ""), "info"),
            "confidence_score": confidence_map.get(alert.get("confidence", ""), 0.5),
            "cwe": alert.get("cweid", ""),
            "source": "zap",
        },
    }


def _zap_name_to_type(name: str) -> str:
    n = name.lower()
    if "sql" in n:             return "sqli"
    if "xss" in n or "cross-site scripting" in n: return "xss"
    if "ssrf" in n:            return "ssrf"
    if "csrf" in n:            return "csrf"
    if "traversal" in n:       return "path_traversal"
    if "redirect" in n:        return "open_redirect"
    if "injection" in n:       return "command_injection"
    if "disclosure" in n or "information" in n: return "info_disclosure"
    if "takeover" in n:        return "subdomain_takeover"
    if "secret" in n or "password" in n: return "secret_exposure"
    return "misconfiguration"


def _url_host(url: str) -> str:
    from urllib.parse import urlparse
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""


def _is_in_scope(url: str, program: dict) -> bool:
    import fnmatch
    host = _url_host(url)
    if not host:
        return False

    out = program.get("out_of_scope", {}).get("domains", [])
    for p in out:
        if fnmatch.fnmatch(host, p) or host == p:
            return False

    inc = program.get("in_scope", {}).get("domains", [])
    if not inc:
        return True
    for p in inc:
        if fnmatch.fnmatch(host, p) or host == p:
            return True
        if p.startswith("*."):
            apex = p[2:]
            if host == apex or host.endswith("." + apex):
                return True
    return False


def _write_zap_results(findings: list[dict], scan_ref: str, run_dir: Path) -> None:
    if not findings:
        return
    raw_dir = run_dir / "raw_output"
    raw_dir.mkdir(exist_ok=True)
    out_path = raw_dir / f"zap_{scan_ref[:8]}.json"

    doc = {
        "schema_version": "1.0",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "run_id": scan_ref,
        "tool_name": "zap",
        "tool_version": "owasp-zap",
        "invocation_command": f"zap_scan:{scan_ref}",
        "target": findings[0].get("host", "unknown") if findings else "unknown",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "duration_seconds": 0,
        "status": "success",
        "findings": findings,
        "errors": [],
    }
    with open(out_path, "w") as f:
        json.dump(doc, f, indent=2)
    log.info("Wrote ZAP results: %s (%d findings)", out_path.name, len(findings))
