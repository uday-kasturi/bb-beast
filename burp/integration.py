"""
Burp Suite REST API integration.

Reads burp_tasks from actions.json and submits them to Burp Suite Pro's
REST API. Pulls results back into the pipeline.

Burp REST API (Professional only):
  Base URL: http://localhost:1337/v0.1
  Endpoints:
    POST /scan                   — start a new scan
    GET  /scan/{task_id}         — get scan status
    GET  /scan/{task_id}/issues  — get scan issues

Configuration:
  BURP_API_URL   — base URL (default: http://localhost:1337/v0.1)
  BURP_API_KEY   — API key if configured in Burp

Burp must be running with the REST API enabled:
  Burp → Extender → APIs → Enable REST API
  Default port: 1337
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

from core.validator import validate_and_write, SchemaValidationError

log = logging.getLogger(__name__)

_DEFAULT_BURP_URL = "http://localhost:1337/v0.1"
_POLL_INTERVAL_SECS = 30
_MAX_WAIT_SECS = 7200  # 2 hours max per scan


class BurpIntegration:
    def __init__(
        self,
        api_url: str = _DEFAULT_BURP_URL,
        api_key: str | None = None,
    ) -> None:
        self.api_url = api_url.rstrip("/")
        self.session = requests.Session()
        if api_key:
            self.session.headers["Authorization"] = f"Bearer {api_key}"
        self.session.headers["Content-Type"] = "application/json"

    def health_check(self) -> bool:
        """Return True if Burp REST API is reachable."""
        try:
            resp = self.session.get(f"{self.api_url}/", timeout=5)
            return resp.status_code < 500
        except requests.RequestException:
            return False

    def submit_tasks(
        self,
        actions_path: Path,
        run_dir: Path,
        program: dict,
        wait_for_completion: bool = False,
    ) -> dict:
        """
        Submit all pending burp_tasks from actions.json to Burp Suite.

        Args:
            actions_path:        Path to actions.json
            run_dir:             Run directory for writing burp results
            program:             program.json document for scope enforcement
            wait_for_completion: If True, poll until all scans complete

        Returns:
            Dict of {task_id: burp_scan_id} mappings
        """
        if not self.health_check():
            log.error(
                "Burp Suite REST API not reachable at %s. "
                "Is Burp running with REST API enabled?",
                self.api_url,
            )
            return {}

        with open(actions_path) as f:
            actions_doc = json.load(f)

        burp_tasks = [
            t for t in actions_doc.get("burp_tasks", [])
            if t.get("status") == "pending"
        ]

        if not burp_tasks:
            log.info("No pending Burp tasks")
            return {}

        log.info("Submitting %d Burp scan tasks", len(burp_tasks))
        task_map: dict[str, str] = {}  # task_id → burp_scan_id

        for task in burp_tasks:
            task_id = task.get("task_id", str(uuid.uuid4()))
            target_url = task.get("target_url", "")
            scan_type = task.get("scan_type", "audit_only")
            config_profile = task.get("config_profile", "default")

            # Scope enforcement
            if not _is_in_scope(target_url, program):
                log.warning("Burp task %s: out of scope — skipping", task_id[:8])
                task["status"] = "failed"
                continue

            try:
                burp_id = self._submit_scan(target_url, scan_type, config_profile)
                task["status"] = "submitted"
                task_map[task_id] = burp_id
                log.info("Submitted Burp scan for %s → scan ID %s", target_url, burp_id)
            except Exception as exc:
                log.error("Failed to submit Burp task %s: %s", task_id[:8], exc)
                task["status"] = "failed"

        # Write updated statuses
        actions_doc["burp_tasks"] = burp_tasks
        with open(actions_path, "w") as f:
            json.dump(actions_doc, f, indent=2)

        # Optionally wait for completion and pull results
        if wait_for_completion and task_map:
            self._wait_and_collect(task_map, run_dir)

        return task_map

    def pull_results(self, burp_scan_id: str) -> list[dict]:
        """
        Pull issues from a completed Burp scan.
        Returns list of normalized findings.
        """
        try:
            resp = self.session.get(
                f"{self.api_url}/scan/{burp_scan_id}/issues",
                timeout=30,
            )
            resp.raise_for_status()
            issues = resp.json().get("issues", [])
        except Exception as exc:
            log.error("Failed to pull Burp results for scan %s: %s", burp_scan_id, exc)
            return []

        findings = []
        for issue in issues:
            severity = _burp_severity_to_ours(issue.get("severity", "information"))
            confidence = _burp_confidence_to_score(issue.get("confidence", "tentative"))

            findings.append({
                "type": _burp_type_to_ours(issue.get("issue_type", 0), issue.get("name", "")),
                "url": issue.get("path", ""),
                "host": issue.get("host", ""),
                "evidence": f"[Burp] {issue.get('name', 'unknown')}: {issue.get('description', '')[:200]}",
                "raw_output": {
                    "issue_type": issue.get("issue_type"),
                    "name": issue.get("name"),
                    "severity": issue.get("severity"),
                    "confidence": issue.get("confidence"),
                    "description": issue.get("description", "")[:500],
                    "remediation": issue.get("remediation", "")[:300],
                    "references": issue.get("references", []),
                    "request_response": issue.get("evidence", []),
                },
                "metadata": {
                    "severity": severity,
                    "burp_scan_id": burp_scan_id,
                },
            })
        return findings

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _submit_scan(self, target_url: str, scan_type: str, config_profile: str) -> str:
        """Submit a scan to Burp and return the scan ID."""
        _SCAN_TYPE_MAP = {
            "crawl_and_audit": ["CrawlAndAudit"],
            "audit_only":      ["Audit"],
            "crawl_only":      ["Crawl"],
            "active_scan":     ["CrawlAndAudit"],
        }
        scan_configurations = _SCAN_TYPE_MAP.get(scan_type, ["Audit"])

        payload = {
            "urls": [target_url],
            "scope": {
                "type": "SimpleScope",
                "include": [{"rule": target_url}],
            },
            "scan_configurations": [
                {"name": cfg, "type": "NamedConfiguration"}
                for cfg in scan_configurations
            ],
        }

        resp = self.session.post(
            f"{self.api_url}/scan",
            json=payload,
            timeout=30,
        )
        resp.raise_for_status()

        scan_id = resp.headers.get("Location", "").split("/")[-1]
        if not scan_id:
            data = resp.json()
            scan_id = str(data.get("task_id", uuid.uuid4()))
        return scan_id

    def _get_scan_status(self, burp_scan_id: str) -> str:
        """Return scan status string."""
        try:
            resp = self.session.get(
                f"{self.api_url}/scan/{burp_scan_id}",
                timeout=10,
            )
            resp.raise_for_status()
            return resp.json().get("scan_status", "unknown")
        except Exception:
            return "unknown"

    def _wait_and_collect(self, task_map: dict[str, str], run_dir: Path) -> None:
        """Poll until all scans complete, then write results."""
        pending = dict(task_map)
        deadline = time.monotonic() + _MAX_WAIT_SECS

        while pending and time.monotonic() < deadline:
            time.sleep(_POLL_INTERVAL_SECS)
            completed = []
            for task_id, burp_id in pending.items():
                status = self._get_scan_status(burp_id)
                log.info("Burp scan %s: %s", burp_id, status)
                if status in ("succeeded", "failed"):
                    completed.append(task_id)
                    if status == "succeeded":
                        findings = self.pull_results(burp_id)
                        _write_burp_results(findings, burp_id, run_dir)

            for task_id in completed:
                del pending[task_id]

        if pending:
            log.warning("Burp scans timed out: %s", list(pending.values()))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_in_scope(url: str, program: dict) -> bool:
    import fnmatch
    from urllib.parse import urlparse
    try:
        host = urlparse(url).hostname or ""
    except Exception:
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


def _burp_severity_to_ours(severity: str) -> str:
    return {
        "high":        "high",
        "medium":      "medium",
        "low":         "low",
        "information": "info",
    }.get(severity.lower(), "info")


def _burp_confidence_to_score(confidence: str) -> float:
    return {
        "certain":   0.95,
        "firm":      0.75,
        "tentative": 0.50,
    }.get(confidence.lower(), 0.5)


def _burp_type_to_ours(issue_type: int, name: str) -> str:
    name_lower = name.lower()
    if "sql" in name_lower:
        return "sqli"
    if "xss" in name_lower or "cross-site scripting" in name_lower:
        return "xss"
    if "ssrf" in name_lower:
        return "ssrf"
    if "csrf" in name_lower:
        return "csrf"
    if "traversal" in name_lower or "path" in name_lower:
        return "path_traversal"
    if "redirect" in name_lower:
        return "open_redirect"
    if "injection" in name_lower:
        return "command_injection"
    if "secret" in name_lower or "password" in name_lower:
        return "secret_exposure"
    return "misconfiguration"


def _write_burp_results(findings: list[dict], burp_scan_id: str, run_dir: Path) -> None:
    """Write Burp results as a raw_output doc alongside run outputs."""
    if not findings:
        return

    from datetime import datetime, timezone
    raw_dir = run_dir / "raw_output"
    raw_dir.mkdir(exist_ok=True)
    out_path = raw_dir / f"burp_{burp_scan_id[:8]}.json"

    doc = {
        "schema_version": "1.0",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "run_id": burp_scan_id,
        "tool_name": "burp",
        "tool_version": "professional",
        "invocation_command": f"burp_scan:{burp_scan_id}",
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
    log.info("Wrote Burp results: %s (%d findings)", out_path.name, len(findings))
