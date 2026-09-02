"""
ZAP + Fable 5 intelligent scanning pipeline.

Flow:
  1. Start ZAP daemon if not running
  2. Spider/passive-probe target through ZAP
  3. Pull HTTP message history from ZAP
  4. Deduplicate and template-normalize endpoints
  5. Call Fable 5 (claude-fable-5) with: message samples + program context → attack hypotheses
  6. Execute each hypothesis (direct HTTP or ZAP targeted scan)
  7. Feed results back to Fable 5 for verdict
  8. Return structured findings ready for findings.json aggregation

This module is the primary attack-discovery engine for web targets. It replaces
broad active scanning with targeted LLM-guided testing — fewer requests, higher
signal-to-noise, context-aware about McDonald's specific business logic.

Usage:
    scanner = ZapFableScanner(program=program_dict, run_dir=run_dir)
    findings = scanner.scan(target="https://admin.me.mcd.com", depth="standard")
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

import requests

log = logging.getLogger(__name__)

_ZAP_URL = os.environ.get("ZAP_API_URL", "http://localhost:8090")
_ZAP_KEY = os.environ.get("ZAP_API_KEY", "bb-beast-zap")
_ZAP_INSTALL = "/Applications/ZAP.app/Contents/MacOS/ZAP.sh"   # confirmed path
_FABLE_MODEL = "claude-fable-5"
_MAX_MESSAGES_PER_ENDPOINT = 3     # max raw HTTP samples sent to Fable per endpoint group
_MAX_ENDPOINTS_PER_CALL = 40       # max endpoint groups per Fable call
_MAX_HYPOTHESIS_ATTEMPTS = 5       # max HTTP attempts per attack hypothesis
_REQUEST_DELAY = 0.3               # seconds between requests (respects throttle)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class HttpMessage:
    method: str
    url: str
    request_header: str
    request_body: str
    response_header: str
    response_body: str
    status_code: int
    response_size: int

    @classmethod
    def from_zap(cls, msg: dict) -> "HttpMessage":
        req = msg.get("requestHeader", "")
        resp_hdr = msg.get("responseHeader", "")
        status = 0
        try:
            status_line = resp_hdr.split("\n")[0] if resp_hdr else ""
            parts = status_line.split(" ", 2)
            if len(parts) >= 2:
                status = int(parts[1])
        except Exception:
            pass
        method = "GET"
        try:
            method = req.split(" ", 1)[0].strip()
        except Exception:
            pass
        url = ""
        try:
            url = req.split(" ", 2)[1].strip()
        except Exception:
            pass
        return cls(
            method=method,
            url=url,
            request_header=req[:2000],
            request_body=(msg.get("requestBody") or "")[:1000],
            response_header=resp_hdr[:500],
            response_body=(msg.get("responseBody") or "")[:500],
            status_code=status,
            response_size=msg.get("responseBodyLength", 0),
        )


@dataclass
class AttackHypothesis:
    id: str
    endpoint: str
    method: str
    attack_type: str
    description: str
    payload_url: str
    payload_headers: dict
    payload_body: str
    expected_indicator: str
    priority: int

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "endpoint": self.endpoint,
            "method": self.method,
            "attack_type": self.attack_type,
            "description": self.description,
            "payload_url": self.payload_url,
            "payload_headers": self.payload_headers,
            "payload_body": self.payload_body,
            "expected_indicator": self.expected_indicator,
            "priority": self.priority,
        }


@dataclass
class Finding:
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    type: str = "unknown"
    severity_raw: str = "info"
    url: str = ""
    host: str = ""
    evidence: str = ""
    tool: str = "zap_fable"
    confidence: float = 0.5
    raw_output: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# System prompts
# ---------------------------------------------------------------------------

_HYPOTHESIS_PROMPT = """\
You are an elite bug bounty hunter specializing in web application vulnerabilities.
You will be given HTTP request/response samples from a target web application, plus
context about what the application does.

Your job: generate targeted attack hypotheses — specific, executable tests that
could reveal real vulnerabilities. Think like a red teamer who understands both
technical and business logic flaws.

Focus areas (in priority order):
1. IDOR / broken object-level authorization — look for IDs in URLs/bodies, test other user IDs
2. Auth bypass — missing auth checks on API endpoints, JWT weaknesses, cookie manipulation
3. Business logic — price manipulation, coupon/loyalty point abuse, order tampering
4. Injection — SQL/command/SSTI in parameters that hit the backend
5. CORS misconfiguration — check for credentials + wildcard or same-site origin reflection
6. Sensitive data exposure — PII, session tokens, API keys in responses

For McDonald's specifically:
- Loyalty points and offers are high-value IDOR targets (user account IDs, offer IDs)
- Order IDs (numeric or UUID) appearing in URLs → test adjacent IDs
- Admin panels (Nova, DNA CMS) → look for unauthenticated API routes
- Marketing platform → CORS issues can enable cross-origin account actions
- Staging/dev environments → often have weaker auth or debug endpoints

CONSTRAINTS:
- Only generate hypotheses for in-scope targets (*.mcdonalds.com, *.mcd.com)
- No brute force, no DoS, no spam, no testing other users' accounts without consent
- Max 5 requests per test (don't hammer endpoints)
- If you see JWT: inspect claims, but don't attempt signature bypass without clear weakness
- Do not test out-of-scope assets listed in the program

Respond with JSON only — no markdown, no explanation:
{
  "hypotheses": [
    {
      "id": "<short-slug>",
      "endpoint": "<url-template>",
      "method": "GET|POST|PUT|DELETE|PATCH",
      "attack_type": "idor|auth_bypass|injection|cors|logic|info_disclosure|misconfiguration",
      "description": "<1-2 sentences: what you're testing and why it might work>",
      "payload_url": "<exact URL with payload injected, use {FUZZ} as placeholder if needed>",
      "payload_headers": {"Header-Name": "value"},
      "payload_body": "<exact body string or empty>",
      "expected_indicator": "<what response indicates success: status code, body string, header value>",
      "priority": 1-5
    }
  ],
  "analysis": "<2-3 sentences: overall assessment of the attack surface, what looks most promising>"
}

Generate only REALISTIC hypotheses with strong theoretical basis. Skip speculative ones.
Max 15 hypotheses per call. Prioritize by exploitability × impact."""


_VERDICT_PROMPT = """\
You are a bug bounty triage expert. You executed an attack hypothesis against a live target
and observed the response. Determine if this is a real finding worth reporting.

Be conservative — false positives waste everyone's time. Only call it a finding if you can
write a concrete impact statement. Consider:
- Is the response genuinely different from baseline? (Not just different status codes)
- Does the response reveal something it shouldn't? (Data belonging to other users, internal info)
- Is the behavior actually exploitable, or just unexpected?

For McDonald's VDP specifically:
- IDOR confirmed = seeing another user's name/email/order/offer data in response
- Auth bypass confirmed = accessing protected functionality without valid credentials
- Injection confirmed = error message showing SQL syntax, or OOB callback received
- CORS confirmed = credentials flag + origin reflection to a cross-site origin

Respond with JSON only:
{
  "verdict": "finding|false_positive|needs_more_info",
  "severity": "critical|high|medium|low|info",
  "confidence": 0.0-1.0,
  "finding_type": "<attack_type>",
  "title": "<concise finding title for bug report>",
  "evidence": "<what in the response proves this>",
  "impact": "<concrete: what attacker gains, how, which CIA component>",
  "reproduction_steps": ["step 1", "step 2", ...],
  "reasoning": "<2-3 sentences explaining verdict>"
}"""


# ---------------------------------------------------------------------------
# Main scanner class
# ---------------------------------------------------------------------------

class ZapFableScanner:
    """
    ZAP + Fable 5 integrated vulnerability scanner.

    Probes targets through ZAP, then uses Fable 5 to reason about
    the HTTP traffic and generate targeted attack hypotheses.
    """

    def __init__(
        self,
        program: dict,
        run_dir: Path,
        zap_url: str = _ZAP_URL,
        zap_key: str = _ZAP_KEY,
    ) -> None:
        self.program = program
        self.run_dir = run_dir
        self.zap_url = zap_url.rstrip("/")
        self.zap_key = zap_key
        self._zap = requests.Session()
        self._zap.headers["X-ZAP-API-Key"] = zap_key
        self._http = requests.Session()
        self._http.headers["User-Agent"] = (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/125.0.0.0 Safari/537.36"
        )
        self._http.verify = False
        import urllib3
        urllib3.disable_warnings()

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def scan(
        self,
        target: str,
        depth: str = "standard",
        cookies: dict | None = None,
        auth_headers: dict | None = None,
    ) -> list[Finding]:
        """
        Run ZAP spider + Fable 5 analysis on target.
        Falls back to direct HTTP spider if ZAP is unavailable (e.g. Java not installed).

        Args:
            target:       Base URL (e.g. https://admin.me.mcd.com)
            depth:        quick | standard | exhaustive
            cookies:      Optional session cookies for authenticated scanning
            auth_headers: Optional auth headers (Authorization: Bearer ...)

        Returns:
            List of Finding objects (not yet written to findings.json)
        """
        if not self._scope_check(target):
            log.warning("[zap_fable] %s is out of scope — skipping", target)
            return []

        log.info("[zap_fable] scanning %s (depth=%s)", target, depth)

        if cookies:
            self._http.cookies.update(cookies)
        if auth_headers:
            self._http.headers.update(auth_headers)

        # Phase 1: Spider target — use ZAP if available, else direct HTTP spider
        zap_ok = self._ensure_zap()
        if zap_ok:
            if cookies:
                self._zap.cookies.update(cookies)
            if auth_headers:
                self._zap.headers.update(auth_headers)
            self._set_context(target)
            self._spider_target(target, depth)
            messages = self._get_messages(target)
            if not messages:
                self._fetch_through_proxy(target)
                messages = self._get_messages(target)
        else:
            log.info("[zap_fable] ZAP unavailable — using direct HTTP spider")
            messages = self._direct_spider(target, depth)

        log.info("[zap_fable] %d HTTP messages collected", len(messages))

        if not messages:
            log.warning("[zap_fable] no HTTP messages collected")
            return []

        # Phase 2: Group messages into endpoint templates
        endpoint_groups = _group_by_endpoint(messages)
        log.info("[zap_fable] %d unique endpoint templates", len(endpoint_groups))

        # Phase 3: Fable 5 → attack hypotheses
        hypotheses = self._generate_hypotheses(target, endpoint_groups)
        log.info("[zap_fable] %d attack hypotheses from Fable 5", len(hypotheses))

        if not hypotheses:
            return []

        # Phase 4: Execute hypotheses
        findings = []
        for h in sorted(hypotheses, key=lambda x: x.priority):
            finding = self._execute_hypothesis(h)
            if finding:
                findings.append(finding)

        log.info("[zap_fable] %d findings confirmed", len(findings))
        return findings

    # ------------------------------------------------------------------
    # ZAP control
    # ------------------------------------------------------------------

    def _ensure_zap(self) -> bool:
        if self._zap_alive():
            return True
        if not Path(_ZAP_INSTALL).exists():
            log.error("[zap_fable] ZAP not installed at %s", _ZAP_INSTALL)
            return False
        import subprocess
        port = self._zap_port()
        log.info("[zap_fable] starting ZAP daemon on port %d...", port)
        subprocess.Popen(
            [
                _ZAP_INSTALL, "-daemon",
                "-port", str(port),
                "-config", f"api.key={self.zap_key}",
                "-config", "api.addrs.addr.name=.*",
                "-config", "api.addrs.addr.regex=true",
                "-config", "connection.timeoutInSecs=30",
                "-config", "scanner.threadPerHost=3",
            ],
            stdout=open("/tmp/zap-daemon.log", "w"),
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            time.sleep(3)
            if self._zap_alive():
                log.info("[zap_fable] ZAP daemon ready")
                return True
        log.error("[zap_fable] ZAP daemon failed to start — see /tmp/zap-daemon.log")
        return False

    def _zap_alive(self) -> bool:
        try:
            r = self._zap.get(f"{self.zap_url}/JSON/core/view/version/", timeout=4)
            return r.status_code == 200
        except Exception:
            return False

    def _zap_port(self) -> int:
        try:
            return int(self.zap_url.rsplit(":", 1)[-1])
        except Exception:
            return 8090

    def _set_context(self, target_url: str) -> None:
        try:
            self._zap.get(
                f"{self.zap_url}/JSON/context/action/includeInContext/",
                params={"contextName": "Default Context", "regex": f"{target_url}.*"},
                timeout=10,
            )
        except Exception:
            pass

    def _spider_target(self, target_url: str, depth: str) -> None:
        try:
            if depth in ("standard", "exhaustive"):
                resp = self._zap.get(
                    f"{self.zap_url}/JSON/spider/action/scan/",
                    params={"url": target_url, "recurse": "true", "maxChildren": "20"},
                    timeout=30,
                )
                spider_id = resp.json().get("scan", "0")
                log.info("[zap_fable] spider started: %s", spider_id)
                deadline = time.monotonic() + 300
                while time.monotonic() < deadline:
                    time.sleep(8)
                    r = self._zap.get(
                        f"{self.zap_url}/JSON/spider/view/status/",
                        params={"scanId": spider_id},
                        timeout=10,
                    )
                    pct = int(r.json().get("status", 0))
                    log.debug("[zap_fable] spider %d%%", pct)
                    if pct >= 100:
                        break

            if depth == "exhaustive":
                self._zap.get(
                    f"{self.zap_url}/JSON/ajaxSpider/action/scan/",
                    params={"url": target_url},
                    timeout=30,
                )
                deadline = time.monotonic() + 180
                while time.monotonic() < deadline:
                    time.sleep(8)
                    r = self._zap.get(
                        f"{self.zap_url}/JSON/ajaxSpider/view/status/",
                        timeout=10,
                    )
                    if r.json().get("status") == "stopped":
                        break

            if depth == "quick":
                self._fetch_through_proxy(target_url)

        except Exception as exc:
            log.warning("[zap_fable] spider error: %s", exc)

    def _fetch_through_proxy(self, url: str) -> None:
        port = self._zap_port()
        try:
            proxied = requests.Session()
            proxied.proxies = {
                "http": f"http://127.0.0.1:{port}",
                "https": f"http://127.0.0.1:{port}",
            }
            proxied.verify = False
            proxied.headers["User-Agent"] = self._http.headers["User-Agent"]
            proxied.get(url, timeout=15)
            time.sleep(3)
        except Exception as exc:
            log.debug("[zap_fable] proxy fetch failed: %s", exc)

    def _get_messages(self, base_url: str) -> list[HttpMessage]:
        try:
            resp = self._zap.get(
                f"{self.zap_url}/JSON/core/view/messages/",
                params={"baseurl": base_url, "start": "0", "count": "500"},
                timeout=30,
            )
            raw_msgs = resp.json().get("messages", [])
            return [HttpMessage.from_zap(m) for m in raw_msgs]
        except Exception as exc:
            log.error("[zap_fable] failed to get messages: %s", exc)
            return []

    # ------------------------------------------------------------------
    # Direct HTTP spider (ZAP fallback)
    # ------------------------------------------------------------------

    def _direct_spider(
        self,
        target: str,
        depth: str,
        max_pages: int = 50,
    ) -> list[HttpMessage]:
        """
        Basic HTTP spider: fetches the target, extracts links, follows them.
        Collects all HTTP traffic as HttpMessage objects for Fable 5.
        No JS execution — static link following only.
        """
        from html.parser import HTMLParser
        from urllib.parse import urljoin, urlparse

        class LinkExtractor(HTMLParser):
            def __init__(self):
                super().__init__()
                self.links: list[str] = []
                self.forms: list[dict] = []
                self._current_form: dict | None = None
                self.scripts: list[str] = []

            def handle_starttag(self, tag, attrs):
                attrs_d = dict(attrs)
                if tag == "a" and "href" in attrs_d:
                    self.links.append(attrs_d["href"])
                elif tag == "link" and attrs_d.get("rel") == "alternate":
                    if "href" in attrs_d:
                        self.links.append(attrs_d["href"])
                elif tag == "form":
                    self._current_form = {
                        "action": attrs_d.get("action", ""),
                        "method": attrs_d.get("method", "GET").upper(),
                        "inputs": [],
                    }
                elif tag == "input" and self._current_form is not None:
                    self._current_form["inputs"].append({
                        "name": attrs_d.get("name", ""),
                        "type": attrs_d.get("type", "text"),
                        "value": attrs_d.get("value", ""),
                    })
                elif tag == "script":
                    if "src" in attrs_d:
                        src = attrs_d["src"]
                        if not src.startswith("http") or urlparse(target).hostname in src:
                            self.scripts.append(attrs_d["src"])

            def handle_endtag(self, tag):
                if tag == "form" and self._current_form is not None:
                    self.forms.append(self._current_form)
                    self._current_form = None

        visited: set[str] = set()
        queue: list[str] = [target]
        messages: list[HttpMessage] = []
        target_parsed = urlparse(target)

        def in_scope(url: str) -> bool:
            try:
                p = urlparse(url)
                return p.hostname == target_parsed.hostname and p.scheme in ("http", "https")
            except Exception:
                return False

        while queue and len(visited) < max_pages:
            url = queue.pop(0)
            if url in visited:
                continue
            if not in_scope(url):
                continue
            # Skip static assets
            path = urlparse(url).path.lower()
            if _EXT_RE.search(path):
                continue

            visited.add(url)
            time.sleep(_REQUEST_DELAY)

            resp = self._safe_request("GET", url)
            if resp is None:
                continue

            # Build HttpMessage
            req_hdr = f"GET {url} HTTP/1.1\r\nHost: {target_parsed.hostname}\r\n"
            for k, v in self._http.headers.items():
                req_hdr += f"{k}: {v}\r\n"
            resp_hdr = f"HTTP/1.1 {resp.status_code}\r\n"
            for k, v in resp.headers.items():
                resp_hdr += f"{k}: {v}\r\n"

            msg = HttpMessage(
                method="GET",
                url=url,
                request_header=req_hdr[:2000],
                request_body="",
                response_header=resp_hdr[:500],
                response_body=resp.text[:500],
                status_code=resp.status_code,
                response_size=len(resp.content),
            )
            messages.append(msg)

            # Extract links from HTML responses
            ct = resp.headers.get("Content-Type", "")
            if "html" not in ct:
                continue
            try:
                parser = LinkExtractor()
                parser.feed(resp.text)
                for link in parser.links:
                    abs_url = urljoin(url, link).split("#")[0]
                    if abs_url not in visited and in_scope(abs_url):
                        queue.append(abs_url)
                # Also probe form actions
                for form in parser.forms:
                    action = form.get("action", "")
                    if action:
                        form_url = urljoin(url, action)
                        if form_url not in visited and in_scope(form_url):
                            queue.append(form_url)
            except Exception:
                pass

        log.info("[zap_fable] direct spider: %d pages visited", len(visited))
        return messages

    # ------------------------------------------------------------------
    # Fable 5 hypothesis generation
    # ------------------------------------------------------------------

    def _generate_hypotheses(
        self,
        target: str,
        endpoint_groups: dict[str, list[HttpMessage]],
    ) -> list[AttackHypothesis]:
        # Pick the most interesting endpoint groups to send
        groups_to_send = _select_interesting_groups(endpoint_groups, _MAX_ENDPOINTS_PER_CALL)

        # Build message samples for the prompt
        samples = []
        for template, msgs in groups_to_send.items():
            for msg in msgs[:_MAX_MESSAGES_PER_ENDPOINT]:
                redacted_req = _redact_sensitive(msg.request_header + "\n" + msg.request_body)
                redacted_resp = _redact_sensitive(msg.response_header + "\n" + msg.response_body)
                samples.append({
                    "endpoint_template": template,
                    "method": msg.method,
                    "url": msg.url,
                    "status_code": msg.status_code,
                    "request_sample": redacted_req[:800],
                    "response_sample": redacted_resp[:400],
                })

        user_msg = (
            f"Target: {target}\n"
            f"Program: McDonald's VDP (Bugcrowd, non-monetary hall of fame)\n"
            f"In scope: *.mcdonalds.com, *.mcd.com\n"
            f"Tech stack: Akamai CDN, Java backend, some Laravel (admin.me.mcd.com), "
            f"React SPAs, Spring Boot APIs\n"
            f"Business context: Global fast food chain — loyalty points, mobile ordering, "
            f"franchise management, marketing platforms, employee portals\n\n"
            f"HTTP message samples ({len(samples)} endpoints):\n\n"
            f"{json.dumps(samples, indent=2)}"
        )

        try:
            response_text = _call_fable(
                system=_HYPOTHESIS_PROMPT,
                user=user_msg,
            )
            data = json.loads(response_text)
            raw_hyps = data.get("hypotheses", [])
            analysis = data.get("analysis", "")
            if analysis:
                log.info("[zap_fable] Fable 5 analysis: %s", analysis)

            results = []
            for h in raw_hyps:
                results.append(AttackHypothesis(
                    id=h.get("id", str(uuid.uuid4())),
                    endpoint=h.get("endpoint", target),
                    method=h.get("method", "GET").upper(),
                    attack_type=h.get("attack_type", "unknown"),
                    description=h.get("description", ""),
                    payload_url=h.get("payload_url", target),
                    payload_headers=h.get("payload_headers", {}),
                    payload_body=h.get("payload_body", ""),
                    expected_indicator=h.get("expected_indicator", ""),
                    priority=int(h.get("priority", 3)),
                ))
            return results

        except json.JSONDecodeError as exc:
            log.error("[zap_fable] Fable 5 returned non-JSON: %s", exc)
            return []
        except Exception as exc:
            log.error("[zap_fable] hypothesis generation failed: %s", exc)
            return []

    # ------------------------------------------------------------------
    # Hypothesis execution + verdict
    # ------------------------------------------------------------------

    def _execute_hypothesis(self, h: AttackHypothesis) -> Finding | None:
        if not self._scope_check(h.payload_url):
            log.warning("[zap_fable] hypothesis %s targets out-of-scope URL — skipping", h.id)
            return None

        log.info("[zap_fable] testing [%s] %s %s", h.attack_type, h.method, h.payload_url[:80])

        # Get baseline response for comparison
        baseline_resp = self._safe_request("GET", h.endpoint)
        baseline_status = baseline_resp.status_code if baseline_resp else 0

        # Execute the attack
        headers = dict(self._http.headers)
        headers.update(h.payload_headers)

        attack_resp = None
        for attempt in range(_MAX_HYPOTHESIS_ATTEMPTS):
            time.sleep(_REQUEST_DELAY)
            attack_resp = self._safe_request(
                method=h.method,
                url=h.payload_url,
                headers=headers,
                body=h.payload_body,
            )
            if attack_resp is not None:
                break
            log.debug("[zap_fable] attempt %d failed for %s", attempt + 1, h.id)

        if attack_resp is None:
            log.debug("[zap_fable] all attempts failed for hypothesis %s", h.id)
            return None

        # Ask Fable 5 to verdict
        verdict_data = self._get_verdict(h, baseline_status, attack_resp)
        if not verdict_data:
            return None

        if verdict_data.get("verdict") != "finding":
            log.debug(
                "[zap_fable] %s: %s (%s)",
                h.id, verdict_data.get("verdict"), verdict_data.get("reasoning", "")[:80],
            )
            return None

        # Build Finding
        finding = Finding(
            type=verdict_data.get("finding_type", h.attack_type),
            severity_raw=verdict_data.get("severity", "medium"),
            url=h.payload_url,
            host=_host(h.payload_url),
            evidence=verdict_data.get("evidence", ""),
            confidence=float(verdict_data.get("confidence", 0.7)),
            raw_output={
                "hypothesis_id": h.id,
                "attack_type": h.attack_type,
                "description": h.description,
                "payload_url": h.payload_url,
                "payload_headers": h.payload_headers,
                "payload_body": h.payload_body,
                "expected_indicator": h.expected_indicator,
                "baseline_status": baseline_status,
                "attack_status": attack_resp.status_code,
                "attack_response_excerpt": attack_resp.text[:500],
                "verdict": verdict_data,
                "title": verdict_data.get("title", ""),
                "impact": verdict_data.get("impact", ""),
                "reproduction_steps": verdict_data.get("reproduction_steps", []),
            },
        )
        log.info(
            "[zap_fable] FINDING: [%s] %s — %s",
            finding.severity_raw.upper(), finding.type, finding.url[:80],
        )
        return finding

    def _get_verdict(
        self,
        h: AttackHypothesis,
        baseline_status: int,
        attack_resp: requests.Response,
    ) -> dict | None:
        user_msg = (
            f"Hypothesis tested:\n{json.dumps(h.to_dict(), indent=2)}\n\n"
            f"Baseline status (GET {h.endpoint}): {baseline_status}\n\n"
            f"Attack response:\n"
            f"  Status: {attack_resp.status_code}\n"
            f"  Headers:\n{_format_headers(attack_resp.headers)}\n"
            f"  Body (first 1000 chars):\n{attack_resp.text[:1000]}\n\n"
            f"Program: McDonald's VDP\n"
            f"Expected indicator: {h.expected_indicator}"
        )
        try:
            response_text = _call_fable(system=_VERDICT_PROMPT, user=user_msg)
            return json.loads(response_text)
        except Exception as exc:
            log.debug("[zap_fable] verdict call failed: %s", exc)
            return None

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------

    def _safe_request(
        self,
        method: str,
        url: str,
        headers: dict | None = None,
        body: str = "",
    ) -> requests.Response | None:
        try:
            req_headers = dict(self._http.headers)
            if headers:
                req_headers.update(headers)
            kwargs: dict = {"headers": req_headers, "timeout": 15, "allow_redirects": True}
            if body:
                kwargs["data"] = body
                if "Content-Type" not in req_headers:
                    if body.startswith("{") or body.startswith("["):
                        req_headers["Content-Type"] = "application/json"
            return self._http.request(method, url, **kwargs)
        except Exception as exc:
            log.debug("[zap_fable] request failed %s %s: %s", method, url[:60], exc)
            return None

    # ------------------------------------------------------------------
    # Scope check
    # ------------------------------------------------------------------

    def _scope_check(self, url: str) -> bool:
        try:
            host = urlparse(url).hostname or ""
        except Exception:
            return False
        # Support both program.json schema variants:
        #   1. program["in_scope"]["domains"] = ["*.mcdonalds.com", ...]
        #   2. program["scope"]["in_scope"] = [{"asset": "*.mcdonalds.com"}, ...]
        domains: list[str] = []
        if "in_scope" in self.program and isinstance(self.program["in_scope"], dict):
            domains = self.program["in_scope"].get("domains", [])
        elif "scope" in self.program:
            rules = self.program["scope"].get("in_scope", [])
            domains = [r.get("asset", "") for r in rules if r.get("asset")]

        if not domains:
            # No scope configured — allow (conservative: scan may proceed)
            return True
        for pattern in domains:
            if not pattern:
                continue
            if pattern.startswith("*."):
                domain = pattern[2:]
                if host == domain or host.endswith("." + domain):
                    return True
            elif host == pattern:
                return True
        return False


# ---------------------------------------------------------------------------
# Endpoint grouping
# ---------------------------------------------------------------------------

_ID_RE = re.compile(
    r"(?<=/)"                         # preceded by /
    r"("
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"  # UUID
    r"|[0-9]{3,}"                     # numeric ID ≥ 3 digits
    r")"
    r"(?=/|$|[?#])"
)
_EXT_RE = re.compile(r"\.(js|css|png|jpg|jpeg|gif|svg|woff|woff2|ico|map)$", re.I)


def _endpoint_template(url: str) -> str:
    parsed = urlparse(url)
    path = _ID_RE.sub("{id}", parsed.path)
    # Strip query string for grouping key
    return f"{parsed.scheme}://{parsed.netloc}{path}"


def _group_by_endpoint(messages: list[HttpMessage]) -> dict[str, list[HttpMessage]]:
    groups: dict[str, list[HttpMessage]] = {}
    for msg in messages:
        if not msg.url:
            continue
        # Skip static assets
        path = urlparse(msg.url).path
        if _EXT_RE.search(path):
            continue
        key = _endpoint_template(msg.url)
        groups.setdefault(key, []).append(msg)
    return groups


def _select_interesting_groups(
    groups: dict[str, list[HttpMessage]],
    max_groups: int,
) -> dict[str, list[HttpMessage]]:
    """
    Score endpoint groups by interest level and return the top N.

    Scoring boosts:
    - POST/PUT/DELETE methods
    - JSON request bodies
    - Auth headers / session cookies
    - URLs containing: api, auth, user, order, account, offer, loyalty, admin
    - Responses that are 4xx (may indicate auth-gated paths)
    - Responses with JSON bodies
    """
    def score(template: str, msgs: list[HttpMessage]) -> float:
        s = 0.0
        for kw in ("api", "auth", "user", "order", "account", "offer", "loyalty", "admin",
                   "payment", "cart", "checkout", "coupon", "reward", "point"):
            if kw in template.lower():
                s += 2
        for msg in msgs:
            if msg.method in ("POST", "PUT", "DELETE", "PATCH"):
                s += 3
            if msg.request_body and (msg.request_body.startswith("{") or "=" in msg.request_body):
                s += 2
            if "authorization" in msg.request_header.lower():
                s += 2
            if "bearer" in msg.request_header.lower():
                s += 3
            if msg.status_code in (401, 403):
                s += 1
            if "application/json" in msg.response_header.lower():
                s += 1
        return s

    scored = [(template, msgs, score(template, msgs)) for template, msgs in groups.items()]
    scored.sort(key=lambda x: x[2], reverse=True)
    return {t: msgs for t, msgs, _ in scored[:max_groups]}


# ---------------------------------------------------------------------------
# Fable 5 API
# ---------------------------------------------------------------------------

def _call_fable(system: str, user: str) -> str:
    """
    Attack hypothesis generation / verdict, via the unified router (core.models).

    Migrated off the bespoke anthropic-SDK + CLI fallback. Routes to the
    "zap_fable" role (claude-fable-5 by default, config-swappable per BB_MODEL_*).
    """
    from core.models import complete
    return complete(
        "zap_fable",
        [{"role": "system", "content": system},
         {"role": "user", "content": user}],
        max_tokens=4096,
    ).text


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _redact_sensitive(text: str) -> str:
    redacted = re.sub(
        r"(Authorization:\s*Bearer\s+)\S+",
        r"\1[REDACTED]",
        text,
        flags=re.I,
    )
    redacted = re.sub(
        r"(Cookie:\s*).*",
        lambda m: m.group(1) + "[COOKIES-REDACTED]",
        redacted,
        flags=re.I,
    )
    return redacted


def _host(url: str) -> str:
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""


def _format_headers(headers: Any) -> str:
    try:
        return "\n".join(f"  {k}: {v}" for k, v in headers.items())
    except Exception:
        return str(headers)


# ---------------------------------------------------------------------------
# CLI runner (standalone use)
# ---------------------------------------------------------------------------

def run_scan(
    target: str,
    program_file: str,
    run_dir: str,
    depth: str = "standard",
) -> None:
    """
    Standalone entry point for running a ZAP + Fable 5 scan.

    Usage:
        python -m core.zap_fable https://admin.me.mcd.com programs/mcdonalds.json runs/mcdonalds.com/...
    """
    import sys

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    with open(program_file) as f:
        program = json.load(f)

    run_path = Path(run_dir)
    run_path.mkdir(parents=True, exist_ok=True)

    scanner = ZapFableScanner(program=program, run_dir=run_path)
    findings = scanner.scan(target=target, depth=depth)

    if not findings:
        print(f"[!] No findings for {target}")
        return

    print(f"\n[+] {len(findings)} finding(s):")
    for f in findings:
        print(f"  [{f.severity_raw.upper()}] {f.type} — {f.url}")
        if f.raw_output.get("title"):
            print(f"    {f.raw_output['title']}")
        if f.evidence:
            print(f"    Evidence: {f.evidence[:100]}")

    # Write findings to run dir
    out_file = run_path / "zap_fable_findings.json"
    with open(out_file, "w") as fh:
        json.dump(
            [
                {
                    "finding_id": f.finding_id,
                    "type": f.type,
                    "severity_raw": f.severity_raw,
                    "url": f.url,
                    "host": f.host,
                    "evidence": f.evidence,
                    "tool": f.tool,
                    "confidence": f.confidence,
                    "raw_output": f.raw_output,
                }
                for f in findings
            ],
            fh,
            indent=2,
        )
    print(f"\n[+] Findings written to {out_file}")


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 4:
        print("Usage: python -m core.zap_fable <target> <program.json> <run_dir> [depth]")
        sys.exit(1)
    run_scan(
        target=sys.argv[1],
        program_file=sys.argv[2],
        run_dir=sys.argv[3],
        depth=sys.argv[4] if len(sys.argv) > 4 else "standard",
    )
