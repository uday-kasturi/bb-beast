"""
core/agents/validator.py — XBOW-lite: the evidence-gated validation loop.

The validator is the agent that actually FIRES probes and refuses to claim a
bug without hard evidence. It takes triage's exploitable/needs_more_info
findings and, per finding, runs a bounded loop:

    hypothesize -> SCOPE GATE -> fire probe -> observe -> judge

It emits an execution_status per finding — the SAME field the triage evidence
rule keys on — and writes the evidence artifacts (OAST callbacks, screenshots)
into the run's evidence/ dir. It never stamps "exploitable" itself; it produces
evidence, and the orchestrator's evidence gate decides.

NON-NEGOTIABLE GUARDRAILS (this agent sends real traffic at real targets):
  1. SCOPE GATE before every probe — in-scope host, not out-of-scope, and the
     vuln class must be an allowed test type. A gate failure skips the finding.
  2. NON-DESTRUCTIVE payloads only — reflect / OAST callback / boolean-diff /
     redirect-location. Never state-changing, never DoS.
  3. BOUNDED — max rounds per finding, max findings per run, throttle between
     requests (jitter). An unbounded prober gets you banned or causes harm.

Strategy per class:
  xss            -> headless browser + OAST (intelligence/browser.py)
  ssrf/blind_*   -> interactsh OAST callback (tools/interactsh.py)
  sqli           -> boolean/error differential over HTTP
  open_redirect  -> follow-less request, inspect Location header
  (fallback)     -> reflection probe

The uncensored "validator" model role is used to craft/refine the exact payload
for the target each round; deterministic fallbacks keep it working model-free.
"""

from __future__ import annotations

import logging
import random
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from core.agents.base import Agent, Blackboard, make_message, ref, cost_of
from core.models import complete_json, ModelError

log = logging.getLogger(__name__)

# Which triage verdicts are worth validating (unconfirmed only).
_VALIDATE_VERDICTS = {"exploitable", "needs_more_info"}
_CONFIRMED = {"callback_received", "screenshot_confirmed"}

_DEFAULT_MAX_FINDINGS = 25          # cap findings validated per run
_THROTTLE_MIN = 0.5                 # seconds between probes (base)
_THROTTLE_JITTER = 1.0              # + up to this many seconds

# Map vuln types to the OAST payload kind + interactsh template selector.
_BLIND_TYPES = {"ssrf", "blind_ssrf", "command_injection", "blind_rce", "xxe", "blind_sqli", "log4shell"}
_OAST_KIND = {
    "ssrf": "ssrf", "blind_ssrf": "ssrf", "xxe": "oob",
    "command_injection": "oob", "blind_rce": "oob", "blind_sqli": "oob", "log4shell": "oob",
}


# ---------------------------------------------------------------------------
# Scope gate — the safety-critical precondition on every probe
# ---------------------------------------------------------------------------

def _scope_gate(url: str, vuln_type: str, program: dict) -> tuple[bool, str]:
    """
    Return (allowed, reason). A probe runs only if this returns (True, ...).
    Enforces in-scope host, out-of-scope exclusion, and allowed test types.
    """
    from core.agent import _in_scope  # reuse the existing in-scope matcher

    host = (urlparse(url).hostname or "").lower()
    if not host:
        return False, "no host in url"

    if not _in_scope(url, program):
        return False, f"{host} not in in-scope domains"

    # Explicit out-of-scope domain exclusion.
    oos = program.get("out_of_scope", {}) or {}
    for d in oos.get("domains", []) or []:
        d = str(d).lstrip("*.").lower()
        if host == d or host.endswith("." + d):
            return False, f"{host} matches out-of-scope domain {d}"

    # Test-type gating. Map our vuln classes to program test-type language loosely.
    oos_types = {str(t).lower() for t in (oos.get("test_types", []) or [])}
    allowed = {str(t).lower() for t in (program.get("allowed_test_types", []) or [])}
    vt = vuln_type.lower()
    # Common program prohibitions.
    if vt in ("sqli", "blind_sqli") and ("sqli" in oos_types or "sql injection" in oos_types):
        return False, "SQLi disallowed by program"
    if "dos" in oos_types and vt in ("dos", "rate_limit"):
        return False, "DoS disallowed by program"
    # If the program enumerates an allowlist and this class isn't in it, block.
    if allowed and not _type_allowed(vt, allowed):
        return False, f"{vt} not in allowed_test_types"

    return True, "in scope"


def _type_allowed(vt: str, allowed: set[str]) -> bool:
    if not allowed:
        return True
    aliases = {
        "xss": {"xss", "cross-site scripting", "web"},
        "sqli": {"sqli", "sql injection", "web"},
        "ssrf": {"ssrf", "web"},
        "open_redirect": {"open_redirect", "open redirect", "web"},
    }
    keys = aliases.get(vt, {vt, "web"})
    return bool(keys & allowed)


# ---------------------------------------------------------------------------
# Probe result
# ---------------------------------------------------------------------------

@dataclass
class ProbeResult:
    finding_id: str
    vuln_type: str
    url: str
    execution_status: str = "not_attempted"   # not_attempted | attempted_no_callback | callback_received | screenshot_confirmed | out_of_scope | error
    confirmed: bool = False
    payload: str = ""
    evidence: dict = field(default_factory=dict)
    rounds: int = 0
    notes: str = ""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------

class ValidatorAgent(Agent):
    name = "validator"
    role = "validator"
    reads = ["triage", "findings", "program"]
    writes = "validations"

    def handle(self, msg: dict, bb: Blackboard) -> dict:
        payload_in = msg.get("payload") or {}
        max_rounds = int(payload_in.get("max_rounds", 6))
        max_findings = int(payload_in.get("max_findings", _DEFAULT_MAX_FINDINGS))

        triage = bb.read_json("triage.json")
        run_id = triage.get("run_id", bb.run_id)
        program = bb.read_json("program.json") if bb.exists("program.json") else {}
        findings_by_id = {}
        if bb.exists("findings.json"):
            for f in bb.read_json("findings.json").get("findings", []):
                findings_by_id[f.get("finding_id", "")] = f

        # Candidates: unconfirmed exploitable/needs_more_info with a testable URL.
        candidates = []
        for v in triage.get("verdicts", []):
            if v.get("verdict") not in _VALIDATE_VERDICTS:
                continue
            f = findings_by_id.get(v.get("finding_id", ""), {})
            if f.get("execution_status") in _CONFIRMED:
                continue  # already proven, don't re-fire
            url = f.get("url") or f.get("host")
            if not url:
                continue
            candidates.append((v, f, url))

        candidates = candidates[:max_findings]
        log.info("[validator] %d candidate finding(s) to probe", len(candidates))

        results: list[ProbeResult] = []
        total_cost = {"prompt_tokens": 0, "completion_tokens": 0, "model": "", "backend": "openrouter"}

        for v, f, url in candidates:
            vt = (f.get("type") or "").lower()
            allowed, reason = _scope_gate(url, vt, program)
            if not allowed:
                log.warning("[validator] SCOPE GATE blocked %s (%s): %s", url, vt, reason)
                results.append(ProbeResult(f.get("finding_id", ""), vt, url,
                                           execution_status="out_of_scope", notes=reason))
                continue

            res = self._validate_one(v, f, url, vt, bb, program, max_rounds, total_cost)
            results.append(res)
            self._throttle()

        # Write back execution_status onto findings + persist validations.json.
        self._apply_results(results, bb)

        confirmed = sum(1 for r in results if r.confirmed)
        blocked = sum(1 for r in results if r.execution_status == "out_of_scope")
        cost = {
            "backend": "openrouter", "model": total_cost.get("model", ""),
            "prompt_tokens": total_cost["prompt_tokens"], "completion_tokens": total_cost["completion_tokens"],
        }
        log.info("[validator] done: %d probed, %d CONFIRMED, %d scope-blocked",
                 len(results), confirmed, blocked)

        return bb.post(make_message(
            run_id=run_id, from_agent=self.name, to_agent="orchestrator",
            intent="result",
            refs=[ref("validations", "validations.json")],
            payload={"probed": len(results), "confirmed": confirmed, "scope_blocked": blocked},
            cost=cost,
        ))

    # -- per-finding loop ------------------------------------------------
    def _validate_one(self, v, f, url, vt, bb, program, max_rounds, total_cost) -> ProbeResult:
        fid = f.get("finding_id", "")
        result = ProbeResult(fid, vt, url)

        for rnd in range(max_rounds):
            result.rounds = rnd + 1
            payload = self._hypothesize(v, f, url, vt, rnd, total_cost)
            result.payload = payload

            try:
                if vt == "xss":
                    self._probe_xss(url, payload, fid, bb, result)
                elif vt in _BLIND_TYPES:
                    self._probe_blind_oast(url, vt, fid, result)
                elif vt in ("sqli",):
                    self._probe_sqli_boolean(url, result)
                elif vt in ("open_redirect", "open-redirect"):
                    self._probe_open_redirect(url, result)
                else:
                    self._probe_reflection(url, payload, result)
            except Exception as exc:  # a probe failure must not sink the run
                log.error("[validator] probe error on %s: %s", url, exc)
                result.execution_status = "error"
                result.notes = f"probe error: {exc}"

            if result.confirmed:
                break
            self._throttle()

        return result

    # -- hypothesis (uncensored model, deterministic fallback) -----------
    def _hypothesize(self, v, f, url, vt, rnd, total_cost) -> str:
        fallback = _fallback_payload(vt)
        try:
            prompt = (
                "Craft ONE non-destructive proof payload to validate this finding. "
                "Return JSON {\"payload\": \"...\", \"note\": \"...\"}. "
                "Read-only proofs only (reflect / OAST callback / boolean-diff / redirect). "
                "No destructive or DoS payloads.\n\n"
                f"type={vt} url={url} round={rnd+1}\n"
                f"evidence={str(f.get('evidence',''))[:300]}"
            )
            parsed, comp = complete_json(
                self.role, [{"role": "user", "content": prompt}], max_tokens=300,
            )
            total_cost["prompt_tokens"] += comp.prompt_tokens
            total_cost["completion_tokens"] += comp.completion_tokens
            total_cost["model"] = comp.model
            return parsed.get("payload") or fallback
        except (ModelError, Exception) as exc:
            log.debug("[validator] hypothesis fell back to default (%s)", exc)
            return fallback

    # -- probes ----------------------------------------------------------
    def _probe_xss(self, url, payload, fid, bb, result: ProbeResult) -> None:
        """Headless browser + OAST: proves the payload actually EXECUTES."""
        try:
            from intelligence import browser
            from tools.interactsh import InteractshWrapper
        except Exception as exc:
            result.execution_status = "error"
            result.notes = f"xss deps unavailable: {exc}"
            return

        wrapper = InteractshWrapper()
        if not wrapper.available():
            # Fall back to pure screenshot confirmation (no OAST).
            probe_url = _inject_param(url, f"<svg/onload=alert(document.domain)>")
            shot = browser.capture_xss_screenshot(probe_url, fid, bb.run_dir)
            if shot:
                result.confirmed = True
                result.execution_status = "screenshot_confirmed"
                result.evidence = {"screenshot": str(shot)}
            else:
                result.execution_status = "attempted_no_callback"
            return

        session = wrapper.new_session()
        try:
            session.start()
            oast_payload = f"<script>fetch('//{{oast}}/x')</script>".replace("{oast}", session.oast_host)
            probe_url = _inject_param(url, oast_payload)
            outcome = browser.confirm_xss_with_oast(probe_url, session, fid, bb.run_dir)
            result.execution_status = outcome.get("execution_status", "attempted_no_callback")
            result.confirmed = result.execution_status in _CONFIRMED
            result.evidence = {
                "screenshot": outcome.get("screenshot_path"),
                "callbacks": outcome.get("callbacks", []),
            }
        finally:
            session.stop()

    def _probe_blind_oast(self, url, vt, fid, result: ProbeResult) -> None:
        """Inject an OAST payload, fire one request, wait for the callback."""
        import requests
        try:
            from tools.interactsh import InteractshWrapper
        except Exception as exc:
            result.execution_status = "error"
            result.notes = f"interactsh unavailable: {exc}"
            return

        wrapper = InteractshWrapper()
        if not wrapper.available():
            result.execution_status = "error"
            result.notes = "interactsh not installed"
            return

        session = wrapper.new_session()
        try:
            session.start()
            payload = session.get_payload(_OAST_KIND.get(vt, "oob"))
            result.payload = payload
            probe_url = _inject_param(url, payload)
            try:
                requests.get(probe_url, timeout=15, allow_redirects=False)
            except requests.RequestException as exc:
                result.notes = f"request failed: {exc}"
            callbacks = session.poll_callbacks(timeout=30)
            if callbacks:
                result.confirmed = True
                result.execution_status = "callback_received"
                result.evidence = {"callbacks": callbacks, "oast_host": session.oast_host}
            else:
                result.execution_status = "attempted_no_callback"
        finally:
            session.stop()

    def _probe_sqli_boolean(self, url, result: ProbeResult) -> None:
        """Differential: TRUE vs FALSE condition should change the response."""
        import requests
        true_url = _inject_param(url, "1' AND '1'='1")
        false_url = _inject_param(url, "1' AND '1'='2")
        try:
            rt = requests.get(true_url, timeout=15, allow_redirects=False)
            rf = requests.get(false_url, timeout=15, allow_redirects=False)
        except requests.RequestException as exc:
            result.execution_status = "attempted_no_callback"
            result.notes = f"request failed: {exc}"
            return
        diff = abs(len(rt.content) - len(rf.content))
        status_diff = rt.status_code != rf.status_code
        # Differential is suggestive, NOT hard OAST/screenshot evidence — so this
        # stays needs_more_info-grade: report the signal, don't self-confirm.
        result.execution_status = "attempted_no_callback"
        result.evidence = {
            "true_len": len(rt.content), "false_len": len(rf.content),
            "len_diff": diff, "status_diff": status_diff,
            "signal": diff > 50 or status_diff,
        }
        result.notes = "boolean differential (suggestive, needs manual confirm)"

    def _probe_open_redirect(self, url, result: ProbeResult) -> None:
        import requests
        marker = "https://oast.example.evil/"
        probe_url = _inject_param(url, marker)
        try:
            r = requests.get(probe_url, timeout=15, allow_redirects=False)
        except requests.RequestException as exc:
            result.execution_status = "attempted_no_callback"
            result.notes = f"request failed: {exc}"
            return
        loc = r.headers.get("Location", "")
        if r.status_code in (301, 302, 303, 307, 308) and marker.rstrip("/") in loc:
            result.confirmed = True
            result.execution_status = "screenshot_confirmed"  # deterministic proof
            result.evidence = {"status": r.status_code, "location": loc}
            result.notes = "redirect to attacker-controlled host confirmed"
        else:
            result.execution_status = "attempted_no_callback"
            result.evidence = {"status": r.status_code, "location": loc}

    def _probe_reflection(self, url, payload, result: ProbeResult) -> None:
        import requests
        marker = "bbrefl3ct0r"
        probe_url = _inject_param(url, marker)
        try:
            r = requests.get(probe_url, timeout=15, allow_redirects=False)
        except requests.RequestException as exc:
            result.execution_status = "attempted_no_callback"
            result.notes = f"request failed: {exc}"
            return
        if marker in r.text:
            result.execution_status = "attempted_no_callback"
            result.evidence = {"reflected": True}
            result.notes = "input reflected (not proven executed) — needs_more_info"
        else:
            result.execution_status = "attempted_no_callback"
            result.evidence = {"reflected": False}

    # -- write-back ------------------------------------------------------
    def _apply_results(self, results: list[ProbeResult], bb: Blackboard) -> None:
        # 1. persist validations.json
        validations = {
            "schema_version": "1.0",
            "created_at": _now(),
            "run_id": bb.run_id,
            "validations": [
                {
                    "finding_id": r.finding_id, "vuln_type": r.vuln_type, "url": r.url,
                    "execution_status": r.execution_status, "confirmed": r.confirmed,
                    "payload": r.payload, "rounds": r.rounds, "evidence": r.evidence, "notes": r.notes,
                }
                for r in results
            ],
        }
        bb.write_json("validations.json", validations)

        # 2. stamp execution_status back onto findings.json so the evidence gate sees it
        if bb.exists("findings.json"):
            findings_doc = bb.read_json("findings.json")
            by_id = {r.finding_id: r for r in results}
            for f in findings_doc.get("findings", []):
                r = by_id.get(f.get("finding_id"))
                if r and r.execution_status not in ("out_of_scope", "error", "not_attempted"):
                    f["execution_status"] = r.execution_status
            bb.write_json("findings.json", findings_doc)

    # -- util ------------------------------------------------------------
    def _throttle(self) -> None:
        time.sleep(_THROTTLE_MIN + random.random() * _THROTTLE_JITTER)


# ---------------------------------------------------------------------------
# Payload helpers
# ---------------------------------------------------------------------------

def _fallback_payload(vt: str) -> str:
    return {
        "xss": "<svg/onload=alert(document.domain)>",
        "sqli": "1' AND '1'='1",
        "open_redirect": "https://oast.example.evil/",
        "ssrf": "http://oast/",
    }.get(vt, "bbrefl3ct0r")


def _inject_param(url: str, value: str) -> str:
    """
    Put `value` into the URL's first query parameter (or append `?q=` if none).
    Keeps probes surgical — one parameter, non-destructive.
    """
    parts = urlparse(url)
    qs = parse_qs(parts.query, keep_blank_values=True)
    if qs:
        first = next(iter(qs))
        qs[first] = [value]
        new_q = urlencode({k: v[0] for k, v in qs.items()})
    else:
        new_q = urlencode({"q": value})
    return urlunparse(parts._replace(query=new_q))


AGENT = ValidatorAgent()
