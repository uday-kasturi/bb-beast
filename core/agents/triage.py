"""
core/agents/triage.py — bulk triage agent (Hermes worker tier).

The first agent ported onto the bus. It does exactly what core/llm.py's triage()
did — filter by confidence, dedup, cap, prompt, parse, cap severity escalation —
but the model call goes through core.models (role "triage" -> Hermes by default)
instead of the hardcoded `claude` CLI, and the result is announced as a bus
message with a ref to triage.json.

The hard-won bits (system prompt, severity escalation checker, finding stripper)
are imported from core.llm — single source of truth, no fork.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from core.agents.base import Agent, Blackboard, make_message, ref, cost_of
from core.models import complete_json, ModelError
from core.llm import (
    _SYSTEM_PROMPT,
    _strip_finding,
    _check_severity_escalation,
    _MAX_FINDINGS_PER_CALL,
    _DEFAULT_CONFIDENCE_THRESHOLD,
)

log = logging.getLogger(__name__)

_RECON_TYPES = {"historical_url", "subdomain", "dns_record", "dns_resolution"}
_SEV_TRIM_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4, "info": 5}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _prepare(findings: list[dict], confidence_threshold: float) -> list[dict]:
    """Confidence filter -> dedup by (type, lowered-url) -> severity-first trim."""
    eligible = [f for f in findings if f.get("confidence", 0) >= confidence_threshold]

    seen: dict[tuple, dict] = {}
    for f in eligible:
        key = (f.get("type", ""), (f.get("url") or f.get("host") or "").lower())
        cur = seen.get(key)
        if cur is None or f.get("confidence", 0) > cur.get("confidence", 0):
            seen[key] = f
    eligible = list(seen.values())

    if len(eligible) > _MAX_FINDINGS_PER_CALL:
        def sort_key(f):
            sev = _SEV_TRIM_ORDER.get(f.get("severity_raw", "info"), 5)
            is_recon = 1 if f.get("type", "") in _RECON_TYPES else 0
            return (is_recon, sev, -f.get("confidence", 0))
        eligible = sorted(eligible, key=sort_key)[:_MAX_FINDINGS_PER_CALL]

    return eligible


class TriageAgent(Agent):
    name = "triage"
    role = "triage"
    system_prompt = _SYSTEM_PROMPT
    reads = ["findings"]
    writes = "triage"

    def handle(self, msg: dict, bb: Blackboard) -> dict:
        confidence_threshold = _DEFAULT_CONFIDENCE_THRESHOLD
        payload_in = msg.get("payload") or {}
        if "confidence_threshold" in payload_in:
            confidence_threshold = float(payload_in["confidence_threshold"])

        findings_doc = bb.read_json("findings.json")
        all_findings = findings_doc.get("findings", [])
        run_id = findings_doc.get("run_id", bb.run_id)

        eligible = _prepare(all_findings, confidence_threshold)
        log.info("[triage] %d/%d findings eligible after prep", len(eligible), len(all_findings))

        if not eligible:
            triage_doc = self._empty_doc(run_id, len(all_findings))
            bb.write_json("triage.json", triage_doc, schema="triage")
            return bb.post(make_message(
                run_id=run_id, from_agent=self.name, to_agent="orchestrator",
                intent="result",
                refs=[ref("triage", "triage.json")],
                payload={"verdicts": 0, "note": "no findings met confidence threshold"},
                cost=cost_of(None),
            ))

        findings_for_llm = [_strip_finding(f) for f in eligible]
        user_message = (
            f"Program: {findings_doc.get('program_id', 'unknown')}\n"
            f"Playbook: {findings_doc.get('playbook_name', 'unknown')}\n"
            f"Depth: {findings_doc.get('depth', 'unknown')}\n\n"
            f"Findings to triage ({len(findings_for_llm)} total):\n\n"
            f"{__import__('json').dumps(findings_for_llm, indent=2)}"
        )

        try:
            parsed, comp = complete_json(
                self.role,
                [
                    {"role": "system", "content": self.system_prompt},
                    {"role": "user", "content": user_message},
                ],
            )
        except ModelError as exc:
            log.error("[triage] model call failed: %s", exc)
            return bb.post(make_message(
                run_id=run_id, from_agent=self.name, to_agent="orchestrator",
                intent="escalate",
                payload={"error": str(exc), "stage": "triage"},
                cost=cost_of(None),
            ))

        findings_by_id = {f.get("finding_id", ""): f for f in eligible}
        cleaned_verdicts, escalation_audit = _check_severity_escalation(
            parsed.get("verdicts", []), findings_by_id,
        )
        if escalation_audit:
            log.warning("[triage] capped %d verdict(s) — see triage_audit.json", len(escalation_audit))
            bb.write_json("triage_audit.json", {"escalations": escalation_audit})

        triage_doc = {
            "schema_version": "1.0",
            "created_at": _now(),
            "run_id": run_id,
            "model": comp.model,
            "input_findings_count": len(eligible),
            "prompt_tokens": comp.prompt_tokens,
            "completion_tokens": comp.completion_tokens,
            "verdicts": cleaned_verdicts,
            "run_summary": parsed.get("run_summary", {
                "overall_assessment": "No summary provided.",
                "top_findings": [],
                "recommended_focus": "Review findings manually.",
            }),
        }
        bb.write_json("triage.json", triage_doc, schema="triage")

        counts: dict[str, int] = {}
        for v in cleaned_verdicts:
            counts[v.get("verdict", "unknown")] = counts.get(v.get("verdict", "unknown"), 0) + 1
        log.info("[triage] %d verdicts %s", len(cleaned_verdicts), counts)

        return bb.post(make_message(
            run_id=run_id, from_agent=self.name, to_agent="orchestrator",
            intent="result",
            refs=[ref("triage", "triage.json")],
            payload={"verdicts": len(cleaned_verdicts), "counts": counts},
            cost=cost_of(comp),
        ))

    @staticmethod
    def _empty_doc(run_id: str, total: int) -> dict:
        return {
            "schema_version": "1.0",
            "created_at": _now(),
            "run_id": run_id,
            "model": "none",
            "input_findings_count": 0,
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "verdicts": [],
            "run_summary": {
                "overall_assessment": f"No findings met threshold. {total} below threshold.",
                "top_findings": [],
                "recommended_focus": "Lower confidence threshold or run exhaustive depth.",
            },
        }


AGENT = TriageAgent()
