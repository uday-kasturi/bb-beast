"""
core/agents/critic.py — adversarial second opinion on triage (Hermes worker).

The critic's ONLY job is to tear down. It reads triage.json and, for every
verdict that claims exploitable or needs_more_info, argues the false-positive
case. A cheap model disagreeing with itself catches the rubber-stamps a single
triage pass misses.

Guardrails that keep this from becoming chatty bloat:
  - Critic never UPGRADES a verdict — it can only challenge downward.
  - The orchestrator only applies a downgrade when the critic is confident
    (>= _DOWNGRADE_CONFIDENCE). Weak challenges are logged, not applied.
  - Bounded: the orchestrator runs this at most max_critic_rounds times and
    stops as soon as a round applies zero downgrades (converged).
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from core.agents.base import Agent, Blackboard, make_message, ref, cost_of
from core.models import complete_json, ModelError

log = logging.getLogger(__name__)

_DOWNGRADE_CONFIDENCE = 0.7          # min critic confidence to actually downgrade
_CHALLENGEABLE = {"exploitable", "needs_more_info"}

_SYSTEM = """You are a red-team reviewer auditing another analyst's vulnerability triage.
Your job is to find where they were WRONG — specifically, verdicts that overstate a finding.

For each verdict you are given, argue whether it is actually a FALSE POSITIVE or NOT EXPLOITABLE.
Automated scanners and eager triage routinely over-call: reflected input that isn't executed,
"vulnerable" version banners with no reachable exploit, missing headers rated as bugs,
self-XSS, theoretical SSRF with no internal reachability.

You may ONLY challenge downward. Never argue a finding is more severe.

Respond with EXACTLY this JSON, no prose:
{
  "challenges": [
    {
      "finding_id": "<uuid>",
      "recommended_verdict": "false_positive|not_exploitable|keep",
      "confidence": 0.0,
      "reasoning": "<1-2 sentences: why the original verdict overstates it, or why to keep>"
    }
  ]
}
Use "keep" when the original verdict is defensible. Be specific, not reflexively skeptical."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class CriticAgent(Agent):
    name = "critic"
    role = "critic"
    system_prompt = _SYSTEM
    reads = ["triage", "findings"]
    writes = "triage"  # applies conservative downgrades in place

    def handle(self, msg: dict, bb: Blackboard) -> dict:
        rnd = int(msg.get("round", 0))
        triage = bb.read_json("triage.json")
        verdicts = triage.get("verdicts", [])
        run_id = triage.get("run_id", bb.run_id)

        targets = [v for v in verdicts if v.get("verdict") in _CHALLENGEABLE]
        if not targets:
            return bb.post(make_message(
                run_id=run_id, from_agent=self.name, to_agent="orchestrator",
                intent="result", round=rnd,
                payload={"downgrades_applied": 0, "note": "nothing challengeable"},
                cost=cost_of(None),
            ))

        # Enrich with finding context so the critic isn't reasoning blind.
        findings_by_id = {}
        if bb.exists("findings.json"):
            for f in bb.read_json("findings.json").get("findings", []):
                findings_by_id[f.get("finding_id", "")] = f

        payload_for_llm = []
        for v in targets:
            f = findings_by_id.get(v.get("finding_id", ""), {})
            payload_for_llm.append({
                "finding_id": v.get("finding_id"),
                "verdict": v.get("verdict"),
                "adjusted_severity": v.get("adjusted_severity"),
                "reasoning": v.get("reasoning", ""),
                "impact": v.get("impact", ""),
                "type": f.get("type"),
                "url": f.get("url") or f.get("host"),
                "execution_status": f.get("execution_status"),
                "evidence": str(f.get("evidence", ""))[:300],
            })

        user = (
            f"Audit these {len(payload_for_llm)} verdicts (review round {rnd + 1}):\n\n"
            f"{json.dumps(payload_for_llm, indent=2)}"
        )

        try:
            parsed, comp = complete_json(
                self.role,
                [{"role": "system", "content": self.system_prompt},
                 {"role": "user", "content": user}],
            )
        except ModelError as exc:
            log.error("[critic] model call failed: %s", exc)
            return bb.post(make_message(
                run_id=run_id, from_agent=self.name, to_agent="orchestrator",
                intent="escalate", round=rnd,
                payload={"error": str(exc), "stage": "critic"}, cost=cost_of(None),
            ))

        # Apply conservative downgrades in place.
        vindex = {v.get("finding_id"): v for v in verdicts}
        applied = 0
        audit = []
        for ch in parsed.get("challenges", []):
            fid = ch.get("finding_id")
            rec = ch.get("recommended_verdict", "keep")
            conf = float(ch.get("confidence", 0))
            v = vindex.get(fid)
            if not v or rec == "keep":
                continue
            if rec in ("false_positive", "not_exploitable") and conf >= _DOWNGRADE_CONFIDENCE:
                audit.append({"finding_id": fid, "from": v.get("verdict"), "to": rec,
                              "confidence": conf, "reasoning": ch.get("reasoning", "")})
                v["verdict"] = rec
                v["critic_downgraded"] = True
                v["reasoning"] = f"[critic r{rnd+1}] {ch.get('reasoning','')} | prior: {v.get('reasoning','')}"
                applied += 1

        if applied:
            bb.write_json("triage.json", triage, schema="triage")
            # append to a running critique log
            crit_log = bb.read_json("critic_audit.json") if bb.exists("critic_audit.json") else {"rounds": []}
            crit_log["rounds"].append({"round": rnd, "downgrades": audit, "at": _now()})
            bb.write_json("critic_audit.json", crit_log)
            log.info("[critic] round %d applied %d downgrade(s)", rnd + 1, applied)

        return bb.post(make_message(
            run_id=run_id, from_agent=self.name, to_agent="orchestrator",
            intent="result", round=rnd,
            refs=[ref("triage", "triage.json")],
            payload={"downgrades_applied": applied, "challenged": len(targets)},
            cost=cost_of(comp),
        ))


AGENT = CriticAgent()
