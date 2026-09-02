"""
core/orchestrator.py — the conductor of the agent bus.

Sequences the post-scan pipeline. Two kinds of edges:

  STATIC  (deterministic, no orchestrator LLM):
      triage -> critic reconcile -> validator -> exploit_smith -> actions
      The orchestrator does NOT "think" about these — it just dispatches.

  DYNAMIC (orchestrator LLM, role "orchestrator", used sparingly):
      final evidence sign-off — a single low-volume, high-value call that
      reviews validator evidence and writes the run-level go/no-go summary.

Design guarantees:
  - Missing agents are skipped gracefully (build incrementally; the pipeline
    lights up as critic/validator/exploit_smith land).
  - A per-run TOKEN BUDGET caps spend: once exceeded, no further LLM agents are
    dispatched and the run is flagged partial.
  - Every handoff is a schema-valid message on the blackboard's audit log.
  - Evidence gate is enforced by the orchestrator, not trusted to a worker:
    "exploitable" only survives with callback_received / screenshot_confirmed.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.agents import get_agent, all_agents, make_message, ref, cost_of
from core.agents.base import Blackboard
from core.models import complete, ModelError

log = logging.getLogger(__name__)

# Verdicts whose severity may only stand with hard execution evidence.
_CONFIRMED_STATES = {"callback_received", "screenshot_confirmed"}

_DEFAULT_TOKEN_BUDGET = 500_000       # across all worker+orchestrator calls
_DEFAULT_MAX_CRITIC_ROUNDS = 2
_DEFAULT_MAX_VALIDATOR_ROUNDS = 6     # per finding, inside the validator loop


class Orchestrator:
    """Runs the triage->...->actions pipeline over one run_dir."""

    def __init__(
        self,
        run_dir: Path,
        program: dict,
        *,
        token_budget: int = _DEFAULT_TOKEN_BUDGET,
        max_critic_rounds: int = _DEFAULT_MAX_CRITIC_ROUNDS,
        max_validator_rounds: int = _DEFAULT_MAX_VALIDATOR_ROUNDS,
    ) -> None:
        self.run_dir = Path(run_dir)
        self.program = program
        self.token_budget = token_budget
        self.max_critic_rounds = max_critic_rounds
        self.max_validator_rounds = max_validator_rounds

        findings = self._peek_run_id()
        self.run_id = findings
        self.bb = Blackboard(self.run_dir, self.run_id)
        self.tokens_used = 0
        self.registered = set(all_agents())

    # -- public ----------------------------------------------------------
    def run(self) -> dict:
        """Execute the pipeline. Returns an orchestration summary dict."""
        if not self.bb.exists("findings.json"):
            raise FileNotFoundError(f"findings.json not found in {self.run_dir}")

        # Persist the program to the blackboard so scope-gating agents (validator)
        # can read it without the orchestrator having to thread it through.
        if not self.bb.exists("program.json"):
            self.bb.write_json("program.json", self.program)

        log.info("[orchestrator] run %s — agents available: %s",
                 self.run_id, ", ".join(sorted(self.registered)) or "(none)")

        status = "complete"
        stages: list[dict] = []

        # 1. Triage (required)
        stages.append(self._stage("triage", self._run_triage))

        # 2. Critic reconcile (optional, dynamic-lite)
        if "critic" in self.registered:
            stages.append(self._stage("critic", self._run_critic))

        # 3. Validator — the XBOW-lite evidence loop (optional)
        if "validator" in self.registered:
            stages.append(self._stage("validator", self._run_validator))

        # 4. Enforce the evidence gate regardless of who ran
        self._enforce_evidence_gate()

        # 5. Exploit smith — payloads for confirmed exploitables (optional)
        if "exploit_smith" in self.registered:
            stages.append(self._stage("exploit_smith", self._run_exploit_smith))

        # 6. Actions (rules — no LLM)
        stages.append(self._stage("actions", self._run_actions))

        # 7. Final sign-off (orchestrator LLM, best-effort)
        signoff = self._final_signoff()

        if self.tokens_used > self.token_budget:
            status = "partial"

        summary = {
            "schema_version": "1.0",
            "created_at": _now(),
            "run_id": self.run_id,
            "status": status,
            "tokens_used": self.tokens_used,
            "token_budget": self.token_budget,
            "stages": stages,
            "signoff": signoff,
        }
        self.bb.write_json("orchestration_summary.json", summary)
        log.info("[orchestrator] done — status=%s tokens=%d/%d",
                 status, self.tokens_used, self.token_budget)
        return summary

    # -- stages ----------------------------------------------------------
    def _run_triage(self) -> dict:
        msg = self._task_msg("triage")
        result = get_agent("triage").handle(msg, self.bb)
        self._charge(result)
        return {"verdicts": (result.get("payload") or {}).get("verdicts", 0)}

    def _run_critic(self) -> dict:
        """Bounded critic<->triage reconcile. Critic challenges verdicts; the
        orchestrator applies conservative downgrades it agrees with."""
        applied = 0
        for rnd in range(self.max_critic_rounds):
            if self._over_budget():
                break
            msg = self._task_msg("critic", round=rnd,
                                 refs=[ref("triage", "triage.json")])
            result = get_agent("critic").handle(msg, self.bb)
            self._charge(result)
            changed = (result.get("payload") or {}).get("downgrades_applied", 0)
            applied += changed
            if not changed:  # converged — stop early
                break
        return {"rounds": rnd + 1, "downgrades_applied": applied}

    def _run_validator(self) -> dict:
        """Dispatch the validator over unconfirmed exploitable/needs_more_info
        findings. The validator fires probes and writes execution evidence."""
        if self._over_budget():
            return {"skipped": "token budget exceeded"}
        msg = self._task_msg(
            "validator",
            refs=[ref("triage", "triage.json"), ref("findings", "findings.json")],
            payload={"max_rounds": self.max_validator_rounds},
        )
        result = get_agent("validator").handle(msg, self.bb)
        self._charge(result)
        return result.get("payload") or {}

    def _run_exploit_smith(self) -> dict:
        if self._over_budget():
            return {"skipped": "token budget exceeded"}
        msg = self._task_msg(
            "exploit_smith",
            refs=[ref("triage", "triage.json"), ref("findings", "findings.json")],
        )
        result = get_agent("exploit_smith").handle(msg, self.bb)
        self._charge(result)
        return result.get("payload") or {}

    def _run_actions(self) -> dict:
        """Rules-based actions.json — reuse the existing generator."""
        from core.llm import generate_actions
        triage_path = self.bb.path("triage.json")
        generate_actions(triage_path, self.run_dir)
        return {"actions": "generated"}

    # -- evidence gate ---------------------------------------------------
    def _enforce_evidence_gate(self) -> None:
        """
        Downgrade any 'exploitable' verdict whose finding lacks hard execution
        evidence to 'needs_more_info'. This is the non-negotiable rule; workers
        propose, the orchestrator is the gate.
        """
        if not self.bb.exists("triage.json"):
            return
        triage = self.bb.read_json("triage.json")
        findings_by_id = {}
        if self.bb.exists("findings.json"):
            for f in self.bb.read_json("findings.json").get("findings", []):
                findings_by_id[f.get("finding_id", "")] = f

        downgraded = 0
        for v in triage.get("verdicts", []):
            if v.get("verdict") != "exploitable":
                continue
            finding = findings_by_id.get(v.get("finding_id", ""), {})
            exec_status = finding.get("execution_status")
            # Recon/infra findings have no execution_status — leave them alone.
            if exec_status is not None and exec_status not in _CONFIRMED_STATES:
                v["verdict"] = "needs_more_info"
                v["evidence_gate"] = f"downgraded: execution_status={exec_status}"
                downgraded += 1

        if downgraded:
            log.warning("[orchestrator] evidence gate downgraded %d unconfirmed exploitable(s)", downgraded)
            self.bb.write_json("triage.json", triage, schema="triage")

    # -- final sign-off (the one real orchestrator LLM call) -------------
    def _final_signoff(self) -> dict:
        if not self.bb.exists("triage.json"):
            return {"assessment": "no triage produced"}
        if self._over_budget():
            return {"assessment": "skipped — token budget exceeded"}

        triage = self.bb.read_json("triage.json")
        exploitable = [v for v in triage.get("verdicts", []) if v.get("verdict") == "exploitable"]
        summary_in = {
            "program": self.program.get("name", self.program.get("program_id", "unknown")),
            "counts": _verdict_counts(triage.get("verdicts", [])),
            "exploitable": [
                {"finding_id": v.get("finding_id"), "severity": v.get("adjusted_severity"),
                 "impact": v.get("impact", "")[:300]}
                for v in exploitable
            ],
        }
        prompt = (
            "You are the run orchestrator for a bug bounty pipeline. Given the "
            "final triage counts and the confirmed-exploitable findings below, "
            "write a JSON object: {\"go_no_go\": \"submit\"|\"investigate\"|\"drop\", "
            "\"assessment\": \"2-3 sentences\", \"priority_finding_ids\": [...]}\n"
            "Only recommend 'submit' for findings with concrete confirmed impact.\n\n"
            f"{json.dumps(summary_in, indent=2)}"
        )
        try:
            comp = complete("orchestrator",
                            [{"role": "user", "content": prompt}],
                            temperature=0.2, max_tokens=600)
            self.tokens_used += comp.total_tokens
            self.bb.post(make_message(
                run_id=self.run_id, from_agent="orchestrator", to_agent="broadcast",
                intent="done", payload={"signoff": True}, cost=cost_of(comp),
            ))
            from core.models import _extract_json
            parsed = _extract_json(comp.text)
            return parsed if isinstance(parsed, dict) else {"assessment": comp.text[:500]}
        except ModelError as exc:
            log.error("[orchestrator] sign-off call failed: %s", exc)
            return {"assessment": f"sign-off unavailable: {exc}"}

    # -- helpers ---------------------------------------------------------
    def _stage(self, name: str, fn) -> dict:
        try:
            out = fn()
            return {"stage": name, "status": "ok", **({} if out is None else {"result": out})}
        except Exception as exc:  # one failing stage must not sink the run
            log.exception("[orchestrator] stage '%s' failed", name)
            return {"stage": name, "status": "error", "error": str(exc)}

    def _task_msg(self, to_agent: str, *, refs=None, payload=None, round=None) -> dict:
        return make_message(
            run_id=self.run_id, from_agent="orchestrator", to_agent=to_agent,
            intent="task", refs=refs, payload=payload, round=round,
        )

    def _charge(self, msg: dict) -> None:
        cost = msg.get("cost") or {}
        self.tokens_used += int(cost.get("prompt_tokens", 0)) + int(cost.get("completion_tokens", 0))

    def _over_budget(self) -> bool:
        if self.tokens_used > self.token_budget:
            log.warning("[orchestrator] token budget %d exceeded (used %d) — halting LLM agents",
                        self.token_budget, self.tokens_used)
            return True
        return False

    def _peek_run_id(self) -> str:
        fp = self.run_dir / "findings.json"
        if fp.exists():
            try:
                with open(fp) as f:
                    return json.load(f).get("run_id", str(uuid.uuid4()))
            except Exception:
                pass
        return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Module helpers
# ---------------------------------------------------------------------------

def _verdict_counts(verdicts: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for v in verdicts:
        k = v.get("verdict", "unknown")
        counts[k] = counts.get(k, 0) + 1
    return counts


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def run_pipeline(run_dir: Path, program: dict, **kwargs) -> dict:
    """Convenience entrypoint."""
    return Orchestrator(Path(run_dir), program, **kwargs).run()
