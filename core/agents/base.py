"""
core/agents/base.py — agent bus primitives.

Three things live here:

  Blackboard    — the shared state agents read/write. It IS the run_dir: the
                  9 pipeline artifacts (findings.json, triage.json, ...) plus an
                  append-only agent_messages.jsonl audit log of every handoff.

  AgentMessage  — helper to build schema-valid agent_message docs. Messages
                  carry `refs` (pointers to blackboard artifacts), never bulk
                  data inline. That's what keeps inter-agent traffic bounded.

  Agent         — base class. An agent is a config bundle (name + model role +
                  system prompt + I/O contract) with one method: handle().

Agents never touch models.py's transport directly beyond `complete()` — routing
lives in models.py, the work lives here.
"""

from __future__ import annotations

import json
import logging
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core import validator
from core.models import Completion

log = logging.getLogger(__name__)

_MESSAGE_LOG = "agent_messages.jsonl"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Messages
# ---------------------------------------------------------------------------

def make_message(
    *,
    run_id: str,
    from_agent: str,
    to_agent: str,
    intent: str,
    refs: list[dict] | None = None,
    payload: dict | None = None,
    cost: dict | None = None,
    reply_to: str | None = None,
    round: int | None = None,
) -> dict:
    """Build a schema-valid agent_message document."""
    msg: dict[str, Any] = {
        "schema_version": "1.0",
        "created_at": _now(),
        "run_id": run_id,
        "message_id": str(uuid.uuid4()),
        "from_agent": from_agent,
        "to_agent": to_agent,
        "intent": intent,
    }
    if refs is not None:
        msg["refs"] = refs
    if payload is not None:
        msg["payload"] = payload
    if cost is not None:
        msg["cost"] = cost
    if reply_to is not None:
        msg["reply_to"] = reply_to
    if round is not None:
        msg["round"] = round
    return msg


def ref(artifact: str, path: str, finding_ids: list[str] | None = None) -> dict:
    """Build a single ref entry pointing at a blackboard artifact."""
    entry: dict[str, Any] = {"artifact": artifact, "path": path}
    if finding_ids is not None:
        entry["finding_ids"] = finding_ids
    return entry


def cost_of(comp: Completion | None) -> dict:
    """Turn a models.Completion into a message `cost` block (audit trail)."""
    if comp is None:
        return {"backend": "none", "model": "", "prompt_tokens": 0, "completion_tokens": 0}
    return {
        "backend": comp.backend,
        "model": comp.model,
        "prompt_tokens": comp.prompt_tokens,
        "completion_tokens": comp.completion_tokens,
    }


# ---------------------------------------------------------------------------
# Blackboard
# ---------------------------------------------------------------------------

class Blackboard:
    """
    Shared state for one run. Wraps run_dir with validated artifact I/O and an
    append-only message log. Agents pass this around and read/write through it.
    """

    def __init__(self, run_dir: Path, run_id: str) -> None:
        self.run_dir = Path(run_dir)
        self.run_id = run_id
        self.run_dir.mkdir(parents=True, exist_ok=True)

    # --- artifacts -------------------------------------------------------
    def path(self, rel: str) -> Path:
        """Resolve a run-dir-relative artifact path."""
        return self.run_dir / rel

    def exists(self, rel: str) -> bool:
        return self.path(rel).exists()

    def read_json(self, rel: str) -> dict:
        p = self.path(rel)
        if not p.exists():
            raise FileNotFoundError(f"blackboard artifact missing: {rel}")
        with open(p) as f:
            return json.load(f)

    def write_json(self, rel: str, doc: Any, schema: str | None = None) -> Path:
        """
        Write an artifact. If `schema` is given, validate first; on failure the
        doc is still written (so work is never lost) but the error is logged.
        """
        p = self.path(rel)
        p.parent.mkdir(parents=True, exist_ok=True)
        if schema:
            try:
                validator.validate(schema, doc)
            except validator.SchemaValidationError as exc:
                log.error("blackboard write %s failed schema '%s': %s", rel, schema, exc)
        with open(p, "w") as f:
            json.dump(doc, f, indent=2)
        return p

    # --- message log -----------------------------------------------------
    def post(self, msg: dict) -> dict:
        """Validate and append a message to the audit log. Returns the message."""
        try:
            validator.validate("agent_message", msg)
        except validator.SchemaValidationError as exc:
            log.error("agent_message failed validation, logging anyway: %s", exc)
        with open(self.path(_MESSAGE_LOG), "a") as f:
            f.write(json.dumps(msg) + "\n")
        log.info("[bus] %s -> %s  (%s)", msg.get("from_agent"), msg.get("to_agent"), msg.get("intent"))
        return msg

    def messages(self) -> list[dict]:
        """Read the full message log for this run."""
        p = self.path(_MESSAGE_LOG)
        if not p.exists():
            return []
        out = []
        with open(p) as f:
            for line in f:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
        return out


# ---------------------------------------------------------------------------
# Agent base
# ---------------------------------------------------------------------------

class Agent(ABC):
    """
    Base agent. Subclasses set the class attributes and implement handle().

    name          — unique bus identity (also the registry key)
    role          — models.py role key deciding which model/backend runs it
    system_prompt — the agent's standing instructions
    reads         — logical artifact names it consumes (documentation + wiring)
    writes        — logical artifact name it produces, or None
    """

    name: str = "agent"
    role: str = ""
    system_prompt: str = ""
    reads: list[str] = []
    writes: str | None = None

    @abstractmethod
    def handle(self, msg: dict, bb: Blackboard) -> dict:
        """
        Process an inbound message against the blackboard and return an outbound
        agent_message (built with make_message). Side effects (writing artifacts)
        go through the blackboard.
        """
        raise NotImplementedError

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Agent {self.name} role={self.role!r}>"
