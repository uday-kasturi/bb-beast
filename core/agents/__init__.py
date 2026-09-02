"""
core/agents — the agent registry.

Drop a new agent file in this folder and it registers itself. No wiring edits
anywhere else — same plugin principle as tools/ and playbooks/.

Convention: each agent module (any *.py here except base.py / __init__.py)
exposes a module-level `AGENT` that is an Agent instance. The registry imports
every such module once and indexes AGENT by its `.name`.

    from core.agents import get_agent, all_agents
    triage = get_agent("triage")
"""

from __future__ import annotations

import importlib
import logging
import pkgutil
from pathlib import Path

from core.agents.base import Agent, Blackboard, make_message, ref, cost_of

log = logging.getLogger(__name__)

_REGISTRY: dict[str, Agent] = {}
_LOADED = False

_SKIP = {"base", "__init__"}


def _discover() -> None:
    """Import every agent module in this package and collect its AGENT."""
    global _LOADED
    if _LOADED:
        return

    pkg_dir = Path(__file__).parent
    for info in pkgutil.iter_modules([str(pkg_dir)]):
        if info.name in _SKIP:
            continue
        module_name = f"{__name__}.{info.name}"
        try:
            module = importlib.import_module(module_name)
        except Exception as exc:  # a broken agent must not sink the whole bus
            log.error("Failed to import agent module %s: %s", module_name, exc)
            continue

        agent = getattr(module, "AGENT", None)
        if agent is None:
            log.debug("Module %s defines no AGENT — skipping", module_name)
            continue
        if not isinstance(agent, Agent):
            log.error("%s.AGENT is not an Agent instance — skipping", module_name)
            continue
        if agent.name in _REGISTRY:
            log.warning("Duplicate agent name '%s' (%s) — keeping first", agent.name, module_name)
            continue
        _REGISTRY[agent.name] = agent
        log.debug("Registered agent '%s' (role=%s)", agent.name, agent.role)

    _LOADED = True
    log.info("Agent registry: %d agents [%s]", len(_REGISTRY), ", ".join(sorted(_REGISTRY)))


def get_agent(name: str) -> Agent:
    _discover()
    if name not in _REGISTRY:
        raise KeyError(f"Unknown agent '{name}'. Registered: {sorted(_REGISTRY)}")
    return _REGISTRY[name]


def all_agents() -> dict[str, Agent]:
    _discover()
    return dict(_REGISTRY)


def agent_names() -> list[str]:
    _discover()
    return sorted(_REGISTRY)


__all__ = [
    "Agent",
    "Blackboard",
    "make_message",
    "ref",
    "cost_of",
    "get_agent",
    "all_agents",
    "agent_names",
]
