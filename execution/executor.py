"""
Execution engine. Reads actions.json and runs follow-up actions.

Responsibilities:
- Read actions.json
- Execute actions in priority order (1 = highest)
- Guard every action against out-of-scope rules BEFORE execution
- Skip high-risk actions unless explicitly approved by operator
- Flag items for human review by printing to stdout with clear formatting
- Update action statuses in actions.json as they run
- Write results back alongside the original run

This module does NOT:
- Make LLM calls
- Generate findings (it runs tools and their output goes into raw_output/)
- Modify triage.json
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# Risk levels that require explicit human approval before running
_REQUIRES_APPROVAL = {"high"}


def execute(
    actions_path: Path,
    run_dir: Path,
    program: dict,
    auto_approve_low_risk: bool = True,
    dry_run: bool = False,
) -> dict:
    """
    Execute all pending actions from actions.json.

    Args:
        actions_path:          Path to actions.json
        run_dir:               Run directory (for writing follow-up outputs)
        program:               Loaded program.json document
        auto_approve_low_risk: Auto-run low/medium risk actions without prompting
        dry_run:               If True, print what would run but don't execute

    Returns:
        Summary dict with counts of completed/skipped/failed actions
    """
    if not actions_path.exists():
        raise FileNotFoundError(f"actions.json not found: {actions_path}")

    with open(actions_path) as f:
        actions_doc = json.load(f)

    run_id = actions_doc.get("run_id", "unknown")
    actions = actions_doc.get("actions", [])
    burp_tasks = actions_doc.get("burp_tasks", [])

    # Sort by priority (1 = run first)
    actions_sorted = sorted(actions, key=lambda a: a.get("priority", 5))

    stats = {"completed": 0, "skipped": 0, "failed": 0, "flagged": 0}

    log.info("=" * 60)
    log.info("Execution engine: %d actions, %d burp tasks", len(actions), len(burp_tasks))
    log.info("=" * 60)

    for action in actions_sorted:
        action_id = action.get("action_id", "?")
        action_type = action.get("action_type", "skip")
        finding_id = action.get("finding_id", "?")
        risk = action.get("risk_level", "low")
        priority = action.get("priority", 5)
        reason = action.get("reason", "")

        log.info(
            "Action [P%d] %s | type=%s | risk=%s | finding=%s",
            priority, action_id[:8], action_type, risk, finding_id[:8],
        )

        # Skip already-processed actions
        if action.get("status") in ("completed", "failed", "skipped"):
            continue

        # ----------------------------------------------------------------
        # Out-of-scope guard
        # ----------------------------------------------------------------
        target = action.get("parameters", {}).get("url", "") or action.get("command", "")
        if target and not _is_target_in_scope(target, program):
            log.warning("Action %s: target out of scope — skipping", action_id[:8])
            action["status"] = "skipped"
            stats["skipped"] += 1
            continue

        # ----------------------------------------------------------------
        # High-risk gate — requires explicit approval
        # ----------------------------------------------------------------
        if risk in _REQUIRES_APPROVAL and not dry_run:
            log.warning(
                "Action %s is HIGH RISK — requires manual approval. Flagging for human.",
                action_id[:8],
            )
            _print_flag(action, reason="HIGH RISK — manual approval required")
            action["status"] = "skipped"
            stats["flagged"] += 1
            continue

        # ----------------------------------------------------------------
        # Dispatch by action type
        # ----------------------------------------------------------------
        if action_type == "skip":
            action["status"] = "skipped"
            stats["skipped"] += 1

        elif action_type == "flag_for_human":
            _print_flag(action, reason)
            action["status"] = "completed"
            stats["flagged"] += 1

        elif action_type == "run_tool":
            if dry_run:
                log.info("[DRY RUN] Would run: %s", action.get("command", "?"))
                action["status"] = "skipped"
                stats["skipped"] += 1
            else:
                success = _run_tool_action(action, run_dir, program)
                action["status"] = "completed" if success else "failed"
                stats["completed" if success else "failed"] += 1

        elif action_type == "burp_scan":
            if dry_run:
                log.info("[DRY RUN] Would submit Burp scan for finding %s", finding_id[:8])
                action["status"] = "skipped"
                stats["skipped"] += 1
            else:
                from burp.integration import BurpIntegration
                burp = BurpIntegration()
                if burp.health_check():
                    task_map = burp.submit_tasks(
                        actions_path=actions_path,
                        run_dir=run_dir,
                        program=program,
                    )
                    action["status"] = "completed" if task_map else "failed"
                    stats["completed" if task_map else "failed"] += 1
                else:
                    log.warning("Burp not reachable — skipping burp_scan action %s", action_id[:8])
                    action["status"] = "skipped"
                    stats["skipped"] += 1

    # Write updated statuses back to actions.json
    actions_doc["actions"] = actions_sorted
    with open(actions_path, "w") as f:
        json.dump(actions_doc, f, indent=2)

    log.info("Execution complete: %s", stats)
    return stats


# ---------------------------------------------------------------------------
# Action runners
# ---------------------------------------------------------------------------

def _run_tool_action(action: dict, run_dir: Path, program: dict) -> bool:
    """Run a tool action. Returns True on success."""
    tool_name = action.get("tool", "")
    command = action.get("command", "")
    params = action.get("parameters", {})

    if not tool_name and not command:
        log.error("run_tool action has no tool or command specified")
        return False

    log.info("Running follow-up tool: %s", tool_name or command[:50])

    # Dynamically load the tool wrapper
    try:
        import importlib
        module = importlib.import_module(f"tools.{tool_name}")
        # Find the wrapper class (convention: *Wrapper)
        wrapper_class = None
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if (
                isinstance(attr, type) and
                attr_name.endswith("Wrapper") and
                attr_name != "ToolWrapper"
            ):
                wrapper_class = attr
                break
        if not wrapper_class:
            log.error("No Wrapper class found in tools.%s", tool_name)
            return False

        wrapper = wrapper_class()
        raw_output_dir = run_dir / "raw_output"

        # Build kwargs from parameters
        run_kwargs = dict(params)
        wrapper.run(
            target=params.get("target", ""),
            depth=params.get("depth", "standard"),
            run_id=action.get("finding_id", str(uuid.uuid4())),
            raw_output_dir=raw_output_dir,
            program=program,
            **{k: v for k, v in run_kwargs.items() if k not in ("target", "depth")},
        )
        return True
    except Exception as exc:
        log.error("Tool action failed: %s", exc, exc_info=True)
        return False


# ---------------------------------------------------------------------------
# Scope and output helpers
# ---------------------------------------------------------------------------

def _is_target_in_scope(target: str, program: dict) -> bool:
    """Check if a target URL or host is within program scope."""
    import fnmatch
    from urllib.parse import urlparse

    try:
        host = urlparse(target).hostname or target
    except Exception:
        host = target

    out_domains = program.get("out_of_scope", {}).get("domains", [])
    for pattern in out_domains:
        if fnmatch.fnmatch(host, pattern) or host == pattern:
            return False

    in_domains = program.get("in_scope", {}).get("domains", [])
    if not in_domains:
        return True  # No scope restrictions defined

    for pattern in in_domains:
        if fnmatch.fnmatch(host, pattern) or host == pattern:
            return True
        if pattern.startswith("*."):
            apex = pattern[2:]
            if host == apex or host.endswith("." + apex):
                return True

    return False


def _print_flag(action: dict, reason: str = "") -> None:
    """Print a human-readable flag to stdout."""
    finding_id = action.get("finding_id", "?")
    sev = action.get("parameters", {}).get("severity", "unknown")
    line = "=" * 70
    print(f"\n{line}")
    print(f"  *** FLAGGED FOR HUMAN REVIEW ***")
    print(f"  Finding ID : {finding_id}")
    print(f"  Reason     : {reason}")
    if action.get("command"):
        print(f"  Suggested  : {action['command']}")
    print(f"{line}\n")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
