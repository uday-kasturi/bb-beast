"""
Patch system. Reads playbook_patch.json files from /patches/ and applies them.

Patch application is mechanical — no LLM involved.

Workflow:
  1. Scan /patches/ for unapplied .json files
  2. Validate each against playbook_patch schema
  3. Check requires_human_review flag — skip if True and not force mode
  4. Apply the change (add/update/remove a field in a playbook chain or manifest)
  5. Mark patch as applied (set applied=true, applied_at timestamp)
  6. Git commit with source URL as message

Patch types:
  new_payload       — add a payload to a tool's payload list in chain.py
  new_step          — add a new stage to a playbook chain
  update_tool_flag  — change a CLI flag in a tool wrapper
  new_playbook      — create a new playbook folder (rarely automated)
  deprecate_technique — mark a technique as disabled
"""

from __future__ import annotations

import json
import logging
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.validator import validate_file, SchemaValidationError

log = logging.getLogger(__name__)

ROOT = Path(__file__).parent.parent
PATCHES_DIR = ROOT / "patches"
PLAYBOOKS_DIR = ROOT / "playbooks"


def apply_pending_patches(force: bool = False, dry_run: bool = False) -> dict:
    """
    Apply all unapplied patches in /patches/.

    Args:
        force:   Apply even if requires_human_review=True
        dry_run: Print what would happen but don't modify files

    Returns:
        Dict with applied/skipped/failed counts
    """
    stats = {"applied": 0, "skipped": 0, "failed": 0}

    patch_files = sorted(PATCHES_DIR.glob("*.json"))
    if not patch_files:
        log.info("No patch files found in %s", PATCHES_DIR)
        return stats

    log.info("Found %d patch files", len(patch_files))

    for patch_path in patch_files:
        try:
            patch = validate_file("playbook_patch", patch_path)
        except (SchemaValidationError, Exception) as exc:
            log.error("Invalid patch file %s: %s — skipping", patch_path.name, exc)
            stats["failed"] += 1
            continue

        # Skip already-applied patches
        if patch.get("applied"):
            log.debug("Patch %s already applied — skipping", patch_path.name)
            continue

        # Human review gate
        if patch.get("requires_human_review") and not force:
            log.warning(
                "Patch %s requires human review. "
                "Review it, then run with --force to apply.",
                patch_path.name,
            )
            stats["skipped"] += 1
            continue

        # Apply the patch
        patch_id = patch.get("patch_id", patch_path.stem)
        source = patch.get("source", "unknown source")
        log.info("Applying patch %s from: %s", patch_id[:8], source)

        if dry_run:
            log.info("[DRY RUN] Would apply: %s", _describe_patch(patch))
            stats["skipped"] += 1
            continue

        try:
            _apply_patch(patch)
            # Mark as applied
            patch["applied"] = True
            patch["applied_at"] = _now()
            with open(patch_path, "w") as f:
                json.dump(patch, f, indent=2)
            # Git commit
            _git_commit(patch_path, source)
            stats["applied"] += 1
            log.info("Patch %s applied successfully", patch_id[:8])
        except Exception as exc:
            log.error("Failed to apply patch %s: %s", patch_id[:8], exc, exc_info=True)
            stats["failed"] += 1

    log.info("Patch run complete: %s", stats)
    return stats


def _apply_patch(patch: dict) -> None:
    """Apply a single patch to the target playbook."""
    target_playbooks = patch.get("target_playbooks", [])
    change = patch.get("change", {})
    patch_type = patch.get("patch_type", "")
    operation = change.get("operation", "")
    target_field = change.get("target", "")
    new_value = change.get("value")

    for pb_name in target_playbooks:
        pb_dir = PLAYBOOKS_DIR / pb_name
        if not pb_dir.exists():
            log.warning("Playbook dir not found: %s — skipping", pb_dir)
            continue

        if patch_type in ("new_payload", "update_tool_flag", "new_step"):
            _patch_manifest_or_chain(pb_dir, patch_type, operation, target_field, new_value, change)
        elif patch_type == "deprecate_technique":
            _deprecate_technique(pb_dir, target_field)
        elif patch_type == "new_playbook":
            log.warning(
                "new_playbook patches require manual creation of playbook folder. "
                "Skipping automated apply."
            )
        else:
            log.warning("Unknown patch type: %s", patch_type)


def _patch_manifest_or_chain(
    pb_dir: Path,
    patch_type: str,
    operation: str,
    target_field: str,
    new_value: Any,
    change: dict,
) -> None:
    """Apply a patch to playbook_manifest.json or chain.py."""

    # Manifest patches: dot-path to a field in playbook_manifest.json
    if target_field.startswith("manifest.") or patch_type == "update_tool_flag":
        manifest_path = pb_dir / "playbook_manifest.json"
        if not manifest_path.exists():
            raise FileNotFoundError(f"manifest not found: {manifest_path}")

        with open(manifest_path) as f:
            manifest = json.load(f)

        field_path = target_field.replace("manifest.", "").split(".")
        _apply_json_operation(manifest, field_path, operation, new_value)

        # Bump last_updated
        manifest["last_updated"] = _now()

        with open(manifest_path, "w") as f:
            json.dump(manifest, f, indent=2)
        log.info("Patched manifest: %s [%s] %s", manifest_path.parent.name, operation, target_field)

    # Chain patches: inject comments/code into chain.py
    elif target_field.startswith("chain.") or patch_type == "new_step":
        chain_path = pb_dir / "chain.py"
        if not chain_path.exists():
            raise FileNotFoundError(f"chain.py not found: {chain_path}")

        # For new_step patches, append a comment block describing the new step
        # Full code injection is not automated — it's flagged for human to implement
        if patch_type == "new_step":
            description = change.get("value", {})
            _append_patch_comment(chain_path, description)
            log.info(
                "Appended new_step comment to %s/chain.py — "
                "requires human implementation",
                pb_dir.name,
            )
        else:
            log.warning(
                "chain.py patches for type '%s' require manual implementation. "
                "Change description: %s",
                patch_type,
                change.get("description", ""),
            )


def _apply_json_operation(
    doc: dict, path: list[str], operation: str, new_value: Any
) -> None:
    """Mutate *doc* in place following the dot-path and operation."""
    if not path:
        return

    # Navigate to parent
    node = doc
    for key in path[:-1]:
        if isinstance(node, dict):
            node = node.setdefault(key, {})
        elif isinstance(node, list):
            try:
                node = node[int(key)]
            except (ValueError, IndexError):
                return

    leaf_key = path[-1]

    if operation == "add":
        if isinstance(node, dict):
            if isinstance(node.get(leaf_key), list):
                node[leaf_key].append(new_value)
            else:
                node[leaf_key] = new_value
        elif isinstance(node, list):
            node.append(new_value)

    elif operation == "update":
        if isinstance(node, dict):
            node[leaf_key] = new_value

    elif operation == "remove":
        if isinstance(node, dict) and leaf_key in node:
            del node[leaf_key]
        elif isinstance(node, list):
            try:
                node.remove(new_value)
            except ValueError:
                pass


def _deprecate_technique(pb_dir: Path, target_field: str) -> None:
    """Mark a technique as deprecated by appending to a deprecations list in manifest."""
    manifest_path = pb_dir / "playbook_manifest.json"
    if not manifest_path.exists():
        return

    with open(manifest_path) as f:
        manifest = json.load(f)

    deprecated = manifest.setdefault("deprecated_techniques", [])
    if target_field not in deprecated:
        deprecated.append(target_field)
        manifest["last_updated"] = _now()
        with open(manifest_path, "w") as f:
            json.dump(manifest, f, indent=2)
        log.info("Deprecated technique '%s' in %s", target_field, pb_dir.name)


def _append_patch_comment(chain_path: Path, description: Any) -> None:
    """Append a TODO comment block to chain.py for human implementation."""
    comment = (
        f"\n\n# =========================================================\n"
        f"# PATCH APPLIED — REQUIRES HUMAN IMPLEMENTATION\n"
        f"# Description: {json.dumps(description, indent=2)}\n"
        f"# Applied at: {_now()}\n"
        f"# =========================================================\n"
        f"# TODO: Implement the above change in this chain\n"
    )
    with open(chain_path, "a") as f:
        f.write(comment)


def _git_commit(patch_path: Path, source: str) -> None:
    """Commit the patch and modified playbook files with source as message."""
    try:
        subprocess.run(
            ["git", "add", str(patch_path), str(PLAYBOOKS_DIR)],
            cwd=ROOT, check=True, capture_output=True,
        )
        message = f"Apply playbook patch\n\nSource: {source}\nApplied: {_now()}"
        subprocess.run(
            ["git", "commit", "-m", message],
            cwd=ROOT, check=True, capture_output=True,
        )
        log.info("Git commit made for patch from: %s", source)
    except subprocess.CalledProcessError as exc:
        log.warning("Git commit failed (not a git repo or nothing staged?): %s", exc.stderr)


def _describe_patch(patch: dict) -> str:
    return (
        f"[{patch.get('patch_type')}] on {patch.get('target_playbooks')} — "
        f"{patch.get('change_description', '')}"
    )


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
