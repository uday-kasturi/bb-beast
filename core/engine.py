"""
Core orchestration engine.

Responsibilities:
  - Discover all playbooks under /playbooks/
  - Resolve execution order from playbook_dependencies
  - Run each playbook's chain.py in dependency order
  - Enforce program scope before any playbook runs
  - Aggregate tool outputs into findings.json
  - Write run_manifest.json as the audit trail
  - Hand findings.json off to the LLM triage layer

This module does NOT:
  - Make any LLM calls (that is core/llm.py)
  - Know anything about individual tools (that is tools/*.py)
  - Execute follow-up actions (that is execution/executor.py)
"""
from __future__ import annotations

import importlib.util
import json
import logging
import re
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.validator import validate_file, validate_and_write, SchemaValidationError

log = logging.getLogger(__name__)

ROOT = Path(__file__).parent.parent
PLAYBOOKS_DIR = ROOT / "playbooks"
RUNS_DIR = ROOT / "runs"
PROGRAMS_DIR = ROOT / "programs"


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run(
    program_id: str,
    depth: str = "standard",
    playbooks: list[str] | None = None,
    operator: str = "operator",
) -> Path:
    """
    Run the full pipeline for *program_id*.

    Args:
        program_id: Matches a file in /programs/<program_id>.json
        depth:      quick | standard | exhaustive
        playbooks:  Optional list of playbook names to run. Defaults to all.
        operator:   Human operator identifier for the audit trail.

    Returns:
        Path to the run output directory.
    """
    if depth not in ("quick", "standard", "exhaustive"):
        raise ValueError(f"Invalid depth: {depth!r}")

    run_id = str(uuid.uuid4())
    started_at = _now()

    # -- Load and validate program first so we can use the domain in the path
    program = _load_program(program_id)

    # Build output path: runs/{domain}/{YYYY-MM-DD_HH-MM}_{run_id[:8]}/
    domain = _primary_domain(program)
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M")
    run_dir = RUNS_DIR / domain / f"{ts}_{run_id[:8]}"
    run_dir.mkdir(parents=True, exist_ok=True)
    raw_output_dir = run_dir / "raw_output"
    raw_output_dir.mkdir(parents=True, exist_ok=True)

    # Attach persistent log file for this run — captures all logger output
    _fh = logging.FileHandler(run_dir / "run.log", mode="w", encoding="utf-8")
    _fh.setLevel(logging.DEBUG)
    _fh.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    ))
    logging.getLogger().addHandler(_fh)

    log.info("=" * 60)
    log.info("Run ID  : %s", run_id)
    log.info("Program : %s", program_id)
    log.info("Domain  : %s", domain)
    log.info("Depth   : %s", depth)
    log.info("Output  : %s", run_dir)
    log.info("=" * 60)

    # -- Load session (optional) --------------------------------------------
    session = _load_session(program_id)
    if session:
        log.info("Session : %s (%s)", session.get("authenticated_as"), session.get("auth_type"))
    else:
        log.info("Session : none — running unauthenticated")

    # -- Discover playbooks -------------------------------------------------
    available = _discover_playbooks()
    if playbooks:
        unknown = set(playbooks) - set(available)
        if unknown:
            raise ValueError(f"Unknown playbooks requested: {unknown}")
        selected = {k: v for k, v in available.items() if k in playbooks}
    else:
        selected = available

    # -- Resolve dependency tiers -------------------------------------------
    # Tiers are groups of playbooks with no inter-dependencies — every
    # playbook in a tier can run in parallel. Sequential order is preserved
    # between tiers (tier N+1 only starts after tier N is complete).
    tiers = _resolve_tiers(selected)
    log.info(
        "Execution plan: %s",
        " → ".join("[" + " + ".join(t) + "]" for t in tiers),
    )

    # -- Run each tier (parallel within tier, sequential across tiers) ------
    manifest_playbooks: list[dict] = []
    manifest_tools: list[dict] = []
    all_raw_outputs: list[Path] = []
    errors: list[dict] = []

    for tier_idx, tier_names in enumerate(tiers):
        runnable = [
            n for n in tier_names
            if _scope_allows_playbook(program, selected[n]["manifest"])
        ]
        skipped_names = [n for n in tier_names if n not in runnable]

        for pb_name in skipped_names:
            pb_manifest = selected[pb_name]["manifest"]
            log.warning("Playbook %s skipped — test types not allowed by program scope", pb_name)
            manifest_playbooks.append({
                "name": pb_name,
                "version": pb_manifest["version"],
                "status": "skipped",
                "started_at": _now(),
            })

        if not runnable:
            continue

        if len(runnable) == 1:
            # Single playbook — no thread overhead
            pb_name = runnable[0]
            log.info("--- Tier %d: %s [%s] ---", tier_idx, pb_name, depth)
            entry, tools, paths, errs = _run_playbook(
                pb_name, selected[pb_name]["manifest"],
                program, depth, run_id, run_dir, raw_output_dir,
                session=session,
            )
            manifest_playbooks.append(entry)
            manifest_tools.extend(tools)
            all_raw_outputs.extend(paths)
            errors.extend(errs)
        else:
            # Multiple independent playbooks — run in parallel
            log.info(
                "--- Tier %d: [%s] in parallel [%s] ---",
                tier_idx, " + ".join(runnable), depth,
            )
            with ThreadPoolExecutor(max_workers=len(runnable)) as executor:
                future_to_pb = {
                    executor.submit(
                        _run_playbook,
                        pb_name, selected[pb_name]["manifest"],
                        program, depth, run_id, run_dir, raw_output_dir,
                        session,
                    ): pb_name
                    for pb_name in runnable
                }
                for future in as_completed(future_to_pb):
                    entry, tools, paths, errs = future.result()
                    manifest_playbooks.append(entry)
                    manifest_tools.extend(tools)
                    all_raw_outputs.extend(paths)
                    errors.extend(errs)

    # -- Aggregate findings -------------------------------------------------
    findings_path = run_dir / "findings.json"
    findings_doc = aggregate_findings(
        run_id=run_id,
        program_id=program_id,
        raw_output_paths=all_raw_outputs,
        ordered_playbooks=[pb for tier in tiers for pb in tier],
        depth=depth,
    )
    try:
        validate_and_write("findings", findings_doc, findings_path)
        log.info("findings.json written: %d findings", findings_doc["summary"]["total"])
    except SchemaValidationError as exc:
        log.error("findings.json validation failed: %s", exc)
        errors.append({"stage": "aggregate_findings", "message": str(exc)})

    # -- Write run manifest -------------------------------------------------
    finished_at = _now()
    run_manifest = _build_run_manifest(
        run_id=run_id,
        program_id=program_id,
        invoked_by=operator,
        depth=depth,
        started_at=started_at,
        finished_at=finished_at,
        playbooks_run=manifest_playbooks,
        tools_invoked=manifest_tools,
        run_dir=run_dir,
        errors=errors,
    )
    try:
        validate_and_write("run_manifest", run_manifest, run_dir / "run_manifest.json")
    except SchemaValidationError as exc:
        log.error("run_manifest validation failed: %s", exc)
        # Write raw anyway so we don't lose the audit trail
        with open(run_dir / "run_manifest.json", "w") as f:
            json.dump(run_manifest, f, indent=2)

    log.info("Run complete. Output directory: %s", run_dir)
    return run_dir


def gate_for_triage(findings_doc: dict) -> tuple[list[dict], list[dict]]:
    """
    Split findings into two buckets based on execution_status:

    eligible   — execution_status is callback_received, screenshot_confirmed,
                 OR execution_status field is absent (pre-interactsh findings,
                 non-XSS/SSRF types like recon/info that don't need OAST).
    blocked    — execution_status is not_attempted or attempted_no_callback.
                 These are flagged for human review before triage.

    Returns (eligible, blocked) lists.
    """
    eligible: list[dict] = []
    blocked: list[dict] = []

    _confirmed = {"callback_received", "screenshot_confirmed"}
    _unconfirmed = {"not_attempted", "attempted_no_callback"}

    # Finding types that require OAST confirmation before triage
    _oast_required_types = {"xss", "ssrf", "xxe", "ssti", "command_injection"}

    for finding in findings_doc.get("findings", []):
        status = finding.get("execution_status")
        ftype  = finding.get("type", "")

        if status in _confirmed:
            eligible.append(finding)
        elif status in _unconfirmed:
            blocked.append(finding)
        elif status is None and ftype in _oast_required_types:
            # OAST-required type but no execution_status recorded yet
            # (tool wrapper hasn't been updated) — block and flag
            blocked.append(finding)
        else:
            # Non-OAST type (recon, sqli, secret, etc.) or already has evidence
            eligible.append(finding)

    log.info(
        "Triage gate: %d eligible, %d blocked (need OAST confirmation)",
        len(eligible), len(blocked),
    )
    return eligible, blocked


# ---------------------------------------------------------------------------
# Program loading
# ---------------------------------------------------------------------------

def _load_session(program_id: str) -> dict | None:
    path = ROOT / "sessions" / f"{program_id}.json"
    if not path.exists():
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except Exception as exc:
        log.warning("Could not load session file %s: %s", path, exc)
        return None


def _primary_domain(program: dict) -> str:
    """
    Extract the primary domain from a program for use in the output path.
    Strips wildcards, sanitizes for filesystem use.
    e.g. *.example.com → example.com, https://example.com → example.com
    """
    domains = program.get("in_scope", {}).get("domains", [])
    if not domains:
        return "unknown"
    d = domains[0].lstrip("*.")
    # Strip any scheme that crept in, keep only hostname-safe chars
    d = re.sub(r"^https?://", "", d).split("/")[0]
    d = re.sub(r"[^\w.\-]", "_", d)
    return d or "unknown"


def _load_program(program_id: str) -> dict:
    path = PROGRAMS_DIR / f"{program_id}.json"
    try:
        program = validate_file("program", path)
    except FileNotFoundError:
        raise FileNotFoundError(
            f"Program file not found: {path}\n"
            f"Create /programs/{program_id}.json first."
        )
    log.info("Loaded program: %s (%s)", program["name"], program["platform"])
    return program


# ---------------------------------------------------------------------------
# Playbook discovery and dependency resolution
# ---------------------------------------------------------------------------

def _discover_playbooks() -> dict[str, dict]:
    """
    Walk /playbooks/ and return a dict of {name: {manifest, path}} for every
    playbook that has a valid playbook_manifest.json and a chain.py.
    """
    playbooks = {}
    for pb_dir in sorted(PLAYBOOKS_DIR.iterdir()):
        if not pb_dir.is_dir():
            continue
        manifest_path = pb_dir / "playbook_manifest.json"
        chain_path = pb_dir / "chain.py"
        if not manifest_path.exists() or not chain_path.exists():
            log.debug("Skipping %s — missing manifest or chain.py", pb_dir.name)
            continue
        try:
            manifest = validate_file("playbook_manifest", manifest_path)
        except (SchemaValidationError, Exception) as exc:
            log.warning("Skipping %s — invalid manifest: %s", pb_dir.name, exc)
            continue
        playbooks[pb_dir.name] = {"manifest": manifest, "path": pb_dir}
        log.debug("Discovered playbook: %s v%s", pb_dir.name, manifest["version"])

    log.info("Discovered %d playbooks: %s", len(playbooks), list(playbooks))
    return playbooks


def _resolve_order(playbooks: dict[str, dict]) -> list[str]:
    """
    Topological sort of playbooks based on playbook_dependencies.
    Raises ValueError if there's a circular dependency or missing dependency.
    """
    return [pb for tier in _resolve_tiers(playbooks) for pb in tier]


def _resolve_tiers(playbooks: dict[str, dict]) -> list[list[str]]:
    """
    Group playbooks into execution tiers using Kahn's algorithm.
    All playbooks in the same tier have no dependencies on each other
    and can be run in parallel. Tiers must be executed in order.

    Example: recon has no deps → tier 0.
             auth/exposure/infra all depend only on recon → tier 1 (parallel).
    """
    deps: dict[str, list[str]] = {
        name: [d for d in info["manifest"].get("playbook_dependencies", []) if d in playbooks]
        for name, info in playbooks.items()
    }
    in_degree: dict[str, int] = {n: len(d) for n, d in deps.items()}
    remaining = set(playbooks.keys())
    tiers: list[list[str]] = []

    while remaining:
        tier = sorted(n for n in remaining if in_degree[n] == 0)
        if not tier:
            raise ValueError(f"Circular playbook dependency detected among: {remaining}")
        tiers.append(tier)
        for node in tier:
            remaining.discard(node)
            for name in remaining:
                if node in deps[name]:
                    in_degree[name] -= 1

    return tiers


# ---------------------------------------------------------------------------
# Playbook runner (used by both single-playbook and parallel-tier paths)
# ---------------------------------------------------------------------------

def _run_playbook(
    pb_name: str,
    pb_manifest: dict,
    program: dict,
    depth: str,
    run_id: str,
    run_dir: Path,
    raw_output_dir: Path,
    session: dict | None = None,
) -> tuple[dict, list, list, list]:
    """
    Run one playbook's chain and return (manifest_entry, tools_invoked, raw_paths, errors).
    Safe to call from multiple threads simultaneously (file-level locks in base.py
    protect concurrent writes to the same raw_output file).
    """
    pb_started = _now()
    try:
        chain_module = load_chain(pb_name)
        result = chain_module.run(
            program=program,
            depth=depth,
            run_id=run_id,
            run_dir=run_dir,
            raw_output_dir=raw_output_dir,
            session=session,
        )
        pb_status = "completed"
        tools = result.get("tools_invoked", [])
        raw_paths = result.get("raw_output_paths", [])
        errs: list = []
    except Exception as exc:
        log.error("Playbook %s failed: %s", pb_name, exc, exc_info=True)
        pb_status = "failed"
        tools = []
        raw_paths = []
        errs = [{"stage": f"playbook:{pb_name}", "message": str(exc)}]

    entry = {
        "name": pb_name,
        "version": pb_manifest.get("version", "unknown"),
        "status": pb_status,
        "started_at": pb_started,
        "finished_at": _now(),
    }
    return entry, tools, raw_paths, errs


# ---------------------------------------------------------------------------
# Chain loading
# ---------------------------------------------------------------------------

def load_chain(playbook_name: str):
    """Dynamically import and return the chain module for a playbook."""
    chain_path = PLAYBOOKS_DIR / playbook_name / "chain.py"
    spec = importlib.util.spec_from_file_location(
        f"playbooks.{playbook_name}.chain", chain_path
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[f"playbooks.{playbook_name}.chain"] = module
    spec.loader.exec_module(module)
    if not hasattr(module, "run"):
        raise AttributeError(f"chain.py in playbook '{playbook_name}' must define a run() function")
    return module


# ---------------------------------------------------------------------------
# Scope enforcement
# ---------------------------------------------------------------------------

def _scope_allows_playbook(program: dict, pb_manifest: dict) -> bool:
    """
    Return True if the program's allowed_test_types cover at least one of the
    test types this playbook would exercise.
    We infer test types from the playbook name for now; can be made explicit later.
    """
    allowed = set(program.get("allowed_test_types", []))
    pb_name = pb_manifest["name"]

    _PLAYBOOK_TEST_TYPE_MAP = {
        "recon":        {"recon"},
        "exposure":     {"secrets_scan", "web_scan"},
        "injection":    {"sqli", "xss", "ssti", "command_injection"},
        "auth":         {"auth_bypass", "idor"},
        "infra":        {"port_scan", "web_scan"},
        "cloud":        {"cloud_enum"},
        "takeover":     {"subdomain_takeover"},
        "supply_chain": {"supply_chain"},
    }

    required = _PLAYBOOK_TEST_TYPE_MAP.get(pb_name, set())
    if not required:
        # Unknown playbook — allow by default, warn
        log.warning("No test type mapping for playbook '%s' — allowing by default", pb_name)
        return True

    return bool(required & allowed)


# ---------------------------------------------------------------------------
# Findings aggregation
# ---------------------------------------------------------------------------

def aggregate_findings(
    run_id: str,
    program_id: str,
    raw_output_paths: list[Path],
    ordered_playbooks: list[str],
    depth: str,
) -> dict:
    """
    Read all raw_output/*.json files and merge them into a findings.json document.
    Deduplication: exact (url, type, evidence) triples are merged.
    Confidence scoring is rules-based — no LLM.
    """
    from core.confidence import score_finding  # local import to avoid circular

    all_findings: list[dict] = []
    seen: dict[tuple, str] = {}  # (url, type, evidence_hash) → finding_id

    for raw_path in raw_output_paths:
        try:
            with open(raw_path) as f:
                raw_doc = json.load(f)
        except Exception as exc:
            log.warning("Could not read %s: %s", raw_path, exc)
            continue

        tool_name = raw_doc.get("tool_name", "unknown")
        raw_output_ref = str(raw_path.relative_to(raw_path.parent.parent.parent))

        for item in raw_doc.get("findings", []):
            url = item.get("url") or item.get("host") or ""
            finding_type = item.get("type", "unknown")
            evidence = item.get("evidence", "")
            dedup_key = (url, finding_type, evidence[:120])

            if dedup_key in seen:
                # Merge: append to deduplicated_from list
                existing_id = seen[dedup_key]
                for f in all_findings:
                    if f["finding_id"] == existing_id:
                        f.setdefault("deduplicated_from", [])
                        # nothing to add since we track by key
                        break
                continue

            finding_id = str(uuid.uuid4())
            seen[dedup_key] = finding_id

            confidence = score_finding(finding_type, item, raw_doc)

            finding: dict[str, Any] = {
                "finding_id": finding_id,
                "type": finding_type,
                "severity_raw": _infer_severity(finding_type, item),
                "url": url,
                "evidence": evidence,
                "tool": tool_name,
                "confidence": confidence,
                "raw_output_ref": raw_output_ref,
            }
            if item.get("host"):
                finding["host"] = item["host"]
            if item.get("ip"):
                finding["ip"] = item["ip"]
            if item.get("port"):
                finding["port"] = item["port"]

            all_findings.append(finding)

    # Build summary
    summary_by_sev: dict[str, int] = {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0
    }
    summary_by_type: dict[str, int] = {}
    summary_by_tool: dict[str, int] = {}
    for f in all_findings:
        sev = f.get("severity_raw", "unknown")
        summary_by_sev[sev] = summary_by_sev.get(sev, 0) + 1
        ftype = f.get("type", "unknown")
        summary_by_type[ftype] = summary_by_type.get(ftype, 0) + 1
        tool = f.get("tool", "unknown")
        summary_by_tool[tool] = summary_by_tool.get(tool, 0) + 1

    # Use first playbook name for reference (recon is always first)
    pb_name = ordered_playbooks[0] if ordered_playbooks else "unknown"

    return {
        "schema_version": "1.0",
        "created_at": _now(),
        "run_id": run_id,
        "program_id": program_id,
        "playbook_name": pb_name,
        "playbook_version": "1.0.0",
        "depth": depth,
        "findings": all_findings,
        "summary": {
            "total": len(all_findings),
            "total_findings": len(all_findings),
            "by_severity": summary_by_sev,
            "by_type": summary_by_type,
            "by_tool": summary_by_tool,
        },
    }


def _infer_severity(finding_type: str, item: dict) -> str:
    """Rules-based severity inference from tool output. No LLM."""
    # If the tool already gave us a severity, use it
    raw_sev = (
        item.get("severity") or
        item.get("metadata", {}).get("severity") or
        ""
    ).lower()
    valid = {"critical", "high", "medium", "low", "info"}
    if raw_sev in valid:
        return raw_sev

    # Fall back to type-based defaults
    _TYPE_SEVERITY = {
        "sqli":                 "high",
        "rce":                  "critical",
        "ssrf":                 "high",
        "xxe":                  "high",
        "ssti":                 "high",
        "command_injection":    "critical",
        "xss":                  "medium",
        "open_redirect":        "low",
        "subdomain_takeover":   "high",
        "secret_exposure":      "high",
        "exposed_s3":           "high",
        "path_traversal":       "high",
        "csrf":                 "medium",
        "idor":                 "high",
        "misconfiguration":     "medium",
        "open_port":            "info",
        "subdomain":            "info",
        "tech_detection":       "info",
        "historical_url":       "info",
    }
    return _TYPE_SEVERITY.get(finding_type, "unknown")


# ---------------------------------------------------------------------------
# Run manifest construction
# ---------------------------------------------------------------------------

def _build_run_manifest(
    run_id: str,
    program_id: str,
    invoked_by: str,
    depth: str,
    started_at: str,
    finished_at: str,
    playbooks_run: list[dict],
    tools_invoked: list[dict],
    run_dir: Path,
    errors: list[dict],
) -> dict:
    from datetime import datetime
    t0 = datetime.fromisoformat(started_at)
    t1 = datetime.fromisoformat(finished_at)
    duration = (t1 - t0).total_seconds()

    failed = any(p["status"] == "failed" for p in playbooks_run)
    partial = any(p["status"] in ("failed", "skipped") for p in playbooks_run)
    status = "failed" if failed else ("partial" if partial else "complete")

    return {
        "schema_version": "1.0",
        "created_at": _now(),
        "run_id": run_id,
        "program_id": program_id,
        "invoked_by": invoked_by,
        "depth": depth,
        "started_at": started_at,
        "finished_at": finished_at,
        "duration_seconds": round(duration, 2),
        "playbooks_run": playbooks_run,
        "tools_invoked": tools_invoked,
        "output_files": {
            "findings": str(run_dir / "findings.json"),
            "triage":   str(run_dir / "triage.json"),
            "actions":  str(run_dir / "actions.json"),
        },
        "llm_calls": {
            "count": 0,
            "model": "",
            "total_prompt_tokens": 0,
            "total_completion_tokens": 0,
        },
        "errors": errors,
        "status": status,
    }


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
