#!/usr/bin/env python3
"""
BugBounty Beast — CLI entrypoint.

Usage:
  bb.py run          <program_id> [--depth DEPTH] [--playbooks PB,...] [--no-triage] [--no-attack]
  bb.py rescan       <run_id>    [--playbooks auth,exposure] [--depth DEPTH]
  bb.py export       <run_id>     [--confidence-threshold FLOAT] [--offset INT]
  bb.py import-triage <run_id>   <response_file>
  bb.py aggregate    <run_id>    [--program-id ID] [--depth DEPTH]
  bb.py triage       <run_id>
  bb.py exploit-guide <run_id>
  bb.py attack       <run_id>    [--vectors-only] [--chains-only] [--logic-only]
  bb.py exec         <run_id>    [--dry-run] [--auto-approve]
  bb.py burp         <run_id>    [--wait] [--api-url URL] [--api-key KEY]
  bb.py zap          <target>    <program_id> [--depth DEPTH] [--run-id ID]
  bb.py patch        [--force]   [--dry-run]
  bb.py session      show <program_id>
  bb.py session      clear <program_id>
  bb.py list-programs
  bb.py list-runs

Manual triage workflow (no API key needed):
  1. python bb.py run google-vrp --depth standard --no-triage
  2. python bb.py export <run_id>                  → triage_input.json
  3. Paste system_prompt + triage_request into Claude Pro
  4. Save Claude Pro's JSON response as e.g. triage_response.json
  5. python bb.py import-triage <run_id> triage_response.json
  6. python bb.py exec <run_id> --dry-run

Examples:
  python bb.py run google-vrp --depth standard
  python bb.py run google-vrp --depth exhaustive --playbooks recon,exposure,injection --no-triage
  python bb.py export a1b2c3d4
  python bb.py export a1b2c3d4 --offset 150        # second batch of 150
  python bb.py import-triage a1b2c3d4 triage_response.json
  python bb.py triage a1b2c3d4-...                 # uses claude CLI (no API key needed)
  python bb.py exec a1b2c3d4-... --dry-run
  python bb.py patch --force
"""

import argparse
import json
import logging
import os
import sys
from pathlib import Path

# Extend PATH with common tool locations so Go/Ruby/brew tools are found
# even when invoked non-interactively (e.g. python3 bb.py, not via shell).
_EXTRA_PATHS = [
    str(Path.home() / "go" / "bin"),                          # Go tools
    "/opt/homebrew/bin",                                       # Homebrew (Apple Silicon)
    "/usr/local/bin",                                          # Homebrew (Intel)
    "/opt/homebrew/opt/ruby/bin",                              # Homebrew Ruby
    "/opt/homebrew/lib/ruby/gems/4.0.0/bin",                  # Ruby gems (wpscan)
]
_current_path = os.environ.get("PATH", "")
_additions = ":".join(p for p in _EXTRA_PATHS if p not in _current_path)
if _additions:
    os.environ["PATH"] = _additions + ":" + _current_path

# Set up logging before any imports that use it
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("bb")


def _attach_run_log(run_dir: Path) -> None:
    """Add a file handler that writes all log output to run_dir/run.log."""
    fh = logging.FileHandler(run_dir / "run.log", mode="a", encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    ))
    logging.getLogger().addHandler(fh)

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))


def cmd_run(args):
    from core.engine import run as engine_run
    from core.llm import triage, generate_actions, generate_exploit_guide

    program_path = ROOT / "programs" / f"{args.program_id}.json"
    if not program_path.exists():
        log.error("Program not found: %s", program_path)
        log.error("Create it first: programs/%s.json", args.program_id)

        sys.exit(1)

    playbooks = args.playbooks.split(",") if args.playbooks else None

    log.info("Starting run: program=%s depth=%s", args.program_id, args.depth)
    run_dir = engine_run(
        program_id=args.program_id,
        depth=args.depth,
        playbooks=playbooks,
        operator=args.operator,
    )
    _attach_run_log(run_dir)

    log.info("Pipeline complete. Run directory: %s", run_dir)

    # Opus attack intelligence — runs after recon regardless of triage flag
    if not getattr(args, "no_attack", False):
        from core.attack_engine import generate_attack_plan
        program_path2 = ROOT / "programs" / f"{args.program_id}.json"
        with open(program_path2) as f:
            program_for_attack = json.load(f)
        recon_summary = run_dir / "recon_summary.json"
        if recon_summary.exists():
            log.info("Running Opus attack intelligence...")
            try:
                plan_path = generate_attack_plan(run_dir, program_for_attack)
                log.info("Attack plan: %s", plan_path)
            except Exception as exc:
                log.warning("Attack intelligence failed (non-fatal): %s", exc)
        else:
            log.warning("recon_summary.json not found — skipping attack intelligence")

    # Auto-triage unless skipped
    if not args.no_triage:
        findings_path = run_dir / "findings.json"
        if findings_path.exists():
            with open(findings_path) as f:
                fd = json.load(f)
            total = fd.get("summary", {}).get("total", 0)
            if total > 0:
                log.info("Starting LLM triage on %d findings...", total)
                threshold = args.confidence_threshold
                triage_path = triage(findings_path, run_dir, confidence_threshold=threshold)
                actions_path = generate_actions(triage_path, run_dir)
                log.info("Triage complete. Actions: %s", actions_path)
                guide_path = generate_exploit_guide(triage_path, findings_path, run_dir)
                log.info("Exploit guide: %s", guide_path)
                # Chain analysis — runs after triage has confirmed findings
                if not getattr(args, "no_attack", False):
                    try:
                        from core.attack_engine import generate_chain_analysis
                        chains_path = generate_chain_analysis(run_dir)
                        log.info("Chain analysis: %s", chains_path)
                    except Exception as exc:
                        log.warning("Chain analysis failed (non-fatal): %s", exc)
            else:
                log.info("No findings to triage.")
        else:
            log.warning("findings.json not found — skipping triage")
    else:
        print(f"\nSkipped auto-triage. To triage manually with Claude Pro:")
        print(f"  python bb.py export {run_dir.name}")

    print(f"\nOutput: {run_dir}")


def cmd_export(args):
    from core.export import export_for_triage, export_batch

    run_dir = _find_run_dir(args.run_id)

    if args.offset > 0:
        out_path = export_batch(
            run_dir=run_dir,
            confidence_threshold=args.confidence_threshold,
            offset=args.offset,
        )
    else:
        out_path = export_for_triage(
            run_dir=run_dir,
            confidence_threshold=args.confidence_threshold,
        )

    print(f"\nExport written: {out_path}")
    print(f"\nNext steps:")
    print(f"  1. Open triage_input.json")
    print(f"  2. Copy 'system_prompt' → paste as System Prompt in Claude Pro")
    print(f"  3. Copy 'triage_request' object → paste as User Message in Claude Pro")
    print(f"  4. Save Claude Pro's JSON response to a file, e.g. triage_response.json")
    print(f"  5. python bb.py import-triage {run_dir.name} triage_response.json")


def cmd_import_triage(args):
    from core.triage_import import import_triage

    run_dir = _find_run_dir(args.run_id)
    response_file = Path(args.response_file)

    if not response_file.exists():
        log.error("Response file not found: %s", response_file)
        sys.exit(1)

    log.info("Importing triage response from %s", response_file)
    try:
        triage_path, actions_path = import_triage(run_dir, response_file)
    except ValueError as exc:
        log.error("Import failed: %s", exc)
        sys.exit(1)

    print(f"\nTriage:  {triage_path}")
    print(f"Actions: {actions_path}")
    print(f"\nNext step: python bb.py exec {run_dir.name} --dry-run")


def cmd_triage(args):
    from core.llm import triage, generate_actions, generate_exploit_guide

    run_dir = _find_run_dir(args.run_id)
    findings_path = run_dir / "findings.json"

    if not findings_path.exists():
        log.error("findings.json not found in %s", run_dir)
        sys.exit(1)

    log.info("Running triage on %s", run_dir.name)
    triage_path = triage(
        findings_path,
        run_dir,
        confidence_threshold=args.confidence_threshold,
    )
    actions_path = generate_actions(triage_path, run_dir)
    guide_path = generate_exploit_guide(triage_path, findings_path, run_dir)
    print(f"Triage:  {triage_path}")
    print(f"Actions: {actions_path}")
    print(f"Guide:   {guide_path}")


def cmd_exploit_guide(args):
    from core.llm import generate_exploit_guide

    run_dir = _find_run_dir(args.run_id)
    triage_path = run_dir / "triage.json"
    findings_path = run_dir / "findings.json"

    if not triage_path.exists():
        log.error("triage.json not found in %s. Run triage first.", run_dir)
        sys.exit(1)

    guide_path = generate_exploit_guide(triage_path, findings_path, run_dir)
    print(f"Guide: {guide_path}")


def cmd_rescan(args):
    from core.engine import load_chain, aggregate_findings
    from core.validator import validate_file, validate_and_write, SchemaValidationError

    run_dir = _find_run_dir(args.run_id)
    raw_output_dir = run_dir / "raw_output"

    if not raw_output_dir.exists():
        log.error("No raw_output/ directory in %s — run 'bb.py run' first", run_dir)
        sys.exit(1)

    # Extract run_id from first readable raw_output file
    run_id_str = args.run_id
    for rp in sorted(raw_output_dir.glob("*.json")):
        try:
            with open(rp) as f:
                run_id_str = json.load(f).get("run_id", run_id_str)
            break
        except Exception:
            continue

    # Resolve program_id: CLI arg > run_manifest > strip TLD from parent dir
    program_id = args.program_id
    manifest_path = run_dir / "run_manifest.json"
    if not program_id and manifest_path.exists():
        with open(manifest_path) as f:
            program_id = json.load(f).get("program_id", "")
    if not program_id:
        # runs/docusign.com/... → parent = "docusign.com" → strip .com → "docusign"
        domain_dir = run_dir.parent.name  # e.g. "docusign.com"
        program_id = domain_dir.split(".")[0]   # "docusign"

    program_path = ROOT / "programs" / f"{program_id}.json"
    if not program_path.exists():
        log.error("Program file not found: %s — use --program-id to specify", program_path)
        sys.exit(1)
    program = validate_file("program", program_path)
    log.info("Program: %s  Run: %s  Depth: %s", program_id, run_id_str[:8], args.depth)

    playbook_names = [p.strip() for p in args.playbooks.split(",")]
    all_raw_paths: list = []

    for pb_name in playbook_names:
        log.info("=" * 50)
        log.info("Re-running playbook: %s [%s]", pb_name, args.depth)
        try:
            chain_module = load_chain(pb_name)
            result = chain_module.run(
                program=program,
                depth=args.depth,
                run_id=run_id_str,
                run_dir=run_dir,
                raw_output_dir=raw_output_dir,
            )
            paths = result.get("raw_output_paths", [])
            all_raw_paths.extend(paths)
            log.info("Playbook %s done: %d raw output files updated", pb_name, len(paths))
        except Exception as exc:
            log.error("Playbook %s failed: %s", pb_name, exc, exc_info=True)

    # Auto-aggregate into findings.json
    if all_raw_paths:
        log.info("Auto-aggregating %d raw output files...", len(all_raw_paths))
        # Re-aggregate ALL raw_output/*.json (not just the ones we just ran)
        all_raw = sorted(p for p in raw_output_dir.iterdir()
                         if p.is_file() and p.suffix == ".json")
        findings_doc = aggregate_findings(
            run_id=run_id_str,
            program_id=program_id,
            raw_output_paths=all_raw,
            ordered_playbooks=["recon"] + playbook_names,
            depth=args.depth,
        )
        findings_path = run_dir / "findings.json"
        try:
            validate_and_write("findings", findings_doc, findings_path)
        except SchemaValidationError as exc:
            log.warning("findings.json validation issue (writing anyway): %s", exc)
            with open(findings_path, "w") as f:
                json.dump(findings_doc, f, indent=2)
        total = findings_doc["summary"]["total"]
        log.info("findings.json updated: %d total findings", total)

        # Write minimal run_manifest.json if missing (needed for cmd_exec)
        if not manifest_path.exists():
            from datetime import datetime, timezone
            now = datetime.now(timezone.utc).isoformat()
            minimal = {
                "schema_version": "1.0",
                "created_at": now,
                "run_id": run_id_str,
                "program_id": program_id,
                "invoked_by": "rescan-recovery",
                "depth": args.depth,
                "started_at": now,
                "finished_at": now,
                "duration_seconds": 0,
                "playbooks_run": [{"name": p, "status": "completed"} for p in playbook_names],
                "tools_invoked": [],
                "output_files": {
                    "findings": str(findings_path),
                    "triage": str(run_dir / "triage.json"),
                    "actions": str(run_dir / "actions.json"),
                },
                "llm_calls_made": 0,
                "errors": [],
                "status": "partial",
            }
            with open(manifest_path, "w") as f:
                json.dump(minimal, f, indent=2)
            log.info("run_manifest.json (minimal) written")

        print(f"\nFindings: {findings_path}  ({total} total)")
    else:
        print("\nNo tools produced output — check logs for errors")

    print(f"\nNext: python bb.py triage {run_dir.parent.name}/{run_dir.name}")


def cmd_aggregate(args):
    from core.engine import aggregate_findings
    from core.validator import validate_and_write, SchemaValidationError

    run_dir = _find_run_dir(args.run_id)
    raw_output_dir = run_dir / "raw_output"

    if not raw_output_dir.exists():
        log.error("No raw_output/ directory in %s", run_dir)
        sys.exit(1)

    # Only direct JSON files — exclude subdirs like sqlmap_sessions/
    raw_paths = sorted(p for p in raw_output_dir.iterdir()
                       if p.is_file() and p.suffix == ".json")
    if not raw_paths:
        log.error("No raw_output/*.json files found in %s", run_dir)
        sys.exit(1)

    log.info("Found %d raw output files", len(raw_paths))

    # Extract run_id from first readable raw_output file
    run_id_str = args.run_id  # fallback
    for rp in raw_paths:
        try:
            with open(rp) as f:
                run_id_str = json.load(f).get("run_id", run_id_str)
            break
        except Exception:
            continue

    # Resolve program_id: CLI arg > run_manifest > parent dir name
    program_id = args.program_id
    manifest_path = run_dir / "run_manifest.json"
    if not program_id and manifest_path.exists():
        with open(manifest_path) as f:
            program_id = json.load(f).get("program_id", "")
    if not program_id:
        # run dir is runs/{domain}/{timestamp}_{runid[:8]} — parent is domain
        program_id = run_dir.parent.name

    log.info("Aggregating: program=%s  run=%s  depth=%s",
             program_id, run_id_str[:8], args.depth)

    findings_doc = aggregate_findings(
        run_id=run_id_str,
        program_id=program_id,
        raw_output_paths=raw_paths,
        ordered_playbooks=["recon"],
        depth=args.depth,
    )

    findings_path = run_dir / "findings.json"
    try:
        validate_and_write("findings", findings_doc, findings_path)
    except SchemaValidationError as exc:
        log.warning("findings.json validation issue (writing anyway): %s", exc)
        with open(findings_path, "w") as f:
            json.dump(findings_doc, f, indent=2)

    total = findings_doc["summary"]["total"]
    log.info("findings.json written: %d findings", total)

    # Write a minimal run_manifest.json if one doesn't exist
    # (cmd_exec needs it to load the program for scope checks)
    if not manifest_path.exists():
        minimal_manifest = {
            "schema_version": "1.0",
            "created_at": findings_doc["created_at"],
            "run_id": run_id_str,
            "program_id": program_id,
            "invoked_by": "aggregate-recovery",
            "depth": args.depth,
            "started_at": findings_doc["created_at"],
            "finished_at": findings_doc["created_at"],
            "duration_seconds": 0,
            "playbooks_run": [],
            "tools_invoked": [],
            "output_files": {
                "findings": str(findings_path),
                "triage": str(run_dir / "triage.json"),
                "actions": str(run_dir / "actions.json"),
            },
            "llm_calls_made": 0,
            "errors": [],
            "status": "partial",
        }
        with open(manifest_path, "w") as f:
            json.dump(minimal_manifest, f, indent=2)
        log.info("run_manifest.json (minimal) written")

    print(f"\nFindings: {findings_path}  ({total} total)")
    print(f"\nNext steps:")
    print(f"  python bb.py triage {run_dir.parent.name}/{run_dir.name}")
    print(f"  python bb.py exec   {run_dir.parent.name}/{run_dir.name} --dry-run")


def cmd_exec(args):
    from execution.executor import execute
    from core.validator import validate_file

    run_dir = _find_run_dir(args.run_id)
    actions_path = run_dir / "actions.json"

    if not actions_path.exists():
        log.error("actions.json not found in %s. Run triage first.", run_dir)
        sys.exit(1)

    # Load program for scope enforcement
    manifest_path = run_dir / "run_manifest.json"
    program_id = "unknown"
    if manifest_path.exists():
        with open(manifest_path) as f:
            program_id = json.load(f).get("program_id", "unknown")

    program_path = ROOT / "programs" / f"{program_id}.json"
    if not program_path.exists():
        log.error("Program file not found: %s", program_path)
        sys.exit(1)

    program = validate_file("program", program_path)

    stats = execute(
        actions_path=actions_path,
        run_dir=run_dir,
        program=program,
        auto_approve_low_risk=args.auto_approve,
        dry_run=args.dry_run,
    )
    print(f"\nExecution stats: {stats}")


def cmd_burp(args):
    from burp.integration import BurpIntegration
    from burp.zap_integration import ZapIntegration
    from core.validator import validate_file

    run_dir = _find_run_dir(args.run_id)
    actions_path = run_dir / "actions.json"

    if not actions_path.exists():
        log.error("actions.json not found in %s. Run triage first.", run_dir)
        sys.exit(1)

    manifest_path = run_dir / "run_manifest.json"
    program_id = "unknown"
    if manifest_path.exists():
        with open(manifest_path) as f:
            program_id = json.load(f).get("program_id", "unknown")

    program_path = ROOT / "programs" / f"{program_id}.json"
    if not program_path.exists():
        log.error("Program file not found: %s", program_path)
        sys.exit(1)

    program = validate_file("program", program_path)

    burp = BurpIntegration(
        api_url=args.api_url,
        api_key=args.api_key,
    )

    if burp.health_check():
        log.info("Burp Suite Pro reachable — submitting tasks")
        task_map = burp.submit_tasks(
            actions_path=actions_path,
            run_dir=run_dir,
            program=program,
            wait_for_completion=args.wait,
        )
        backend = "Burp"
    else:
        log.warning(
            "Burp Suite REST API not reachable at %s — falling back to OWASP ZAP",
            args.api_url,
        )
        log.info("  (To use Burp: Burp → Extensions → APIs → Enable REST API port 1337)")
        zap = ZapIntegration()
        if not zap.ensure_running():
            log.error(
                "ZAP also not available. Install OWASP ZAP at %s or start Burp Pro.",
                "/Applications/ZAP.app",
            )
            sys.exit(1)
        task_map = zap.submit_tasks(
            actions_path=actions_path,
            run_dir=run_dir,
            program=program,
            wait_for_completion=args.wait,
        )
        backend = "ZAP"

    if task_map:
        print(f"\nSubmitted {len(task_map)} {backend} scan(s):")
        for task_id, scan_id in task_map.items():
            print(f"  task {task_id[:8]} → {backend} scan {scan_id}")
        if not args.wait:
            print(f"\nRe-run with --wait to block until scans complete and pull results.")
    else:
        print(f"\nNo pending scan tasks found in actions.json.")
        print("Make sure triage found burp_worthy=true findings.")


def cmd_attack(args):
    """Run Opus attack intelligence on an existing run."""
    from core.attack_engine import (
        generate_attack_vectors,
        generate_chain_analysis,
        generate_business_logic_probes,
        generate_attack_plan,
    )
    from core.validator import validate_file

    run_dir = _find_run_dir(args.run_id)
    recon_summary = run_dir / "recon_summary.json"
    if not recon_summary.exists():
        log.error("recon_summary.json not found in %s — run recon first", run_dir)
        sys.exit(1)

    manifest_path = run_dir / "run_manifest.json"
    program_id = "unknown"
    if manifest_path.exists():
        with open(manifest_path) as f:
            program_id = json.load(f).get("program_id", "unknown")

    program_path = ROOT / "programs" / f"{program_id}.json"
    if not program_path.exists():
        log.error("Program file not found: %s", program_path)
        sys.exit(1)
    program = validate_file("program", program_path)

    vectors_only = getattr(args, "vectors_only", False)
    chains_only = getattr(args, "chains_only", False)
    logic_only = getattr(args, "logic_only", False)
    run_all = not (vectors_only or chains_only or logic_only)

    if run_all:
        plan_path = generate_attack_plan(run_dir, program)
        print(f"\nAttack plan: {plan_path}")
        print(f"Vectors:     {run_dir}/attack_vectors.json")
        print(f"Chains:      {run_dir}/chains.json")
        print(f"Logic:       {run_dir}/business_logic_probes.json")
    else:
        if vectors_only:
            out = generate_attack_vectors(run_dir, program)
            print(f"\nAttack vectors: {out}")
        if chains_only:
            triage_path = run_dir / "triage.json"
            if not triage_path.exists():
                log.error("triage.json not found — run triage first for chain analysis")
                sys.exit(1)
            out = generate_chain_analysis(run_dir)
            print(f"\nChains: {out}")
        if logic_only:
            out = generate_business_logic_probes(run_dir, program)
            print(f"\nBusiness logic probes: {out}")


def cmd_agent(args):
    """Run the Opus agentic recon + attack loop against an existing run."""
    from core.agent import run_agent
    from core.validator import validate_file

    run_dir = _find_run_dir(args.run_id)

    manifest_path = run_dir / "run_manifest.json"
    program_id = "unknown"
    if manifest_path.exists():
        with open(manifest_path) as f:
            program_id = json.load(f).get("program_id", "unknown")

    program_path = ROOT / "programs" / f"{program_id}.json"
    if not program_path.exists():
        log.error("Program file not found: %s", program_path)
        sys.exit(1)
    program = validate_file("program", program_path)

    depth = getattr(args, "depth", "standard")
    report_path = run_agent(run_dir, program, depth=depth)
    print(f"\nAgent report: {report_path}")


def cmd_zap(args):
    """Direct ZAP scan of a single URL — bypasses the full pipeline."""
    from tools.zap import ZapWrapper
    from core.validator import validate_file
    import uuid as _uuid

    program_path = ROOT / "programs" / f"{args.program_id}.json"
    if not program_path.exists():
        log.error("Program not found: %s", program_path)
        sys.exit(1)
    program = validate_file("program", program_path)

    run_id = args.run_id or str(_uuid.uuid4())
    run_dir = ROOT / "runs" / args.program_id / run_id[:8]
    run_dir.mkdir(parents=True, exist_ok=True)
    raw_output_dir = run_dir / "raw_output"
    raw_output_dir.mkdir(exist_ok=True)

    zap = ZapWrapper()
    if not zap.available():
        log.error(
            "ZAP daemon not reachable and not installed at %s",
            "/Applications/ZAP.app",
        )
        sys.exit(1)

    log.info("ZAP scan: target=%s depth=%s", args.target, args.depth)
    result = zap.run(
        target=args.target,
        depth=args.depth,
        run_id=run_id,
        raw_output_dir=raw_output_dir,
        program=program,
    )

    count = result.get("findings_count", 0)
    out = result.get("raw_output_path", "?")
    print(f"\nZAP scan complete: {count} finding(s)")
    print(f"Raw output: {out}")
    print(f"\nTo aggregate and triage:")
    print(f"  python bb.py aggregate {run_dir.parent.name}/{run_dir.name} --program-id {args.program_id}")
    print(f"  python bb.py triage    {run_dir.parent.name}/{run_dir.name}")


def cmd_session(args):
    sessions_dir = ROOT / "sessions"
    session_path = sessions_dir / f"{args.program_id}.json"

    if args.action == "show":
        if not session_path.exists():
            print(f"No session file found for '{args.program_id}'.")
            print(f"Expected: {session_path}")
            return
        with open(session_path) as f:
            session = json.load(f)
        print(f"Session for: {args.program_id}")
        print(f"  authenticated_as : {session.get('authenticated_as', '?')}")
        print(f"  auth_type        : {session.get('auth_type', '?')}")
        print(f"  privilege_level  : {session.get('privilege_level', '?')}")
        print(f"  expires_approx   : {session.get('expires_approx', '?')}")
        print(f"  notes            : {session.get('notes', '')}")
        headers = session.get("headers", {})
        if headers:
            print(f"  headers:")
            for k, v in headers.items():
                # Mask credential values — show key name + length only
                masked = f"<{len(v)} chars>"
                print(f"    {k}: {masked}")

    elif args.action == "clear":
        if not session_path.exists():
            print(f"No session file for '{args.program_id}' — nothing to clear.")
            return
        session_path.unlink()
        print(f"Session cleared: {session_path}")


def cmd_patch(args):
    from core.patcher import apply_pending_patches

    stats = apply_pending_patches(force=args.force, dry_run=args.dry_run)
    print(f"\nPatch stats: {stats}")


def cmd_list_programs(args):
    programs_dir = ROOT / "programs"
    if not programs_dir.exists() or not list(programs_dir.glob("*.json")):
        print("No programs found. Create one in /programs/<program_id>.json")
        return
    for p in sorted(programs_dir.glob("*.json")):
        with open(p) as f:
            doc = json.load(f)
        print(f"  {p.stem:30s}  {doc.get('name', '?'):40s}  [{doc.get('platform', '?')}]")


def cmd_list_runs(args):
    runs_dir = ROOT / "runs"
    if not runs_dir.exists():
        print("No runs yet.")
        return

    # New structure: runs/{domain}/{timestamp}_{run_id[:8]}/
    all_runs = []
    for domain_dir in sorted(runs_dir.iterdir()):
        if not domain_dir.is_dir():
            continue
        for run_dir in domain_dir.iterdir():
            if run_dir.is_dir():
                all_runs.append(run_dir)

    # Fall back: also pick up old-style UUID dirs at top level
    for d in runs_dir.iterdir():
        if d.is_dir() and not any(d.name == r.parent.name for r in all_runs):
            all_runs.append(d)

    all_runs.sort(key=lambda p: p.stat().st_mtime, reverse=True)

    if not all_runs:
        print("No runs yet.")
        return

    print(f"  {'RUN DIR':35s}  {'PROGRAM':20s}  {'DEPTH':12s}  {'STATUS':10s}  STARTED")
    print("  " + "-" * 100)
    for run_dir in all_runs[:30]:
        manifest_path = run_dir / "run_manifest.json"
        domain = run_dir.parent.name
        if manifest_path.exists():
            with open(manifest_path) as f:
                m = json.load(f)
            label = f"{domain}/{run_dir.name}"
            print(
                f"  {label:35s}  "
                f"{m.get('program_id', '?'):20s}  "
                f"{m.get('depth', '?'):12s}  "
                f"{m.get('status', '?'):10s}  "
                f"{m.get('started_at', '')[:19]}"
            )
        else:
            findings_path = run_dir / "findings.json"
            status = "in-progress" if findings_path.exists() else "incomplete"
            print(f"  {domain}/{run_dir.name:35s}  {'':20s}  {'':12s}  {status}")


def _find_run_dir(run_id: str) -> Path:
    """
    Find a run directory by partial name match.
    Searches both new-style (runs/domain/timestamp_id/) and old-style (runs/uuid/).
    """
    runs_dir = ROOT / "runs"
    matches = []

    for domain_dir in runs_dir.iterdir():
        if not domain_dir.is_dir():
            continue
        # New-style: runs/{domain}/{timestamp}_{run_id[:8]}
        for run_dir in domain_dir.iterdir():
            if run_dir.is_dir() and run_id in run_dir.name:
                matches.append(run_dir)
        # Old-style: runs/{uuid} (domain_dir IS the run_dir)
        if domain_dir.name.startswith(run_id):
            matches.append(domain_dir)

    if not matches:
        log.error("No run found matching: %s", run_id)
        sys.exit(1)
    if len(matches) > 1:
        log.error("Ambiguous run ID '%s' matches: %s", run_id, [str(d) for d in matches])
        sys.exit(1)
    return matches[0]


def main():
    parser = argparse.ArgumentParser(
        description="BugBounty Beast — automated bug bounty scanning pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # --- run ---
    p_run = sub.add_parser("run", help="Run the full pipeline against a program")
    p_run.add_argument("program_id", help="Program ID (matches programs/<id>.json)")
    p_run.add_argument("--depth", choices=["quick", "standard", "exhaustive"],
                       default="standard", help="Scan depth (default: standard)")
    p_run.add_argument("--playbooks", default=None,
                       help="Comma-separated playbook names to run (default: all)")
    p_run.add_argument("--operator", default="operator",
                       help="Your name/identifier for the audit trail")
    p_run.add_argument("--no-triage", action="store_true",
                       help="Skip LLM triage after scanning")
    p_run.add_argument("--no-attack", action="store_true",
                       help="Skip Opus attack intelligence (vectors, chains, business logic)")
    p_run.add_argument("--confidence-threshold", type=float, default=0.3,
                       help="Minimum confidence for LLM triage (default: 0.5)")
    p_run.set_defaults(func=cmd_run)

    # --- export ---
    p_export = sub.add_parser(
        "export",
        help="Export findings for manual triage in Claude Pro (no API key needed)",
    )
    p_export.add_argument("run_id", help="Run ID or prefix")
    p_export.add_argument(
        "--confidence-threshold", type=float, default=0.3,
        help="Minimum confidence score to include (default: 0.5)",
    )
    p_export.add_argument(
        "--offset", type=int, default=0,
        help="Skip first N eligible findings (for batch export, default: 0)",
    )
    p_export.set_defaults(func=cmd_export)

    # --- import-triage ---
    p_import = sub.add_parser(
        "import-triage",
        help="Import Claude Pro's triage response into the pipeline",
    )
    p_import.add_argument("run_id", help="Run ID or prefix")
    p_import.add_argument("response_file", help="Path to Claude Pro's JSON response file")
    p_import.set_defaults(func=cmd_import_triage)

    # --- rescan ---
    p_rescan = sub.add_parser(
        "rescan",
        help="Re-run specific playbooks against existing recon data (no re-scanning from scratch)",
    )
    p_rescan.add_argument("run_id", help="Run ID or prefix")
    p_rescan.add_argument(
        "--playbooks", default="auth,exposure",
        help="Comma-separated playbooks to re-run (default: auth,exposure)",
    )
    p_rescan.add_argument(
        "--depth", choices=["quick", "standard", "exhaustive"], default="standard",
    )
    p_rescan.add_argument(
        "--program-id", default=None,
        help="Program ID (auto-detected from run dir if omitted)",
    )
    p_rescan.set_defaults(func=cmd_rescan)

    # --- aggregate ---
    p_aggregate = sub.add_parser(
        "aggregate",
        help="Reconstruct findings.json from raw_output for an interrupted run",
    )
    p_aggregate.add_argument("run_id", help="Run ID or prefix")
    p_aggregate.add_argument(
        "--program-id", default=None,
        help="Program ID (auto-detected from run directory if omitted)",
    )
    p_aggregate.add_argument(
        "--depth", choices=["quick", "standard", "exhaustive"], default="standard",
        help="Scan depth label to embed in findings.json (default: standard)",
    )
    p_aggregate.set_defaults(func=cmd_aggregate)

    # --- triage ---
    p_triage = sub.add_parser("triage", help="Run LLM triage on an existing run's findings (uses claude CLI, no API key needed)")
    p_triage.add_argument("run_id", help="Run ID or prefix")
    p_triage.add_argument("--confidence-threshold", type=float, default=0.3)
    p_triage.set_defaults(func=cmd_triage)

    # --- exploit-guide ---
    p_exploit_guide = sub.add_parser(
        "exploit-guide",
        help="(Re)generate exploit_guide.md for an existing run",
    )
    p_exploit_guide.add_argument("run_id", help="Run ID or prefix")
    p_exploit_guide.set_defaults(func=cmd_exploit_guide)

    # --- exec ---
    p_exec = sub.add_parser("exec", help="Execute actions from an existing run")
    p_exec.add_argument("run_id", help="Run ID or prefix")
    p_exec.add_argument("--dry-run", action="store_true",
                        help="Print what would run without executing")
    p_exec.add_argument("--auto-approve", action="store_true",
                        help="Auto-approve low/medium risk actions")
    p_exec.set_defaults(func=cmd_exec)

    # --- burp ---
    p_burp = sub.add_parser("burp", help="Submit burp_worthy findings to Burp Suite Pro REST API")
    p_burp.add_argument("run_id", help="Run ID or prefix")
    p_burp.add_argument("--wait", action="store_true",
                        help="Block until Burp scans complete and pull results")
    p_burp.add_argument("--api-url", default="http://localhost:1337/v0.1",
                        help="Burp REST API base URL (default: http://localhost:1337/v0.1)")
    p_burp.add_argument("--api-key", default=None,
                        help="Burp REST API key (if configured)")
    p_burp.set_defaults(func=cmd_burp)

    # --- attack ---
    p_attack = sub.add_parser(
        "attack",
        help="Run Opus attack intelligence: targeted vectors, exploit chains, business logic probes",
    )
    p_attack.add_argument("run_id", help="Run ID or prefix (recon must have completed)")
    p_attack.add_argument("--vectors-only", action="store_true",
                          help="Only generate attack vectors from recon data")
    p_attack.add_argument("--chains-only", action="store_true",
                          help="Only run chain analysis (requires triage.json)")
    p_attack.add_argument("--logic-only", action="store_true",
                          help="Only generate business logic probes")
    p_attack.set_defaults(func=cmd_attack)

    # --- agent ---
    p_agent = sub.add_parser("agent", help="Opus agentic recon: Opus calls tools and decides what to probe")
    p_agent.add_argument("run_id", help="Run ID or prefix (recon must have completed)")
    p_agent.add_argument("--depth", choices=["quick", "standard", "exhaustive"], default="standard")
    p_agent.set_defaults(func=cmd_agent)

    # --- zap ---
    p_zap = sub.add_parser("zap", help="Direct ZAP active scan of a single URL (no full pipeline needed)")
    p_zap.add_argument("target", help="Target URL to scan (e.g. https://example.com)")
    p_zap.add_argument("program_id", help="Program ID for scope enforcement (matches programs/<id>.json)")
    p_zap.add_argument("--depth", choices=["quick", "standard", "exhaustive"],
                       default="standard", help="Scan depth (default: standard)")
    p_zap.add_argument("--run-id", default=None,
                       help="Reuse an existing run ID to write results into that run dir")
    p_zap.set_defaults(func=cmd_zap)

    # --- patch ---
    p_patch = sub.add_parser("patch", help="Apply pending playbook patches from /patches/")
    p_patch.add_argument("--force", action="store_true",
                         help="Apply even if requires_human_review=true")
    p_patch.add_argument("--dry-run", action="store_true",
                         help="Show what would be applied without modifying files")
    p_patch.set_defaults(func=cmd_patch)

    # --- session ---
    p_session = sub.add_parser("session", help="Manage authenticated session files")
    p_session.add_argument("action", choices=["show", "clear"],
                           help="show: display session info (masked); clear: delete session file")
    p_session.add_argument("program_id", help="Program ID (matches sessions/<id>.json)")
    p_session.set_defaults(func=cmd_session)

    # --- list-programs ---
    p_lp = sub.add_parser("list-programs", help="List all configured programs")
    p_lp.set_defaults(func=cmd_list_programs)

    # --- list-runs ---
    p_lr = sub.add_parser("list-runs", help="List recent runs")
    p_lr.set_defaults(func=cmd_list_runs)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
