"""
Triage import module. Ingests Claude Pro's JSON response and writes triage.json
and actions.json into the run directory.

Workflow:
  1. python bb.py run <program_id> --no-triage
  2. python bb.py export <run_id>           → writes triage_input.json
  3. Open Claude Pro, paste system_prompt as System, paste file content as User message
  4. Copy Claude Pro's JSON response → save as e.g. triage_response.json
  5. python bb.py import-triage <run_id> triage_response.json
     → writes triage.json + actions.json, ready for bb.py exec
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from core.validator import validate_and_write, SchemaValidationError

log = logging.getLogger(__name__)

# Valid verdict values — reject anything outside these
_VALID_VERDICTS = {"exploitable", "not_exploitable", "needs_more_info", "false_positive"}
_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}


def import_triage(run_dir: Path, response_file: Path) -> tuple[Path, Path]:
    """
    Import Claude Pro's triage response and write triage.json + actions.json.

    Args:
        run_dir:       Run output directory (contains findings.json).
        response_file: Path to the file containing Claude Pro's raw JSON response.

    Returns:
        Tuple of (triage_path, actions_path).

    Raises:
        FileNotFoundError: If findings.json or response_file don't exist.
        ValueError: If the response is not valid JSON or missing required fields.
    """
    if not response_file.exists():
        raise FileNotFoundError(f"Response file not found: {response_file}")

    findings_path = run_dir / "findings.json"
    if not findings_path.exists():
        raise FileNotFoundError(f"findings.json not found in {run_dir}")

    # Load run context from findings.json
    with open(findings_path) as f:
        findings_doc = json.load(f)

    run_id = findings_doc.get("run_id", str(uuid.uuid4()))
    all_findings = findings_doc.get("findings", [])
    eligible_count = sum(1 for f in all_findings if f.get("confidence", 0) >= 0.5)

    # Load Claude Pro's response
    raw_text = response_file.read_text().strip()
    llm_output = _parse_response(raw_text)

    # Validate structure
    verdicts = llm_output.get("verdicts")
    run_summary = llm_output.get("run_summary")

    if not isinstance(verdicts, list):
        raise ValueError(
            f"Response missing 'verdicts' array. Got keys: {list(llm_output.keys())}"
        )
    if not isinstance(run_summary, dict):
        raise ValueError(
            f"Response missing 'run_summary' object. Got keys: {list(llm_output.keys())}"
        )

    # Normalize and validate each verdict
    clean_verdicts = []
    skipped = 0
    for v in verdicts:
        if not isinstance(v, dict):
            skipped += 1
            continue

        finding_id = v.get("finding_id", "")
        verdict = v.get("verdict", "")
        adjusted_severity = v.get("adjusted_severity", "info")

        if not finding_id:
            log.warning("Verdict missing finding_id — skipping")
            skipped += 1
            continue

        if verdict not in _VALID_VERDICTS:
            log.warning(
                "Invalid verdict '%s' for finding %s — defaulting to needs_more_info",
                verdict, finding_id[:8],
            )
            verdict = "needs_more_info"

        if adjusted_severity not in _VALID_SEVERITIES:
            log.warning(
                "Invalid severity '%s' for finding %s — defaulting to info",
                adjusted_severity, finding_id[:8],
            )
            adjusted_severity = "info"

        clean_verdicts.append({
            "finding_id": finding_id,
            "verdict": verdict,
            "reasoning": str(v.get("reasoning", ""))[:500],
            "adjusted_severity": adjusted_severity,
            "impact": str(v.get("impact", ""))[:300],
            "suggested_next_steps": _clean_steps(v.get("suggested_next_steps", [])),
            "burp_worthy": bool(v.get("burp_worthy", False)),
        })

    log.info(
        "Import: %d verdicts accepted, %d skipped",
        len(clean_verdicts), skipped,
    )

    if skipped > 0:
        log.warning("%d verdicts were skipped due to missing/invalid fields", skipped)

    # Build triage.json
    triage_doc = {
        "schema_version": "1.0",
        "created_at": _now(),
        "run_id": run_id,
        "model": "claude-pro-manual",
        "input_findings_count": eligible_count,
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "verdicts": clean_verdicts,
        "run_summary": {
            "overall_assessment": str(
                run_summary.get("overall_assessment", "Manual triage via Claude Pro.")
            )[:1000],
            "top_findings": [
                str(fid) for fid in run_summary.get("top_findings", [])[:10]
            ],
            "recommended_focus": str(
                run_summary.get("recommended_focus", "Review flagged findings.")
            )[:300],
        },
    }

    triage_path = run_dir / "triage.json"
    try:
        validate_and_write("triage", triage_doc, triage_path)
    except SchemaValidationError as exc:
        log.error("triage.json schema validation failed: %s", exc)
        log.warning("Writing triage.json anyway — fix validation errors before exec")
        with open(triage_path, "w") as f:
            json.dump(triage_doc, f, indent=2)

    log.info("triage.json written: %d verdicts", len(clean_verdicts))

    # Generate actions.json from triage.json
    from core.llm import generate_actions
    actions_path = generate_actions(triage_path, run_dir)

    log.info("actions.json written: %s", actions_path)
    return triage_path, actions_path


def _parse_response(raw_text: str) -> dict:
    """
    Parse Claude Pro's response. Handles both raw JSON and markdown-fenced JSON.

    Raises:
        ValueError: If the text cannot be parsed as JSON.
    """
    # First try: direct parse
    try:
        return json.loads(raw_text)
    except json.JSONDecodeError:
        pass

    # Second try: extract from markdown code fence
    fence_match = re.search(
        r"```(?:json)?\s*(\{.*?\})\s*```",
        raw_text,
        re.DOTALL,
    )
    if fence_match:
        try:
            return json.loads(fence_match.group(1))
        except json.JSONDecodeError:
            pass

    # Third try: find the outermost { ... } block
    brace_match = re.search(r"\{.*\}", raw_text, re.DOTALL)
    if brace_match:
        try:
            return json.loads(brace_match.group(0))
        except json.JSONDecodeError:
            pass

    raise ValueError(
        f"Could not parse Claude Pro response as JSON.\n"
        f"First 300 chars: {raw_text[:300]}\n\n"
        f"Make sure Claude Pro responded with raw JSON (no explanation text)."
    )


def _clean_steps(steps) -> list[str]:
    """Normalize suggested_next_steps to a list of strings."""
    if not isinstance(steps, list):
        return []
    return [str(s)[:300] for s in steps if s][:10]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
