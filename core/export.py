"""
Export module. Compiles findings.json into a clean JSON document for
manual triage in Claude Pro (or any LLM chat interface).

The exported file contains:
  - Program context
  - Run metadata
  - Filtered, cleaned findings (above confidence threshold)
  - The exact system prompt to paste into Claude Pro
  - The exact output format Claude Pro must respond with

Workflow:
  1. python bb.py run <program_id> --no-triage
  2. python bb.py export <run_id>           → writes triage_input.json
  3. Open Claude Pro, paste system_prompt as System, paste the file content as User message
  4. Copy Claude Pro's response JSON → save as e.g. triage_response.json
  5. python bb.py import-triage <run_id> triage_response.json
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger(__name__)

DEFAULT_CONFIDENCE_THRESHOLD = 0.5
MAX_FINDINGS = 150  # cap before asking Claude Pro to triage in batches


def export_for_triage(
    run_dir: Path,
    confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD,
    max_findings: int = MAX_FINDINGS,
) -> Path:
    """
    Read findings.json from run_dir and write triage_input.json.

    Args:
        run_dir:              Run output directory.
        confidence_threshold: Exclude findings below this confidence score.
        max_findings:         Cap on findings per export file (highest confidence first).

    Returns:
        Path to triage_input.json
    """
    findings_path = run_dir / "findings.json"
    if not findings_path.exists():
        raise FileNotFoundError(f"findings.json not found in {run_dir}")

    with open(findings_path) as f:
        findings_doc = json.load(f)

    all_findings = findings_doc.get("findings", [])
    run_id = findings_doc.get("run_id", "unknown")
    program_id = findings_doc.get("program_id", "unknown")
    playbook = findings_doc.get("playbook_name", "unknown")
    depth = findings_doc.get("depth", "unknown")
    summary = findings_doc.get("summary", {})

    # Filter by confidence threshold
    eligible = [
        f for f in all_findings
        if f.get("confidence", 0) >= confidence_threshold
    ]

    log.info(
        "Export: %d/%d findings meet confidence threshold %.2f",
        len(eligible), len(all_findings), confidence_threshold,
    )

    # Sort by confidence descending, cap
    eligible_sorted = sorted(eligible, key=lambda f: -f.get("confidence", 0))
    batch = eligible_sorted[:max_findings]
    is_truncated = len(eligible_sorted) > max_findings

    if is_truncated:
        log.warning(
            "Findings truncated from %d to %d (highest confidence). "
            "Run export again with --offset %d for the next batch.",
            len(eligible_sorted), max_findings, max_findings,
        )

    # Build clean finding objects — strip noise, keep what Claude needs
    clean_findings = [_clean_finding(f) for f in batch]

    # Load program for context
    program_context = _load_program_context(run_dir, program_id)

    # Build the export document
    export_doc = {
        "_instructions": (
            "INSTRUCTIONS FOR MANUAL TRIAGE:\n"
            "1. Copy the text from 'system_prompt' below and paste it as the SYSTEM PROMPT "
            "in Claude Pro (Projects → Project Instructions, or the system field).\n"
            "2. Paste the entire contents of the 'triage_request' object as your USER MESSAGE.\n"
            "3. Claude Pro will respond with a JSON object. Copy that entire response.\n"
            "4. Save it as a .json file (e.g. triage_response.json).\n"
            "5. Run: python bb.py import-triage <run_id> triage_response.json"
        ),
        "system_prompt": _SYSTEM_PROMPT,
        "triage_request": {
            "run_id": run_id,
            "program_id": program_id,
            "program_context": program_context,
            "playbook": playbook,
            "depth": depth,
            "scan_summary": {
                "total_findings_in_run": summary.get("total", 0),
                "findings_above_threshold": len(eligible_sorted),
                "findings_in_this_batch": len(batch),
                "is_truncated": is_truncated,
                "by_severity": summary.get("by_severity", {}),
                "by_type": summary.get("by_type", {}),
            },
            "findings": clean_findings,
        },
        "expected_output_format": _OUTPUT_FORMAT_SPEC,
        "meta": {
            "exported_at": _now(),
            "confidence_threshold_used": confidence_threshold,
            "total_eligible": len(eligible_sorted),
            "batch_size": len(batch),
        },
    }

    out_path = run_dir / "triage_input.json"
    with open(out_path, "w") as f:
        json.dump(export_doc, f, indent=2)

    log.info(
        "triage_input.json written: %d findings, %.1f KB",
        len(batch),
        out_path.stat().st_size / 1024,
    )

    if is_truncated:
        log.warning(
            "Only %d/%d eligible findings exported. "
            "Use --offset for subsequent batches.",
            len(batch), len(eligible_sorted),
        )

    return out_path


def export_batch(
    run_dir: Path,
    confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD,
    max_findings: int = MAX_FINDINGS,
    offset: int = 0,
) -> Path:
    """
    Export a specific batch (for runs with >150 findings).
    Writes triage_input_batch_N.json.
    """
    findings_path = run_dir / "findings.json"
    with open(findings_path) as f:
        findings_doc = json.load(f)

    all_findings = findings_doc.get("findings", [])
    run_id = findings_doc.get("run_id", "unknown")
    program_id = findings_doc.get("program_id", "unknown")

    eligible = sorted(
        [f for f in all_findings if f.get("confidence", 0) >= confidence_threshold],
        key=lambda f: -f.get("confidence", 0),
    )

    batch = eligible[offset: offset + max_findings]
    batch_num = (offset // max_findings) + 1
    total_batches = (len(eligible) + max_findings - 1) // max_findings

    clean_findings = [_clean_finding(f) for f in batch]
    program_context = _load_program_context(run_dir, program_id)

    export_doc = {
        "_instructions": (
            f"BATCH {batch_num} of {total_batches}. "
            "Use the same system prompt as batch 1. "
            f"Findings {offset + 1}–{offset + len(batch)} of {len(eligible)} eligible."
        ),
        "system_prompt": _SYSTEM_PROMPT,
        "triage_request": {
            "run_id": run_id,
            "program_id": program_id,
            "program_context": program_context,
            "batch": batch_num,
            "total_batches": total_batches,
            "findings": clean_findings,
        },
        "expected_output_format": _OUTPUT_FORMAT_SPEC,
        "meta": {
            "exported_at": _now(),
            "offset": offset,
            "batch_size": len(batch),
        },
    }

    out_path = run_dir / f"triage_input_batch_{batch_num}.json"
    with open(out_path, "w") as f:
        json.dump(export_doc, f, indent=2)

    log.info("Batch %d/%d exported → %s", batch_num, total_batches, out_path.name)
    return out_path


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _clean_finding(f: dict) -> dict:
    """Strip internal noise, return only what's useful for triage."""
    raw = f.get("raw_output", {})
    # Include a short raw excerpt — enough for context, not so much it bloats the prompt
    if isinstance(raw, dict):
        raw_excerpt = {k: str(v)[:200] for k, v in list(raw.items())[:6]}
    else:
        raw_excerpt = str(raw)[:300]

    return {
        "finding_id": f.get("finding_id"),
        "type": f.get("type"),
        "severity_raw": f.get("severity_raw"),
        "url": f.get("url", ""),
        "host": f.get("host", ""),
        "port": f.get("port"),
        "evidence": f.get("evidence", ""),
        "tool": f.get("tool"),
        "confidence": f.get("confidence"),
        "raw_excerpt": raw_excerpt,
        "tags": f.get("tags", []),
    }


def _load_program_context(run_dir: Path, program_id: str) -> dict:
    """Load a minimal program context for the LLM."""
    # Try to find program.json
    candidates = [
        run_dir.parent.parent / "programs" / f"{program_id}.json",
        Path(__file__).parent.parent / "programs" / f"{program_id}.json",
    ]
    for p in candidates:
        if p.exists():
            with open(p) as f:
                prog = json.load(f)
            return {
                "program_id": prog.get("program_id"),
                "name": prog.get("name"),
                "platform": prog.get("platform"),
                "non_monetary": prog.get("non_monetary"),
                "in_scope_domains": prog.get("in_scope", {}).get("domains", []),
                "out_of_scope_test_types": prog.get("out_of_scope", {}).get("test_types", []),
                "allowed_test_types": prog.get("allowed_test_types", []),
                "notes": prog.get("notes", ""),
            }
    return {"program_id": program_id, "note": "Program file not found — context unavailable"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# System prompt — this is what you paste into Claude Pro
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
You are a senior security researcher performing triage on automated vulnerability scanner findings for a bug bounty program.

Your job is to:
1. Assess each finding for REAL exploitability — not just theoretical risk. Most automated scanner findings are false positives.
2. Eliminate false positives. Tools like nikto, ffuf, and nuclei produce significant noise.
3. Prioritize findings by actual business impact to the target organization.
4. Suggest concrete, actionable next steps for confirmed findings.
5. Be skeptical. Only mark "exploitable" if you have high confidence it represents a real, exploitable vulnerability given the evidence provided.

Bug bounty focus areas (prioritize these):
- Authentication/authorization issues (IDOR, broken auth, JWT flaws, OAuth misconfigs)
- Injection vulnerabilities (SQLi, RCE, SSTI, SSRF, XXe) — only if evidence is strong
- Significant data exposure (credentials, PII, internal configs in responses)
- Subdomain takeover (dangling CNAME to unclaimed service)
- Supply chain compromise (scripts from malicious CDNs)

Deprioritize / likely false positive:
- Missing security headers (low bounty value)
- Informational findings from nikto with no PoC
- Version disclosure without a specific exploitable CVE
- Open ports that are expected (80, 443)
- Historical URLs that likely no longer exist

You will receive a JSON object in the user message. It contains a "triage_request" with a "findings" array.
Each finding has a "finding_id" (UUID) that you MUST reference exactly in your response.

Respond with ONLY a valid JSON object — no markdown code fences, no explanation text before or after, just the raw JSON.
The JSON must match this exact structure:

{
  "verdicts": [
    {
      "finding_id": "<exact UUID from input>",
      "verdict": "<exploitable|not_exploitable|needs_more_info|false_positive>",
      "reasoning": "<1-3 sentences. Be specific about why.>",
      "adjusted_severity": "<critical|high|medium|low|info>",
      "impact": "<1 sentence: what can an attacker actually do?>",
      "suggested_next_steps": ["<step 1>", "<step 2>"],
      "burp_worthy": <true|false>
    }
  ],
  "run_summary": {
    "overall_assessment": "<2-3 sentences about the overall security posture of this target>",
    "top_findings": ["<finding_id_1>", "<finding_id_2>", "<finding_id_3>"],
    "recommended_focus": "<1 sentence: where should the researcher spend their time next?>"
  }
}

Verdict definitions:
  exploitable     — High confidence this is a real, exploitable vulnerability
  not_exploitable — The finding is real but not exploitable (e.g. info disclosure with no impact)
  needs_more_info — Cannot determine without manual testing (describe what to check)
  false_positive  — Automated scanner error, expected behavior, or out of scope

burp_worthy: true if you recommend feeding this finding into Burp Suite for deeper active scanning.
"""

# ---------------------------------------------------------------------------
# Output format spec embedded in the export — for reference
# ---------------------------------------------------------------------------

_OUTPUT_FORMAT_SPEC = {
    "description": (
        "Claude Pro must respond with ONLY a raw JSON object (no markdown fences). "
        "Save the entire response as a .json file. "
        "Then run: python bb.py import-triage <run_id> <response_file.json>"
    ),
    "schema": {
        "verdicts": [
            {
                "finding_id": "exact UUID from triage_request.findings[n].finding_id",
                "verdict": "exploitable | not_exploitable | needs_more_info | false_positive",
                "reasoning": "string — 1-3 sentences",
                "adjusted_severity": "critical | high | medium | low | info",
                "impact": "string — 1 sentence",
                "suggested_next_steps": ["string", "string"],
                "burp_worthy": "boolean",
            }
        ],
        "run_summary": {
            "overall_assessment": "string — 2-3 sentences",
            "top_findings": ["finding_id_1", "finding_id_2", "finding_id_3"],
            "recommended_focus": "string — 1 sentence",
        },
    },
}
