"""
Opus-driven agentic recon + attack engine.

Opus gets the subdomain / live host list and a set of callable tools.
It decides what to probe, calls tools, reads results, and decides what
to probe next — running until it's satisfied.

Uses claude CLI (same auth as rest of codebase). Each round sends the
full conversation transcript with Opus responding in structured JSON:
  {"action": "call_tool", "tool": "...", "params": {...}}
  {"action": "report_finding", "finding": {...}}
  {"action": "done", "summary": "..."}

Usage:
    python3 bb.py agent <run_id>
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger(__name__)

_MAX_TOOL_ROUNDS = 25
_CLAUDE_TIMEOUT = 180  # seconds per Opus call


def run_agent(run_dir: Path, program: dict, depth: str = "standard") -> Path:
    recon = _load_recon(run_dir)
    if not recon:
        raise FileNotFoundError(f"recon_summary.json not found in {run_dir}")

    run_id = str(uuid.uuid4())
    raw_output_dir = run_dir / "raw_output"
    raw_output_dir.mkdir(exist_ok=True)

    # Resume from prior agent_report.json if it exists
    prior_report_path = run_dir / "agent_report.json"
    prior_report: dict = {}
    if prior_report_path.exists():
        try:
            with open(prior_report_path) as f:
                prior_report = json.load(f)
            log.info("[Agent] Resuming — loading prior report (%d findings, %d tool calls)",
                     len(prior_report.get("confirmed_findings", [])),
                     len(prior_report.get("tool_call_log", [])))
        except Exception as exc:
            log.warning("[Agent] Could not load prior report: %s", exc)

    system_prompt = _build_system_prompt(program, recon)
    if prior_report:
        initial_context = _build_resume_context(program, recon, prior_report)
    else:
        initial_context = _build_initial_context(program, recon)

    # Conversation transcript — appended each round
    transcript: list[dict] = [
        {"role": "user", "content": initial_context}
    ]

    # Carry forward confirmed findings from prior run
    confirmed_findings: list[dict] = list(prior_report.get("confirmed_findings", []))
    tool_call_log: list[dict] = []
    rounds = 0
    final_summary = ""

    subdomains = recon.get("discovered_subdomains", []) or recon.get("seed_domains", [])
    live_urls = recon.get("live_urls", [])
    log.info(
        "[Agent] Starting agentic loop | %d subdomains | %d live URLs | max %d rounds",
        len(subdomains), len(live_urls), _MAX_TOOL_ROUNDS,
    )

    while rounds < _MAX_TOOL_ROUNDS:
        rounds += 1
        log.info("[Agent] Round %d — calling Opus", rounds)

        prompt = _build_prompt(system_prompt, transcript)
        raw = _call_claude(prompt)

        if not raw:
            log.warning("[Agent] Empty response from Opus — stopping")
            break

        # Parse Opus response
        action = _parse_action(raw)
        if action is None:
            log.warning("[Agent] Could not parse action — raw response:\n%s", raw[:1000])
            # Append so _last_assistant_text sees it
            transcript.append({"role": "assistant", "content": raw})
            break

        action_type = action.get("action")
        log.info("[Agent] Opus action: %s", action_type)

        if action_type == "done":
            log.info("[Agent] Opus signalled done after %d rounds", rounds)
            transcript.append({"role": "assistant", "content": raw})
            # Extract summary from the done action directly
            final_summary = action.get("summary", "")
            break

        elif action_type == "report_finding":
            finding_data = action.get("finding", {})
            finding = {
                "finding_id": str(uuid.uuid4()),
                "reported_at": datetime.now(timezone.utc).isoformat(),
                **finding_data,
            }
            confirmed_findings.append(finding)
            log.info(
                "[Agent] Finding: [%s] %s — %s",
                finding.get("severity", "?").upper(),
                finding.get("type", "?"),
                finding.get("url", "?")[:60],
            )
            result_text = json.dumps({"status": "finding_recorded", "finding_id": finding["finding_id"]})

        elif action_type == "call_tool":
            tool_name = action.get("tool", "")
            tool_params = action.get("params", {})
            log.info("[Agent] Tool: %s(%s)", tool_name, _summarize(tool_params))

            t0 = time.monotonic()
            result = _dispatch_tool(tool_name, tool_params, program, run_id, raw_output_dir, depth)
            elapsed = time.monotonic() - t0

            tool_call_log.append({
                "round": rounds,
                "tool": tool_name,
                "params": tool_params,
                "elapsed_s": round(elapsed, 1),
            })

            result_text = json.dumps(result)
            log.info("[Agent] Tool result: %d chars in %.1fs", len(result_text), elapsed)

        else:
            log.warning("[Agent] Unknown action type: %s", action_type)
            break

        # Append this round's exchange to transcript
        transcript.append({"role": "assistant", "content": raw})
        transcript.append({"role": "user", "content": f"Tool result:\n{result_text}"})

    else:
        log.warning("[Agent] Reached max rounds (%d)", _MAX_TOOL_ROUNDS)
        final_summary = ""

    summary = {
        "assessment": final_summary or _last_assistant_text(transcript),
        "confirmed_findings_count": len(confirmed_findings),
        "finding_types": list({f.get("type") for f in confirmed_findings}),
    }

    report = {
        "schema_version": "1.0",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "run_id": run_id,
        "model": "claude-opus-4-8",
        "tool_rounds": rounds,
        "tool_calls": len(tool_call_log),
        "confirmed_findings": confirmed_findings,
        "tool_call_log": tool_call_log,
        "summary": summary,  # type: ignore[assignment]
    }

    report_path = run_dir / "agent_report.json"
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)

    log.info(
        "[Agent] Done. %d findings | %d tool calls | %d rounds → %s",
        len(confirmed_findings), len(tool_call_log), rounds, report_path,
    )
    return report_path


# ---------------------------------------------------------------------------
# Prompt construction
# ---------------------------------------------------------------------------

def _build_system_prompt(program: dict, recon: dict) -> str:
    allowed = program.get("allowed_test_types", [])
    out_of_scope = program.get("out_of_scope", {})
    oos_test_types = out_of_scope.get("test_types", [])
    in_scope_domains = (program.get("in_scope") or program.get("scope") or {}).get("domains", [])

    return f"""You are an expert bug bounty analyst directing a local security testing executor against {program.get('name', 'target')}.

You output JSON instructions. The executor runs them against real infrastructure and returns results. You are NOT Claude Code and you do NOT have Claude Code tools. You are a pure reasoning model that receives recon data, decides what to test, outputs JSON instructions, and analyzes results returned by the executor.

YOUR ONLY JOB: output a single JSON object per turn. The executor reads it, runs the action, and sends you back the result. No prose, no explanation — only the JSON object.

FORMAT (one of these per turn):

Dispatch a tool:
{{"action": "call_tool", "tool": "<tool_name>", "params": {{...}}}}

Record a finding:
{{"action": "report_finding", "finding": {{"type": "...", "severity": "critical|high|medium|low|info", "url": "...", "evidence": "...", "reproduction_steps": ["..."], "impact": "...", "curl_command": "..."}}}}

Finish investigation:
{{"action": "done", "summary": "..."}}

EXECUTOR TOOLS (these run on the operator's machine against real targets):
- probe_httpx: {{"hosts": ["host1", "host2", ...]}} — check which hosts are live, get status/tech
- run_nuclei: {{"urls": [...], "tags": [...], "template_ids": [...]}} — targeted vuln scan
- get_historical_urls: {{"domain": "example.com", "keyword_filter": "api", "limit": 100}} — wayback/GAU URLs
- test_sqli: {{"url": "...", "post_data": "...", "dbms_hint": "..."}} — sqlmap on a specific URL
- test_xss: {{"urls": [...]}} — dalfox XSS scan
- fetch_url: {{"url": "...", "method": "GET", "headers": {{}}, "body": "..."}} — inspect a URL manually
- check_takeover: {{"subdomains": [...]}} — check CNAME-based subdomain takeover

CONSTRAINTS:
- Allowed test types: {json.dumps(allowed)}
- Disallowed test types: {json.dumps(oos_test_types)}
- In-scope domains: {json.dumps(in_scope_domains[:10]) if in_scope_domains else "all eurofins.* domains"}
- Rate limit: max ~5 req/s
- Do NOT modify/delete data
- If you find patient health data or pharmaceutical compliance data: report_finding type=sensitive_data_exposure immediately and stop

STRATEGY:
- Prioritize: staging/dev/admin subdomains, API endpoints, endpoints with parameters
- Use probe_httpx first on interesting subdomains before deep scanning
- Use run_nuclei with specific tags — not everything at once
- Use fetch_url to manually inspect suspicious responses (headers, body)
- Use get_historical_urls to find old endpoints that may still be live
- Use check_takeover on CNAME-based subdomains
- Call report_finding for ANYTHING with evidence — unauthenticated endpoints, version/env disclosure, exposed admin panels, open redirects, interesting API responses. Report low/info findings and let the human decide. Better to over-report than miss.
- Call done when you've covered the high-value surface or are confident in your findings

WHAT PAYS:
- Exposed admin panels / default credentials
- Unauthenticated API endpoints
- Subdomain takeover (confirmed CNAME to unclaimed service)
- SQL injection with confirmed extraction
- SSRF to internal services
- Open redirect enabling OAuth hijack
- Sensitive data in responses (credentials, PII, API keys)
- Auth bypass

WHAT DOESN'T PAY:
- Missing security headers alone
- Self-XSS
- Version disclosure without PoC
- Theoretical risk without evidence"""


def _build_initial_context(program: dict, recon: dict) -> str:
    subdomains = recon.get("discovered_subdomains", []) or recon.get("seed_domains", [])
    live_urls = recon.get("live_urls", [])

    interest_kws = [
        "admin", "api", "staging", "dev", "beta", "internal", "portal",
        "login", "auth", "sso", "manage", "dashboard", "app", "secure",
        "test", "uat", "qa", "lab", "old", "legacy", "shop", "payment",
    ]

    def _score(s: str) -> int:
        s = s.lower()
        return sum(1 for kw in interest_kws if kw in s)

    sorted_subs = sorted(subdomains, key=_score, reverse=True)
    sorted_live = sorted(live_urls, key=_score, reverse=True)

    lines = [
        f"Target: {program.get('name', 'unknown')} ({program.get('platform', 'VDP')})",
        f"Scope: {', '.join((program.get('in_scope') or program.get('scope') or {}).get('domains', [])[:5])}",
        "",
        f"Passive recon found {len(subdomains)} subdomains. Sorted by interest (most interesting first):",
    ]
    for s in sorted_subs[:80]:
        lines.append(f"  {s}")

    if sorted_live:
        lines.append(f"\n{len(live_urls)} live HTTP hosts confirmed. Top interesting:")
        for u in sorted_live[:80]:
            lines.append(f"  {u}")

    lines.append("\nBegin your investigation. Call tools, follow interesting leads, report findings.")
    return "\n".join(lines)


def _build_resume_context(program: dict, recon: dict, prior_report: dict) -> str:
    """Build initial context for a resumed agent run including prior findings."""
    base = _build_initial_context(program, recon)
    prior_calls = prior_report.get("tool_call_log", [])
    prior_findings = prior_report.get("confirmed_findings", [])
    summary = prior_report.get("summary", {})

    lines = [base, "", "=" * 60,
             "RESUMING PREVIOUS INVESTIGATION — context from prior run:",
             f"Prior tool calls: {len(prior_calls)}"]

    if prior_calls:
        lines.append("Tools already called (skip repeating these):")
        for tc in prior_calls[-20:]:  # last 20
            lines.append(f"  - {tc['tool']}({list(tc.get('params', {}).keys())[:3]})")

    if prior_findings:
        lines.append(f"\nFindings already reported ({len(prior_findings)}):")
        for f in prior_findings:
            lines.append(f"  [{f.get('severity','?').upper()}] {f.get('type','?')} @ {f.get('url','?')}")
    else:
        lines.append("\nNo findings formally reported yet in prior run.")

    prior_summary = summary.get("assessment", "")
    if prior_summary and len(prior_summary) > 20:
        lines.append(f"\nPrior run assessment:\n{prior_summary[:800]}")

    lines.append("\nContinue where the prior run left off. Focus on uncovered subdomains and deeper investigation of interesting targets found.")
    return "\n".join(lines)


_MAX_TRANSCRIPT_CHARS = 40_000  # compress when prompt exceeds this


def _compress_transcript(transcript: list[dict]) -> list[dict]:
    """Keep first user message + last 6 exchanges; summarise middle into one block."""
    if len(transcript) <= 8:
        return transcript

    first = transcript[0]          # initial context (subdomain list)
    tail = transcript[-6:]          # last 3 rounds (6 entries: assistant+user each)
    middle = transcript[1:-6]       # everything in between

    # Build a compact summary of what happened in the middle
    summary_lines = ["[COMPRESSED HISTORY — actions and findings so far]"]
    i = 0
    while i < len(middle):
        turn = middle[i]
        if turn["role"] == "assistant":
            action = _parse_action(turn["content"])
            if action:
                atype = action.get("action", "?")
                if atype == "call_tool":
                    summary_lines.append(f"- Called {action.get('tool')}({list(action.get('params', {}).keys())})")
                elif atype == "report_finding":
                    f = action.get("finding", {})
                    summary_lines.append(f"- REPORTED FINDING: [{f.get('severity','?').upper()}] {f.get('type','?')} @ {f.get('url','?')}")
                elif atype == "done":
                    summary_lines.append(f"- Called done: {action.get('summary','')[:100]}")
        elif turn["role"] == "user" and turn["content"].startswith("Tool result:"):
            # Truncate long tool results in summary
            result_text = turn["content"][len("Tool result:\n"):]
            summary_lines.append(f"  → result: {result_text[:150]}…")
        i += 1

    compressed_middle = {
        "role": "user",
        "content": "\n".join(summary_lines),
    }
    return [first, compressed_middle] + tail


def _build_prompt(system: str, transcript: list[dict]) -> str:
    # Compress if the transcript is getting large
    effective = transcript
    raw_size = sum(len(t["content"]) for t in transcript)
    if raw_size > _MAX_TRANSCRIPT_CHARS:
        effective = _compress_transcript(transcript)
        log.debug("[Agent] Transcript compressed: %d→%d chars", raw_size, sum(len(t["content"]) for t in effective))

    parts = [system, "\n\n---\n\nCONVERSATION:\n"]
    for turn in effective:
        role = turn["role"].upper()
        content = turn["content"]
        parts.append(f"[{role}]\n{content}\n")
    parts.append("\n[ASSISTANT]\n")
    return "".join(parts)


# ---------------------------------------------------------------------------
# Claude CLI invocation
# ---------------------------------------------------------------------------

def _call_claude(prompt: str) -> str:
    # Migrated onto the unified router (core.models), role "recon" (fable-5 on
    # the CLI by default with --tools none, config-swappable). Preserves the
    # original contract: return "" on failure so the recon loop keeps going.
    from core.models import complete, ModelError
    try:
        return complete("recon", [{"role": "user", "content": prompt}],
                        timeout=_CLAUDE_TIMEOUT).text
    except ModelError as exc:
        log.warning("[Agent] recon model call failed: %s", exc)
        return ""


# ---------------------------------------------------------------------------
# Action parsing
# ---------------------------------------------------------------------------

def _parse_action(raw: str) -> dict | None:
    # Try direct JSON parse first
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass

    # Try extracting JSON block from markdown
    import re
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            pass

    # Try finding the first { ... } in the text
    m = re.search(r"(\{.*\})", raw, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            pass

    return None


# ---------------------------------------------------------------------------
# Tool dispatch
# ---------------------------------------------------------------------------

def _dispatch_tool(name: str, params: dict, program: dict, run_id: str, raw_output_dir: Path, depth: str) -> dict:
    try:
        if name == "probe_httpx":
            return _tool_httpx(params, program, run_id, raw_output_dir, depth)
        elif name == "run_nuclei":
            return _tool_nuclei(params, program, run_id, raw_output_dir, depth)
        elif name == "get_historical_urls":
            return _tool_wayback(params, program, run_id, raw_output_dir, depth)
        elif name == "test_sqli":
            return _tool_sqlmap(params, program, run_id, raw_output_dir, depth)
        elif name == "test_xss":
            return _tool_dalfox(params, program, run_id, raw_output_dir, depth)
        elif name == "fetch_url":
            return _tool_fetch(params, program)
        elif name == "check_takeover":
            return _tool_takeover(params)
        else:
            return {"error": f"Unknown tool: {name}"}
    except Exception as exc:
        log.warning("[Agent] Tool %s error: %s", name, exc)
        return {"error": str(exc)}


def _tool_httpx(params, program, run_id, raw_output_dir, depth):
    from tools.httpx import HttpxWrapper
    w = HttpxWrapper()
    if not w.available():
        return {"error": "httpx not available"}
    hosts = params.get("hosts", [])[:200]
    r = w.run(
        target=_primary(program), depth=depth, run_id=run_id,
        raw_output_dir=raw_output_dir, program=program, hosts=hosts,
    )
    # Findings are written to disk — read them back
    raw_path = r.get("raw_output_path")
    findings = []
    if raw_path and Path(raw_path).exists():
        with open(raw_path) as f:
            doc = json.load(f)
        findings = doc.get("findings", [])
    # Score hosts by interest (admin/api/staging etc rank higher)
    interest_kws = ["admin", "api", "staging", "dev", "auth", "login", "portal", "internal", "test", "qa"]
    def _score_host(h: dict) -> int:
        url = (h.get("url") or "").lower()
        return sum(1 for kw in interest_kws if kw in url)

    findings_sorted = sorted(findings, key=_score_host, reverse=True)
    return {
        "live": len(findings),
        "hosts": [
            {"url": f.get("url"), "status": f.get("evidence", {}).get("status_code") if isinstance(f.get("evidence"), dict) else None, "info": str(f.get("evidence", ""))[:80]}
            for f in findings_sorted[:60]
        ],
    }


def _tool_nuclei(params, program, run_id, raw_output_dir, depth):
    from tools.nuclei import NucleiWrapper
    w = NucleiWrapper()
    if not w.available():
        return {"error": "nuclei not available"}
    urls = params.get("urls", [])[:100]
    tags = params.get("tags") or []
    templates = params.get("template_ids") or []
    r = w.run(
        target=_primary(program), depth=depth, run_id=run_id,
        raw_output_dir=raw_output_dir, program=program,
        urls=urls,
        extra_tags=tags or None,
        extra_templates=templates or None,
    )
    findings = r.get("findings", [])
    non_info = [f for f in findings if f.get("severity_raw", "info") != "info"]
    show = non_info if non_info else findings[:20]
    return {
        "total": len(findings),
        "actionable": len(non_info),
        "findings": [
            {
                "template": (f.get("raw_output") or {}).get("template_id", "?") if isinstance(f.get("raw_output"), dict) else "?",
                "severity": f.get("severity_raw"),
                "url": f.get("url"),
                "evidence": str(f.get("evidence", ""))[:200],
            }
            for f in show[:30]
        ],
    }


def _tool_wayback(params, program, run_id, raw_output_dir, depth):
    from tools.waybackurls import WaybackurlsWrapper
    w = WaybackurlsWrapper()
    if not w.available():
        return {"error": "waybackurls not available"}
    domain = params.get("domain", "")
    keyword = params.get("keyword_filter", "")
    limit = min(int(params.get("limit", 100)), 500)
    r = w.run(
        target=domain, depth=depth, run_id=run_id,
        raw_output_dir=raw_output_dir, program=program,
    )
    urls = [f.get("url", "") for f in r.get("findings", [])]
    if keyword:
        urls = [u for u in urls if keyword.lower() in u.lower()]
    return {"count": len(urls[:limit]), "urls": urls[:limit]}


def _tool_sqlmap(params, program, run_id, raw_output_dir, depth):
    from tools.sqlmap import SqlmapWrapper
    w = SqlmapWrapper()
    if not w.available():
        return {"error": "sqlmap not available"}
    r = w.run(
        target=_primary(program), depth=depth, run_id=run_id,
        raw_output_dir=raw_output_dir, program=program,
        url=params.get("url"),
        post_data=params.get("post_data"),
        dbms_hint=params.get("dbms_hint"),
    )
    findings = r.get("findings", [])
    return {
        "findings": len(findings),
        "results": [
            {"severity": f.get("severity_raw"), "evidence": str(f.get("evidence", ""))[:300]}
            for f in findings[:10]
        ],
    }


def _tool_dalfox(params, program, run_id, raw_output_dir, depth):
    from tools.dalfox import DalfoxWrapper
    w = DalfoxWrapper()
    if not w.available():
        return {"error": "dalfox not available"}
    r = w.run(
        target=_primary(program), depth=depth, run_id=run_id,
        raw_output_dir=raw_output_dir, program=program,
        urls=params.get("urls", [])[:50],
    )
    findings = r.get("findings", [])
    return {
        "xss_found": len(findings) > 0,
        "findings": [
            {"url": f.get("url"), "evidence": str(f.get("evidence", ""))[:200]}
            for f in findings[:10]
        ],
    }


def _tool_fetch(params, program):
    import urllib.request
    import urllib.error
    url = params.get("url", "")
    if not _in_scope(url, program):
        return {"error": f"Out of scope: {url}"}
    method = params.get("method", "GET").upper()
    extra_headers = params.get("headers") or {}
    body = params.get("body")

    req = urllib.request.Request(url, method=method)
    req.add_header("User-Agent", "BugBountyBeast/1.0 (authorized security testing)")
    for k, v in extra_headers.items():
        req.add_header(k, v)
    if body:
        req.data = body.encode()

    _INTERESTING_HEADERS = {
        "server", "x-powered-by", "content-type", "location",
        "x-frame-options", "content-security-policy", "strict-transport-security",
        "access-control-allow-origin", "set-cookie", "www-authenticate",
        "x-aspnet-version", "x-aspnetmvc-version", "x-debug-token",
        "x-generator", "x-robots-tag", "x-version", "x-env",
    }
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            headers = {k.lower(): v for k, v in dict(resp.headers).items() if k.lower() in _INTERESTING_HEADERS}
            body_bytes = resp.read(8192)
            body_text = body_bytes.decode("utf-8", errors="replace")
            return {
                "status": resp.status,
                "final_url": resp.url,
                "headers": headers,
                "body_length": len(body_bytes),
                "body_excerpt": body_text[:2000],
            }
    except urllib.error.HTTPError as e:
        headers = {k.lower(): v for k, v in dict(e.headers).items() if k.lower() in _INTERESTING_HEADERS}
        return {"status": e.code, "error": str(e), "headers": headers}
    except Exception as e:
        return {"error": str(e)}


def _tool_takeover(params):
    import subprocess as sp
    import shutil as sh
    subdomains = params.get("subdomains", [])[:100]
    dig = sh.which("dig")
    _UNCLAIMED = {
        "github.io": "There isn't a GitHub Pages",
        "herokuapp.com": "no-such-app",
        "azurewebsites.net": "does not exist",
        "s3.amazonaws.com": "NoSuchBucket",
        "shopify.com": "currently unavailable",
        "fastly.net": "unknown domain",
        "zendesk.com": "Help Center Closed",
        "surge.sh": "project not found",
        "bitbucket.io": "Repository not found",
        "readme.io": "Project doesnt exist",
        "ghost.io": "404",
        "helpscout.net": "No settings were found",
        "uservoice.com": "set up your UserVoice",
    }
    results = []
    for sub in subdomains:
        entry = {"subdomain": sub, "cname": None, "candidate": False, "service": None}
        if dig:
            try:
                out = sp.check_output(["dig", "+short", "CNAME", sub], timeout=5, text=True).strip()
                if out:
                    entry["cname"] = out
                    for svc, _ in _UNCLAIMED.items():
                        if svc in out:
                            entry["candidate"] = True
                            entry["service"] = svc
            except Exception:
                pass
        results.append(entry)

    candidates = [r for r in results if r["candidate"]]
    return {
        "checked": len(results),
        "candidates": len(candidates),
        "takeover_candidates": candidates,
        "all_cnames": [r for r in results if r["cname"]],
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_recon(run_dir: Path) -> dict:
    p = run_dir / "recon_summary.json"
    if not p.exists():
        return {}
    with open(p) as f:
        return json.load(f)


def _primary(program: dict) -> str:
    # program.json uses "in_scope" key with "domains" list
    domains = (
        program.get("in_scope", {}).get("domains", [])
        or program.get("scope", {}).get("domains", [])
    )
    return domains[0].lstrip("*.") if domains else "target"


def _in_scope(url: str, program: dict) -> bool:
    from urllib.parse import urlparse
    host = (urlparse(url).hostname or "").lower()
    domains = (
        program.get("in_scope", {}).get("domains", [])
        or program.get("scope", {}).get("domains", [])
    )
    if not domains:
        return True  # no scope defined = allow all (VDP with wildcard scope)
    for d in domains:
        d = d.lstrip("*.").lower()
        if host == d or host.endswith("." + d):
            return True
    return False


def _summarize(params: dict) -> str:
    parts = []
    for k, v in params.items():
        if isinstance(v, list):
            parts.append(f"{k}=[{len(v)}]")
        elif isinstance(v, str) and len(v) > 40:
            parts.append(f"{k}={v[:40]}...")
        else:
            parts.append(f"{k}={v}")
    return ", ".join(parts)


def _last_assistant_text(transcript: list[dict]) -> str:
    for turn in reversed(transcript):
        if turn["role"] == "assistant":
            action = _parse_action(turn["content"]) or {}
            return action.get("summary", turn["content"][:500])
    return "No summary available"
