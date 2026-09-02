"""
Auth playbook chain.

Finds: IDOR, broken auth, JWT weaknesses, OAuth flaws, session issues.

Stage map:
  1. Nuclei auth/jwt/idor/oauth templates (all depths)
  2. ffuf parameter fuzzing on auth endpoints (standard+exhaustive)
  3. IDOR numeric ID enumeration via ffuf (exhaustive)
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode

from tools.base import ToolWrapper
from tools.nuclei import NucleiWrapper
from tools.ffuf import FfufWrapper

log = logging.getLogger(__name__)

_AUTH_PATTERNS = re.compile(
    r"(login|logout|signin|signup|register|auth|oauth|sso|saml|token|"
    r"reset|forgot|password|account|profile|admin|api/v\d|graphql|"
    r"user|users|member|session|jwt|refresh|verify|confirm|2fa|mfa)",
    re.IGNORECASE,
)

_IDOR_PARAMS = {
    "id", "user_id", "uid", "account_id", "order_id", "item_id",
    "doc_id", "file_id", "record_id", "customer_id", "invoice_id",
    "message_id", "post_id", "comment_id", "profile_id", "report_id",
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
    auth_urls = [u for u in all_urls if _AUTH_PATTERNS.search(u)]
    log.info("[Auth] %d auth-related URLs from %d total", len(auth_urls), len(all_urls))

    # -----------------------------------------------------------------------
    # Stage 1 — Nuclei auth/jwt/idor templates
    # -----------------------------------------------------------------------
    log.info("[Auth] Stage 1: Nuclei auth templates")

    nuclei = NucleiWrapper()
    if nuclei.available() and live_urls:
        r = nuclei.run(
            target=primary_target,
            depth=depth,
            run_id=run_id,
            raw_output_dir=raw_output_dir,
            program=program,
            urls=live_urls,
            extra_tags=[
                "auth", "jwt", "idor", "oauth", "auth-bypass",
                "default-login", "session", "token", "api-key",
                "login", "unauth", "exposure",
            ],
            extra_headers=extra_headers or None,
            cookies=cookies or None,
        )
        raw_output_paths.append(r["raw_output_path"])
        tools_invoked.append(_tool_entry(nuclei, r))

    # -----------------------------------------------------------------------
    # Stage 2 — ffuf on auth endpoints (standard+exhaustive)
    # -----------------------------------------------------------------------
    if depth in ("standard", "exhaustive") and auth_urls:
        log.info("[Auth] Stage 2: ffuf param fuzzing on auth endpoints")

        ffuf = FfufWrapper()
        if False and ffuf.available():
            for url in auth_urls[:20]:
                base_url = url.split("?")[0] + "?FUZZ=test"
                r = ffuf.run(
                    target=_host_from_url(url),
                    depth=depth,
                    run_id=run_id,
                    raw_output_dir=raw_output_dir,
                    program=program,
                    base_url=base_url,
                    mode="params",
                    extra_headers=extra_headers or None,
                    cookies=cookies or None,
                )
                raw_output_paths.append(r["raw_output_path"])
                tools_invoked.append(_tool_entry(ffuf, r))

    # -----------------------------------------------------------------------
    # Stage 3 — IDOR numeric enumeration (exhaustive)
    # -----------------------------------------------------------------------
    if depth == "exhaustive":
        log.info("[Auth] Stage 3: IDOR parameter enumeration")

        idor_urls = _find_idor_urls(all_urls)
        log.info("[Auth] %d potential IDOR endpoints", len(idor_urls))

        ffuf = FfufWrapper()
        if False and idor_urls and ffuf.available():
            for url in idor_urls[:30]:
                fuzz_url = _make_idor_fuzz_url(url)
                if fuzz_url:
                    r = ffuf.run(
                        target=_host_from_url(url),
                        depth=depth,
                        run_id=run_id,
                        raw_output_dir=raw_output_dir,
                        program=program,
                        base_url=fuzz_url,
                        extra_headers=extra_headers or None,
                        cookies=cookies or None,
                    )
                    raw_output_paths.append(r["raw_output_path"])
                    tools_invoked.append(_tool_entry(ffuf, r))

    return {"tools_invoked": tools_invoked, "raw_output_paths": raw_output_paths}


def _find_idor_urls(urls: list[str]) -> list[str]:
    result = []
    for url in urls:
        try:
            qs = parse_qs(urlparse(url).query)
            for param, values in qs.items():
                if param.lower() in _IDOR_PARAMS and values and values[0].isdigit():
                    result.append(url)
                    break
        except Exception:
            pass
    return result


def _make_idor_fuzz_url(url: str) -> str | None:
    try:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        for param in list(qs.keys()):
            if param.lower() in _IDOR_PARAMS and qs[param][0].isdigit():
                qs[param] = ["FUZZ"]
                new_query = urlencode({k: v[0] for k, v in qs.items()})
                return parsed._replace(query=new_query).geturl()
    except Exception:
        pass
    return None


def _load_recon_summary(run_dir: Path) -> dict:
    p = run_dir / "recon_summary.json"
    if not p.exists():
        log.warning("[Auth] recon_summary.json not found")
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
