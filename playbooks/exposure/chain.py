"""
Exposure playbook chain.

Finds: backup files, exposed panels, debug endpoints, secrets in repos,
misconfigurations, open directories, default credentials.

Depends on recon completing first (reads recon_summary.json).

Stage map:
  1. Content discovery — ffuf on live hosts (all depths)
  2. feroxbuster recursive (standard+exhaustive)
  3. Nuclei exposure/misconfiguration templates (all depths)
  4. Nikto web server checks (standard+exhaustive)
  5. TruffleHog on GitHub orgs (exhaustive)
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from tools.base import ToolWrapper
from tools.ffuf import FfufWrapper
from tools.feroxbuster import FeroxbusterWrapper
from tools.nuclei import NucleiWrapper
from tools.nikto import NiktoWrapper
from tools.trufflehog import TrufflehogWrapper

log = logging.getLogger(__name__)

_FFUF_HOST_CAP   = {"quick": 10, "standard": 50,  "exhaustive": 100}
_FERO_HOST_CAP   = {"quick":  0, "standard": 50,  "exhaustive": 100}
_TOTAL_HOST_CAP  = {"quick": 50, "standard": 250, "exhaustive": 500}

# Keywords that make a URL interesting for content discovery
_INTEREST_KEYWORDS = [
    "admin", "api", "auth", "login", "portal", "manage", "dashboard",
    "upload", "file", "download", "report", "order", "result", "lab",
    "patient", "clinical", "test", "sample", "account", "user", "config",
    "dev", "staging", "beta", "internal", "secure", "payment", "shop",
    "cart", "checkout", "invoice", "billing",
]


def _prioritize_urls(urls: list[str], cap: int) -> list[str]:
    """Score and return top *cap* URLs, prioritising interesting hostnames."""
    if len(urls) <= cap:
        return urls

    from urllib.parse import urlparse

    def _score(url: str) -> int:
        host = (urlparse(url).hostname or "").lower()
        score = 0
        for kw in _INTEREST_KEYWORDS:
            if kw in host:
                score += 2
        # prefer HTTPS
        if url.startswith("https://"):
            score += 1
        return score

    return sorted(urls, key=_score, reverse=True)[:cap]


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
    seed_domains = recon.get("seed_domains", [])

    if not live_urls:
        log.warning("[Exposure] No live URLs from recon — using seed domains")
        live_urls = [f"https://{d}" for d in seed_domains]

    total_cap = _TOTAL_HOST_CAP[depth]
    live_urls = _prioritize_urls(live_urls, total_cap)
    log.info("[Exposure] Starting with %d live URLs (cap=%d)", len(live_urls), total_cap)
    primary_target = seed_domains[0] if seed_domains else "target"

    # -----------------------------------------------------------------------
    # Stage 1 — ffuf directory/file discovery
    # -----------------------------------------------------------------------
    log.info("[Exposure] Stage 1: ffuf content discovery (skipped — low ROI vs historical URLs)")

    ffuf = FfufWrapper()
    if False and ffuf.available():
        from concurrent.futures import ThreadPoolExecutor, as_completed

        ffuf_targets = live_urls[:_FFUF_HOST_CAP[depth]]
        log.info("[Exposure] ffuf: %d hosts, max_workers=5", len(ffuf_targets))

        def _run_ffuf(url):
            return ffuf.run(
                target=_host_from_url(url),
                depth=depth,
                run_id=run_id,
                raw_output_dir=raw_output_dir,
                program=program,
                base_url=url.rstrip("/") + "/FUZZ",
                extra_headers=extra_headers or None,
                cookies=cookies or None,
            )

        with ThreadPoolExecutor(max_workers=5) as pool:
            futures = {pool.submit(_run_ffuf, url): url for url in ffuf_targets}
            for fut in as_completed(futures):
                try:
                    r = fut.result()
                    raw_output_paths.append(r["raw_output_path"])
                    tools_invoked.append(_tool_entry(ffuf, r))
                except Exception as exc:
                    log.warning("[Exposure] ffuf error on %s: %s", futures[fut], exc)
    else:
        log.warning("[Exposure] ffuf not available — skipping")

    # -----------------------------------------------------------------------
    # Stage 2 — feroxbuster recursive (standard+exhaustive)
    # -----------------------------------------------------------------------
    if depth in ("standard", "exhaustive"):
        log.info("[Exposure] Stage 2: feroxbuster recursive content discovery")

        fero = FeroxbusterWrapper()
        if False and fero.available():
            from concurrent.futures import ThreadPoolExecutor, as_completed

            fero_targets = live_urls[:_FERO_HOST_CAP[depth]]
            log.info("[Exposure] feroxbuster: %d hosts, max_workers=3", len(fero_targets))

            def _run_fero(url):
                return fero.run(
                    target=_host_from_url(url),
                    depth=depth,
                    run_id=run_id,
                    raw_output_dir=raw_output_dir,
                    program=program,
                    base_url=url,
                    extra_headers=extra_headers or None,
                    cookies=cookies or None,
                )

            with ThreadPoolExecutor(max_workers=3) as pool:
                futures = {pool.submit(_run_fero, url): url for url in fero_targets}
                for fut in as_completed(futures):
                    try:
                        r = fut.result()
                        raw_output_paths.append(r["raw_output_path"])
                        tools_invoked.append(_tool_entry(fero, r))
                    except Exception as exc:
                        log.warning("[Exposure] feroxbuster error on %s: %s", futures[fut], exc)
        else:
            log.warning("[Exposure] feroxbuster not available — skipping")

    # -----------------------------------------------------------------------
    # Stage 3 — Nuclei exposure/misconfiguration templates
    # -----------------------------------------------------------------------
    log.info("[Exposure] Stage 3: Nuclei exposure/misconfiguration templates")

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
                "exposure", "misconfiguration", "panel", "config", "backup",
                "default-login", "exposed-panels", "secrets", "generic",
                "file", "git",
            ],
            extra_headers=extra_headers or None,
            cookies=cookies or None,
        )
        raw_output_paths.append(r["raw_output_path"])
        tools_invoked.append(_tool_entry(nuclei, r))
    else:
        log.warning("[Exposure] nuclei not available or no live URLs")

    # -----------------------------------------------------------------------
    # Stage 4 — Nikto (standard+exhaustive)
    # -----------------------------------------------------------------------
    if depth in ("standard", "exhaustive"):
        log.info("[Exposure] Stage 4: Nikto web server checks")

        nikto = NiktoWrapper()
        if False and nikto.available():
            seen_hosts: set[str] = set()
            for url in live_urls:
                host = _host_from_url(url)
                if host in seen_hosts or len(seen_hosts) >= 10:
                    continue
                seen_hosts.add(host)
                r = nikto.run(
                    target=host,
                    depth=depth,
                    run_id=run_id,
                    raw_output_dir=raw_output_dir,
                    program=program,
                    url=url,
                    ssl="https" in url.lower(),
                )
                raw_output_paths.append(r["raw_output_path"])
                tools_invoked.append(_tool_entry(nikto, r))
        else:
            log.warning("[Exposure] nikto not available — skipping")

    # -----------------------------------------------------------------------
    # Stage 5 — TruffleHog GitHub org scan (exhaustive)
    # -----------------------------------------------------------------------
    if depth == "exhaustive":
        log.info("[Exposure] Stage 5: TruffleHog GitHub org secrets scan")

        trufflehog = TrufflehogWrapper()
        if trufflehog.available():
            for domain in seed_domains[:3]:
                org = domain.split(".")[0]
                r = trufflehog.run(
                    target=domain,
                    depth=depth,
                    run_id=run_id,
                    raw_output_dir=raw_output_dir,
                    program=program,
                    github_org=org,
                )
                raw_output_paths.append(r["raw_output_path"])
                tools_invoked.append(_tool_entry(trufflehog, r))
        else:
            log.warning("[Exposure] trufflehog not available — skipping")

    return {"tools_invoked": tools_invoked, "raw_output_paths": raw_output_paths}


def _load_recon_summary(run_dir: Path) -> dict:
    p = run_dir / "recon_summary.json"
    if not p.exists():
        log.warning("[Exposure] recon_summary.json not found in %s", run_dir)
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
