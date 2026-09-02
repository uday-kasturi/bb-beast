"""
Recon playbook chain.

Stage map:
  1. Subdomain enumeration
     1a. subfinder  (passive, all depths)
     1b. amass      (passive: standard+exhaustive | active+brute: exhaustive)
     1c. assetfinder(passive, standard+exhaustive)

  2. DNS resolution + validation
     2a. dnsx       (resolves all collected subdomains, filters dead ones)

  3. Live host probing
     3a. httpx      (probes all resolved hosts, tech detection)

  4. Historical URL collection
     4a. waybackurls (quick+standard: resolved hosts only | exhaustive: all)
     4b. gau         (standard+exhaustive only)

  5. Deep crawling
     5a. katana     (standard+exhaustive only)

  6. Screenshots
     6a. gowitness  (exhaustive only)

Each stage writes its own raw_output/[tool].json.
Outputs are threaded through stages: subfinder → dnsx → httpx → katana etc.

The function `run()` is the entry point called by core/engine.py.
It returns a dict with:
  - tools_invoked: list of tool manifest dicts (for run_manifest)
  - raw_output_paths: list of Paths (for findings aggregation)
"""

from __future__ import annotations

import json
import logging
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from tools.amass import AmassWrapper
from tools.assetfinder import AssetfinderWrapper
from tools.base import ToolWrapper
from tools.dnsx import DnsxWrapper
from tools.gau import GauWrapper
from tools.gowitness import GoWitnessWrapper
from tools.httpx import HttpxWrapper
from tools.katana import KatanaWrapper
from tools.subfinder import SubfinderWrapper
from tools.waybackurls import WaybackurlsWrapper

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run(
    program: dict,
    depth: str,
    run_id: str,
    run_dir: Path,
    raw_output_dir: Path,
    session: dict | None = None,
) -> dict:
    """Called by core/engine.py. Returns tools_invoked list and raw_output_paths."""

    extra_headers = ToolWrapper._auth_headers(session)
    cookies = ToolWrapper._auth_cookies(session)

    tools_invoked: list[dict] = []
    raw_output_paths: list[Path] = []

    # Root domains in scope — these are the seeds for all enumeration
    seed_domains = _extract_seed_domains(program)
    if not seed_domains:
        log.error("Recon: no in-scope domains found in program. Aborting.")
        return {"tools_invoked": [], "raw_output_paths": []}

    log.info("Recon seeds: %s", seed_domains)

    # Shared state — accumulated across all enumeration tools per stage
    all_subdomains: set[str] = set()
    all_live_urls: list[str] = []
    all_historical_urls: list[str] = []

    # -----------------------------------------------------------------------
    # Stage 1 — Subdomain enumeration
    # -----------------------------------------------------------------------
    log.info("[Recon] Stage 1: Subdomain enumeration")

    # 1a. subfinder (all depths)
    sf = SubfinderWrapper()
    if sf.available():
        for domain in seed_domains:
            r = sf.run(
                target=domain,
                depth=depth,
                run_id=run_id,
                raw_output_dir=raw_output_dir,
                program=program,
            )
            raw_output_paths.append(r["raw_output_path"])
            tools_invoked.append(_tool_entry(sf, r, raw_output_dir / "subfinder.json"))
            all_subdomains.update(_read_subdomains_from_raw(r["raw_output_path"]))
    else:
        log.warning("[Recon] subfinder not available — skipping")

    # 1b. amass (standard + exhaustive)
    if depth in ("standard", "exhaustive"):
        amass = AmassWrapper()
        if amass.available():
            for domain in seed_domains:
                r = amass.run(
                    target=domain,
                    depth=depth,
                    run_id=run_id,
                    raw_output_dir=raw_output_dir,
                    program=program,
                )
                raw_output_paths.append(r["raw_output_path"])
                tools_invoked.append(_tool_entry(amass, r, r["raw_output_path"]))
                all_subdomains.update(_read_subdomains_from_raw(r["raw_output_path"]))
        else:
            log.warning("[Recon] amass not available — skipping")

    # 1c. assetfinder (standard + exhaustive)
    if depth in ("standard", "exhaustive"):
        af = AssetfinderWrapper()
        if af.available():
            for domain in seed_domains:
                r = af.run(
                    target=domain,
                    depth=depth,
                    run_id=run_id,
                    raw_output_dir=raw_output_dir,
                    program=program,
                )
                raw_output_paths.append(r["raw_output_path"])
                tools_invoked.append(_tool_entry(af, r, r["raw_output_path"]))
                all_subdomains.update(_read_subdomains_from_raw(r["raw_output_path"]))
        else:
            log.warning("[Recon] assetfinder not available — skipping")

    log.info("[Recon] Stage 1 complete. Unique subdomains: %d", len(all_subdomains))

    if not all_subdomains:
        log.warning("[Recon] No subdomains found. Continuing with seed domains only.")
        all_subdomains = set(seed_domains)

    # -----------------------------------------------------------------------
    # Stage 2 — DNS resolution + validation
    # -----------------------------------------------------------------------
    log.info("[Recon] Stage 2: DNS resolution (%d hosts)", len(all_subdomains))

    resolved_hosts: set[str] = set()
    dnsx = DnsxWrapper()
    if dnsx.available():
        subdomain_list = sorted(all_subdomains)
        r = dnsx.run(
            target=seed_domains[0],
            depth=depth,
            run_id=run_id,
            raw_output_dir=raw_output_dir,
            program=program,
            hosts=subdomain_list,
        )
        raw_output_paths.append(r["raw_output_path"])
        tools_invoked.append(_tool_entry(dnsx, r, r["raw_output_path"]))
        resolved_hosts = _read_resolved_hosts_from_raw(r["raw_output_path"])
    else:
        log.warning("[Recon] dnsx not available — using all subdomains unfiltered")
        resolved_hosts = all_subdomains

    log.info("[Recon] Stage 2 complete. Resolved hosts: %d", len(resolved_hosts))

    # -----------------------------------------------------------------------
    # Stage 3 — Live host probing
    # -----------------------------------------------------------------------
    log.info("[Recon] Stage 3: Live host probing (%d hosts)", len(resolved_hosts))

    _HTTPX_HOST_CAP = {"quick": 250, "standard": 750, "exhaustive": 2500}
    httpx_hosts = sorted(resolved_hosts)[: _HTTPX_HOST_CAP[depth]]
    log.info(
        "[Recon] httpx host cap for depth=%s: %d / %d resolved",
        depth, len(httpx_hosts), len(resolved_hosts),
    )
    httpx = HttpxWrapper()
    if httpx.available() and httpx_hosts:
        r = httpx.run(
            target=seed_domains[0],
            depth=depth,
            run_id=run_id,
            raw_output_dir=raw_output_dir,
            program=program,
            hosts=httpx_hosts,
            extra_headers=extra_headers or None,
            cookies=cookies or None,
        )
        raw_output_paths.append(r["raw_output_path"])
        tools_invoked.append(_tool_entry(httpx, r, r["raw_output_path"]))
        all_live_urls = _read_live_urls_from_raw(r["raw_output_path"])
    else:
        log.warning("[Recon] httpx not available or no resolved hosts — skipping")

    log.info("[Recon] Stage 3 complete. Live URLs: %d", len(all_live_urls))

    # -----------------------------------------------------------------------
    # Stage 4 — Historical URL collection (parallel)
    #
    # waybackurls runs once per host (can be hundreds). gau runs once per
    # seed domain. Both are I/O-bound (network), so they all run in parallel
    # under a ThreadPoolExecutor. The base class file-lock ensures concurrent
    # writes to waybackurls.json / gau.json are race-condition-free.
    # -----------------------------------------------------------------------
    if depth in ("standard", "exhaustive"):
        wbu = WaybackurlsWrapper()
        gau = GauWrapper()

        # Build a flat list of (wrapper, target) tasks
        stage4_tasks: list[tuple] = []

        if wbu.available():
            probe_targets = sorted(resolved_hosts) if depth == "standard" else sorted(all_subdomains)
            # Cap: 100 hosts at 10 workers ≈ 10× faster than 200 sequential
            for host in probe_targets[:100]:
                stage4_tasks.append((wbu, host))
        else:
            log.warning("[Recon] waybackurls not available — skipping")

        if gau.available():
            for domain in seed_domains:
                stage4_tasks.append((gau, domain))
        else:
            log.warning("[Recon] gau not available — skipping")

        log.info(
            "[Recon] Stage 4: %d historical fetch tasks (parallel, max_workers=10)",
            len(stage4_tasks),
        )

        def _fetch_historical(wrapper, target):
            r = wrapper.run(
                target=target,
                depth=depth,
                run_id=run_id,
                raw_output_dir=raw_output_dir,
                program=program,
            )
            urls = _read_urls_from_raw(r["raw_output_path"])
            entry = _tool_entry(wrapper, r, r["raw_output_path"])
            return r["raw_output_path"], urls, entry

        seen_raw_paths: set[Path] = set()
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {
                executor.submit(_fetch_historical, wrapper, target): (wrapper.name, target)
                for wrapper, target in stage4_tasks
            }
            for future in as_completed(futures):
                try:
                    raw_path, urls, entry = future.result()
                    if raw_path not in seen_raw_paths:
                        raw_output_paths.append(raw_path)
                        seen_raw_paths.add(raw_path)
                    tools_invoked.append(entry)
                    all_historical_urls.extend(urls)
                except Exception as exc:
                    tool_name, target = futures[future]
                    log.warning("[Recon] Stage 4 task %s/%s failed: %s", tool_name, target, exc)

        log.info("[Recon] Stage 4 complete. Historical URLs: %d", len(all_historical_urls))

    # -----------------------------------------------------------------------
    # Stage 5 — Deep crawling
    # -----------------------------------------------------------------------
    if depth in ("standard", "exhaustive") and all_live_urls:
        log.info("[Recon] Stage 5: Deep crawling (%d live URLs)", len(all_live_urls))

        katana = KatanaWrapper()
        if katana.available():
            r = katana.run(
                target=seed_domains[0],
                depth=depth,
                run_id=run_id,
                raw_output_dir=raw_output_dir,
                program=program,
                urls=all_live_urls[:500],  # cap to avoid runaway crawl
                extra_headers=extra_headers or None,
                cookies=cookies or None,
            )
            raw_output_paths.append(r["raw_output_path"])
            tools_invoked.append(_tool_entry(katana, r, r["raw_output_path"]))
        else:
            log.warning("[Recon] katana not available — skipping")

    # -----------------------------------------------------------------------
    # Stage 6 — Screenshots (exhaustive only)
    # -----------------------------------------------------------------------
    if depth == "exhaustive" and all_live_urls:
        log.info("[Recon] Stage 6: Screenshots (%d URLs)", len(all_live_urls))

        screenshots_dir = run_dir / "screenshots"
        screenshots_dir.mkdir(exist_ok=True)

        gowitness = GoWitnessWrapper()
        if gowitness.available():
            r = gowitness.run(
                target=seed_domains[0],
                depth=depth,
                run_id=run_id,
                raw_output_dir=raw_output_dir,
                program=program,
                urls=all_live_urls,
                output_dir=screenshots_dir,
            )
            raw_output_paths.append(r["raw_output_path"])
            tools_invoked.append(_tool_entry(gowitness, r, r["raw_output_path"]))
        else:
            log.warning("[Recon] gowitness not available — skipping")

    # -----------------------------------------------------------------------
    # Write recon summary for downstream playbooks
    # -----------------------------------------------------------------------
    # Sanitize historical URLs before saving — waybackurls/gau produce noise
    # (embedded schemes, over-long paths, non-HTTP URLs, duplicates)
    clean_historical = ToolWrapper.sanitize_urls(all_historical_urls)[:5000]
    clean_live = ToolWrapper.sanitize_urls(all_live_urls)

    summary = {
        "seed_domains": seed_domains,
        "subdomains": sorted(all_subdomains),
        "resolved_hosts": sorted(resolved_hosts),
        "live_urls": clean_live,
        "historical_urls": clean_historical,
    }
    summary_path = run_dir / "recon_summary.json"
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)
    log.info("[Recon] Summary written to %s", summary_path)

    return {
        "tools_invoked": tools_invoked,
        "raw_output_paths": raw_output_paths,
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _extract_seed_domains(program: dict) -> list[str]:
    """
    Extract root domains from program in_scope.
    Wildcards like *.example.com → example.com.
    """
    domains = []
    for d in program.get("in_scope", {}).get("domains", []):
        if d.startswith("*."):
            domains.append(d[2:])
        else:
            domains.append(d)
    return list(dict.fromkeys(domains))  # dedupe, preserve order


def _read_subdomains_from_raw(path: Path) -> set[str]:
    """Read subdomain findings from a raw_output file."""
    try:
        with open(path) as f:
            doc = json.load(f)
        hosts = set()
        for finding in doc.get("findings", []):
            h = finding.get("host") or finding.get("url", "")
            if h:
                hosts.add(h.strip().lower())
        return hosts
    except Exception as exc:
        log.warning("Could not read subdomains from %s: %s", path, exc)
        return set()


def _read_resolved_hosts_from_raw(path: Path) -> set[str]:
    """Read DNS-resolved hosts from dnsx raw_output."""
    try:
        with open(path) as f:
            doc = json.load(f)
        hosts = set()
        for finding in doc.get("findings", []):
            h = finding.get("host") or finding.get("raw_output", {}).get("host", "")
            if h:
                hosts.add(h.strip().lower())
        return hosts
    except Exception as exc:
        log.warning("Could not read resolved hosts from %s: %s", path, exc)
        return set()


def _read_live_urls_from_raw(path: Path) -> list[str]:
    """Read live URLs from httpx raw_output."""
    try:
        with open(path) as f:
            doc = json.load(f)
        urls = []
        for finding in doc.get("findings", []):
            u = finding.get("url", "")
            if u:
                urls.append(u)
        return urls
    except Exception as exc:
        log.warning("Could not read live URLs from %s: %s", path, exc)
        return []


def _read_urls_from_raw(path: Path) -> list[str]:
    """Read URL findings from waybackurls/gau/katana raw_output."""
    try:
        with open(path) as f:
            doc = json.load(f)
        urls = []
        for finding in doc.get("findings", []):
            u = finding.get("url", "")
            if u:
                urls.append(u)
        return urls
    except Exception as exc:
        log.warning("Could not read URLs from %s: %s", path, exc)
        return []


def _tool_entry(wrapper, result: dict, path: Path) -> dict:
    """Build a tool entry for the run_manifest tools_invoked list."""
    return {
        "tool_name": wrapper.name,
        "tool_version": wrapper.tool_version(),
        "status": "success" if result.get("findings_count", 0) >= 0 else "failed",
        "raw_output_path": str(path),
        "findings_count": result.get("findings_count", 0),
    }
