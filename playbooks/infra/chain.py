"""
Infra playbook chain.

Finds: open ports, outdated services, CVEs, exposed network services.

Stage map:
  1. naabu — fast port discovery on all resolved hosts
  2. nmap — service detection + NSE scripts (standard+exhaustive)
  3. nuclei CVE templates on live web hosts (all depths)
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from tools.naabu import NaabuWrapper
from tools.nmap import NmapWrapper
from tools.nuclei import NucleiWrapper

log = logging.getLogger(__name__)


def run(
    program: dict,
    depth: str,
    run_id: str,
    run_dir: Path,
    raw_output_dir: Path,
    session: dict | None = None,
) -> dict:
    tools_invoked: list[dict] = []
    raw_output_paths: list[Path] = []

    recon = _load_recon_summary(run_dir)
    resolved_hosts = recon.get("resolved_hosts", [])
    live_urls = recon.get("live_urls", [])
    seed_domains = recon.get("seed_domains", ["target"])
    primary_target = seed_domains[0] if seed_domains else "target"

    if not resolved_hosts:
        log.warning("[Infra] No resolved hosts from recon — using seed domains")
        resolved_hosts = seed_domains

    log.info("[Infra] Scanning %d resolved hosts", len(resolved_hosts))

    # -----------------------------------------------------------------------
    # Stage 1 — naabu port discovery
    # -----------------------------------------------------------------------
    log.info("[Infra] Stage 1: naabu port discovery")

    naabu = NaabuWrapper()
    if naabu.available() and resolved_hosts and "port_scan" in program.get("allowed_test_types", []):
        r = naabu.run(
            target=primary_target,
            depth=depth,
            run_id=run_id,
            raw_output_dir=raw_output_dir,
            program=program,
            hosts=resolved_hosts,
        )
        raw_output_paths.append(r["raw_output_path"])
        tools_invoked.append(_tool_entry(naabu, r))
    else:
        log.warning("[Infra] naabu skipped (not available or port_scan not allowed)")

    # -----------------------------------------------------------------------
    # Stage 2 — nmap service detection (standard+exhaustive)
    # -----------------------------------------------------------------------
    if depth in ("standard", "exhaustive") and "port_scan" in program.get("allowed_test_types", []):
        log.info("[Infra] Stage 2: nmap service detection + NSE scripts")

        nmap = NmapWrapper()
        if nmap.available() and resolved_hosts:
            r = nmap.run(
                target=primary_target,
                depth=depth,
                run_id=run_id,
                raw_output_dir=raw_output_dir,
                program=program,
                hosts=resolved_hosts[:100],
            )
            raw_output_paths.append(r["raw_output_path"])
            tools_invoked.append(_tool_entry(nmap, r))
        else:
            log.warning("[Infra] nmap not available — skipping service detection")

    # -----------------------------------------------------------------------
    # Stage 3 — Nuclei CVE templates on live web hosts
    # -----------------------------------------------------------------------
    log.info("[Infra] Stage 3: Nuclei CVE templates")

    nuclei = NucleiWrapper()
    if nuclei.available() and live_urls:
        r = nuclei.run(
            target=primary_target,
            depth=depth,
            run_id=run_id,
            raw_output_dir=raw_output_dir,
            program=program,
            urls=live_urls,
            extra_tags=["cve", "rce", "lfi", "ssrf", "deserialization", "xxe"],
        )
        raw_output_paths.append(r["raw_output_path"])
        tools_invoked.append(_tool_entry(nuclei, r))
    else:
        log.warning("[Infra] nuclei not available or no live URLs")

    return {"tools_invoked": tools_invoked, "raw_output_paths": raw_output_paths}


def _load_recon_summary(run_dir: Path) -> dict:
    p = run_dir / "recon_summary.json"
    if not p.exists():
        log.warning("[Infra] recon_summary.json not found")
        return {}
    with open(p) as f:
        return json.load(f)


def _tool_entry(wrapper, result: dict) -> dict:
    return {
        "tool_name": wrapper.name,
        "tool_version": wrapper.tool_version(),
        "status": "success",
        "raw_output_path": str(result["raw_output_path"]),
        "findings_count": result.get("findings_count", 0),
    }
