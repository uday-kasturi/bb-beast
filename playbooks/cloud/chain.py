"""
Cloud playbook chain.

Finds: exposed S3/GCS/Azure buckets, cloud metadata SSRF, cloud misconfigs.

Stage map:
  1. s3scanner — bucket name permutations for AWS, GCP, DigitalOcean
  2. nuclei cloud/misconfiguration/ssrf templates on live hosts
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from tools.s3scanner import S3ScannerWrapper
from tools.nuclei import NucleiWrapper

log = logging.getLogger(__name__)


def run(
    program: dict,
    depth: str,
    run_id: str,
    run_dir: Path,
    raw_output_dir: Path,
    **kwargs,
) -> dict:
    tools_invoked: list[dict] = []
    raw_output_paths: list[Path] = []

    recon = _load_recon_summary(run_dir)
    live_urls = recon.get("live_urls", [])
    seed_domains = recon.get("seed_domains", ["target"])
    primary_target = seed_domains[0] if seed_domains else "target"

    if "cloud_enum" not in program.get("allowed_test_types", []):
        log.info("[Cloud] cloud_enum not in allowed_test_types — skipping S3 scan")
    else:
        # -----------------------------------------------------------------------
        # Stage 1 — S3 bucket enumeration across providers
        # -----------------------------------------------------------------------
        log.info("[Cloud] Stage 1: S3 bucket enumeration")

        s3 = S3ScannerWrapper()
        if s3.available():
            providers = ["aws", "gcp", "do"] if depth in ("standard", "exhaustive") else ["aws"]
            for domain in seed_domains[:5]:
                for provider in providers:
                    r = s3.run(
                        target=domain,
                        depth=depth,
                        run_id=run_id,
                        raw_output_dir=raw_output_dir,
                        program=program,
                        provider=provider,
                    )
                    raw_output_paths.append(r["raw_output_path"])
                    tools_invoked.append(_tool_entry(s3, r))
        else:
            log.warning("[Cloud] s3scanner not available — skipping bucket enumeration")

    # -----------------------------------------------------------------------
    # Stage 2 — Nuclei cloud/misconfiguration/SSRF templates
    # -----------------------------------------------------------------------
    log.info("[Cloud] Stage 2: Nuclei cloud templates")

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
                "cloud", "misconfig", "s3", "aws", "gcp", "azure",
                "metadata", "ssrf", "exposure", "iam", "bucket",
            ],
        )
        raw_output_paths.append(r["raw_output_path"])
        tools_invoked.append(_tool_entry(nuclei, r))
    else:
        log.warning("[Cloud] nuclei not available or no live URLs")

    return {"tools_invoked": tools_invoked, "raw_output_paths": raw_output_paths}


def _load_recon_summary(run_dir: Path) -> dict:
    p = run_dir / "recon_summary.json"
    if not p.exists():
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
