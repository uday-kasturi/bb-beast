"""
Takeover playbook chain.

Finds: subdomain takeovers via dangling CNAMEs to unclaimed services.

Known vulnerable services checked:
  GitHub Pages, Heroku, Netlify, AWS S3, Azure Web Apps,
  CloudFront, Fastly, Pantheon, Surge, Ghost, Shopify,
  WordPress, Tumblr, Zendesk, Readme.io, Help Scout,
  Bitbucket, Firebase, Vercel, Cloudflare Pages, Fly.io,
  Koyeb, Render

Stage map:
  1. nuclei subdomain-takeover templates (all depths)
  2. dnsx CNAME resolution + dangling CNAME analysis (standard+exhaustive)
"""

from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path

from tools.nuclei import NucleiWrapper
from tools.dnsx import DnsxWrapper

log = logging.getLogger(__name__)

_TAKEOVER_SERVICES = {
    "github.io":          "GitHub Pages",
    "herokuapp.com":      "Heroku",
    "netlify.app":        "Netlify",
    "netlify.com":        "Netlify",
    "s3.amazonaws.com":   "AWS S3",
    "s3-website":         "AWS S3 Website",
    "azurewebsites.net":  "Azure Web Apps",
    "cloudapp.net":       "Azure Cloud",
    "fastly.net":         "Fastly",
    "pantheonsite.io":    "Pantheon",
    "surge.sh":           "Surge",
    "ghost.io":           "Ghost",
    "myshopify.com":      "Shopify",
    "wordpress.com":      "WordPress",
    "tumblr.com":         "Tumblr",
    "zendesk.com":        "Zendesk",
    "readme.io":          "Readme.io",
    "helpscoutdocs.com":  "Help Scout",
    "bitbucket.io":       "Bitbucket",
    "cloudfront.net":     "CloudFront",
    "firebaseapp.com":    "Firebase",
    "web.app":            "Firebase",
    "vercel.app":         "Vercel",
    "pages.dev":          "Cloudflare Pages",
    "fly.dev":            "Fly.io",
    "koyeb.app":          "Koyeb",
    "render.com":         "Render",
    "onrender.com":       "Render",
    "ngrok.io":           "ngrok",
    "trafficmanager.net": "Azure Traffic Manager",
    "elasticbeanstalk.com": "AWS Elastic Beanstalk",
    "awsapps.com":        "AWS WorkMail",
    "s3-ap-":             "AWS S3 Asia Pacific",
    "s3-eu-":             "AWS S3 Europe",
    "s3-us-":             "AWS S3 US",
}


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
    subdomains = recon.get("subdomains", [])
    seed_domains = recon.get("seed_domains", ["target"])
    live_urls = recon.get("live_urls", [])
    resolved_hosts = recon.get("resolved_hosts", [])
    primary_target = seed_domains[0] if seed_domains else "target"

    all_hosts = list(set(subdomains + seed_domains))
    log.info("[Takeover] Checking %d hosts for takeover", len(all_hosts))

    # -----------------------------------------------------------------------
    # Stage 1 — Nuclei takeover templates (all depths)
    # -----------------------------------------------------------------------
    log.info("[Takeover] Stage 1: nuclei subdomain-takeover templates")

    nuclei = NucleiWrapper()
    if nuclei.available():
        # Build URL list: both https:// prefixed subdomains and live URLs
        check_urls = list(set(
            [f"https://{h}" for h in all_hosts[:1000]] + live_urls
        ))
        r = nuclei.run(
            target=primary_target,
            depth=depth,
            run_id=run_id,
            raw_output_dir=raw_output_dir,
            program=program,
            urls=check_urls,
            extra_tags=["takeover", "dns", "subdomain-takeover", "cname", "service"],
        )
        raw_output_paths.append(r["raw_output_path"])
        tools_invoked.append(_tool_entry(nuclei, r))
    else:
        log.warning("[Takeover] nuclei not available — skipping template scan")

    # -----------------------------------------------------------------------
    # Stage 2 — CNAME dangling check via dnsx (standard+exhaustive)
    # -----------------------------------------------------------------------
    if depth in ("standard", "exhaustive") and all_hosts:
        log.info("[Takeover] Stage 2: dnsx CNAME resolution + dangling check")

        dnsx = DnsxWrapper()
        if dnsx.available():
            r = dnsx.run(
                target=primary_target,
                depth=depth,
                run_id=run_id,
                raw_output_dir=raw_output_dir,
                program=program,
                hosts=all_hosts,
            )
            raw_output_paths.append(r["raw_output_path"])
            tools_invoked.append(_tool_entry(dnsx, r))

            # Analyze for dangling CNAMEs
            dangling = _find_dangling_cnames(r["raw_output_path"])
            if dangling:
                log.warning("[Takeover] %d potentially dangling CNAMEs found:", len(dangling))
                for host, cname, service in dangling:
                    log.warning("  %s CNAME→ %s  [%s] *** POTENTIAL TAKEOVER ***", host, cname, service)
                # Write dangling findings as a synthetic raw output entry
                _write_dangling_findings(dangling, run_id, raw_output_dir)
        else:
            log.warning("[Takeover] dnsx not available — skipping CNAME check")

    return {"tools_invoked": tools_invoked, "raw_output_paths": raw_output_paths}


def _find_dangling_cnames(raw_output_path: Path) -> list[tuple[str, str, str]]:
    """Identify dangling CNAMEs pointing to takeover-vulnerable services."""
    try:
        with open(raw_output_path) as f:
            doc = json.load(f)
    except Exception:
        return []

    dangling = []
    for finding in doc.get("findings", []):
        raw = finding.get("raw_output", {})
        cnames = raw.get("cname", [])
        host = finding.get("host", "")
        ips = raw.get("a", [])

        for cname in cnames:
            cname_lower = cname.lower().rstrip(".")
            for suffix, service in _TAKEOVER_SERVICES.items():
                if cname_lower.endswith(suffix) or suffix in cname_lower:
                    # If no IPs resolved, CNAME is dangling
                    if not ips or _is_nxdomain(cname):
                        dangling.append((host, cname, service))
                    break
    return dangling


def _is_nxdomain(hostname: str) -> bool:
    """Return True if hostname resolves to nothing (NXDOMAIN)."""
    try:
        result = subprocess.run(
            ["dig", "+short", hostname.rstrip(".")],
            capture_output=True, text=True, timeout=10,
        )
        output = result.stdout.strip()
        return not output or "NXDOMAIN" in result.stderr
    except Exception:
        return False


def _write_dangling_findings(
    dangling: list[tuple[str, str, str]],
    run_id: str,
    raw_output_dir: Path,
) -> None:
    """Write dangling CNAME findings as a synthetic raw_output document."""
    from datetime import datetime, timezone
    findings = []
    for host, cname, service in dangling:
        findings.append({
            "type": "subdomain_takeover",
            "host": host,
            "evidence": (
                f"Dangling CNAME: {host} → {cname} "
                f"({service} — service appears unclaimed)"
            ),
            "raw_output": {
                "host": host,
                "cname": cname,
                "service": service,
                "matched_at": host,
            },
            "metadata": {"severity": "high"},
        })

    doc = {
        "schema_version": "1.0",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "run_id": run_id,
        "tool_name": "cname_dangling_checker",
        "tool_version": "1.0.0",
        "invocation_command": "cname_dangling_checker (internal)",
        "target": "all subdomains",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "duration_seconds": 0,
        "status": "success",
        "findings": findings,
        "errors": [],
    }
    out_path = raw_output_dir / "cname_dangling.json"
    with open(out_path, "w") as f:
        json.dump(doc, f, indent=2)
    log.info("[Takeover] Wrote %d dangling CNAME findings to cname_dangling.json", len(findings))


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
