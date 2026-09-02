"""
Supply chain playbook chain.

Finds: missing SRI on third-party scripts, scripts from known-bad CDNs,
deprecated CDN URLs, vulnerable JS library versions.

Stage map:
  1. nuclei supply-chain/tech templates (all depths)
  2. katana JS crawl + bad CDN / vulnerable library detection (standard+exhaustive)
  3. threat_alert CDN checks from /alerts/ (exhaustive)
"""

from __future__ import annotations

import json
import logging
import re
from datetime import date
from pathlib import Path

from tools.nuclei import NucleiWrapper
from tools.katana import KatanaWrapper

log = logging.getLogger(__name__)

ROOT = Path(__file__).parent.parent.parent
ALERTS_DIR = ROOT / "alerts"

# CDNs that have had supply chain compromises or are known bad
_KNOWN_BAD_CDNS = {
    "cdn.polyfill.io":   "polyfill.io supply chain compromise (Jun 2024)",
    "polyfill.io":       "polyfill.io supply chain compromise (Jun 2024)",
    "bootcss.com":       "known malicious CDN serving modified jQuery",
    "bootcdn.net":       "potentially malicious CDN",
    "staticfile.org":    "potentially malicious CDN",
}

# Regex patterns for known vulnerable JS library versions
_VULNERABLE_LIBRARIES = [
    (re.compile(r"jquery[/-](1\.[0-9]|2\.[0-2])\.", re.I),
     "jQuery <3.0 — XSS via $.htmlPrefilter and other vectors"),
    (re.compile(r"bootstrap[/-](2\.|3\.[0-3])", re.I),
     "Bootstrap <3.4 — XSS in data-target attribute"),
    (re.compile(r"angular(?:js)?[/-]1\.[0-6]\.", re.I),
     "AngularJS <1.7 — multiple sandbox escapes and XSS"),
    (re.compile(r"lodash[/-](0\.|1\.|2\.|3\.|4\.[0-9]\b)", re.I),
     "Lodash <4.17.21 — prototype pollution (CVE-2021-23337)"),
    (re.compile(r"moment[/-](2\.[0-9]\.|2\.[12][0-9]\.)", re.I),
     "Moment.js <2.29.4 — path traversal (CVE-2022-24785)"),
    (re.compile(r"handlebars[/-][0-3]\.", re.I),
     "Handlebars <4.7.7 — prototype pollution (CVE-2021-23369)"),
    (re.compile(r"underscore[/-](1\.[0-7])\.", re.I),
     "Underscore.js <1.12.1 — arbitrary code execution"),
    (re.compile(r"highlight\.?js[/-](9\.|10\.[0-9])\.", re.I),
     "highlight.js <10.4.1 — ReDoS (CVE-2020-26237)"),
    (re.compile(r"marked[/-](0\.|1\.|2\.[0]\b)", re.I),
     "marked <2.1.3 — XSS via sanitize option bypass"),
    (re.compile(r"dompurify[/-](0\.|1\.|2\.[0-2])\.", re.I),
     "DOMPurify <2.3 — mXSS bypass"),
    (re.compile(r"axios[/-](0\.[0-9]\b)", re.I),
     "axios <0.21.2 — SSRF and ReDoS"),
    (re.compile(r"vue[/-](2\.[0-5])\.", re.I),
     "Vue.js <2.6 — XSS via v-html"),
]


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
    live_urls = recon.get("live_urls", [])
    seed_domains = recon.get("seed_domains", ["target"])
    primary_target = seed_domains[0] if seed_domains else "target"

    # -----------------------------------------------------------------------
    # Stage 1 — Nuclei supply chain / tech templates
    # -----------------------------------------------------------------------
    log.info("[SupplyChain] Stage 1: nuclei supply chain templates")

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
                "tech", "javascript", "cdn", "sri", "supply-chain",
                "outdated", "version", "third-party",
            ],
        )
        raw_output_paths.append(r["raw_output_path"])
        tools_invoked.append(_tool_entry(nuclei, r))
    else:
        log.warning("[SupplyChain] nuclei not available or no live URLs")

    # -----------------------------------------------------------------------
    # Stage 2 — katana JS crawl + bad CDN / vulnerable library detection
    # -----------------------------------------------------------------------
    if depth in ("standard", "exhaustive") and live_urls:
        log.info("[SupplyChain] Stage 2: katana JS crawl + supply chain analysis")

        katana = KatanaWrapper()
        if katana.available():
            r = katana.run(
                target=primary_target,
                depth=depth,
                run_id=run_id,
                raw_output_dir=raw_output_dir,
                program=program,
                urls=live_urls[:100],
            )
            raw_output_paths.append(r["raw_output_path"])
            tools_invoked.append(_tool_entry(katana, r))

            # Analyze katana output for supply chain issues
            sc_findings = _analyze_for_supply_chain_issues(r["raw_output_path"])
            if sc_findings:
                _write_supply_chain_findings(sc_findings, run_id, raw_output_dir)
                log.warning("[SupplyChain] %d supply chain issues found", len(sc_findings))
        else:
            log.warning("[SupplyChain] katana not available — skipping JS crawl")

    # -----------------------------------------------------------------------
    # Stage 3 — threat_alert CDN checks from /alerts/ (exhaustive)
    # -----------------------------------------------------------------------
    if depth == "exhaustive":
        log.info("[SupplyChain] Stage 3: threat alert CDN checks")
        alert_findings = _check_threat_alerts(live_urls)
        if alert_findings:
            _write_supply_chain_findings(alert_findings, run_id, raw_output_dir,
                                         filename="threat_alert_matches.json")

    return {"tools_invoked": tools_invoked, "raw_output_paths": raw_output_paths}


def _analyze_for_supply_chain_issues(katana_output_path: Path) -> list[dict]:
    """Parse katana output and detect bad CDNs and vulnerable library versions."""
    findings = []
    try:
        with open(katana_output_path) as f:
            doc = json.load(f)
    except Exception:
        return []

    for finding in doc.get("findings", []):
        url = finding.get("url", "")
        if not url:
            continue

        url_lower = url.lower()

        # Check for known bad CDNs
        for cdn_host, reason in _KNOWN_BAD_CDNS.items():
            if cdn_host in url_lower:
                findings.append({
                    "type": "supply_chain",
                    "url": url,
                    "evidence": f"Script from compromised/malicious CDN ({cdn_host}): {reason}",
                    "severity": "high",
                })
                break

        # Check for vulnerable library versions (JS files only)
        if ".js" in url_lower or url_lower.endswith(".js"):
            for pattern, vuln_desc in _VULNERABLE_LIBRARIES:
                if pattern.search(url):
                    findings.append({
                        "type": "supply_chain",
                        "url": url,
                        "evidence": f"Vulnerable JS library: {vuln_desc}",
                        "severity": "medium",
                    })
                    break

    return findings


def _check_threat_alerts(live_urls: list[str]) -> list[dict]:
    """Check live URLs against active threat alerts from /alerts/."""
    findings = []
    if not ALERTS_DIR.exists():
        return findings

    for alert_path in ALERTS_DIR.glob("*.json"):
        try:
            with open(alert_path) as f:
                alert = json.load(f)
        except Exception:
            continue

        if not alert.get("active", True):
            continue

        expiry_str = alert.get("expiry_date", "")
        if expiry_str:
            try:
                if date.fromisoformat(expiry_str) < date.today():
                    log.debug("[SupplyChain] Alert %s expired — skipping", alert_path.name)
                    continue
            except Exception:
                pass

        indicator = alert.get("affected_indicator", {})
        indicator_type = indicator.get("type", "")
        indicator_value = indicator.get("value", "").lower()

        if indicator_type == "cdn_url":
            for url in live_urls:
                if indicator_value in url.lower():
                    findings.append({
                        "type": "supply_chain",
                        "url": url,
                        "evidence": (
                            f"THREAT ALERT: {alert.get('name', 'unknown')} | "
                            f"Severity: {alert.get('severity', '?')} | "
                            f"Source: {alert.get('source_url', '')}"
                        ),
                        "severity": alert.get("severity", "high"),
                    })
                    log.warning(
                        "[SupplyChain] THREAT ALERT MATCH: %s at %s",
                        alert.get("name", ""), url,
                    )

    return findings


def _write_supply_chain_findings(
    findings: list[dict],
    run_id: str,
    raw_output_dir: Path,
    filename: str = "supply_chain_analysis.json",
) -> None:
    from datetime import datetime, timezone
    doc = {
        "schema_version": "1.0",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "run_id": run_id,
        "tool_name": "supply_chain_analyzer",
        "tool_version": "1.0.0",
        "invocation_command": "supply_chain_analyzer (internal)",
        "target": "crawled JS assets",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "duration_seconds": 0,
        "status": "success",
        "findings": [
            {
                "type": f.get("type", "supply_chain"),
                "url": f.get("url", ""),
                "evidence": f.get("evidence", ""),
                "raw_output": f,
                "metadata": {"severity": f.get("severity", "medium")},
            }
            for f in findings
        ],
        "errors": [],
    }
    out_path = raw_output_dir / filename
    with open(out_path, "w") as f_out:
        json.dump(doc, f_out, indent=2)


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
