"""
Rules-based confidence scoring for findings.
No LLM involved. These run fast at aggregation time.

Confidence is a float from 0.0 to 1.0.
Factors considered:
  - Finding type (some types are inherently noisier)
  - Evidence quality signals (presence of response body, match strings, etc.)
  - Tool reliability weight (some tools produce more false positives than others)
  - Whether the finding has a PoC or match string
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Per-type base confidence scores
# ---------------------------------------------------------------------------

_TYPE_BASE: dict[str, float] = {
    # High signal — very few false positives when properly evidenced
    "rce":                  0.85,
    "sqli":                 0.75,
    "ssrf":                 0.80,
    "xxe":                  0.75,
    "ssti":                 0.75,
    "command_injection":    0.80,
    "path_traversal":       0.70,
    "subdomain_takeover":   0.90,  # CNAME check is binary
    "exposed_s3":           0.90,  # bucket existence is binary
    "secret_exposure":      0.80,
    "lfi":                  0.70,

    # Medium signal — common false positives
    "xss":                  0.60,
    "open_redirect":        0.65,
    "csrf":                 0.55,
    "idor":                 0.60,
    "misconfiguration":     0.60,
    "auth_bypass":          0.65,
    "jwt_weakness":         0.70,

    # Informational — almost always accurate but low exploitability signal
    "open_port":            0.95,
    "subdomain":            0.98,
    "tech_detection":       0.90,
    "historical_url":       0.95,
    "dns_record":           0.98,
}

_DEFAULT_BASE = 0.50


# ---------------------------------------------------------------------------
# Per-tool reliability multipliers
# ---------------------------------------------------------------------------

_TOOL_WEIGHT: dict[str, float] = {
    # Active scanners with template matching — fairly reliable
    "nuclei":       1.00,

    # Passive enumeration — always accurate
    "subfinder":    1.00,
    "amass":        1.00,
    "assetfinder":  1.00,
    "dnsx":         1.00,

    # Live probing — accurate
    "httpx":        1.00,
    "nmap":         0.98,
    "masscan":      0.95,  # can have open-port false positives at high speed
    "naabu":        0.97,

    # Historical URL tools — URLs may no longer exist
    "waybackurls":  0.80,
    "gau":          0.80,

    # Fuzzing tools — high false positive rate without manual confirmation
    "ffuf":         0.65,
    "feroxbuster":  0.65,

    # Injection scanners — medium confidence, need confirmation
    "sqlmap":       0.85,
    "dalfox":       0.80,
    "commix":       0.80,

    # Web server scanner — notoriously noisy
    "nikto":        0.55,

    # WordPress scanner
    "wpscan":       0.75,

    # Secrets scanners — high precision if pattern matched
    "trufflehog":   0.85,
    "gitleaks":     0.85,

    # Cloud scanners — accurate
    "s3scanner":    0.95,
    "cloudenum":    0.80,
    "prowler":      0.85,
}

_DEFAULT_TOOL_WEIGHT = 0.70


# ---------------------------------------------------------------------------
# Public function
# ---------------------------------------------------------------------------

def score_finding(finding_type: str, item: dict, raw_doc: dict) -> float:
    """
    Compute a confidence score for a single finding.

    Args:
        finding_type: The normalized finding type string.
        item:         The raw finding dict from the tool output.
        raw_doc:      The full raw_output document (for tool name, status).

    Returns:
        Float between 0.0 and 1.0.
    """
    base = _TYPE_BASE.get(finding_type, _DEFAULT_BASE)
    tool = raw_doc.get("tool_name", "")
    weight = _TOOL_WEIGHT.get(tool, _DEFAULT_TOOL_WEIGHT)

    score = base * weight

    # Bonus: finding has explicit match / proof string
    raw_output = item.get("raw_output")
    evidence = item.get("evidence", "")
    if raw_output and isinstance(raw_output, dict):
        if raw_output.get("matched_at") or raw_output.get("match"):
            score = min(score + 0.05, 1.0)
        if raw_output.get("curl_command") or raw_output.get("poc"):
            score = min(score + 0.05, 1.0)

    # Bonus: evidence string is substantive (> 30 chars)
    if len(evidence) > 30:
        score = min(score + 0.03, 1.0)

    # Penalty: tool run was only partial
    if raw_doc.get("status") == "partial":
        score = max(score - 0.10, 0.0)

    # Penalty: no URL or host — we can't do anything with it
    has_target = bool(item.get("url") or item.get("host") or item.get("ip"))
    if not has_target:
        score = max(score - 0.15, 0.0)

    return round(score, 3)
