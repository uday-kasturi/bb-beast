"""
McDonald's VDP — ZAP + Fable 5 targeted scan runner.

Usage:
    python scan_mcdonalds.py [target] [depth]

    target: URL to scan (default: runs against all priority targets)
    depth:  quick | standard | exhaustive (default: standard)

Examples:
    python scan_mcdonalds.py https://admin.me.mcd.com standard
    python scan_mcdonalds.py https://admin.staging.me.mcd.com quick
    python scan_mcdonalds.py all standard
"""

import json
import logging
import sys
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)

RUN_DIR = Path("runs/mcdonalds.com/2026-07-02_19-54_53b2c0b0")
PROGRAM_FILE = Path("programs/mcdonalds.json")

# Priority targets for ZAP + Fable 5 — ordered by exploitability potential
PRIORITY_TARGETS = [
    # Admin panels (highest value — exposed without network restriction)
    "https://admin.me.mcd.com",
    "https://admin.staging.me.mcd.com",
    "https://dnaadmin-dev.mcd.com",

    # Credential admin (found in dnsx — unknown what this is)
    "https://aagcredentialadmin.mcdonalds.com",

    # APIs (look for unauth endpoints, IDOR)
    "https://eu-prod.api.mcd.com",
    "https://us-prod.api.mcd.com",
    "https://ap-prod.api.mcd.com",

    # Marketing platform
    "https://me.mcd.com",

    # Dev/staging analytics (usually weaker auth)
    "https://alchemyinsight-dev.mcd.com",
]


def load_program() -> dict:
    with open(PROGRAM_FILE) as f:
        return json.load(f)


def run_target(target: str, depth: str, program: dict) -> None:
    from core.zap_fable import ZapFableScanner

    print(f"\n{'='*60}")
    print(f"TARGET: {target}")
    print(f"DEPTH:  {depth}")
    print(f"{'='*60}\n")

    scanner = ZapFableScanner(program=program, run_dir=RUN_DIR)
    findings = scanner.scan(target=target, depth=depth)

    if not findings:
        print(f"  [~] No findings for {target}\n")
        return

    print(f"\n  [+] {len(findings)} finding(s) for {target}:")
    for f in findings:
        sev = f.severity_raw.upper()
        print(f"    [{sev}] {f.type} — {f.url}")
        title = f.raw_output.get("title", "")
        if title:
            print(f"           {title}")
        impact = f.raw_output.get("impact", "")
        if impact:
            print(f"           Impact: {impact[:120]}")

    # Append to run findings file
    out_file = RUN_DIR / "zap_fable_findings.json"
    existing = []
    if out_file.exists():
        try:
            existing = json.loads(out_file.read_text())
        except Exception:
            pass

    for f in findings:
        existing.append({
            "finding_id": f.finding_id,
            "type": f.type,
            "severity_raw": f.severity_raw,
            "url": f.url,
            "host": f.host,
            "evidence": f.evidence,
            "tool": f.tool,
            "confidence": f.confidence,
            "raw_output": f.raw_output,
        })

    out_file.write_text(json.dumps(existing, indent=2))
    print(f"\n  [+] Appended to {out_file}")


def main() -> None:
    program = load_program()
    depth = "standard"
    targets = []

    args = sys.argv[1:]
    if not args or args[0] == "all":
        targets = PRIORITY_TARGETS
        if len(args) > 1:
            depth = args[1]
    else:
        targets = [args[0]]
        if len(args) > 1:
            depth = args[1]

    print(f"\nMcDonald's VDP — ZAP + Fable 5 scan")
    print(f"Targets: {len(targets)}")
    print(f"Depth: {depth}")
    print(f"Run dir: {RUN_DIR}\n")

    for target in targets:
        try:
            run_target(target, depth, program)
        except KeyboardInterrupt:
            print("\n[!] Interrupted")
            sys.exit(0)
        except Exception as exc:
            print(f"  [!] Error scanning {target}: {exc}")

    print(f"\n[+] Scan complete. Check {RUN_DIR}/zap_fable_findings.json")


if __name__ == "__main__":
    main()
