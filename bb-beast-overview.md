# BugBounty Beast (bb-beast)

A modular, AI-assisted bug bounty automation tool built in Python. You point it at a target, it runs a full vulnerability scanning pipeline, and Claude triages the findings so you know exactly what's worth pursuing.

---

## The Core Idea

Most bug bounty hunters run tools manually, copy-paste output, and spend hours deciding what matters. bb-beast automates the boring parts:

1. **You invoke it** with a target domain
2. **It runs playbooks** — sequenced chains of security tools (subfinder, nuclei, ffuf, etc.)
3. **All output is normalized** into a unified JSON format
4. **Claude triages the findings** — decides what's exploitable, assigns severity, explains why
5. **You get an action list** — structured next steps ranked by priority
6. **Burp / ZAP gets fed** the interesting targets for deeper scanning

You stay in the loop for judgment calls. The tool handles the grunt work.

---

## What's Been Built

### Core Pipeline (`core/`)
| File | What it does |
|------|--------------|
| `engine.py` | Orchestrates everything — discovers playbooks, runs them in dependency order, manages the run lifecycle |
| `validator.py` | Validates every JSON file against its schema before passing it downstream. Hard stops on schema violations |
| `llm.py` | Sends `findings.json` to Claude API, parses the response into `triage.json` |
| `patcher.py` | Reads `playbook_patch.json` files from `/patches/` and applies them to playbooks |
| `confidence.py` | Confidence decay system — techniques that don't produce findings lose confidence over time |
| `export.py` | Export helpers for run results |
| `triage_import.py` | Imports and processes triage responses |

### Tool Wrappers (`tools/`)
One file per tool. Each handles invocation, output parsing, and normalization into `raw_output/[tool].json` schema.

All wrappers inherit from `ToolWrapper` (god node: 87 edges in the knowledge graph), which provides `run()`, `_auth_headers()`, `_auth_cookies()`, `sanitize_urls()`, scope checking, and rate-limit jitter.

**Recon & Discovery**
- `subfinder.py` — passive subdomain enumeration
- `amass.py` — active subdomain enumeration
- `assetfinder.py` — subdomain discovery via cert transparency + DNS
- `httpx.py` — probe live hosts, grab tech fingerprints, status codes
- `dnsx.py` — DNS resolution and brute-forcing
- `waybackurls.py` — historical URLs from Wayback Machine
- `gau.py` — known URLs from AlienVault OTX, Wayback, Common Crawl
- `katana.py` — deep web crawling
- `gowitness.py` — screenshots of discovered assets

**Scanning & Fuzzing**
- `nuclei.py` — CVE + misconfiguration templates (run `nuclei -update-templates` before scans)
- `ffuf.py` — directory and parameter fuzzing
- `feroxbuster.py` — recursive content discovery
- `sqlmap.py` — SQL injection
- `dalfox.py` — XSS scanning
- `commix.py` — command injection
- `nikto.py` — web server misconfiguration
- `wpscan.py` — WordPress-specific scanning
- `trufflehog.py` — secrets in repos and files
- `gitleaks.py` — secrets scanning
- `interactsh.py` — out-of-band interaction detection (OAST)

**Network & Infrastructure**
- `nmap.py` — port scanning with NSE scripts
- `masscan.py` — fast port discovery
- `naabu.py` — port scanning optimized for bug bounty

**Cloud**
- `s3scanner.py` — exposed S3 bucket detection

### Playbooks (`playbooks/`)
Each playbook is a folder with a `playbook_manifest.json` (metadata, dependencies, depth config) and a `chain.py` (the tool sequence).

| Playbook | What it hunts |
|----------|---------------|
| `recon` | Asset discovery — runs first, everything else depends on it |
| `exposure` | Secrets, misconfigs, open directories |
| `injection` | SQLi, XSS, SSTI, command injection |
| `auth` | IDOR, broken auth, JWT issues, OAuth flaws |
| `infra` | Open ports, outdated services, CVEs |
| `cloud` | S3, GCP, Azure misconfigs |
| `takeover` | Subdomain and service takeovers |
| `supply_chain` | Third-party JS/CSS includes, SRI checks, known bad CDNs |

### Execution Engine (`execution/`)
- `executor.py` — reads `actions.json`, runs follow-up tool calls automatically or flags items for human review

### Burp / ZAP Integration (`burp/`)
- `integration.py` — Burp Suite REST API: feeds validated targets, pulls scan results back into pipeline
- `zap_integration.py` — OWASP ZAP integration as the active scanner
- `scripts/start_zap.sh` — starts ZAP in headless daemon mode

### Schemas (`schemas/`)
All 9 JSON schemas, fully defined with `schema_version` and strict required fields:

```
program.schema.json           — target program definition (scope, platform, rules)
playbook_manifest.schema.json — playbook metadata and config
raw_output.schema.json        — normalized output from a single tool
findings.schema.json          — unified findings across all tools in a run
triage.schema.json            — Claude's verdicts on each finding
actions.schema.json           — structured next steps for the execution engine
playbook_patch.schema.json    — patches derived from disclosures
threat_alert.schema.json      — hot intel injected into active scans
run_manifest.schema.json      — full audit trail for a single invocation
```

`SchemaValidationError` is the third most-connected node in the codebase (47 edges) — schema enforcement is a load-bearing cross-cutting concern throughout the pipeline.

---

## Knowledge Graph (graphify)

The codebase has a Graphify knowledge graph at `graphify-out/`. Generated 2026-04-24.

**Stats:** 741 nodes · 1,421 edges · 53 communities · 137 files · ~287K words

**To navigate the codebase architecturally, read `graphify-out/GRAPH_REPORT.md` first** — it surfaces god nodes, community structure, and surprising connections that grep won't find.

### God Nodes (most connected abstractions)
| Node | Edges | Significance |
|------|-------|--------------|
| `ToolWrapper` | 87 | Base class for all 25 tool wrappers — the entire scanning layer |
| `run()` | 59 | Cross-community bridge: ties recon chain, core engine, Burp/ZAP, auth layer |
| `SchemaValidationError` | 47 | Enforcement point between every pipeline stage |
| Recon `chain.py` stage map | 30 | Entry point for the most-used playbook |
| `ZapIntegration` | 19 | Active scanner integration hub |
| `_is_in_scope()` | 19 | Scope gate — called before every tool invocation |
| `NucleiWrapper` | 18 | Most-referenced scanner wrapper |
| `InteractshWrapper` | 18 | OAST coordination for blind vulns |
| `DnsxWrapper` | 17 | DNS layer — feeds host resolution to rest of pipeline |
| `BurpIntegration` | 17 | Passive scanner output hub |

### Key Communities
- **Recon Tool Wrappers** (62 nodes) — all the individual scanner wrappers
- **Core Engine & Orchestration** (107 nodes) — commands, lifecycle, LLM triage
- **Base Tool Architecture** (72 nodes) — `ToolWrapper`, auth base classes, scope checking
- **Burp/ZAP & Execution Engine** (34 nodes) — output routing and follow-up
- **Browser XSS Methodology** (10 nodes) — headless browser + OAST confirmation loop

### Attack Chain Hyperedges (extracted from research notes)
The graph also captures bug bounty research across active targets:

- **AIRPortal chain** — DomainData disclosure + email enum + stored XSS → admin session takeover (`maryland_01` through `maryland_08`)
- **MPEL chain** — SSRF via vendor URL + stored XSS via `javascript:` URI → IMDS credential exfiltration
- **Antigravity one-click RCE** — URL scheme trust bypass + `runOn:folderOpen` task + `mcp_config.json` persistence
- **Antigravity language server LPE** — ps aux CSRF leak + unrestricted ReadFile/WriteFile/ExecuteCommand
- **CDT MCP DNS rebind** — port scan → rebind → no-auth MCP access → JS exec + arbitrary file write
- **MCP RCE surface** — env injection + malicious `.mcp.json` → `child_process.spawn` with unsanitized args

---

## Data Flow

```
You run: python bb.py --target example.com --playbook recon

[engine.py]
  → discovers all playbooks
  → checks scope (program.json) — abort if out of scope
  → runs playbooks in dependency order

[each playbook chain.py]
  → calls tool wrappers in sequence
  → each wrapper writes: runs/{target}/{run-id}/raw_output/{tool}.json
  → validator.py checks schema before passing downstream

[findings.json]
  → aggregated across all tools in the run
  → each finding has: type, severity, URL, evidence, tool, confidence score

[llm.py → Claude API]
  → sends findings.json
  → gets back: verdict (exploitable/not/needs_more_info/false_positive),
               adjusted severity, reasoning, suggested next steps
  → writes triage.json

[actions.json]
  → derived from triage.json
  → each action: type (run_tool / burp_scan / flag_for_human / skip),
                 exact params, priority 1-5, risk estimate

[executor.py]
  → runs low-risk automated follow-ups
  → feeds burp/zap_integration.py with confirmed targets
  → flags high-judgment items for you
```

---

## The Self-Heal Loop

Playbooks improve themselves over time — but under your control:

```
1. You read an interesting bug bounty disclosure or CVE writeup
2. You paste it into Claude (chat, not Claude Code)
3. Claude outputs a playbook_patch.json
4. You review it and drop it in /patches/
5. Engine picks it up on next run, applies the patch
6. Git commits it automatically with the source URL as the message
```

All patches are version controlled. Every technique has a confidence score that decays if it stops producing findings — this prevents playbooks from becoming bloated with stale techniques. New intel that confirms a technique bumps the score back up.

---

## Confidence Decay

Every technique in a playbook has a confidence score (0.0–1.0). Each run where it finds nothing, the score drops slightly. When it does find something, it resets high. Below a threshold, the technique gets flagged for review rather than running automatically.

This solves the "bloated playbook" problem that kills most long-running automation setups.

---

## Active Hunting Status

### Maryland VDP (`*.maryland.gov` — Bugcrowd, non-monetary)

| # | Target | Finding | Severity |
|---|--------|---------|----------|
| 01 | airportal.maa.maryland.gov | Unauth GET /api/DomainData → 217KB org data | Medium |
| 02 | maa.maryland.gov | PHP 7.4.33 EOL, 30+ plugin namespaces, wp-cron public | Low |
| 03 | airportal.maa.maryland.gov | Stored XSS via unauth POST /api/PendingUser → fires in admin | High |
| 04 | airportal.maa.maryland.gov | Email user enum via /api/PendingUser/email/check, no rate limit | Medium |
| 05 | apps.roads.maryland.gov | Stored XSS via `javascript:` URI in vendor website (MPEL) | Medium |
| 06 | apps.roads.maryland.gov | User enum via differential login response (MPEL) | Low |
| 07 | apps.roads.maryland.gov | Blind SSRF via vendor URL → AWS IMDS confirmed | High |
| 08 | airportal.maa.maryland.gov | Stored XSS resubmission with callback proof + hardcoded AES key | High |

### Henkel (`*.portalehenkel.it` — HackerOne)

| # | Target | Finding | Severity |
|---|--------|---------|----------|
| 01 | loctite.it | Logout redirect to expired domain | Low |
| 02 | pss.raqn.io | Spring Boot actuator endpoints unauth | Medium |
| 03 | martech API | Swagger UI unauthenticated | Low |
| 04 | supplier portal | User enum via response diff | Medium |
| 05 | formazione.portalehenkel.it | 8 endpoints leak /var/www path + phpcraft framework | Low |
| 06 | formazione.portalehenkel.it | User enum + no rate limit; admin confirmed | Medium |
| 07 | formazione.portalehenkel.it | Missing X-Frame-Options/CSP; PHPSESSID no HttpOnly/Secure/SameSite | Low |

### Google Antigravity (VRP)
Research in `research/antigravity/`. Key reference: `04-code-understanding.md`.
- Electron 39.2.3, CDT MCP on `127.0.0.1:{random}` with no auth, language server via named pipe at `/tmp/server_[16 hex]`
- Reports written but mostly have preconditions or dwell-time issues — see trust boundary memory
- Next surfaces: `antigravity://` scheme beyond `file/`, CDT MCP port leakage via newtab override

---

## Infrastructure

**Now (development):**
- Runs locally on macOS
- Test targets: DVWA, VulnHub machines, HackTheBox, intentionally vulnerable apps
- ZAP runs in headless daemon mode locally

**Later (production):**
- Hetzner VPS (€8–15/month) as the scanning node — it takes the heat
- Mac stays as the orchestrator, communicates via SSH
- Residential proxies (Bright Data, pay-as-you-go) only if a target is actively blocking

---

## Target Programs

Non-monetary / hall of fame only during F-1 student status:
- Google VRP
- Microsoft MSRC
- Apple Security
- Meta
- GitHub Security
- US Government / CISA federal agency programs (`.gov` scope)

---

## How to Run

```bash
# Basic scan
python bb.py --target example.com

# Specific playbook
python bb.py --target example.com --playbook injection

# Exhaustive depth
python bb.py --target example.com --depth exhaustive

# Resume a previous run
python bb.py --run-id <uuid>
```

Programs are defined as JSON files in `/programs/`. The engine checks scope before running any tool — if the target isn't in scope it refuses to proceed.

---

## File Structure

```
bb-beast/
├── bb.py                        # Entry point
├── core/
│   ├── engine.py                # Orchestrator
│   ├── validator.py             # Schema validation
│   ├── llm.py                   # Claude API triage
│   ├── patcher.py               # Applies playbook patches
│   └── confidence.py            # Confidence decay
├── playbooks/
│   ├── recon/
│   ├── exposure/
│   ├── injection/
│   ├── auth/
│   ├── infra/
│   ├── cloud/
│   ├── takeover/
│   └── supply_chain/
├── tools/                       # One wrapper per tool (25 tools)
├── execution/
│   └── executor.py
├── burp/
│   ├── integration.py           # Burp REST API
│   └── zap_integration.py       # ZAP integration
├── schemas/                     # 9 JSON schemas
├── programs/                    # One program.json per target
├── patches/                     # Drop playbook_patch.json here
├── runs/                        # Output: one folder per run
│   └── {target}/{date}_{id}/
│       ├── run_manifest.json
│       ├── findings.json
│       ├── triage.json
│       ├── actions.json
│       └── raw_output/
├── alerts/                      # threat_alert.json files
├── graphify-out/                # Knowledge graph (read GRAPH_REPORT.md first)
│   ├── GRAPH_REPORT.md          # God nodes, communities, hyperedges
│   ├── graph.html               # Interactive visualization
│   └── graph.json               # Raw graph data
└── research/
    └── antigravity/             # Google VRP research notes
        ├── 04-code-understanding.md  # PRIMARY reference — read this, not source
        ├── 03-attack-plan.md
        ├── 02-security-analysis.md
        ├── 01-app-structure.md
        └── 00-prior-research-strategies.md
```

---

## Key Design Decisions

**LLM is expensive — use it sparingly.** Fast dumb tools do the scanning. Claude only gets called once per run, on the aggregated `findings.json`. It never sees raw tool output directly.

**Schema-first.** Every file that crosses a pipeline boundary has a versioned JSON schema. The validator runs before anything is passed downstream. A malformed file hard-stops the run rather than silently corrupting results.

**Human in the loop for judgment.** The tool surfaces and prioritizes. You decide what to exploit. Actions that require judgment get flagged to you, not auto-executed.

**Modular by design.** Adding a new tool = one new file in `/tools/`. Adding a new playbook = one new folder in `/playbooks/`. Nothing else changes.

**Use the graph for architecture questions.** Before grepping or re-reading source files, check `graphify-out/GRAPH_REPORT.md`. The god nodes and community structure tell you where to look. The hyperedges map multi-step attack chains across research notes. Run `graphify update .` after modifying code files to keep it current.
