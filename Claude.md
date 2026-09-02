# BugBounty Beast — Project Context for Claude Code

## What This Project Is
A modular, plugin-based bug bounty automation tool that:
1. Runs deep, exhaustive vulnerability scanning playbooks
2. Normalizes all tool output into a unified JSON format
3. Uses Claude (via API) to triage findings and decide what's worth pursuing
4. Produces structured action items the execution engine can act on
5. Integrates with Burp Suite for deeper investigation
6. Has a self-heal loop where manually-fed bug bounty disclosures improve playbooks over time

The operator (human) invokes the tool manually. It is NOT a 24/7 background daemon.

---

## Core Design Principles
- **Modular and plugin-based** — adding a new playbook or tool means dropping files in a folder, nothing else changes
- **LLM is expensive, use it sparingly** — dumb fast tools do the scanning, Claude only gets called when there's something worth thinking about
- **Strict JSON schemas with versioning** — every file that passes between pipeline stages has a defined schema with a `schema_version` field, and a validator runs before anything is passed downstream
- **Parsers run independently** — Claude Code builds and tests normalizers once during development, they run without LLM involvement at runtime
- **Human in the loop for judgment calls** — the tool surfaces findings, the human decides what to exploit further
- **Local first** — everything runs on macOS locally during development, Hetzner VPS added later for production scanning

---

## Pipeline Architecture

```
[Human invokes]
      ↓
[Core Engine] — discovers and runs playbooks automatically
      ↓
[Playbook] — calls tool wrappers in sequence
      ↓
[Tool Wrappers] — each wraps a real tool, handles invocation + output normalization
      ↓
[raw_output/[tool].json] — normalized output per tool per run
      ↓
[findings.json] — unified findings aggregated across all tools in a playbook run
      ↓
[LLM Triage — Claude API] — decides what's interesting, assigns severity, reasons about exploitability
      ↓
[triage.json] — LLM verdicts on each finding
      ↓
[actions.json] — structured next steps the execution engine can act on
      ↓
[Execution Engine] — reads actions.json, runs follow-up tool calls or flags for human
      ↓
[Burp Suite Integration] — feeds validated targets into Burp for deeper scanning

Separate self-heal loop (manual, not automated):
[Human reads disclosure] → [Paste to Claude in chat] → [Claude outputs playbook_patch.json] → [Drop in /patches] → [Engine picks up on next run]
```

---

## The 9 JSON Schemas to Build

Every schema needs:
- `schema_version` field (start at "1.0")
- `created_at` timestamp (ISO 8601)
- Strict required fields
- A corresponding validator

### 1. `program.json`
Describes the target bug bounty program.
- Program name, platform (HackerOne, Bugcrowd, etc.)
- In-scope assets (domains, IPs, endpoints, mobile apps)
- Out-of-scope assets — critical, playbooks must check this before running
- Allowed test types (no SQLi, no DoS, etc.)
- Program URL, hall of fame / non-monetary flag
- Contact info

### 2. `playbook_manifest.json`
Metadata file inside each playbook folder.
- Playbook name, version, description
- Target type (web, network, cloud, etc.)
- Tool dependencies (list of tools required)
- Playbook dependencies (e.g. recon must run before injection)
- Depth levels: `quick`, `standard`, `exhaustive`
- Throttling config — requests per second, jitter range
- Confidence threshold for escalating to LLM
- Author, created_at, last_updated

### 3. `raw_output/[tool].json`
Normalized output from a single tool in a single run.
- Tool name, version, invocation command
- Target
- Run timestamp, duration
- Status (success / partial / failed)
- Raw findings array — each item has type, url/host, evidence, raw_output
- Error log if failed

### 4. `findings.json`
Unified findings aggregated across all tools in a playbook run.
- Run ID (uuid)
- Program reference
- Playbook that generated it
- Timestamp
- Findings array — each finding has:
  - Finding ID (uuid)
  - Type / vulnerability class
  - Severity raw (from tool)
  - URL / host / endpoint
  - Evidence
  - Tool that found it
  - Confidence score (0.0 - 1.0, rules-based, no LLM)
  - Raw tool output reference
- Summary stats (total findings, by severity, by type)

### 5. `triage.json`
LLM's analysis of findings.json. Input to actions.json generation.
- Run ID reference
- Model used, timestamp
- Per-finding verdicts:
  - Finding ID reference
  - Verdict: `exploitable` / `not_exploitable` / `needs_more_info` / `false_positive`
  - Reasoning (LLM explanation)
  - Adjusted severity (CVSS-style: critical/high/medium/low/info)
  - Impact description
  - Suggested next steps (human readable)
- Overall run summary

### 6. `actions.json`
Structured next steps the execution engine can act on. Derived from triage.json.
- Run ID reference
- Actions array — each action has:
  - Action ID (uuid)
  - Finding ID reference
  - Action type: `run_tool` / `burp_scan` / `flag_for_human` / `skip`
  - Tool to run (if applicable)
  - Exact parameters / flags
  - Priority (1-5)
  - Estimated risk level (to avoid accidental out-of-scope actions)
- Burp tasks array:
  - Target URL
  - Scan type
  - Config profile

### 7. `playbook_patch.json`
Output when human pastes a disclosure into Claude and asks for a patch.
- Source (URL or description of the disclosure)
- Date of disclosure
- Target playbook(s) to patch
- Patch type: `new_payload` / `new_step` / `update_tool_flag` / `new_playbook` / `deprecate_technique`
- Change description (human readable)
- Exact change (machine readable — what to add/modify/remove)
- Confidence score
- Requires human review flag (true/false)
- Schema version of target playbook

### 8. `threat_alert.json`
Hot intelligence injected immediately into scans. For supply chain vulns, active CVEs, etc.
- Alert ID (uuid)
- Name
- Type: `supply_chain` / `cve` / `active_exploitation` / `new_technique`
- Severity
- Affected indicator (domain, package name, CDN URL, etc.)
- Detection method (what to look for)
- Which playbook to inject into
- Auto-check flag (true = run automatically, false = flag for human first)
- Expiry date (when to stop checking for this)
- Source URL

### 9. `run_manifest.json`
Audit trail for a single invocation end to end.
- Run ID (uuid)
- Program reference
- Invoked by (human operator identifier)
- Start time, end time, duration
- Playbooks run (list with status per playbook)
- Tools invoked (list with status per tool)
- Output file locations (findings.json path, triage.json path, actions.json path)
- LLM calls made (count, model, total tokens approximate)
- Errors encountered
- Overall run status: `complete` / `partial` / `failed`

---

## Tool Stack (to build wrappers + normalizers for)

### Recon & Discovery
- `amass` — subdomain enumeration
- `subfinder` — passive subdomain discovery
- `assetfinder` — subdomain discovery
- `httpx` — probe live hosts, tech detection
- `dnsx` — DNS resolution and bruteforcing
- `waybackurls` — historical URLs
- `gau` — fetch known URLs from AlienVault, Wayback, Common Crawl
- `katana` — deep crawling
- `gowitness` — screenshots of discovered assets

### Scanning & Fuzzing
- `nuclei` — vulnerability templates (CVEs, misconfigs, exposures)
- `ffuf` — directory and parameter fuzzing
- `feroxbuster` — recursive content discovery
- `sqlmap` — SQL injection
- `dalfox` — XSS scanning
- `commix` — command injection
- `nikto` — web server misconfiguration
- `wpscan` — WordPress specific
- `trufflehog` — secrets in repos and files
- `gitleaks` — secrets scanning

### Network & Infrastructure
- `nmap` with NSE scripts — port scanning, service detection
- `masscan` — fast port discovery
- `naabu` — port scanning optimized for bug bounty

### Cloud & Misconfiguration
- `cloudenum` — cloud asset discovery
- `s3scanner` — exposed S3 buckets
- `prowler` — AWS/GCP/Azure misconfiguration

### Burp Suite
- Burp REST API integration
- Feed discovered URLs as target list
- Pull scan results back into pipeline

---

## Playbook Families to Build

Each playbook lives in `/playbooks/[name]/` with its own `playbook_manifest.json` and tool chain definition.

1. `recon` — asset discovery, always runs first, everything else depends on it
2. `exposure` — secrets, misconfigs, open directories
3. `injection` — SQLi, XSS, SSTI, command injection
4. `auth` — IDOR, broken auth, JWT issues, OAuth flaws
5. `infra` — open ports, outdated services, CVEs
6. `cloud` — S3, GCP, Azure misconfigs
7. `takeover` — subdomain and service takeovers
8. `supply_chain` — third party JS/CSS includes, SRI checks, known bad CDNs

---

## Self-Heal Loop (Manual, Not Automated)

1. Human reads an interesting bug bounty disclosure or threat report
2. Human pastes it into Claude (chat, not Claude Code)
3. Claude outputs a `playbook_patch.json`
4. Human reviews and drops it in `/patches/` folder
5. Core engine picks it up on next run and applies the patch
6. Git commit is made automatically with the source as the commit message

All patches are version controlled. Rollback is always possible.

---

## Confidence Decay System

Playbook techniques have a confidence score that decays over time if they haven't produced findings. New intel that confirms a technique still works bumps it back up. This prevents playbooks becoming bloated with stale techniques.

---

## Infrastructure

**Current (development):** Everything runs locally on macOS. Test against local vulnerable VMs (DVWA, VulnHub, HackTheBox) or intentionally vulnerable targets. Use a VPN during testing if concerned about IP exposure.

**Future (production):** Hetzner VPS as scanning node (€8-15/month), Mac as orchestrator. Mac communicates with VPS via SSH. VPS takes the heat, Mac stays clean. Residential proxies (Bright Data, pay-as-you-go) only if a specific target is actively blocking.

---

## Target Programs

Non-monetary / hall of fame programs only during F-1 student status:
- Google VRP
- Microsoft MSRC
- Apple Security
- Meta
- GitHub Security
- US Government / CISA federal agency programs

---

## What Claude Code's Job Is

1. **Build and test all 9 JSON schemas** with strict validation and versioning
2. **Build the validator module** that runs before any file passes between pipeline stages
3. **Build tool wrappers** — one per tool, handles invocation and output normalization into `raw_output/[tool].json` schema
4. **Build the core engine** — discovers playbooks, runs them in dependency order, orchestrates the pipeline
5. **Build the LLM triage layer** — sends findings.json to Claude API, parses response into triage.json
6. **Build the execution engine** — reads actions.json, runs follow-up tools or flags for human
7. **Build Burp integration** — feeds targets in, pulls results back into pipeline
8. **Build the patch system** — reads playbook_patch.json files from /patches and applies them

---

## Build Order (Do Not Skip Steps)

1. JSON schemas + validator
2. Core engine (discovers and runs playbooks, nothing else)
3. `recon` playbook (everything depends on this)
4. Tool wrappers for: `subfinder`, `httpx`, `nuclei` (prove the pipeline end to end)
5. LLM triage layer
6. Execution engine
7. Remaining tool wrappers
8. Remaining playbooks
9. Burp integration
10. Patch system + self-heal loop

---

## Project Folder Structure

```
bugbounty-beast/
├── CLAUDE.md                  # This file
├── core/
│   ├── engine.py              # Core orchestrator
│   ├── validator.py           # JSON schema validator
│   └── llm.py                 # LLM triage layer
├── playbooks/
│   ├── recon/
│   │   ├── playbook_manifest.json
│   │   └── chain.py
│   ├── exposure/
│   ├── injection/
│   ├── auth/
│   ├── infra/
│   ├── cloud/
│   ├── takeover/
│   └── supply_chain/
├── tools/
│   ├── subfinder.py           # Tool wrapper + normalizer
│   ├── httpx.py
│   ├── nuclei.py
│   └── [one file per tool]
├── execution/
│   └── executor.py            # Reads actions.json, runs next steps
├── burp/
│   └── integration.py         # Burp REST API integration
├── patches/                   # Drop playbook_patch.json files here
├── schemas/                   # All 9 JSON schemas + validators
├── runs/                      # Output folder, one subfolder per run (uuid)
│   └── [run-uuid]/
│       ├── run_manifest.json
│       ├── findings.json
│       ├── triage.json
│       ├── actions.json
│       └── raw_output/
│           ├── subfinder.json
│           ├── httpx.json
│           └── nuclei.json
├── programs/                  # One program.json per target
└── alerts/                    # threat_alert.json files live here
```

---

## Google Antigravity Security Research (Google VRP)

Research files live in `research/antigravity/`. **Read those files instead of re-reading app source code.** The minified JS files (3-11MB each) are token sinks — all useful info is already extracted.

### Key Files
- `04-code-understanding.md` — file-by-file understanding of every readable source file (THE primary reference)
- `03-attack-plan.md` — attack plan (needs rewrite grounded in code understanding)
- `02-security-analysis.md` — security analysis (needs rewrite)
- `01-app-structure.md` — app layout, paths, URLs
- `00-prior-research-strategies.md` — known bugs, prior research

### Architecture (from code reading, not grep)
- **Electron 39.2.3** app, forked from VS Code/Windsurf, codename "Jetski"
- **Main process**: `out/main.js` (11.8MB minified) — window mgmt, IPC, protocol registration
- **AI chat UI**: `out/jetskiAgent/main.js` (11.2MB minified) — React/Redux/Lexical in separate BrowserWindow
- **Language server**: `extensions/antigravity/bin/language_server_macos_arm` (143MB Go binary)
  - IPC via Unix named pipe at `/tmp/server_[16 hex chars]`
  - Connect RPC + protobuf over pipe
  - Talks to `cloudcode-pa.googleapis.com`
- **CDT MCP server**: `extensions/chrome-devtools-mcp/` — HTTP MCP on `127.0.0.1:{random}`, NO auth
  - Controls Chrome via CDP/Puppeteer
  - Tools: evaluate_script, upload_file, take_screenshot, saveFile — several have NO path validation
- **Sandbox**: `extensions/antigravity/bin/sandbox-wrapper.sh` — macOS Seatbelt
  - Base: `(allow default)` then layered denies — permissive starting point
  - Allows writes to workspace subpath + /tmp — **Seatbelt follows symlinks**
  - Network denied by default, `--allow-network` flag enables
- **Extension**: `extensions/antigravity/dist/extension.js` (3MB minified) — runs in untrusted workspaces
  - OAuth via localhost HTTP server, `antigravity://` deep link callback
  - MCP config at `~/.gemini/antigravity/mcp_config.json` (644 perms, arbitrary commands, plaintext secrets)

### Communication Flow
```
User → Cascade UI → Connect RPC (protobuf) → named pipe → language_server → Google Cloud API
Language Server → MCP servers (via mcp_config.json)
Language Server → Chrome DevTools MCP → Chrome (via CDP)
Language Server → Terminal → Optional sandbox-wrapper.sh
```

### What Pays (Google VRP)
- Infrastructure bugs: path traversal, sandbox escapes, auth bypasses
- Code execution from untrusted input (not via LLM decision)
- Token/credential disclosure
- Remote attacks from malicious webpages (DNS rebinding, URL scheme)

### What Doesn't Pay
- Prompt injection, model behavior manipulation, LLM-decision-based chains

### Token-Saving Rules for This Research
- **DO NOT re-read source files** — use `research/antigravity/04-code-understanding.md`
- **DO NOT read minified JS** unless hunting a specific string
- **Keep sessions focused** — one POC per session, not broad exploration
- **Reference notes by line number** when discussing findings

## graphify

This project has a graphify knowledge graph at graphify-out/.

Rules:
- Before answering architecture or codebase questions, read graphify-out/GRAPH_REPORT.md for god nodes and community structure
- If graphify-out/wiki/index.md exists, navigate it instead of reading raw files
- After modifying code files in this session, run `graphify update .` to keep the graph current (AST-only, no API cost)
