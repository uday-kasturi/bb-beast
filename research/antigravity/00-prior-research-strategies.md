# Antigravity Prior Research & Initial Attack Strategies
## Date: 2026-04-02

## What Antigravity Is
- Google's AI-first IDE, Gemini-powered, launched Nov 2025
- Three execution surfaces: editor, terminal, browser agent
- Supports MCP (Model Context Protocol) servers
- Based on licensed Windsurf codebase (Electron/VS Code fork)
- Has a Chrome extension component (ID: `eeijfnjmjelapkebgockoeaadonbchdd`)
- Global config lives at `~/.gemini/antigravity/`
- App data at `~/Library/Application Support/Antigravity/`
- User extensions at `~/.antigravity/extensions/`

---

## Previously Reported Bugs (Do NOT Re-Report)

### 1. RCE via Chrome Extension Path Traversal — $10k (Hacktron AI)
- **Component**: Extension message handler for `SaveScreenRecording` action
- **Root cause**: `externally_connectable: { matches: ["<all_urls>"] }` + no origin validation + path traversal in filename/L params
- **Exploit**: Malicious webpage sends `chrome.runtime.sendMessage(EXT_ID, {action: "SaveScreenRecording", filename: "../poc.txt", za: [...], L: "../../../test"})` → arbitrary file write
- **Fix**: Added `sh()` origin validation function — checks URL includes `/static/offscreen.html`, sender ID matches ext ID, no `tab` property
- **Status**: Patched, bounty paid

### 2. Persistent Backdoor via .agent/mcp_config.json (Mindgard/Aaron Portnoy)
- **Root cause**: `.agent` directory rules treated as trusted instructions → can copy malicious MCP config to `~/.gemini/antigravity/mcp_config.json`
- **Persistence**: Global config survives uninstall/reinstall, `~/.gemini/antigravity/` persists
- **Bypass**: All restrictive settings (terminal off, non-workspace access disabled, review mode) still exploitable
- **Status**: Reported Nov 19, initially "Won't Fix", reopened Nov 21, under evaluation

### 3. Indirect Prompt Injection → Data Exfil (wunderwuzzi/Embrace The Red)
- Five issues: remote cmd exec via prompt injection, Unicode tag hidden instructions, no HITL for MCP tools, data exfil via `read_url_content`, data exfil via image rendering
- **Status**: Known issues, won't pay

### 4. Port 9092 Exposed on 0.0.0.0 macOS (Lumia Security)
- Electron webUI on port 9092 bound to all interfaces, HTML contained auth tokens
- **Status**: Patched Jan 2026, bounty paid

### 5. Memory Extraction from language_server Process (Lumia Security)
- AIKatz-style token extraction from `language_server` process memory
- **Status**: Deemed outside security boundary

---

## Google's Known Issues (OFF LIMITS — No Bounty)
- Data exfiltration via prompt injection (markdown, tool invocation)
- Browser agent prompt injection
- MCP tool auto-invocation without consent
- Code execution via prompt injection through browser agent
- **Key takeaway**: Pure prompt injection chains are excluded. Google wants bugs in TECHNICAL INFRASTRUCTURE, not model behavior.

---

## Initial Attack Strategies (Pre-Source-Code-Review)

### Strategy 1: Chrome Extension Message Handlers
- **Rationale**: $10k RCE class. Extensions are code, not LLM — always in scope.
- **Target**: Extension ID `eeijfnjmjelapkebgockoeaadonbchdd`
- **Approach**: Audit every `chrome.runtime.onMessageExternal` handler for:
  - Other message types with insufficient origin validation
  - File system ops with user-controlled paths
  - TOCTOU races in the new `sh()` validation function
  - CSP bypasses in extension pages
- **POC**: Malicious webpage → `chrome.runtime.sendMessage()` → unvalidated handler → impact

### Strategy 2: Language Server / IPC Auth
- **Rationale**: Port 9092 paid out. IPC surface is rich.
- **Approach**:
  - Check if other ports bound to 0.0.0.0
  - Audit IPC between editor ↔ language server ↔ LLM backend
  - Look for WebSocket/gRPC endpoints lacking auth
  - Check token storage on disk (permissions, encryption)
- **POC**: `lsof -i -P | grep Antigravity` → find open ports → connect unauth → extract data

### Strategy 3: MCP Config Manipulation (Non-Prompt-Injection)
- **Rationale**: Config file controls what executes on every launch. Non-LLM paths to write it = valid bug.
- **Approach**:
  - Symlink attacks on `~/.gemini/antigravity/` directory
  - Race conditions during MCP server install/config
  - Extension/IDE features that write to this path with user input
  - Workspace config → global config merge without sanitization
- **POC**: Symlink `mcp_config.json` → attacker location before launch

### Strategy 4: Update/Auto-Update Mechanism
- **Approach**: MITM update process, check signature verification, HTTP vs HTTPS, cert pinning

### Strategy 5: Workspace Trust Bypass (Non-LLM)
- **Approach**: Check if `.agent/` settings parsed before trust dialog. Git submodules or symlinks bypassing workspace boundaries.

---

## Sources
- https://www.hacktron.ai/blog/hacking-google-antigravity
- https://mindgard.ai/blog/google-antigravity-persistent-code-execution-vulnerability
- https://embracethered.com/blog/posts/2025/security-keeps-google-antigravity-grounded/
- https://www.lumia.security/blog/the-space-race-looking-for-security-issues-in-googles-antigravity
- https://bughunters.google.com/learn/invalid-reports/google-products/4655949258227712/antigravity-known-issues
