# Antigravity Security Analysis — Grounded in Code Reading
## Date: 2026-04-02 (rewritten from code understanding, not grep)

Reference: All claims below trace back to specific files documented in `04-code-understanding.md`.

---

## 1. Sandbox (sandbox-wrapper.sh) — HIGHEST VALUE

### What the code actually does
The file is 267 lines, fully readable. It generates a macOS Seatbelt profile at runtime:

1. Starts with `(allow default)` — everything permitted by default
2. Adds `(deny file-write*)` — block all file writes
3. Then re-allows writes to specific paths:
   - `(allow file-write* (subpath "$WORK_DIR"))` — the workspace
   - `(allow file-write* (subpath "/tmp"))` and `(subpath "/private/tmp")`
4. Processes `.gitignore` and `.agyignore` through a sed pipeline to generate additional deny rules for sensitive files within the workspace
5. Network is denied by default; `--allow-network` flag removes the deny

### Confirmed vulnerability: Symlink escape
Seatbelt's `subpath` directive follows symlinks on macOS. This is documented Apple behavior, not speculation. The sandbox allows writes to `$WORK_DIR` subpaths. If a symlink exists inside the workspace pointing outside it, writes through that symlink are allowed.

**Concrete example from the code:**
- Sandbox rule: `(allow file-write* (subpath "/Users/lazerwild/projects/myapp"))`
- Symlink: `/Users/lazerwild/projects/myapp/link -> /Users/lazerwild/.zshrc`
- Write to `/Users/lazerwild/projects/myapp/link` → Seatbelt resolves to `/Users/lazerwild/.zshrc` → ALLOWED

**Why this is real:** The sandbox-wrapper.sh has zero symlink handling. No `readlink`, no `-L` checks, no `(deny file-write* (subpath-of-symlink ...))`. The sed pipeline that processes .gitignore only generates file-path-based deny rules — it doesn't consider symlinks either.

**Impact:** Arbitrary file write anywhere the user has permission. Escalates to code execution via `~/.zshrc`, `~/Library/LaunchAgents/`, `~/.ssh/authorized_keys`, etc.

### Confirmed issue: .gitignore sed parsing edge cases
The sed pipeline converts gitignore glob patterns to Seatbelt regex. It:
- Strips comment lines (`#`)
- Strips negation patterns (`!`) entirely — meaning `!important` patterns are silently dropped
- Converts `*` to `.*`, `?` to `.`, etc.
- Escapes some regex special chars

**Risk:** Malformed gitignore patterns that produce invalid Seatbelt regex cause the entire deny rule to be silently ignored by Seatbelt. A workspace could craft a .gitignore that neutralizes deny rules.

### Confirmed issue: /tmp is writable
The sandbox explicitly allows writes to `/tmp` and `/private/tmp`. The language server's named pipe lives at `/tmp/server_[hex]`. A sandboxed process can write to that pipe location.

---

## 2. CDT MCP Server (chrome-devtools-mcp/) — HIGH VALUE

### What the code actually does
From reading every file in `cdt_mcp/`:

1. `extension.js` creates `http.createServer()` → `listen(0, "127.0.0.1")` — random port, localhost only
2. Uses `StreamableHTTPServerTransport` — standard HTTP, not WebSocket
3. **No authentication whatsoever** on the HTTP endpoint — no tokens, no Origin check, no session validation
4. The MCP server name is `chrome_devtools` v0.12.1

### Tools with no path validation (from reading the actual tool files):
- **`McpContext.saveFile(data, filename)`** in `McpContext.js`: `path.resolve(filename)` → `fs.writeFile()`. No validation. The `filePath` parameter from MCP tool calls goes straight to disk.
- **`take_screenshot`** in `screenshot.js`: calls `context.saveFile(screenshot, request.params.filePath)` — write screenshot bytes to any path
- **`take_snapshot`** in `snapshot.js`: same pattern, saves accessibility snapshot to any path
- **`upload_file`** in `input.js`: `handle.uploadFile(filePath)` — reads any local file and uploads it to the browser page
- **`evaluate_script`** in `script.js`: `pageOrFrame.evaluateHandle()` with user-provided function string — runs arbitrary JS in the browser context

### Attack path: DNS rebinding
The MCP server is HTTP on localhost with no auth. DNS rebinding allows a remote webpage to send requests to `127.0.0.1:{port}`:

1. Attacker needs to discover the port (random, but scannable from JS via timing attacks or error-based detection)
2. DNS rebinding domain resolves to attacker IP first (serves the attack page), then resolves to 127.0.0.1
3. Attack page sends POST to `http://rebind-domain:{port}/mcp` with MCP tool calls
4. MCP server processes them — no Origin/Host check to prevent this

**What an attacker gets:**
- `evaluate_script` → arbitrary JS in whatever Chrome page is open (could be banking, email, etc.)
- `take_screenshot` + `saveFile` → write arbitrary files to disk
- `upload_file` → read arbitrary local files by uploading them to an attacker-controlled page
- `new_page` → navigate Chrome to any URL

### Attack path: Local process exploitation
Any process running as the same user can hit `http://127.0.0.1:{port}/mcp`. A malicious extension, npm package running in a terminal, or compromised tool in the pipeline could discover the port and use all MCP tools.

---

## 3. Language Server Named Pipe (/tmp/server_*) — MEDIUM VALUE

### What the code actually does
From `extension.js` (string analysis of minified code):
- Pipe name: `crypto.randomBytes(8).toString('hex')` → 16 hex chars
- Full path: `/tmp/server_[16 hex chars]`
- Protocol: Connect RPC with protobuf over the pipe
- Language server args: `--parent_pipe_path /tmp/server_...`

### Attack surface
- **Enumeration**: `ls /tmp/server_*` reveals active pipes to any local user
- **No visible auth on pipe**: The pipe is a Unix domain socket. Standard Unix permissions apply (owner-only by default for named pipes), BUT:
  - Need to verify actual permissions — if the Go binary creates it with broad permissions, any local user connects
  - Even with owner-only, the entropy is in the filename (which is visible via `ls`)
- **Persistent mode**: `--persistent_mode` keeps the server running after the editor closes, extending the attack window
- **Protocol**: Would need to reverse the protobuf schema to send valid messages. The import map in `jetskiAgent.js` lists all proto packages but the actual `.proto` files aren't shipped — they're compiled into the Go binary and JS bundles.

### Realistic assessment
This is a local-only attack. The pipe permissions are the key question. If owner-only (likely default), this requires same-user access, which limits impact. If world-readable/writable, it's a legitimate multi-user escalation.

---

## 4. OAuth / Auth Flow — MEDIUM VALUE

### What the code actually does
From `extension.js` and `auth-success-jetski.html`:
1. `ExternalAuthProvider` starts HTTP server on `localhost:{random_port}`
2. Redirect URI: `http://localhost:{port}/oauth-callback`
3. On success, serves `auth-success-jetski.html` with `{{DEEP_LINK_URL}}` replaced server-side
4. Deep link: `antigravity://` URL scheme redirects back to app
5. `loginWithAuthToken` command accepts raw tokens directly
6. `copyApiKey` puts API key in clipboard

### Attack surface
- **Port race**: Random port makes this hard but not impossible. On a fast system, an attacker could bind to ports rapidly trying to catch the OAuth redirect. Realistic only if the attacker is already running code on the machine.
- **`{{DEEP_LINK_URL}}` injection**: If the OAuth provider allows attacker-controlled redirect parameters that end up in the deep link URL, this could redirect to a malicious `antigravity://` URL. Need to check what the OAuth provider puts in the callback.
- **Clipboard exposure**: `copyApiKey` puts the API key in the system clipboard, accessible to any app with clipboard read permission. Low severity but real.

---

## 5. MCP Config (mcp_config.json) — LOW-MEDIUM VALUE

### What the code actually does
- Path: `~/.gemini/antigravity/mcp_config.json`
- Schema allows: `command` (any string), `args`, `env`, `serverUrl`, `cwd`, `headers`, `oauth.clientSecret`
- File permissions: 644 (world-readable) — confirmed from filesystem
- No command allowlisting in schema or code
- Language server reads this and spawns MCP server processes

### Attack surface
- **World-readable secrets**: If a user adds `oauth.clientSecret` to their MCP config, any local user can read it. This is a real information disclosure but low impact on single-user macOS.
- **Arbitrary command execution via config**: If an attacker can write to this file (via another vulnerability or social engineering), they get arbitrary command execution when Antigravity starts. This is a chaining opportunity, not standalone.

---

## 6. antigravity:// URL Scheme — MEDIUM VALUE

### What the code actually does
- Registered in Info.plist as a deep link handler
- Handled by Electron main process in `out/main.js` (minified, can't read handler logic directly)
- Used in OAuth callback flow: `auth-success-jetski.html` redirects to `antigravity://` URL
- Any app or webpage can trigger `antigravity://` URLs

### Attack surface
- Need to understand what actions the URL scheme supports. Common patterns in VS Code forks:
  - `antigravity://extension/install?id=...` — install extensions
  - `antigravity://file/open?path=...` — open files/workspaces
  - `antigravity://command/...` — execute VS Code commands
- If the URL scheme can install extensions or open workspaces, a malicious webpage could trigger these actions with a single click
- The main.js is minified so we can't read the URL routing directly — need to test empirically

---

## 7. Workspace Trust / Custom Editors — LOW VALUE

### What the code actually does
- `extensionUntrustedWorkspaceSupport: {"google.antigravity": {"override": true}}` — extension runs in untrusted workspaces
- Custom editors for `.agent/rules/*.md` and `.agent/workflows/*.md` (plus `_agent/`, `.agents/`, `_agents/`, `.gemini/jetski*/`, `.gemini/antigravity*/`)
- Editors render in VS Code webviews — already sandboxed by VS Code's webview security
- `hasBannedString()` checks for `---` to prevent YAML frontmatter injection
- postMessage communication between editor webview and extension host

### Realistic assessment
The custom editors are simple HTML forms in webviews. They don't render arbitrary HTML from workspace files — they parse structured fields (trigger, description, content) and display them in input elements. The `---` ban prevents frontmatter injection. XSS here would require bypassing VS Code's webview sandbox AND the editor's input sanitization. Low likelihood.

---

## 8. Electron / Preload Security — LOW VALUE

### What the code actually does
- `preload.js`: Exposes limited API via contextBridge. IPC channels filtered to `vscode:` prefix only: `if (!e?.startsWith("vscode:")) throw`
- `preload-aux.js`: Even more minimal — just send/invoke with vscode: filter + zoom control
- `NSAllowsArbitraryLoads: true` — ATS disabled, but this is standard for Electron apps that need to load arbitrary web content

### Realistic assessment
The preload scripts follow VS Code's standard security model. Channel filtering is solid — only `vscode:` prefixed channels. No obvious way to escape the renderer sandbox through the exposed API. This is well-tested VS Code code, not custom Antigravity code. Very unlikely to have bugs here.

---

## 9. terminateExtensionHostProcess.sh — SPECULATIVE

### What the code actually does
```bash
SERVER_DATA_DIR="$HOME/${SERVER_DATA_FOLDER_NAME}"
# reads PID from $SERVER_DATA_DIR/.$DISTRO_ID.pid
# kill -9 on that PID
```
- `$1` = SERVER_DATA_FOLDER_NAME, `$2` = DISTRO_ID
- If these are user-controlled (e.g., from a URL parameter or config), path traversal via `../../` could read/kill arbitrary PIDs

### Realistic assessment
This script is in `remoteSshDev/scripts/` — it's for remote SSH development scenarios. The parameters likely come from the SSH connection setup, not from user input. Would need to trace how this script is invoked to determine if the parameters are actually attacker-controllable. Low priority unless we find the invocation path.
