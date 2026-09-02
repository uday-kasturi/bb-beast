# Antigravity — Code Understanding Notes
## Date: 2026-04-02

## File-by-File Understanding

### Core App (out/)

**out/main.js** (11.8MB, minified)
- Electron main process. Handles window management, IPC, protocol registration.
- Registers `antigravity://` URL scheme, `vscodeFileResource` file protocol.
- Intercepts `file:` protocol to control file access from renderer.
- Contains the workbench configuration, extension gallery settings, telemetry setup.
- Uses Connect RPC (@connectrpc) for communication with language server.

**out/jetskiAgent/main.js** (11.2MB, minified)  
- The AI agent UI — runs in its own Electron BrowserWindow.
- Bootstrap: `jetskiAgent.js` loads it via import map.
- Uses React (Preact compat), Redux, Lexical editor, React Router.
- Communicates with language server via protobuf over Connect RPC.
- Renders the chat panel (cascade), code diffs, agent actions.

**out/vs/code/electron-browser/workbench/jetskiAgent.js** (21KB, readable)
- Bootstrap for the jetskiAgent window.
- Sets up import maps for all npm dependencies.
- Creates trusted types policy `vscode-bootstrapImportMap`.
- Hardcoded nonce: `0c6a828f1297` — used for the import map script tag.
- Loads `jetskiAgent/main` module.

**out/vs/base/parts/sandbox/electron-browser/preload.js** (readable)
- Electron preload script for renderer windows.
- Exposes limited `vscode` API to renderer via contextBridge:
  - `ipcRenderer` — filtered to only allow channels starting with `vscode:`
  - `ipcMessagePort` — for message port acquisition
  - `webFrame` — zoom control only
  - `webUtils` — getPathForFile only
  - `process` — read-only process info (pid, platform, arch, env, versions)
  - `context` — window configuration
- **Channel validation**: `if (!e?.startsWith("vscode:")) throw` — only vscode: channels allowed.

**out/vs/base/parts/sandbox/electron-browser/preload-aux.js** (readable)
- Minimal preload for auxiliary windows.
- Only exposes `ipcRenderer.send/invoke` (with vscode: channel filter) and `webFrame.setZoomLevel`.
- No process info exposed.

### Core Antigravity Extension

**extensions/antigravity/package.json** (readable)
- Name: `google.antigravity`
- Activation: `"*"` (always active)
- Custom editors for `.agent/rules/` and `.agent/workflows/` files (also `_agent/`, `.agents/`, `_agents/`, `.gemini/jetski*/`, `.gemini/antigravity*/`)
- Auth provider: `antigravity_auth`
- Commands: login, import settings from VS Code/Cursor/Windsurf, generate commit message, restart language server, copy API key, browser management, demo mode
- Settings: marketplace URLs, workspace file count limit (5000), persistent language server toggle
- JSON validation: `mcp_config.json` validated against `schemas/mcp_config.schema.json`
- Language association: `mcp_config.json` treated as JSONC

**extensions/antigravity/dist/extension.js** (3MB, minified)
- Main extension logic. Key components (understood from string analysis):
  - `ExternalAuthProvider` — OAuth flow with localhost HTTP server
  - Language server manager — spawns `language_server_macos_arm`, manages lifecycle
  - MCP config management — reads/creates `~/.gemini/antigravity/mcp_config.json`
  - Browser allowlist — stored as `browserAllowlist.txt` in data directory
  - Demo mode — writes `DEMO_MODE.txt`, sets allowlist to `localhost\n` only
  - Import functions — imports from VS Code, Cursor, Windsurf, Cider
  - Custom editor providers — for rules and workflows

**extensions/antigravity/bin/language_server_macos_arm** (143MB)
- Native Go binary. The AI backend.
- Communicates with extension via Unix named pipe at `/tmp/server_[random hex]`.
- Receives OAuth tokens, handles MCP server management, model API calls.
- Arguments include: `--parent_pipe_path`, `--persistent_mode`, `--use_local_chrome`
- Environment: inherits full process env + `ANTIGRAVITY_EDITOR_APP_ROOT`

**extensions/antigravity/bin/sandbox-wrapper.sh** (readable, 267 lines)
- macOS Seatbelt sandbox for terminal commands.
- Generates dynamic sandbox profiles.
- Base policy: `(allow default)` — starts permissive.
- Then adds specific denies: file-write outside workspace+/tmp, optional network deny.
- Processes `.gitignore` and `.agyignore` via sed pipeline to generate deny rules.
- Symlink handling: NO explicit symlink prevention — Seatbelt `subpath` follows symlinks.
- Network: denied by default, `--allow-network` flag enables it.
- Error detection: checks stderr for "Operation not permitted" to suggest sandbox docs.

**extensions/antigravity/bin/fd** (3MB)
- The `fd` file finder tool (Rust binary). Used for workspace file discovery.

**extensions/antigravity/schemas/mcp_config.schema.json** (readable)
- JSON Schema for MCP config. Allows: command, args, env, serverUrl, cwd, headers, authProviderType, oauth (clientId+clientSecret), disabled, disabledTools, tools.
- No restrictions on what commands can be specified.

**extensions/antigravity/auth-success-jetski.html** (readable)
- Post-OAuth success page served by localhost server.
- `{{DEEP_LINK_URL}}` template in meta refresh and anchor href.
- Template is replaced server-side before serving.

**extensions/antigravity/cascade-panel.html** (readable)
- Minimal HTML shell: just `<div id="react-app">`. React app mounts here.

**extensions/antigravity/dist/languageServer/cert.pem**
- Self-signed TLS cert for localhost, issued to `ENABLES HTTP2`.
- Valid 2025-09-04 to 2026-09-04.
- Used for HTTP/2 communication with language server.

**extensions/antigravity/dist/remoteSshDev/scripts/terminateExtensionHostProcess.sh**
- Takes `$1` (data folder name) and `$2` (distro ID).
- Reads PID from `$HOME/$1/.$2.pid`, then `kill -9` the process tree.
- Path construction: `$HOME/${SERVER_DATA_FOLDER_NAME}` — if SERVER_DATA_FOLDER_NAME is user-controlled, could be path traversal.

**extensions/antigravity/customEditor/utils.js** (readable)
- Shared utilities for custom editors.
- `hasBannedString()` — checks input against banned strings (just `---`).
- `updateCharCounter()` — character count validation.
- Banned string `---` — prevents YAML frontmatter injection in rules/workflows.

**extensions/antigravity/customEditor/media/ruleEditor/ruleEditor.js** (readable)
- Custom editor for `.agent/rules/` files.
- Fields: trigger (dropdown), modelDecisionParam, globParam, content.
- Uses `vscode.postMessage({type: 'update', content: documentState})` to save.
- Banned strings: `['---']` — prevents frontmatter injection.
- Sends updates to extension host which writes to disk.

**extensions/antigravity/customEditor/media/workflowEditor/workflowEditor.js** (readable)
- Custom editor for `.agent/workflows/` files.
- Fields: description, content.
- Same postMessage pattern and banned string (`---`) check.

### Chrome DevTools MCP Extension

**extensions/chrome-devtools-mcp/package.json** (readable)
- Activates `onStartupFinished`.
- API: `none` — no VS Code API exposed.
- One command: `antigravity.getChromeDevtoolsMcpUrl`.
- Uses `antigravityUnifiedStateSync` API proposal.

**extensions/chrome-devtools-mcp/dist/extension.js** (large, minified)
- Extension entry point.
- Gets CDP port from `antigravityUnifiedStateSync.BrowserPreferences.getBrowserCdpPort()`.
- Creates MCP server via imported `createServer()`.
- HTTP server: `http.createServer()` → `listen(0, "127.0.0.1")` — random port, localhost only.
- Uses `StreamableHTTPServerTransport` for MCP protocol.
- MCP URL: `http://127.0.0.1:{port}/mcp` — returned by the command.
- Retry logic: exponential backoff with max 5 retries, 1s base delay.
- Cleanup: on deactivate, closes HTTP server and MCP server.

**extensions/chrome-devtools-mcp/cdt_mcp/main.js** (readable)
- Creates MCP server with name `chrome_devtools`.
- Registers all tools from `tools/tools.js`.
- Each tool handler: acquires mutex, gets browser context, executes tool, returns result.
- Error handling: catches errors, returns error text as MCP response.

**extensions/chrome-devtools-mcp/cdt_mcp/browser.js** (readable)
- Puppeteer browser connection/launch.
- `ensureBrowserConnected()` — connects to existing Chrome via CDP.
  - Reads `DevToolsActivePort` file for port+path.
  - Constructs WS endpoint: `ws://127.0.0.1:{port}{path}`.
  - Supports: browserURL, wsEndpoint, channel, userDataDir.
- `ensureBrowserLaunched()` / `launch()` — launches new Chrome.
  - User data dir: `~/.cache/chrome-devtools-mcp/chrome-profile`.
  - Passes `--hide-crash-restore-bubble`.
  - Supports `--auto-open-devtools-for-tabs`, headless, viewport, proxy, insecure certs.
- Target filter: ignores `chrome://`, `chrome-extension://`, `chrome-untrusted://` except newtab and inspect.

**extensions/chrome-devtools-mcp/cdt_mcp/McpContext.js** (readable)
- Central context for the MCP server.
- Manages pages, snapshots, network/console collectors.
- `createTextSnapshot()` — uses accessibility tree for page snapshots.
- `saveTemporaryFile()` — writes to `os.tmpdir()/chrome-devtools-mcp-*`.
- `saveFile()` — writes to arbitrary path via `path.resolve(filename)`.
  - **No path validation** — `filePath` parameter from tools goes directly to `fs.writeFile`.
- `evaluateScript` tool handler in script.js calls `pageOrFrame.evaluateHandle()` with user-provided function string — executes arbitrary JS in browser context.

**extensions/chrome-devtools-mcp/cdt_mcp/McpResponse.js** (readable)
- Response builder for MCP tool results.
- Formats pages, snapshots, network requests, console messages.
- Handles image attachments (screenshots).

**extensions/chrome-devtools-mcp/cdt_mcp/tools/** (all readable)
- **pages.js**: list_pages, select_page, close_page, new_page (goto any URL), navigate_page, resize_page, handle_dialog.
- **script.js**: evaluate_script — executes arbitrary JS functions in browser page context. No restrictions on what can be evaluated.
- **input.js**: click, hover, fill, drag, fill_form, upload_file (takes local file path), press_key.
  - `upload_file` — accepts `filePath` parameter, reads local file. No path validation.
- **screenshot.js**: take_screenshot — save to arbitrary `filePath` on disk.
  - `saveFile()` → `path.resolve(filePath)` → `fs.writeFile()`. No path validation.
- **snapshot.js**: take_snapshot, wait_for. Snapshot can also save to arbitrary `filePath`.
- **network.js**: list_network_requests, get_network_request. Read-only.
- **console.js**: list_console_messages, get_console_message. Read-only.
- **emulation.js**: emulate — network throttling, CPU throttling, geolocation. Write-only to browser state.
- **performance.js**: start/stop trace, analyze insight. Writes trace data.

**Other CDT MCP files:**
- **cli.js**: CLI argument parsing. Not used in extension mode.
- **PageCollector.js**: Manages network/console data per page with stable IDs.
- **Mutex.js**: Simple FIFO mutex.
- **WaitForHelper.js**: Waits for DOM stability after actions.
- **DevtoolsUtils.js**, **formatters/**: Data formatting utilities.

### Code Executor Extension

**extensions/antigravity-code-executor/package.json** (readable)
- Command: `antigravity-code-executor.executeCode` ("Execute Code (Antigravity)").
- Activates: never automatically (empty `activationEvents`).
- API: `none`.
- Description: "Execute generated code from cascade."

**extensions/antigravity-code-executor/dist/extension.js** (minified)
- Handles code execution from the AI chat (cascade).
- Activated by command invocation, not on startup.

---

## Architecture Understanding

### Communication Flow
```
User → Cascade UI (jetskiAgent window)
  → Redux/React state management
  → Connect RPC (protobuf) over named pipe
  → language_server_macos_arm (Go binary)
  → Google Cloud API (cloudcode-pa.googleapis.com)
  → Gemini model inference
  → Response back through same chain

Language Server → MCP servers (via mcp_config.json)
Language Server → Chrome DevTools MCP → Chrome browser (via CDP)
Language Server → Terminal (via PTY host) → Optional sandbox-wrapper.sh
```

### Trust Boundaries
1. **User input → Cascade UI**: Trusted (user is typing)
2. **Cascade UI → Language Server**: Trusted (internal IPC via pipe)
3. **Language Server → Google API**: TLS, auth tokens
4. **Language Server → MCP servers**: No auth, arbitrary commands from config
5. **Language Server → Terminal**: Optionally sandboxed
6. **CDT MCP → Chrome**: CDP over localhost WebSocket
7. **External webpage → CDT MCP HTTP server**: NO AUTH on the HTTP endpoint
8. **External webpage → antigravity:// URL scheme**: Handled by Electron main process
9. **Workspace files (.agent/) → Custom editors**: Rendered in webview

### Key Protobuf Definitions (from import map)
- `language_server_pb` — language server protocol
- `cortex_pb` — AI model interaction
- `agent_manager_pb` — agent orchestration
- `chat_client_server_pb` — chat protocol
- `unified_state_sync_pb` — shared state between processes
- `cascade_plugins_pb` — plugin system
- `diff_action_pb` — code diff actions
- `jetski_service_pb` — Google Cloud service interface
- `credits_pb` — usage/credits tracking
- `metrics_pb` — telemetry
