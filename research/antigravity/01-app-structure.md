# Antigravity App Structure Analysis
## Date: 2026-04-02

## App Identity
- **Bundle ID**: `com.google.antigravity`
- **Version**: 1.21.9 (IDE), 1.107.0 (package)
- **Electron**: 39.2.3
- **Node**: 22.20.0
- **Based on**: VS Code / Windsurf fork
- **Internal codename**: "Jetski" (seen in code paths, HTML, URLs)

## Key Paths
```
/Applications/Antigravity.app/Contents/
  Resources/app/
    package.json          — entry point: ./out/main.js
    product.json          — 42KB config with URLs, extension gallery, etc.
    out/
      main.js             — 11.8MB main Electron process
      jetskiAgent/main.js — 11.2MB AI agent (separate process)
      vs/                 — VS Code modules
        workbench.desktop.main.js — 23.9MB (biggest file)
    extensions/
      antigravity/        — Core AI extension (google.antigravity)
      chrome-devtools-mcp/ — Chrome DevTools MCP server
      antigravity-code-executor/ — Code execution extension
      antigravity-remote-openssh/ — Remote SSH
      antigravity-dev-containers/ — Dev containers
      [100+ VS Code standard extensions]
  Frameworks/             — Electron framework
  MacOS/Electron          — Main binary

~/.gemini/antigravity/
  installation_id         — UUID: 4ce42961-...
  mcp_config.json         — Empty (user MCP config)
  brain/                  — Empty (agent memory?)
  context_state/          — Empty
  html_artifacts/         — Empty
  knowledge/              — Agent knowledge base

~/.antigravity/
  argv.json               — CLI args config
  extensions/             — User-installed extensions
  antigravity/bin/        — Symlinks to app binary (agy, antigravity)

~/Library/Application Support/Antigravity/
  1.10-main.sock          — Unix domain socket for IPC
  machineid               — 36-char UUID
  Preferences             — Electron preferences
  Cache/, Cookies, etc.   — Standard Electron data
```

## URL Scheme
- Registered: `antigravity://` (CFBundleURLSchemes)
- Used for deep linking after auth and extension installs

## Info.plist Security-Relevant Settings
- **NSAllowsArbitraryLoads: true** — App Transport Security DISABLED
- Camera, Microphone, Bluetooth permissions requested
- AppleScript access requested
- URL scheme: `antigravity://`

## product.json Key Findings

### API Endpoints
- `https://cloudcode-pa.googleapis.com` — Production API
- `https://autopush-cloudcode-pa.sandbox.googleapis.com` — Staging/dev API
- `https://daily-cloudcode-pa.googleapis.com` — Daily build API
- `https://dl.google.com/antigravity/insider_secret` — Insider build URL (interesting name)
- `https://agent-marketplace.corp.google.com` — Internal Google marketplace
- `https://goto.google.com/jetski-skills` — Internal Google docs link
- `https://g3doc.corp.google.com/third_party/jetski/sdk/go/README.md` — Internal corp doc
- `https://play.googleapis.com/log` — Telemetry endpoint
- `https://sites.google.com/corp/google.com/spec-site/projects/lri` — Internal spec

### Extension Gallery
- Uses Open VSX: `https://open-vsx.org/vscode/gallery`
- Not Microsoft marketplace

### Update URL
- Set to `https://example.com` — placeholder? Could indicate custom update mechanism

### Workspace Trust Config
```json
"extensionUntrustedWorkspaceSupport": {
  "vscode.git": {"override": true},
  "google.antigravity": {"override": true}  // RUNS IN UNTRUSTED WORKSPACES
}
```
**google.antigravity extension is marked to run even in untrusted workspaces!**

### Webview CDN Template
- `https://{{uuid}}.vscode-cdn.net/insider/ef65ac1ba57f57f2a3961bfe94aa20481caca4c6/...`

## Extension: google.antigravity
- **Activation**: `"*"` (activates on everything)
- **Main**: `./dist/extension.js` (3MB minified)
- **Dependencies**: `vscode.git`
- **Binaries**:
  - `bin/language_server_macos_arm` — 143MB Go binary (the AI backend)
  - `bin/fd` — 3MB file finder tool
  - `bin/sandbox-wrapper.sh` — macOS Seatbelt sandbox script
- **Custom Editors**: Workflow and Rule editors for `.agent/workflows/` and `.agent/rules/`
- **Auth Provider**: `antigravity_auth`
- **Settings**: marketplace URLs, workspace file count, persistent language server
- **Schema Validation**: `mcp_config.schema.json` for MCP config files

## Extension: chrome-devtools-mcp
- Built-in Chrome DevTools MCP server
- Runs HTTP/SSE transport on **dynamic port**
- Connects to Chrome via CDP (Chrome DevTools Protocol)
- Uses Unified State Sync for CDP port
- Registers command: `antigravity.getChromeDevtoolsMcpUrl`

## Auth Flow
- OAuth via Google account
- Auth success page: `auth-success-jetski.html`
- **Template injection vector**: `{{DEEP_LINK_URL}}` in meta refresh and href
  - If attacker controls this parameter, open redirect + potential XSS
- `antigravity.copyApiKey` command exists — API key accessible in clipboard
- `antigravity.loginWithAuthToken` — backup login with raw token

## Sandbox (macOS Seatbelt)
- `sandbox-wrapper.sh` creates a Seatbelt profile per command
- Default: deny network, deny file-write outside workspace and /tmp
- `--allow-network` flag enables network
- Processes `.gitignore` and `.agyignore` to create deny rules
- **Potential bypass**: gitignore patterns parsed with sed regex conversion
  - Complex pattern handling could have edge cases
  - Only processes workspace root's .gitignore, not nested ones
  - Negation patterns (!) are stripped — could allow writing to "protected" files
  - Symlinks inside workspace pointing outside could bypass sandbox

## Language Server
- `language_server_macos_arm` — 143MB native binary
- Communicates with extension via some IPC mechanism
- Can be made persistent (`antigravity.persistentLanguageServer` setting)
- Has restart and kill commands
- Handles MCP tool execution, AI model calls

## Internal Codename References
- "Jetski" — main product codename (auth-success-jetski.html, jetskiAgent/)
- "Exa" — UI toolkit (@exa/agent-ui-toolkit, @exa/proto-ts)
- "Cascade" — panel name (cascade-panel.html)
- "Cortex" — internal module (config.schema.json comment: "Keep in sync with google3/third_party/jetski/cortex/...")
