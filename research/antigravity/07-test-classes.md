# Antigravity — Test Classes & Interesting Observations
## Date: 2026-04-02

Goal: Map what's worth testing before diving into any one thing. Think chains, not individual findings.

---

## Reality Check: What We Tested So Far

| Test | Result | Reportable? |
|------|--------|-------------|
| Sandbox symlink escape | Seatbelt resolves symlinks. Only escapes to /tmp (already allowed). | No |
| CDT MCP no auth | Works from curl. But localhost-only, CORS blocks browsers. Same pattern as Chrome DevTools. | Probably not standalone |
| CSRF token in ps output | Visible but couldn't use it (wrong header name) | Weak |
| mcp_config.json 644 | World-readable but empty. Low impact. | Weak |

**None of these are reportable on their own.** Need to find chains or higher-impact bugs.

---

## Test Class 1: Workspace Trust (Malicious Repo)

**Why it matters:** User clones a repo → Antigravity opens it → what runs without user action?

**Interesting observations:**
- Extension activates on `"*"` with `untrustedWorkspaceSupport: override: true`
- `.agent/rules/` files are parsed by custom editors — but only when user opens them
- `.agents/rules/` (new default), `.agent/`, `_agent/`, `_agents/`, `.gemini/jetski*/`, `.gemini/antigravity*/` all recognized
- Global rules at `~/.gemini/GEMINI.md` — if writable, attacker can inject persistent rules
- Rules support `@filename` references: "If filename is an absolute path, it will be resolved as a true absolute path" — **can a rule reference `/etc/passwd` or `~/.ssh/id_rsa` and feed it to the model?**
- `.agyignore` is processed by sandbox — a new, less-tested file format
- `.vscode/settings.json` and `.vscode/tasks.json` — standard VS Code workspace attack surface

**Tests to run:**
- [ ] Create workspace with `.agents/rules/evil.md` containing `@/etc/passwd` — does the model see the file contents?
- [ ] Create workspace with `.agyignore` containing regex-breaking patterns
- [ ] Check what auto-executes on workspace open (no user interaction)
- [ ] Check if `.vscode/tasks.json` with `runOn: folderOpen` works in Antigravity

---

## Test Class 2: antigravity:// URL Scheme

**Why it matters:** Any webpage or email can trigger these URLs. If they can open workspaces or install extensions, that's remote → local.

**Interesting observations:**
- Registered in Info.plist as deep link handler
- Used in OAuth flow: `auth-success-jetski.html` redirects to `antigravity://` after login
- VS Code forks typically support: open file, open folder, install extension, execute command
- Handler code is in minified main.js — can't read directly, need empirical testing
- The OAuth flow crafts the URL server-side via `{{DEEP_LINK_URL}}` template

**Tests to run:**
- [ ] `open "antigravity://file/path/to/something"`
- [ ] `open "antigravity://vscode.open-folder?url=file:///tmp/malicious-workspace"`
- [ ] `open "antigravity://extension/install?id=some.extension"`
- [ ] `open "antigravity://command?id=workbench.action.terminal.new"`
- [ ] Monitor Antigravity behavior after each (does it open? prompt? ignore?)
- [ ] If folder-open works: chain with malicious workspace (Class 1)

---

## Test Class 3: Sandbox .gitignore/.agyignore Parsing

**Why it matters:** If a malicious repo's .gitignore breaks the sandbox deny rules, the sandbox becomes permissive.

**Interesting observations:**
- The sed pipeline (lines 209-231 in sandbox-wrapper.sh) has specific handling:
  - `!` negation lines are stripped entirely
  - `#` comments stripped
  - Directory-only patterns (`/` suffix) skipped
  - Glob → regex conversion: `*` → `[^/]*`, `?` → `[^/]`, `**` → `.*`
  - Regex special chars escaped: `. + ( ) { } | ^ $`
- What's NOT escaped: `[` and `]` — these are regex character classes
- A pattern like `[` alone would produce invalid regex → Seatbelt may silently ignore the rule
- `.agyignore` is Antigravity-specific, likely less tested than .gitignore
- Only root-level ignore files are processed — no nested

**Tests to run:**
- [ ] `.gitignore` with lone `[` — does the sandbox profile become invalid?
- [ ] `.gitignore` with `]` or `[^` patterns that mess up the regex
- [ ] `.agyignore` with the same
- [ ] Verify: does Seatbelt silently ignore bad regex rules or reject the entire profile?
- [ ] If profile-breaking works: entire `(deny file-write*)` section could be skipped

---

## Test Class 4: Rules/Workflows `@` File References

**Why it matters:** Docs say rules can reference files with `@filename`. "If filename is an absolute path, it will be resolved as a true absolute path." This could be a path traversal / info disclosure.

**Interesting observations:**
- Rules are markdown files with `@/path/to/file` references
- The model receives the referenced file content as context
- If a malicious workspace has a rule like `Always read @/Users/victim/.ssh/id_rsa` — does the model see the private key?
- Even if the model doesn't exfiltrate it, it's still sensitive file access
- Does this bypass strict mode's "workspace isolation"?

**Tests to run:**
- [ ] Create `.agents/rules/test.md` with `@/etc/passwd` 
- [ ] Create with `@~/.ssh/id_rsa` or `@/Users/lazerwild/.gitconfig`
- [ ] Check if "always on" trigger reads the file automatically
- [ ] Check if strict mode blocks it
- [ ] Check what happens with `@../../outside-workspace/secret`

---

## Test Class 5: MCP Config as Persistence Mechanism

**Why it matters:** If any bug allows writing to `~/.gemini/antigravity/mcp_config.json`, the attacker gets persistent command execution every time Antigravity starts.

**Interesting observations:**
- MCP config allows arbitrary `command` with `args` and `env`
- File is at a predictable path
- Config is reloaded when Antigravity starts (and possibly on change)
- Schema has no command allowlist
- This is a TARGET for chains, not a standalone bug

**Chain scenarios:**
- URL scheme opens malicious workspace → workspace has rule that tells agent to modify mcp_config.json → persistence
- Path traversal writes to mcp_config.json → persistence
- Sandbox escape → write mcp_config.json → persistence

---

## Test Class 6: OAuth Token / Credential Handling

**Why it matters:** Tokens stored insecurely = account takeover.

**Interesting observations:**
- OAuth tokens: `antigravityUnifiedStateSync.OAuthPreferences` (Electron storage)
- MCP OAuth tokens: `~/.gemini/antigravity/mcp_oauth_tokens.json` (file — check perms when it exists)
- `loginWithAuthToken` command accepts raw tokens
- `copyApiKey` puts key in clipboard
- OAuth callback: localhost HTTP server with random port
- MCP OAuth callback: `https://antigravity.google/oauth-callback` (hosted)

**Tests to run:**
- [ ] Check permissions on Electron storage files in `~/Library/Application Support/Antigravity/`
- [ ] Trigger MCP OAuth flow, check if `mcp_oauth_tokens.json` is created 644
- [ ] Check if `antigravity://` URLs can pass tokens to `loginWithAuthToken`

---

## Test Class 7: Extension Server CSRF Bypass

**Why it matters:** Extension server on port 57168 has CSRF protection, but tokens are leaked in `ps aux`. If we find the right header name, we bypass it.

**Interesting observations:**
- `--csrf_token` and `--extension_server_csrf_token` visible in process args
- Server returns 403 with wrong header. Need to find correct header from minified code.
- This is the Connect RPC server that mediates between Electron and language server

**Tests to run:**
- [ ] Search minified extension.js for CSRF header name patterns
- [ ] Try common headers: `x-csrf-token`, `X-CSRF-Token`, `csrf-token`, `Authorization: Bearer {token}`
- [ ] If bypassed: what endpoints does the extension server expose?

---

## Highest-Value Chains to Explore

### Chain A: URL scheme → open malicious workspace → auto-execute
`antigravity://open-folder?path=/tmp/evil-workspace` → workspace has `.agents/rules/` with always-on rule → rule references sensitive files or instructs agent to modify mcp_config.json → persistence

### Chain B: .gitignore regex injection → sandbox becomes permissive
Clone repo with crafted `.gitignore` → sandbox-wrapper.sh produces broken profile → deny rules silently dropped → agent's terminal commands can write anywhere

### Chain C: Rule `@` file reference → sensitive file disclosure
Malicious workspace with rule referencing `@/etc/passwd` or `@~/.ssh/id_rsa` → model receives file content → if model outputs it in response, it's info disclosure without user intent

### Chain D: MCP config write → persistent backdoor
Any write primitive to `~/.gemini/antigravity/mcp_config.json` → add malicious MCP server → runs arbitrary command next time Antigravity starts

---

## Test Class 8: Storage File Permissions

**Why it matters:** World-readable files containing tokens = credential theft on shared systems.

**Interesting observations:**
- `storage.json` (70KB) — **644 (world-readable)**, contains config, preferences, state keys
- `state.vscdb` (SQLite) — **644 (world-readable)**, contains editor state
- `mcp_config.json` — **644 (world-readable)**, can contain oauth.clientSecret
- `installation_id` — **755 (world-executable??)**, contains UUID
- `knowledge.lock` — **600 (owner only)** — someone thought about permissions here
- `Cookies` — **600 (owner only)** — good
- `Preferences` — **600 (owner only)** — good
- Actual OAuth tokens seem to be in `antigravityUnifiedStateSync.oauthToken` — need to check where these are stored when logged in
- Keychain entry: "Antigravity Safe Storage" (Electron safeStorage for cookie encryption)

**Tests to run:**
- [ ] Log in to Antigravity, then check if OAuth tokens appear in storage.json/state.vscdb (644 files)
- [ ] Add MCP server with OAuth, check mcp_oauth_tokens.json permissions
- [ ] Check if the storage.json token migration left tokens in world-readable location

---

## Test Class 9: Internal HTTP Services

**Why it matters:** Multiple HTTP services on localhost with varying auth.

**Interesting observations:**
- **Port 57165** (Electron main) — serves browser landing page HTML, no auth needed
- **Port 57168** (Extension server) — CSRF protected (returns 403), Connect RPC
- **Port 57169** (Language server HTTPS) — self-signed cert, returns 404 on /
- **Port 57178** (LSP) — doesn't respond to HTTP
- **Port 57189** (CDT MCP) — NO AUTH, full MCP tool access
- **Port 57278** (Language server) — no response
- **Port 57170** (Unleash feature flag proxy) — in error logs, not responding now
- CSRF tokens for 57168 leaked in `ps aux` output of language_server process

**Tests to run:**
- [ ] What does the extension server (57168) actually serve? What endpoints exist?
- [ ] Can the language server HTTPS (57169) be used without the CSRF token?
- [ ] Can port 57165 serve arbitrary files or be used for SSRF?
- [ ] When the Unleash proxy is active, does it expose feature flags that control security settings?

---

## Test Class 10: Code Executor Extension

**Why it matters:** Executes code from cascade. If the activation/invocation boundary is weak, it's arbitrary code execution.

**Interesting observations:**
- Activates on command only (not auto-start)
- API: `none` — can't access VS Code API
- Command: `antigravity-code-executor.executeCode`
- dist/extension.js is minified — need to understand: what code does it accept? What language? Is there sandboxing?

**Tests to run:**
- [ ] Can this command be triggered via antigravity:// URL scheme?
- [ ] What happens if you invoke it from another extension or from the terminal?
- [ ] Is the code it executes sandboxed?

---

## Test Class 11: Remote SSH/DevContainers

**Why it matters:** `terminateExtensionHostProcess.sh` has potential path traversal. Remote connection flows may have auth weaknesses.

**Interesting observations:**
- `terminateExtensionHostProcess.sh` constructs path from `$1`: `$HOME/${SERVER_DATA_FOLDER_NAME}/.${DISTRO_ID}.pid` then kills that PID
- Remote SSH extension: `antigravity-remote-openssh` — activates on `ssh-remote` authority
- DevContainers: `antigravity-dev-containers` — activates `onStartupFinished`
- If the distro ID or data folder name comes from a remote server, it could be attacker-controlled

**Tests to run:**
- [ ] Trace how terminateExtensionHostProcess.sh is invoked — are $1/$2 from remote?
- [ ] Can a malicious SSH server feed a path-traversal distro ID?

---

## Test Class 12: Custom Editor Webview Security

**Why it matters:** Custom editors render workspace file content in webviews.

**Interesting observations:**
- Rule editor renders: trigger dropdown, modelDecisionParam, globParam, content textarea
- Workflow editor renders: description, content textarea
- Both ban `---` string only
- Content is sent via `vscode.postMessage({type: 'update', content: documentState})`
- Webviews in VS Code have CSP and sandbox by default
- But: what if the `.md` file contains HTML that's rendered unsanitized in the textarea or description field?

**Tests to run:**
- [ ] Create `.agents/rules/test.md` with HTML/script tags in content — does it render?
- [ ] Test with SVG with onload handler in description field
- [ ] Check if the webview CSP blocks inline scripts

---

## Test Class 13: Import Settings from Other IDEs

**Why it matters:** Import functions read from external directories. If those dirs contain malicious config, it gets imported.

**Interesting observations:**
- Commands: importVSCodeSettings, importCursorSettings, importWindsurfSettings, importCiderSettings
- Also: importVSCodeExtensions, importCursorExtensions, importWindsurfExtensions
- These read from well-known locations (`~/.vscode/`, `~/.cursor/`, etc.)
- If an attacker can write to those directories, they can inject settings/extensions into Antigravity
- Extension import could install a malicious extension

**Tests to run:**
- [ ] What does importVSCodeExtensions actually do? Does it install extensions or just list them?
- [ ] Can a crafted `~/.vscode/extensions/` directory inject a malicious extension into Antigravity?

---

## Test Class 14: Browser Allowlist Manipulation

**Why it matters:** Controls what URLs the browser agent can visit.

**Interesting observations:**
- `browserAllowlist.txt` stored in data directory
- Initialized with just `localhost`
- Denylist is server-side (Google Superroots) — can't be manipulated locally
- But allowlist is a local file — if writable, attacker adds malicious domains
- Demo mode sets allowlist to `localhost\n` only and writes `DEMO_MODE.txt`

**Tests to run:**
- [ ] Find browserAllowlist.txt location and permissions
- [ ] Can the allowlist be modified by writing to storage.json (which is 644)?
- [ ] If allowlist is in a 644 file, other local users could add domains

---

## Test Class 15: Marketplace / Extension Gallery

**Why it matters:** Open VSX instead of Microsoft marketplace = different trust model.

**Interesting observations:**
- Gallery URL: `https://open-vsx.org/vscode/gallery`
- Item URL: `https://open-vsx.org/vscode/item`
- These are configurable settings — if `storage.json` (644) can override them, MITM possible
- Open VSX has different vetting than Microsoft marketplace
- Anyone can publish to Open VSX

**Tests to run:**
- [ ] Can marketplace URLs be overridden via workspace settings?
- [ ] If so, a malicious workspace could point to a fake gallery serving backdoored extensions

---

## Interesting Standalone Observations

1. **`installation_id` is 755** — world-executable file containing a UUID. Why executable?
2. **Unleash feature flag proxy** on 57170 — feature flags may gate security features (sandbox, strict mode). If accessible, could toggle security off.
3. **Self-signed cert** expires 2026-09-04 — after that, HTTP/2 to language server breaks. Not a vuln but interesting.
4. **`--cloud_code_endpoint https://daily-cloudcode-pa.googleapis.com`** — this instance is hitting the DAILY build backend, not production. May have different security posture.
5. **Browser landing page on 57165** has no auth — any local process can load it. Serves antigravity.svg and browser.css. Limited attack surface but worth noting.
6. **`antigravityUnifiedStateSync`** is an API proposal (not standard VS Code API) — custom IPC for shared state. If proposal has bugs, state could be manipulated.

---

## Priority Order for Testing

1. **antigravity:// URL scheme** — untested, remote attack surface, potential chain starter (Class 2)
2. **Rules `@` file references** — quick test, could be real path traversal (Class 4)
3. **.gitignore `[` regex breaking** — quick test, code bug in sandbox (Class 3)
4. **Workspace auto-execution on open** — what runs without user action? (Class 1)
5. **Storage file permissions when logged in** — do 644 files get tokens? (Class 8)
6. **Code executor invocation boundary** — can it be triggered externally? (Class 10)
7. **Custom editor HTML injection** — does content render unsanitized? (Class 12)
8. **Import settings malicious payload** — extension import = extension install? (Class 13)
9. **Marketplace URL override via workspace** — fake gallery serving backdoored extensions (Class 15)
10. **Extension server endpoint enumeration** — what's behind the CSRF on 57168? (Class 9)
11. **Allowlist file location and permissions** (Class 14)
12. **Remote SSH path traversal in terminateExtensionHostProcess.sh** (Class 11)
13. **Unleash feature flag proxy** — can it toggle security features? (Class 9)
