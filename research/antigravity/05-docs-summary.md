# Antigravity Documentation Summary — Security-Relevant Findings
## Date: 2026-04-02

Source: antigravity.google/docs (8 pages fetched, raw snapshots in docs-*.md)

---

## Key Security-Relevant Facts from Official Docs

### Sandbox
- **Disabled by default** — opt-in via settings
- macOS: Seatbelt (`sandbox-exec`), Linux: `nsjail`
- "Commands can only write to your designated workspace directory and essential system locations"
- Users can bypass sandbox per-command in "Request Review" mode
- Strict mode auto-enables sandbox with network denied
- **No mention of symlink protection in docs** — confirms the code finding

### Browser Agent
- Runs in **separate Chrome profile** (isolated from user's normal Chrome)
- Browser tools can be disabled entirely in settings
- Uses existing Chrome installation (user can specify path)
- **Allowlist/Denylist system**:
  - Denylist: server-side via Google Superroots BadUrlsChecker (RPC). If server unavailable, access denied by default.
  - Allowlist: local text file, initialized with just `localhost`
  - User prompted with "always allow" for new domains
  - Denylist always takes precedence over allowlist
- **Important**: The allowlist controls what URLs the *agent* can browse to. It does NOT control what external processes can connect to the CDT MCP HTTP server.

### MCP
- Config at `~/.gemini/antigravity/mcp_config.json`
- Supports: stdio (command), Streamable HTTP (serverUrl)
- OAuth tokens stored at **`~/.gemini/antigravity/mcp_oauth_tokens.json`** — NEW file to check perms
- OAuth callback: `https://antigravity.google/oauth-callback` (hosted, not localhost — this is for MCP OAuth, separate from IDE login OAuth)
- No mention of command restrictions or sandboxing for MCP server processes
- MCP Store for pre-built integrations (Chrome DevTools is listed)

### Strict Mode
- Opt-in, not default
- When enabled:
  - Terminal: always requires review (allowlist ignored)
  - Browser JS: always requires review
  - Artifacts: always requires review
  - File system: respects .gitignore, workspace isolation
  - Sandbox: auto-enabled with network denied
- **NOT mentioned in strict mode**: MCP server access, CDT MCP HTTP endpoint, named pipe security
- Strict mode is about the *agent's* actions, not about protecting *against* external attackers

### What's NOT in the docs (notable absences)
1. No security model documentation (no threat model, no trust boundaries)
2. No mention of authentication on the CDT MCP HTTP endpoint
3. No mention of named pipe security
4. No mention of symlink handling in sandbox
5. No mention of mcp_config.json file permissions
6. No mention of antigravity:// URL scheme security
7. No documentation on the language server binary or its security properties
