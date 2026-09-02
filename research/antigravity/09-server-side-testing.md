# Antigravity Server-Side Testing Results
## Date: 2026-04-04

---

## Architecture Confirmed

### Two Language Server Instances Running
- **PID 37871** — authenticated, workspace `/tmp/antigrav-test-workspace`, outbound to `34.54.84.110:443` (daily-cloudcode-pa.googleapis.com)
  - CSRF: `77ba639d-23fe-48b5-93bb-bb5cfd2dbc44`
  - Extension server port: 62235
  - Language server HTTPS: 62236 (TLS, gRPC-Web+JSON, HTTP/2)
  - Language server: 62237 (TLS)
  - LSP: 62245
- **PID 39448** — not authenticated, workspace `/tmp/antigrav-vsix-test`
  - Extension server port: 62812

### Backend Communication
- REST API: `https://daily-cloudcode-pa.googleapis.com/v1internal:<method>`
- gRPC: `google.internal.cloud.code.v1internal.JetskiService` and `CloudCode`
- Auth: OAuth 2 Bearer token (scopes: cloud-platform, userinfo.email, userinfo.profile, cclog, experimentsandconfigs)
- OAuth Client ID 1: `1071006060591-tmhssin2h21lcre235vtolojh4g403ep.apps.googleusercontent.com` (Electron/auth)
- OAuth Client ID 2: `884354919052-36trc1jjb3tguiac32ov6cod268c5blh.apps.googleusercontent.com` (Go binary, likely Codeium legacy)

---

## REST API Endpoints (from binary extraction)

### JetskiService (Google backend)
- `/v1internal:checkUrlDenylist` — URL validation, potential SSRF
- `/v1internal:rewriteUri` — URI rewriting, potential SSRF/open redirect
- `/v1internal:fetchUserInfo` — user info
- `/v1internal:listAgents` — agent listing
- `/v1internal:listCascadeNuxes` — NUX listing
- `/v1internal:setUserSettings` — settings update
- `/v1internal:recordTrajectoryAnalytics` — analytics

### CloudCode Service (Google backend)
- `/v1internal:completeCode` — code completion
- `/v1internal:generateChat` — chat generation
- `/v1internal:generateCode` — code generation
- `/v1internal:generateContent` — content generation
- `/v1internal:streamGenerateContent` — streaming content
- `/v1internal:transformCode` — code transformation
- `/v1internal:searchSnippets` — snippet search, potential info disclosure
- `/v1internal:listRemoteRepositories` — repo listing, potential IDOR
- `/v1internal:listCloudAICompanionProjects` — project listing
- `/v1internal:fetchAvailableModels` — model listing
- `/v1internal:countTokens` — token counting
- `/v1internal:fetchAdminControls` — admin controls
- `/v1internal:loadCodeAssist` — code assist loading
- `/v1internal:onboardUser` — user onboarding
- `/v1internal:tabChat` — tab chat
- `/v1internal:migrateDatabaseCode` — database migration
- `/v1internal:fetchCodeCustomizationState` — customization
- `/v1internal:getCodeAssistGlobalUserSetting` — user settings
- `/v1internal:setCodeAssistGlobalUserSetting` — update settings
- `/v1internal:internalAtomicAgenticChat` — internal agentic chat
- `/v1internal:listExperiments` — experiment listing
- `/v1internal:listModelConfigs` — model configs
- `/v1internal:recordClientEvent` — event recording
- `/v1internal:retrieveUserQuota` — quota
- `/v1internal:recordCodeAssistMetrics` — metrics
- `/v1internal:recordSmartchoicesFeedback` — feedback

### PredictionService
- `/v1internal:countTokens`
- `/v1internal:fetchAvailableModels`
- `/v1internal:generateContent` (streaming)
- `/v1internal:retrieveUserQuota`

---

## gRPC-Web Testing Results

### Language Server (port 62236, TLS, authenticated)
- **WellSupportedLanguages**: WORKS — returns language list
- **GetUserTrajectoryDebug**: WORKS — returns trajectory with cascadeId, workspaces, timestamps
- **GetCascadeModelConfigs**: WORKS — returns `{}` (empty config)
- **SendUserCascadeMessage**: INTERNAL_ERROR — proto field mismatch (items structure unknown)
- **HandleStreamingCommand**: INTERNAL_ERROR — proto field mismatch
- **API server methods (WhoAmI, GetWebSearchResults, etc.)**: 404 — not exposed on language server port

### Extension Server (port 62235/62812, plaintext gRPC-Web)
- **ExecuteCommand**: WORKS — confirmed RCE (Bug 11)
- **GetChromeDevtoolsMcpUrl**: WORKS — returns `http://127.0.0.1:62874/mcp`
- **GetSecretValue**: grpc-status 13 (INTERNAL) — method exists but wrong field names
- **OpenExternalUrl**: grpc-status 13 (INTERNAL) — method exists but wrong field names

### Key Finding: Language Server HTTPS Port Has NO CSRF on Successful Calls
- With CSRF token: grpc-status 0 (OK)
- Without CSRF token: grpc-status 16 (UNAUTHENTICATED)
- CSRF token leaked in `ps aux` as `--csrf_token`

---

## Blockers

### Cannot directly call Google backend APIs
- Language server doesn't proxy JetskiService/CloudCode calls through its local gRPC interface
- REST API requires OAuth 2 Bearer token
- Token is stored in Electron's safeStorage (Keychain-encrypted)
- Cannot extract token without Keychain password prompt or memory dump

### Proto field mismatch
- `SendUserCascadeMessage` and `HandleStreamingCommand` return INTERNAL_ERROR
- The exact request message structure is needed
- JS client uses `{cascadeId, items, cascadeConfig, artifactComments, fileDiffComments, fileComments, media}`
- But `items` inner structure is unknown (not just `{text: "..."}`)

---

## Next Steps

### Priority 1: Extract proto descriptors properly
- Use `protodump` or similar tool to extract full FileDescriptorProto from Go binary
- Alternatively: hook the language server's proto registration to dump schemas
- Or: search the binary for gzip-compressed proto descriptors more systematically

### Priority 2: Get OAuth token for direct API testing
- Option A: Set HTTPS_PROXY env var and restart Antigravity → intercept token with mitmproxy
- Option B: Dump language server process memory and grep for Bearer token
- Option C: Use Electron DevTools to extract token from JS runtime

### Priority 3: SSRF targets once token obtained
- `/v1internal:checkUrlDenylist` with `http://metadata.google.internal/computeMetadata/v1/`
- `/v1internal:rewriteUri` with internal URIs
- `/v1internal:searchSnippets` with crafted queries
- `/v1internal:listRemoteRepositories` with modified IDs (IDOR)

### Priority 4: Extension server expanded testing
- `GetSecretValue` — figure out field names, could read stored secrets
- `RunExtensionCode` — could be another code execution path
- `StoreSecretValue` — could write secrets
- `OpenExternalUrl` — could trigger SSRF from Electron process
