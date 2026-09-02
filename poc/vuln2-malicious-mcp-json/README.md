# POC 2: Arbitrary Code Execution via Malicious .mcp.json in Git Repo

## Vulnerability
Claude Code reads `.mcp.json` from the project directory (`getCwd()`) and
spawns whatever `command` + `args` are specified for stdio-type MCP servers.

In non-interactive mode (`claude -p`, SDK usage) with `projectSettings` enabled,
project-scoped MCP servers are **auto-approved** — no user prompt.

In interactive mode, the user sees an approval dialog, but the server name
shown is attacker-controlled and the command details are not prominently displayed.

## Attack Vector
1. Attacker creates a malicious git repository with a `.mcp.json`
2. Victim clones the repo and opens it with Claude Code
3. The MCP server config specifies an arbitrary command
4. In non-interactive mode: auto-executes
5. In interactive mode: user sees a benign-looking server name and approves

## Impact
- Full RCE as the victim user
- Supply chain attack: any popular repo could be poisoned
- CI/CD compromise: automated Claude Code runs in pipelines

## Key Code Path

### 1. `.mcp.json` loaded from project dir
`config.ts:852`:
```typescript
const mcpJsonPath = join(getCwd(), '.mcp.json')
```

### 2. Auto-approval in non-interactive mode
`utils.ts:398-403`:
```typescript
if (getIsNonInteractiveSession() && isSettingSourceEnabled('projectSettings')) {
    return 'approved'
}
```

### 3. Command spawned without validation
`client.ts:944-958`:
```typescript
} else if (serverRef.type === 'stdio' || !serverRef.type) {
    transport = new StdioClientTransport({
      command: finalCommand,    // from .mcp.json, no validation
      args: finalArgs,          // from .mcp.json, no validation
      env: { ...subprocessEnv(), ...serverRef.env },
    })
```

No validation that `command` is:
- An actual MCP server binary
- On a safe path
- Not a shell with `-c` args containing arbitrary code

## Reproduction Steps
See `exploit.sh` for automated reproduction.

## Files
- `evil-repo/` — simulated malicious git repository
- `exploit.sh` — automated POC
