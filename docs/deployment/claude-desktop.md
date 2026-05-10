# Deploy with Claude Desktop

Claude Desktop reads MCP servers from a per-platform JSON config:

| OS | Path |
|---|---|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |

## Quick install

```bash
dvarapala install \
  --client claude-desktop \
  --server filesystem \
  --command "npx -y @modelcontextprotocol/server-filesystem ~"
```

The installer backs up the existing config to `<file>.bak` and writes the new entry. Restart Claude Desktop (`Cmd+Q` on macOS, then re-open).

## Manual config

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "dvarapala",
      "args": [
        "wrap",
        "--policy", "/Users/<you>/.dvarapala/policy.yaml",
        "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem", "~"
      ]
    }
  }
}
```

On Windows, the binary path is typically `C:\Users\<you>\scoop\apps\dvarapala\current\dvarapala.exe`. Or just `"dvarapala"` if scoop's shim dir is on `PATH`.

## Verify

After restarting Claude Desktop, in any chat ask:

> List the files in /tmp using the filesystem MCP

Then in another terminal:

```bash
dvarapala logs -n 10
```

You should see `tools/list` and `tools/call` events with `action=allow`.

## Remove

Edit the config file and delete the entry, then restart Claude Desktop. The `<file>.bak` backup is your rollback.

## See also

- [Getting started](../getting-started.md)
- [CLI reference: install / doctor / logs](../cli-reference.md)
