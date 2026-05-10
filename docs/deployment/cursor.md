# Deploy with Cursor

Cursor reads MCP servers from one of:

| Scope | Path |
|---|---|
| Global (all projects) | `~/.cursor/mcp.json` |
| Per-project | `<project>/.cursor/mcp.json` |

## Quick install

```bash
dvarapala install \
  --client cursor \
  --server filesystem \
  --command "npx -y @modelcontextprotocol/server-filesystem ${workspaceFolder}"
```

This writes to the global config (`~/.cursor/mcp.json`). Backup at `<file>.bak`.

Restart Cursor.

## Manual config

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "dvarapala",
      "args": [
        "wrap",
        "--policy", "${env:HOME}/.dvarapala/policy.yaml",
        "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem", "${workspaceFolder}"
      ]
    }
  }
}
```

Cursor expands `${env:HOME}` and `${workspaceFolder}` at launch.

## Verify

In a Cursor chat, ask:

> Use the filesystem MCP to list files in this project

Then:

```bash
dvarapala logs -f
```

You'll see traffic as Cursor invokes the tool.

## Per-project config

Drop a `.cursor/mcp.json` in your project root for project-specific MCPs. Useful when one project has a postgres MCP another doesn't.

## See also

- [Getting started](../getting-started.md)
