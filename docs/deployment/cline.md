# Deploy with Cline (VSCode extension)

Cline reads MCP settings from `~/.config/cline/mcp_settings.json` (or the equivalent on macOS / Windows under the VSCode extension storage path).

## Quick install

```bash
dvarapala install \
  --client cline \
  --server github \
  --command "npx -y @modelcontextprotocol/server-github"
```

The installer backs up the file and adds a wrapped entry. Restart VSCode (or just the Cline extension panel).

## Manual config

```json
{
  "mcpServers": {
    "github": {
      "command": "dvarapala",
      "args": [
        "wrap",
        "--policy", "/Users/<you>/.dvarapala/policy.yaml",
        "--",
        "npx", "-y", "@modelcontextprotocol/server-github"
      ],
      "env": { "GITHUB_TOKEN": "ghp_..." }
    }
  }
}
```

## Verify

In a Cline chat:

> Use the GitHub MCP to list my recent issues

Then:

```bash
dvarapala logs -n 10
```

## See also

- [Getting started](../getting-started.md)
- [CLI reference: install](../cli-reference.md)
