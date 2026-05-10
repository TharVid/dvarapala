# Getting started

## Install

| Platform | Command |
|---|---|
| macOS / Linux | `brew install tharvid/dvarapala/dvarapala` |
| Windows | `scoop install dvarapala` |
| Linux (deb) | `apt install dvarapala` |
| Docker | `docker pull ghcr.io/tharvid/dvarapala` |
| Go | `go install github.com/tharvid/dvarapala/cmd/dvarapala@latest` |

## Initialize

```bash
dvarapala init
# wrote ~/.dvarapala/policy.yaml with defaults:
#   - pii (Presidio)
#   - secrets (gitleaks)
#   - prompt-injection (llm-guard + Prompt-Guard)
#   - tool-poisoning (native)
#   - tool-mutation (native)
#   - destructive-actions (native)
```

## Wrap an MCP server

For Claude Desktop, edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) — see [examples/claude-desktop/](../examples/claude-desktop/).

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "dvarapala",
      "args": [
        "wrap", "--policy", "~/.dvarapala/policy.yaml", "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem", "~/code"
      ]
    }
  }
}
```

Or use the auto-installer:

```bash
dvarapala install --client claude-desktop --server filesystem
```

## Verify

```bash
dvarapala doctor
```

## Inspect events

Events are written as JSONL to `~/.dvarapala/audit.jsonl`:

```bash
tail -f ~/.dvarapala/audit.jsonl | jq .
```
