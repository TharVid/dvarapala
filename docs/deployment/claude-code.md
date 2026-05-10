# Deploy with Claude Code

Claude Code reads MCP servers from `~/.claude.json` (user-scope, applies to every project). Dvarapala ships with first-class support — `dvarapala install --client claude-code` edits the file in place with a backup.

## Wrap everything in one shot (recommended)

If you already have MCP servers configured in Claude Code, use `--wrap-all`:

```bash
dvarapala install --client claude-code --wrap-all
```

That reads `~/.claude.json`, finds every stdio MCP server, and rewrites each entry to route through `dvarapala wrap`. Already-wrapped entries are left alone (idempotent). HTTP-based servers (the cloud ones managed by claude.ai — Atlassian, Sentry, Slack, etc.) are skipped with a note pointing to `dvarapala proxy`.

Restart Claude Code so the new child processes spawn with Dvarapala in front.

Re-run `dvarapala install --client claude-code --wrap-all` any time you `claude mcp add` a new stdio server — the new entry gets wrapped, existing wrapped ones stay as-is.

## Single-server install

If you don't have an entry yet (or want to add one fresh):

```bash
dvarapala install \
  --client claude-code \
  --server filesystem \
  --command "npx -y @modelcontextprotocol/server-filesystem ~"
```

This adds an entry under `mcpServers.filesystem` that wraps the filesystem MCP with `dvarapala wrap --policy ~/.dvarapala/policy.yaml`. Restart Claude Code.

## Verify

```bash
claude mcp list 2>&1 | grep -E '✓|filesystem'
# filesystem: /usr/local/bin/dvarapala wrap --policy /Users/.../policy.yaml -- npx ... - ✓ Connected
```

Then in another terminal:

```bash
dvarapala logs -f
```

Ask Claude to use the filesystem tool ("list files in /tmp") and watch events stream by.

## Wrap multiple MCPs

Re-run `dvarapala install` with different `--server` and `--command` per server:

```bash
dvarapala install --client claude-code --server github \
  --command "npx -y @modelcontextprotocol/server-github"

dvarapala install --client claude-code --server postgres \
  --command "npx -y @modelcontextprotocol/server-postgres postgresql://localhost/mydb"
```

Each lives as its own entry under `mcpServers` in `~/.claude.json`.

## Important: gotchas with restart timing

Claude Code launches each MCP server as a long-lived child process at session start. **If you upgrade the dvarapala binary or change `policy.yaml`, restart Claude Code** so a fresh child loads the new code. Until then the old binary is still running with the old policy.

Two ways to spot this:

```bash
# What's currently running?
ps -ef | grep "dvarapala wrap"

# Was Dvarapala spawned with the latest policy flags?
claude mcp get <server-name>
```

## Manual config edit (skip dvarapala install)

If you'd rather edit `~/.claude.json` yourself, the entry shape is:

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

`dvarapala` must be on `PATH` (or use the absolute path `/usr/local/bin/dvarapala`).

## Remove

```bash
claude mcp remove <server-name> -s user
```

…or edit `~/.claude.json` and delete the entry.

## What about claude.ai-managed (cloud) MCPs?

Servers like Sentry, Atlassian, Slack, Gmail that show up in `claude mcp list` as `claude.ai *: https://...` are **HTTP-hosted** services managed by claude.ai. The stdio `wrap` mode can't intercept them. Route them through `dvarapala proxy` (Phase 6) — point the URL at a local Dvarapala listener:

```bash
dvarapala proxy \
  --upstream https://mcp.atlassian.com/v1/mcp \
  --listen 127.0.0.1:8081 \
  --policy ~/.dvarapala/policy.yaml
```

Then change Atlassian's URL in your claude.ai config to `http://127.0.0.1:8081`.

## See also

- [Getting started](../getting-started.md)
- [CLI reference: install / doctor](../cli-reference.md)
