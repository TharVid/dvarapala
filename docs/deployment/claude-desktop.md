# Deploying with Claude Desktop

## macOS

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` and wrap each `mcpServers` entry. See [examples/claude-desktop/claude_desktop_config.json](../../examples/claude-desktop/claude_desktop_config.json).

Restart Claude Desktop. Logs appear at `~/.dvarapala/audit.jsonl`.

## Windows

Edit `%APPDATA%\Claude\claude_desktop_config.json`. The `dvarapala.exe` binary must be in PATH (Scoop / Chocolatey / Winget handle this).

## Auto-install

```bash
dvarapala install --client claude-desktop --server filesystem
```

The installer reads the existing config, wraps the named server, writes a backup to `claude_desktop_config.json.bak`, and prints the diff before saving.
