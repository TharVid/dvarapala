package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// cmdInstall edits an MCP-client config file (Claude Code's ~/.claude.json,
// Claude Desktop's claude_desktop_config.json, Cursor's mcp.json, Cline's
// settings) to wrap an existing MCP server entry with `dvarapala wrap`, or
// to add a new wrapped entry from scratch.
//
// A backup is always written next to the config before editing.
func cmdInstall(_ context.Context, args []string) error {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	var (
		client     string
		serverName string
		policyPath string
		dvarBinary string
		raw        string
	)
	fs.StringVar(&client, "client", "claude-code", "MCP client: claude-code | claude-desktop | cursor | cline")
	fs.StringVar(&serverName, "server", "", "name to register the wrapped MCP server as (required)")
	fs.StringVar(&policyPath, "policy", defaultPolicyPath(), "path to dvarapala policy YAML")
	fs.StringVar(&dvarBinary, "binary", "", "path to dvarapala binary (default: this binary)")
	fs.StringVar(&raw, "command", "", "raw command for the upstream MCP server (e.g. \"npx -y @modelcontextprotocol/server-filesystem ~\")")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage: dvarapala install --client CLIENT --server NAME --command "CMD ARGS..."

Wrap an MCP server in the specified client's config so all its traffic
flows through Dvarapala.

Flags:
`)
		fs.PrintDefaults()
		fmt.Fprint(fs.Output(), `
Examples:
  dvarapala install --client claude-code --server filesystem \
    --command "npx -y @modelcontextprotocol/server-filesystem ~"

  dvarapala install --client claude-desktop --server github \
    --command "npx -y @modelcontextprotocol/server-github"
`)
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if serverName == "" {
		return errors.New("--server NAME is required")
	}
	if raw == "" {
		return errors.New(`--command "CMD ARGS..." is required`)
	}
	if dvarBinary == "" {
		exe, err := os.Executable()
		if err != nil {
			return fmt.Errorf("locate dvarapala binary: %w", err)
		}
		dvarBinary = exe
	}

	cmdParts := strings.Fields(raw)
	if len(cmdParts) == 0 {
		return errors.New("empty --command")
	}
	wrappedArgs := append([]string{"wrap", "--policy", expandHome(policyPath), "--"}, cmdParts...)

	cfgPath, err := configPathFor(client)
	if err != nil {
		return err
	}
	return rewriteMCPConfig(cfgPath, serverName, dvarBinary, wrappedArgs)
}

// configPathFor returns the JSON config path used by each supported client.
func configPathFor(client string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	switch client {
	case "claude-code":
		return filepath.Join(home, ".claude.json"), nil
	case "claude-desktop":
		return filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"), nil
	case "cursor":
		return filepath.Join(home, ".cursor", "mcp.json"), nil
	case "cline":
		return filepath.Join(home, ".config", "cline", "mcp_settings.json"), nil
	default:
		return "", fmt.Errorf("unknown client %q (valid: claude-code, claude-desktop, cursor, cline)", client)
	}
}

// rewriteMCPConfig reads the JSON config at path, ensures a top-level
// "mcpServers" object exists, and writes/overwrites the entry named
// serverName to point at the dvarapala wrap command. A timestamped backup
// is written first.
func rewriteMCPConfig(path, serverName, binary string, wrappedArgs []string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	var cfg map[string]any
	if data, err := os.ReadFile(path); err == nil && len(data) > 0 {
		if backupErr := os.WriteFile(path+".bak", data, 0o600); backupErr != nil {
			return fmt.Errorf("backup: %w", backupErr)
		}
		if err := json.Unmarshal(data, &cfg); err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	if cfg == nil {
		cfg = map[string]any{}
	}
	servers, _ := cfg["mcpServers"].(map[string]any)
	if servers == nil {
		servers = map[string]any{}
		cfg["mcpServers"] = servers
	}
	servers[serverName] = map[string]any{
		"command": binary,
		"args":    wrappedArgs,
	}

	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %s (backup at %s.bak)\n", path, path)
	fmt.Fprintf(os.Stderr, "registered MCP server %q wrapping: %s %s\n",
		serverName, binary, strings.Join(wrappedArgs, " "))
	return nil
}
