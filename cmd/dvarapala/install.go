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
// settings) to wrap MCP server entries with `dvarapala wrap`.
//
// Two modes:
//
//	--wrap-all                            wrap every existing stdio MCP at once.
//	--server NAME --command "CMD ARGS"    add (or replace) a single server.
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
		wrapAll    bool
	)
	fs.StringVar(&client, "client", "claude-code", "MCP client: claude-code | claude-desktop | cursor | cline")
	fs.StringVar(&serverName, "server", "", "name to register the wrapped MCP server as (single-server mode)")
	fs.StringVar(&policyPath, "policy", defaultPolicyPath(), "path to dvarapala policy YAML")
	fs.StringVar(&dvarBinary, "binary", "", "path to dvarapala binary (default: this binary)")
	fs.StringVar(&raw, "command", "", "raw command for the upstream MCP server (single-server mode)")
	fs.BoolVar(&wrapAll, "wrap-all", false, "wrap every existing stdio MCP server in the client's config (idempotent)")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage:
  dvarapala install --client CLIENT --wrap-all
  dvarapala install --client CLIENT --server NAME --command "CMD ARGS..."

Edit an MCP-client config so its MCP servers route through Dvarapala.

  --wrap-all  reads the existing config and wraps every stdio MCP
              server in place. HTTP/URL-based servers are skipped
              with a note (use 'dvarapala proxy' for those). Already-
              wrapped servers are left alone (idempotent).

  Single-server mode adds or replaces ONE entry by --server name.

A backup is always written to <config>.bak before editing.

Flags:
`)
		fs.PrintDefaults()
		fmt.Fprint(fs.Output(), `
Examples:
  # The "I just brew installed and want everything protected" path:
  dvarapala install --client claude-code --wrap-all

  # Or add one server:
  dvarapala install --client claude-code --server filesystem \
    --command "npx -y @modelcontextprotocol/server-filesystem ~"
`)
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if dvarBinary == "" {
		exe, err := os.Executable()
		if err != nil {
			return fmt.Errorf("locate dvarapala binary: %w", err)
		}
		dvarBinary = exe
	}

	cfgPath, err := configPathFor(client)
	if err != nil {
		return err
	}
	expandedPolicy := expandHome(policyPath)

	if wrapAll {
		if serverName != "" || raw != "" {
			return errors.New("--wrap-all is exclusive with --server / --command")
		}
		return wrapAllMCPs(cfgPath, dvarBinary, expandedPolicy)
	}

	if serverName == "" || raw == "" {
		return errors.New(`single-server mode needs --server NAME and --command "CMD ARGS..." (or pass --wrap-all)`)
	}
	cmdParts := strings.Fields(raw)
	if len(cmdParts) == 0 {
		return errors.New("empty --command")
	}
	wrappedArgs := append([]string{"wrap", "--policy", expandedPolicy, "--"}, cmdParts...)
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

// rewriteMCPConfig adds/replaces a single mcpServers entry.
func rewriteMCPConfig(path, serverName, binary string, wrappedArgs []string) error {
	cfg, err := readConfigForEdit(path)
	if err != nil {
		return err
	}
	servers := getOrCreateServers(cfg)
	servers[serverName] = map[string]any{
		"command": binary,
		"args":    wrappedArgs,
	}
	if err := writeConfig(path, cfg); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %s (backup at %s.bak)\n", path, path)
	fmt.Fprintf(os.Stderr, "registered MCP server %q wrapping: %s %s\n",
		serverName, binary, strings.Join(wrappedArgs, " "))
	return nil
}

// wrapAllMCPs reads the client config, wraps every stdio MCP server in
// place with `dvarapala wrap --policy POLICY -- ORIGINAL_CMD ORIGINAL_ARGS`,
// and writes the result back.
//
// Skipped silently:
//   - servers whose `command` is already this binary (already wrapped)
//   - servers with a `url` field instead of `command` (HTTP/SSE — use proxy)
func wrapAllMCPs(cfgPath, binary, policyPath string) error {
	cfg, err := readConfigForEdit(cfgPath)
	if err != nil {
		return err
	}
	rawServers, _ := cfg["mcpServers"].(map[string]any)
	if rawServers == nil || len(rawServers) == 0 {
		return fmt.Errorf("no mcpServers entries in %s — add one first or use --server / --command", cfgPath)
	}

	binaryAbs, _ := filepath.Abs(binary)
	wrapped := 0
	skippedAlready := 0
	skippedHTTP := []string{}
	wrappedNames := []string{}

	for name, raw := range rawServers {
		entry, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		// HTTP / URL upstream → skip (proxy mode is the right tool)
		if _, hasURL := entry["url"]; hasURL {
			skippedHTTP = append(skippedHTTP, name)
			continue
		}
		cmd, _ := entry["command"].(string)
		if cmd == "" {
			continue
		}
		// Already wrapped? Check by binary path equality on either the raw
		// or absolute form of `command`.
		if cmd == binary || cmd == binaryAbs ||
			filepath.Base(cmd) == "dvarapala" {
			skippedAlready++
			continue
		}

		// Build the wrapped args: [wrap, --policy, POLICY, --, ORIGINAL_CMD, ORIGINAL_ARGS...]
		origArgs := stringSlice(entry["args"])
		wrappedArgs := append([]string{"wrap", "--policy", policyPath, "--", cmd}, origArgs...)

		newEntry := map[string]any{
			"command": binary,
			"args":    wrappedArgs,
		}
		// Preserve env and any other fields the client cares about.
		if env, ok := entry["env"]; ok {
			newEntry["env"] = env
		}
		rawServers[name] = newEntry
		wrapped++
		wrappedNames = append(wrappedNames, name)
	}

	if wrapped == 0 {
		fmt.Fprintf(os.Stderr, "nothing to do — %d already wrapped, %d HTTP/URL servers skipped\n",
			skippedAlready, len(skippedHTTP))
		if len(skippedHTTP) > 0 {
			fmt.Fprintf(os.Stderr, "  HTTP servers: %s\n", strings.Join(skippedHTTP, ", "))
			fmt.Fprintln(os.Stderr, "  → use 'dvarapala proxy --upstream URL' for those")
		}
		return nil
	}

	if err := writeConfig(cfgPath, cfg); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %s (backup at %s.bak)\n", cfgPath, cfgPath)
	fmt.Fprintf(os.Stderr, "wrapped %d stdio MCP server(s): %s\n", wrapped, strings.Join(wrappedNames, ", "))
	if skippedAlready > 0 {
		fmt.Fprintf(os.Stderr, "  %d already wrapped (left as-is)\n", skippedAlready)
	}
	if len(skippedHTTP) > 0 {
		fmt.Fprintf(os.Stderr, "  %d HTTP/URL server(s) skipped: %s\n", len(skippedHTTP), strings.Join(skippedHTTP, ", "))
		fmt.Fprintln(os.Stderr, "  → use 'dvarapala proxy --upstream URL' for those")
	}
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "next: restart your MCP client so the new wrappers take effect.")
	return nil
}

// readConfigForEdit reads path (creating an empty config if absent),
// writes a .bak alongside, and returns the parsed JSON map.
func readConfigForEdit(path string) (map[string]any, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if len(data) > 0 {
		if backupErr := os.WriteFile(path+".bak", data, 0o600); backupErr != nil {
			return nil, fmt.Errorf("backup: %w", backupErr)
		}
	}
	cfg := map[string]any{}
	if len(data) > 0 {
		if err := json.Unmarshal(data, &cfg); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
	}
	return cfg, nil
}

func writeConfig(path string, cfg map[string]any) error {
	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, 0o600)
}

func getOrCreateServers(cfg map[string]any) map[string]any {
	servers, _ := cfg["mcpServers"].(map[string]any)
	if servers == nil {
		servers = map[string]any{}
		cfg["mcpServers"] = servers
	}
	return servers
}

func stringSlice(v any) []string {
	out := []string{}
	if v == nil {
		return out
	}
	if s, ok := v.([]any); ok {
		for _, item := range s {
			if str, ok := item.(string); ok {
				out = append(out, str)
			}
		}
	}
	return out
}
