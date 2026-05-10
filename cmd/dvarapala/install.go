package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
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
	wrappedArgs := append([]string{"wrap", "--policy", expandedPolicy, "--server", serverName, "--"}, cmdParts...)
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

// wrapAllMCPs reads the client config and protects every MCP server in place:
//
//   - stdio servers (have `command:`) get rewritten to route through
//     `dvarapala wrap --policy POLICY -- ORIGINAL_CMD ORIGINAL_ARGS`.
//   - HTTP/SSE servers (have `url:`) get a background `dvarapala proxy`
//     daemon spawned (detached, invisible to the user — Setsid on Unix,
//     DETACHED_PROCESS on Windows). The daemon's PID is recorded under
//     ~/.dvarapala/daemons/<name>.json so `dvarapala daemon list/stop/
//     stop-all` can manage it later. The client config is rewritten to
//     point at the local proxy listen URL.
//   - Already-wrapped or already-proxied entries are left alone
//     (idempotent).
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
	auditPath := defaultAuditPath()

	// Ports already in use by previously-spawned daemons should not be
	// reassigned to a fresh proxy.
	used := map[int]bool{}
	if existing, _ := loadDaemonRecords(); existing != nil {
		for _, r := range existing {
			used[portFromListen(r.Listen)] = true
		}
	}

	wrappedStdio := []string{}
	proxiedHTTP := []string{}
	skippedAlready := 0

	// Sort names so output is deterministic across runs.
	names := make([]string, 0, len(rawServers))
	for n := range rawServers {
		names = append(names, n)
	}
	sort.Strings(names)

	for _, name := range names {
		entry, ok := rawServers[name].(map[string]any)
		if !ok {
			continue
		}

		// HTTP/SSE upstream → spawn a detached proxy daemon for it.
		if rawURL, hasURL := entry["url"].(string); hasURL && rawURL != "" {
			isLocal := strings.Contains(rawURL, "127.0.0.1:") || strings.Contains(rawURL, "localhost:")
			if isLocal {
				// URL already points local. Three sub-cases:
				//
				//   1. matching daemon record + process alive → genuinely
				//      already proxied; skip.
				//   2. matching daemon record + process dead → re-spawn at
				//      the same port using the saved upstream.
				//   3. no daemon record (stale local URL) → look at the
				//      pristine .bak file for the original upstream and
				//      spawn a fresh proxy. This recovers from earlier
				//      versions that lost daemon records on stop-all.
				if rec, exists := findDaemonRecord(name); exists {
					alive := processAlive(rec.PID)
					stale := rec.SchemaVersion < daemonSchemaVersion
					if alive && !stale {
						skippedAlready++
						continue
					}
					if alive && stale {
						// Daemon was spawned by an older version that doesn't
						// tag MCP server names onto audit events. Kill and
						// re-spawn so logs become MCP-attributable.
						_, _ = stopDaemon(rec)
					}
					newRec, perr := spawnProxy(binary, name, rec.Upstream, rec.Listen, policyPath, auditPath)
					if perr != nil {
						return fmt.Errorf("re-spawn proxy for %q: %w", name, perr)
					}
					reason := "re-spawned"
					if stale {
						reason = "re-spawned for server-name tagging"
					}
					proxiedHTTP = append(proxiedHTTP, fmt.Sprintf("%s → %s (pid %d, %s)", name, rec.Listen, newRec.PID, reason))
					continue
				}
				originalURL, ok := findOriginalURLFromBackup(cfgPath, name)
				if !ok {
					fmt.Fprintf(os.Stderr,
						"  WARNING: %q points at %q but no daemon record or backup upstream found.\n"+
							"           Edit %s manually to restore the original URL, or run\n"+
							"           `claude mcp remove %s -s user` then re-add it.\n",
						name, rawURL, cfgPath, name)
					skippedAlready++
					continue
				}
				port, perr := pickFreePort(portStartHint(), used)
				if perr != nil {
					return fmt.Errorf("server %q: %w", name, perr)
				}
				listen := fmt.Sprintf("127.0.0.1:%d", port)
				rec, perr := spawnProxy(binary, name, originalURL, listen, policyPath, auditPath)
				if perr != nil {
					return fmt.Errorf("spawn proxy for %q: %w", name, perr)
				}
				newEntry := map[string]any{"url": "http://" + listen}
				if t, ok := entry["type"]; ok {
					newEntry["type"] = t
				}
				rawServers[name] = newEntry
				proxiedHTTP = append(proxiedHTTP, fmt.Sprintf("%s → %s (pid %d, recovered from backup)", name, listen, rec.PID))
				continue
			}
			port, perr := pickFreePort(portStartHint(), used)
			if perr != nil {
				return fmt.Errorf("server %q: %w", name, perr)
			}
			listen := fmt.Sprintf("127.0.0.1:%d", port)
			rec, perr := spawnProxy(binary, name, rawURL, listen, policyPath, auditPath)
			if perr != nil {
				return fmt.Errorf("spawn proxy for %q: %w", name, perr)
			}
			localURL := "http://" + listen
			newEntry := map[string]any{"url": localURL}
			if t, ok := entry["type"]; ok {
				newEntry["type"] = t
			}
			rawServers[name] = newEntry
			proxiedHTTP = append(proxiedHTTP, fmt.Sprintf("%s → %s (pid %d)", name, listen, rec.PID))
			continue
		}

		// stdio — wrap with dvarapala wrap.
		cmd, _ := entry["command"].(string)
		if cmd == "" {
			continue
		}
		if cmd == binary || cmd == binaryAbs || filepath.Base(cmd) == "dvarapala" {
			// Already wrapped. If the wrap entry predates --server (v0.1.6 and
			// earlier), retag it in-place so audit events get the MCP name.
			existingArgs := stringSlice(entry["args"])
			retagged, changed := ensureServerFlag(existingArgs, name)
			if !changed {
				skippedAlready++
				continue
			}
			newEntry := map[string]any{
				"command": binary,
				"args":    retagged,
			}
			if env, ok := entry["env"]; ok {
				newEntry["env"] = env
			}
			rawServers[name] = newEntry
			wrappedStdio = append(wrappedStdio, name+" (retagged)")
			continue
		}
		origArgs := stringSlice(entry["args"])
		wrappedArgs := append([]string{"wrap", "--policy", policyPath, "--server", name, "--", cmd}, origArgs...)
		newEntry := map[string]any{
			"command": binary,
			"args":    wrappedArgs,
		}
		if env, ok := entry["env"]; ok {
			newEntry["env"] = env
		}
		rawServers[name] = newEntry
		wrappedStdio = append(wrappedStdio, name)
	}

	if len(wrappedStdio) == 0 && len(proxiedHTTP) == 0 {
		fmt.Fprintf(os.Stderr, "nothing to do — %d entries already wrapped/proxied\n", skippedAlready)
		return nil
	}

	if err := writeConfig(cfgPath, cfg); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %s (backup at %s.bak)\n", cfgPath, cfgPath)
	if len(wrappedStdio) > 0 {
		fmt.Fprintf(os.Stderr, "wrapped %d stdio MCP server(s): %s\n",
			len(wrappedStdio), strings.Join(wrappedStdio, ", "))
	}
	if len(proxiedHTTP) > 0 {
		fmt.Fprintf(os.Stderr, "spawned %d HTTP proxy daemon(s) in background:\n", len(proxiedHTTP))
		for _, line := range proxiedHTTP {
			fmt.Fprintf(os.Stderr, "  %s\n", line)
		}
		fmt.Fprintln(os.Stderr, "  manage with: dvarapala daemon list | stop NAME | stop-all")
	}
	if skippedAlready > 0 {
		fmt.Fprintf(os.Stderr, "  %d already wrapped/proxied (left as-is)\n", skippedAlready)
	}
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "next: restart your MCP client so it picks up the new endpoints.")
	return nil
}

// readConfigForEdit reads path, writes a pristine .bak alongside on the
// first run only (so re-running this command never overwrites the
// pre-Dvarapala state), and returns the parsed JSON map.
//
// Older versions overwrote .bak on every run. That meant after two
// invocations the .bak held a *Dvarapala-mutated* config (with local
// 127.0.0.1 URLs from the previous run) instead of the user's actual
// original — and rolling back was impossible. The fix: only write .bak
// when it doesn't exist yet. A timestamped per-run snapshot is also
// written so an audit trail is available.
func readConfigForEdit(path string) (map[string]any, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if len(data) > 0 {
		// Pristine .bak — first-write-wins.
		if _, statErr := os.Stat(path + ".bak"); os.IsNotExist(statErr) {
			if backupErr := os.WriteFile(path+".bak", data, 0o600); backupErr != nil {
				return nil, fmt.Errorf("backup: %w", backupErr)
			}
		}
		// Always write a timestamped snapshot so users can compare runs
		// and we don't lose history.
		ts := time.Now().UTC().Format("20060102-150405")
		_ = os.WriteFile(fmt.Sprintf("%s.bak.%s", path, ts), data, 0o600)
	}
	cfg := map[string]any{}
	if len(data) > 0 {
		if err := json.Unmarshal(data, &cfg); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
	}
	return cfg, nil
}

// findOriginalURLFromBackup looks in <cfgPath>.bak for the entry named
// `name` and returns its URL if it is a non-local upstream. Used when
// --wrap-all encounters a stale local URL with no daemon record so we
// can recover the original upstream automatically.
func findOriginalURLFromBackup(cfgPath, name string) (string, bool) {
	data, err := os.ReadFile(cfgPath + ".bak")
	if err != nil {
		return "", false
	}
	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		return "", false
	}
	servers, _ := cfg["mcpServers"].(map[string]any)
	entry, _ := servers[name].(map[string]any)
	url, _ := entry["url"].(string)
	if url == "" {
		return "", false
	}
	if strings.Contains(url, "127.0.0.1") || strings.Contains(url, "localhost") {
		return "", false // backup itself is also stale, nothing useful
	}
	return url, true
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

// ensureServerFlag inserts "--server NAME" before the "--" separator in a
// `dvarapala wrap` arg slice, if not already present. Returns the (possibly
// updated) slice and a flag indicating whether a change was made. Args are
// expected to look like: ["wrap", "--policy", P, "--", cmd, args…].
func ensureServerFlag(args []string, name string) ([]string, bool) {
	dashIdx := -1
	for i, a := range args {
		if a == "--server" {
			return args, false
		}
		if a == "--" && dashIdx == -1 {
			dashIdx = i
		}
	}
	if dashIdx == -1 || name == "" {
		return args, false
	}
	out := make([]string, 0, len(args)+2)
	out = append(out, args[:dashIdx]...)
	out = append(out, "--server", name)
	out = append(out, args[dashIdx:]...)
	return out, true
}
