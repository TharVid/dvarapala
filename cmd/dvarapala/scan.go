package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/tharvid/dvarapala/internal/detectors"
	"github.com/tharvid/dvarapala/internal/detectors/toolpoisoning"
	"github.com/tharvid/dvarapala/internal/mcp"
)

// cmdScan runs a one-shot security audit against an MCP stdio server: it
// spawns the server, completes the initialize handshake, requests the tool
// list, and runs the native MCP detectors (tool-poisoning at minimum)
// against every tool description. Useful before adding a community MCP to
// your client config.
func cmdScan(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	var (
		raw   string
		jsonF bool
	)
	fs.StringVar(&raw, "command", "", `the upstream MCP server command (e.g. "npx -y @modelcontextprotocol/server-filesystem /tmp")`)
	fs.BoolVar(&jsonF, "json", false, "emit findings as JSON (one finding per line)")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage: dvarapala scan --command "CMD ARGS..."

Spawn an MCP stdio server, list its tools, and run the native MCP
security detectors (tool-poisoning) against every tool description.
Exit code 0 = no findings, 1 = at least one finding.

Flags:
`)
		fs.PrintDefaults()
		fmt.Fprint(fs.Output(), `
Example:
  dvarapala scan --command "npx -y @some-org/maybe-evil-mcp"
`)
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if raw == "" {
		return errors.New(`--command "CMD ARGS..." is required`)
	}
	parts := strings.Fields(raw)
	cmd := exec.CommandContext(ctx, parts[0], parts[1:]...)
	cmd.Stderr = os.Stderr

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	defer func() { _ = cmd.Process.Kill() }()

	tools, err := tcpHandshakeAndListTools(stdin, stdout)
	if err != nil {
		return fmt.Errorf("handshake: %w", err)
	}

	tp := toolpoisoning.New()
	totalHits := 0
	if !jsonF {
		fmt.Fprintf(os.Stderr, "scanned %d tools from %q\n\n", len(tools), raw)
	}
	for _, t := range tools {
		var tool struct {
			Name        string `json:"name"`
			Description string `json:"description"`
		}
		_ = json.Unmarshal(t, &tool)
		hits, _ := tp.Detect(ctx, tool.Description)
		for _, h := range hits {
			totalHits++
			if jsonF {
				out := map[string]any{
					"tool":     tool.Name,
					"detector": h.Detector,
					"rule_id":  h.RuleID,
					"match":    h.Match,
				}
				b, _ := json.Marshal(out)
				fmt.Println(string(b))
			} else {
				fmt.Fprintf(os.Stderr, "  ✗ %-30s rule=%-32s match=%q\n", tool.Name, h.RuleID, h.Match)
			}
		}
		if !jsonF && len(hits) == 0 {
			fmt.Fprintf(os.Stderr, "  ✓ %-30s (no findings)\n", tool.Name)
		}
	}
	if !jsonF {
		fmt.Fprintln(os.Stderr, "")
		if totalHits == 0 {
			fmt.Fprintln(os.Stderr, "no tool-poisoning findings.")
		} else {
			fmt.Fprintf(os.Stderr, "%d tool-poisoning finding(s) across %d tools.\n", totalHits, len(tools))
		}
	}
	if totalHits > 0 {
		os.Exit(1)
	}
	return nil
}

// tcpHandshakeAndListTools talks to an MCP stdio server: initialize +
// notifications/initialized + tools/list. Returns the list of raw tool
// JSON entries.
func tcpHandshakeAndListTools(stdin io.WriteCloser, stdout io.Reader) ([]json.RawMessage, error) {
	if err := mcp.WriteMessage(stdin, mcp.Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Method:  "initialize",
		Params:  json.RawMessage(`{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"dvarapala-scan","version":"0"}}`),
	}); err != nil {
		return nil, fmt.Errorf("send initialize: %w", err)
	}

	sc := mcp.NewScanner(stdout)
	deadline := time.Now().Add(15 * time.Second)
	if !readUntil(sc, deadline, func(m mcp.Message) bool {
		return string(m.ID) == "1" && (len(m.Result) > 0 || m.Error != nil)
	}) {
		return nil, errors.New("no initialize response")
	}

	if err := mcp.WriteMessage(stdin, mcp.Message{
		JSONRPC: "2.0",
		Method:  "notifications/initialized",
	}); err != nil {
		return nil, fmt.Errorf("send initialized: %w", err)
	}
	if err := mcp.WriteMessage(stdin, mcp.Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`2`),
		Method:  "tools/list",
	}); err != nil {
		return nil, fmt.Errorf("send tools/list: %w", err)
	}

	var listResp mcp.Message
	if !readUntil(sc, deadline, func(m mcp.Message) bool {
		if string(m.ID) == "2" && (len(m.Result) > 0 || m.Error != nil) {
			listResp = m
			return true
		}
		return false
	}) {
		return nil, errors.New("no tools/list response")
	}
	if listResp.Error != nil {
		return nil, fmt.Errorf("tools/list error: %s", listResp.Error.Message)
	}
	var env struct {
		Tools []json.RawMessage `json:"tools"`
	}
	if err := json.Unmarshal(listResp.Result, &env); err != nil {
		return nil, fmt.Errorf("parse tools/list result: %w", err)
	}
	return env.Tools, nil
}

func readUntil(sc *mcp.Scanner, deadline time.Time, accept func(mcp.Message) bool) bool {
	for sc.Scan() {
		m := sc.Message()
		if accept(m) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
	}
	return false
}

// silence unused-import in some build configs
var _ = detectors.Finding{}
