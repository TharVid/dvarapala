package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// methodsHiddenByDefault are setup/handshake messages that just create
// noise. The user can `--all` to see them or `--exclude` to add more.
var methodsHiddenByDefault = []string{
	"initialize",
	"notifications/initialized",
	"notifications/tools/list_changed",
	"notifications/resources/list_changed",
	"notifications/prompts/list_changed",
	"notifications/message",
	"roots/list",
	"prompts/list",
	"resources/list",
}

func cmdLogs(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("logs", flag.ContinueOnError)
	var (
		path         string
		follow       bool
		lastN        int
		raw          bool
		noColour     bool
		showAll      bool
		extraExclude string
		methodsOnly  string
		denyOnly     bool
		full         bool
	)
	fs.StringVar(&path, "audit", defaultAuditPath(), "audit log path")
	fs.BoolVar(&follow, "f", false, "follow (tail -f) the audit log")
	fs.BoolVar(&follow, "follow", false, "follow (tail -f) the audit log")
	fs.IntVar(&lastN, "n", 0, "show only the last N events before optional follow (0 = all)")
	fs.BoolVar(&raw, "json", false, "emit raw JSON instead of formatted")
	fs.BoolVar(&noColour, "no-color", false, "disable colour even if stdout is a TTY")
	fs.BoolVar(&showAll, "all", false, "show every event including handshake/boilerplate (initialize, roots/list, etc.)")
	fs.StringVar(&extraExclude, "exclude", "", "comma-separated method names to additionally hide")
	fs.StringVar(&methodsOnly, "methods", "", "comma-separated method names to ONLY show (overrides --all)")
	fs.BoolVar(&denyOnly, "deny", false, "show only deny / redact events")
	fs.BoolVar(&full, "full", false, "include full payload alongside the formatted line")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage: dvarapala logs [flags]

Pretty-print the Dvarapala audit log. By default, handshake noise like
'initialize' / 'roots/list' / 'notifications/...' is hidden so the
interesting traffic (tool calls, denies, redactions) stands out. Tool
names and arguments are extracted; response excerpts are shown.

Flags:
`)
		fs.PrintDefaults()
		fmt.Fprint(fs.Output(), `
Examples:
  dvarapala logs                     # interesting events, formatted
  dvarapala logs -f                  # tail -f
  dvarapala logs -n 50               # last 50
  dvarapala logs --deny              # only deny / redact actions
  dvarapala logs --all               # show even handshake chatter
  dvarapala logs --methods tools/call
  dvarapala logs --json -f           # raw JSONL, pipeable into jq
  dvarapala logs --full              # show payload too
`)
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	hidden := map[string]struct{}{}
	if !showAll {
		for _, m := range methodsHiddenByDefault {
			hidden[m] = struct{}{}
		}
	}
	for _, m := range strings.Split(extraExclude, ",") {
		m = strings.TrimSpace(m)
		if m != "" {
			hidden[m] = struct{}{}
		}
	}
	whitelist := map[string]struct{}{}
	if methodsOnly != "" {
		for _, m := range strings.Split(methodsOnly, ",") {
			m = strings.TrimSpace(m)
			if m != "" {
				whitelist[m] = struct{}{}
			}
		}
	}

	p := expandHome(path)
	f, err := os.Open(p)
	if err != nil {
		if os.IsNotExist(err) && follow {
			f, err = waitForFile(ctx, p)
		}
		if err != nil {
			return fmt.Errorf("open %s: %w", p, err)
		}
	}
	defer f.Close()

	pretty := !raw && (!noColour && isTerminal(os.Stdout))
	fmtr := &logFormatter{
		methodByID: map[string]string{},
		hidden:     hidden,
		whitelist:  whitelist,
		denyOnly:   denyOnly,
		colour:     pretty,
		full:       full,
	}

	emit := func(line []byte) {
		if raw {
			os.Stdout.Write(line)
			os.Stdout.Write([]byte{'\n'})
			return
		}
		fmtr.formatLine(os.Stdout, line)
	}

	// Phase 1: read existing content (apply -n if set).
	if lastN > 0 {
		ring := make([][]byte, 0, lastN)
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64<<10), 16<<20)
		for sc.Scan() {
			line := append([]byte(nil), sc.Bytes()...)
			if len(ring) == lastN {
				ring = ring[1:]
			}
			ring = append(ring, line)
		}
		if err := sc.Err(); err != nil {
			return err
		}
		for _, line := range ring {
			emit(line)
		}
	} else {
		rd := bufio.NewReader(f)
		for {
			line, err := rd.ReadBytes('\n')
			if len(line) > 0 {
				emit(bytes.TrimRight(line, "\r\n"))
			}
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return err
			}
		}
	}

	if !follow {
		return nil
	}

	rd := bufio.NewReader(f)
	var partial []byte
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		line, err := rd.ReadBytes('\n')
		if len(line) > 0 {
			partial = append(partial, line...)
			if line[len(line)-1] == '\n' {
				emit(bytes.TrimRight(partial, "\r\n"))
				partial = partial[:0]
			}
		}
		if errors.Is(err, io.EOF) {
			select {
			case <-ctx.Done():
				return nil
			case <-tick.C:
			}
			continue
		}
		if err != nil {
			return err
		}
	}
}

// waitForFile blocks until path exists or ctx is done.
func waitForFile(ctx context.Context, path string) (*os.File, error) {
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	for {
		f, err := os.Open(path)
		if err == nil {
			return f, nil
		}
		if !os.IsNotExist(err) {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-tick.C:
		}
	}
}

// logFormatter holds per-stream state needed to correlate responses to
// their original tool-call requests by id.
type logFormatter struct {
	methodByID map[string]string // id (as JSON) → method name on inbound request
	toolByID   map[string]string // id → tool name (for tools/call requests)
	hidden     map[string]struct{}
	whitelist  map[string]struct{}
	denyOnly   bool
	colour     bool
	full       bool
}

// auditEvent is the JSONL shape we read.
type auditEvent struct {
	TS        string          `json:"ts"`
	Direction string          `json:"direction"`
	Kind      string          `json:"kind"`
	Method    string          `json:"method,omitempty"`
	ID        json.RawMessage `json:"id,omitempty"`
	Action    string          `json:"action"`
	Reason    string          `json:"reason,omitempty"`
	Rule      string          `json:"rule,omitempty"`
	Payload   json.RawMessage `json:"payload,omitempty"`
}

func (f *logFormatter) formatLine(w io.Writer, line []byte) {
	if f.toolByID == nil {
		f.toolByID = map[string]string{}
	}
	var e auditEvent
	if err := json.Unmarshal(line, &e); err != nil {
		fmt.Fprintf(w, "? %s\n", line)
		return
	}

	idStr := ""
	if len(e.ID) > 0 {
		idStr = string(e.ID)
	}

	// Track id → method mapping on inbound requests so outbound responses
	// can be labelled by what they're responding to.
	if e.Method != "" && idStr != "" && e.Direction == "inbound" {
		f.methodByID[idStr] = e.Method
	}

	// Decide what to display + whether to filter this line out.
	s := f.summarise(e)

	if f.shouldHide(e, s) {
		return
	}
	display := s.display

	arrow := "→"
	if e.Direction == "outbound" {
		arrow = "←"
	}
	ts := e.TS
	if len(ts) >= 19 {
		ts = ts[11:19]
	}
	pad := func(s string, n int) string {
		if len(s) >= n {
			return s[:n]
		}
		return s + strings.Repeat(" ", n-len(s))
	}

	if !f.colour {
		fmt.Fprintf(w, "%s  %s  %-6s  %s",
			ts, arrow, e.Action, display)
		if e.Reason != "" {
			fmt.Fprintf(w, "  // %s", e.Reason)
		}
		if e.Rule != "" {
			fmt.Fprintf(w, "  [%s]", e.Rule)
		}
		fmt.Fprintln(w)
	} else {
		fmt.Fprintf(w, "%s%s%s  %s%s%s  %s%s%s  %s",
			dim, ts, reset,
			f.colourArrow(e.Direction), arrow, reset,
			f.colourAction(e.Action), pad(e.Action, 6), reset,
			display,
		)
		if e.Reason != "" {
			fmt.Fprintf(w, "  %s// %s%s", dim, e.Reason, reset)
		}
		if e.Rule != "" {
			fmt.Fprintf(w, "  %s[%s]%s", dim, e.Rule, reset)
		}
		fmt.Fprintln(w)
	}

	if f.full && len(e.Payload) > 0 {
		fmt.Fprintf(w, "    %s%s%s\n", dim, string(e.Payload), reset)
	}
}

// summary is what summarise returns: a one-line display, the optional
// tool name (for tool-call correlation), and the effective method (the
// request's method for inbound, the correlated request's method for
// outbound responses) used by shouldHide.
type summary struct {
	display         string
	tool            string
	effectiveMethod string
}

// summarise turns the JSON-RPC payload into a human-friendly one-liner:
// tool names + key args for tools/call requests, content excerpts for
// tool-call responses, etc.
func (f *logFormatter) summarise(e auditEvent) summary {
	idStr := ""
	if len(e.ID) > 0 {
		idStr = string(e.ID)
	}

	switch e.Direction {
	case "inbound":
		switch e.Method {
		case "tools/call":
			toolName, args := parseToolCall(e.Payload)
			if toolName != "" {
				if idStr != "" {
					f.toolByID[idStr] = toolName
				}
				return summary{
					display:         fmt.Sprintf("%s(%s)", toolName, formatArgs(args)),
					tool:            toolName,
					effectiveMethod: "tools/call",
				}
			}
			return summary{display: "tools/call", effectiveMethod: "tools/call"}
		default:
			return summary{display: e.Method, effectiveMethod: e.Method}
		}

	case "outbound":
		// JSON-RPC response — find what method/tool it's for.
		method := f.methodByID[idStr]
		tool := f.toolByID[idStr]
		switch {
		case tool != "":
			delete(f.toolByID, idStr)
			delete(f.methodByID, idStr)
			excerpt := parseToolCallResponse(e.Payload)
			if excerpt != "" {
				return summary{
					display:         fmt.Sprintf("%s → %s", tool, excerpt),
					tool:            tool,
					effectiveMethod: "tools/call",
				}
			}
			return summary{
				display:         fmt.Sprintf("%s → (response)", tool),
				tool:            tool,
				effectiveMethod: "tools/call",
			}
		case method == "tools/list":
			delete(f.methodByID, idStr)
			n := countToolsListed(e.Payload)
			if n >= 0 {
				return summary{
					display:         fmt.Sprintf("tools/list → %d tools", n),
					effectiveMethod: "tools/list",
				}
			}
			return summary{display: "tools/list (response)", effectiveMethod: "tools/list"}
		case method != "":
			delete(f.methodByID, idStr)
			return summary{
				display:         fmt.Sprintf("%s (response)", method),
				effectiveMethod: method,
			}
		case e.Method != "":
			// Server-initiated request to client (e.g. roots/list, sampling).
			return summary{display: e.Method, effectiveMethod: e.Method}
		default:
			// Orphan response — its request scrolled out of our log window.
			id := "?"
			if idStr != "" {
				id = idStr
			}
			return summary{display: fmt.Sprintf("response id=%s", id)}
		}
	}
	return summary{display: e.Method, effectiveMethod: e.Method}
}

func (f *logFormatter) shouldHide(e auditEvent, s summary) bool {
	// Always show denies / redacts.
	if e.Action == "deny" || e.Action == "redact" {
		return false
	}
	if f.denyOnly {
		return true
	}
	if len(f.whitelist) > 0 {
		if _, ok := f.whitelist[s.effectiveMethod]; ok {
			return false
		}
		return true
	}
	// Default: hide handshake noise.
	if _, ok := f.hidden[s.effectiveMethod]; ok {
		return true
	}
	// Hide orphan responses (no correlated method — request scrolled out
	// of the window). Still visible under --all.
	if s.effectiveMethod == "" && e.Direction == "outbound" {
		return true
	}
	// Hide entries with truly empty display (malformed or notification with
	// no method captured).
	if strings.TrimSpace(s.display) == "" {
		return true
	}
	return false
}

// parseToolCall extracts (toolName, arguments) from a tools/call payload.
func parseToolCall(payload json.RawMessage) (string, map[string]any) {
	if len(payload) == 0 {
		return "", nil
	}
	var msg struct {
		Params struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		} `json:"params"`
	}
	if err := json.Unmarshal(payload, &msg); err != nil {
		return "", nil
	}
	return msg.Params.Name, msg.Params.Arguments
}

// parseToolCallResponse extracts a short excerpt from a tools/call
// result payload — typically result.content[0].text or the structured
// content, truncated to ~80 chars.
func parseToolCallResponse(payload json.RawMessage) string {
	if len(payload) == 0 {
		return ""
	}
	var msg struct {
		Result struct {
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
			IsError bool `json:"isError"`
		} `json:"result"`
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(payload, &msg); err != nil {
		return ""
	}
	if msg.Error != nil {
		return fmt.Sprintf("error %d: %s", msg.Error.Code, truncForLog(msg.Error.Message, 80))
	}
	for _, c := range msg.Result.Content {
		if c.Type == "text" && c.Text != "" {
			return truncForLog(strings.ReplaceAll(c.Text, "\n", " "), 80)
		}
	}
	return ""
}

// countToolsListed returns the number of tools in a tools/list response,
// or -1 if it can't be parsed.
func countToolsListed(payload json.RawMessage) int {
	if len(payload) == 0 {
		return -1
	}
	var msg struct {
		Result struct {
			Tools []json.RawMessage `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(payload, &msg); err != nil {
		return -1
	}
	return len(msg.Result.Tools)
}

func formatArgs(args map[string]any) string {
	if len(args) == 0 {
		return ""
	}
	parts := make([]string, 0, len(args))
	for k, v := range args {
		val := truncForLog(stringifyArg(v), 60)
		parts = append(parts, fmt.Sprintf("%s=%s", k, val))
	}
	return strings.Join(parts, ", ")
}

func stringifyArg(v any) string {
	if s, ok := v.(string); ok {
		return fmt.Sprintf("%q", s)
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func truncForLog(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n < 4 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

const (
	reset  = "\x1b[0m"
	bold   = "\x1b[1m"
	dim    = "\x1b[2m"
	red    = "\x1b[31m"
	green  = "\x1b[32m"
	yellow = "\x1b[33m"
	blue   = "\x1b[34m"
	cyan   = "\x1b[36m"
	purple = "\x1b[35m"
)

func (f *logFormatter) colourArrow(dir string) string {
	if dir == "outbound" {
		return cyan
	}
	return blue
}

func (f *logFormatter) colourAction(action string) string {
	switch action {
	case "allow":
		return green
	case "deny":
		return red
	case "redact", "rewrite":
		return yellow
	default:
		return ""
	}
}

// isTerminal reports whether f is attached to a TTY.
func isTerminal(f *os.File) bool {
	if strings.ToLower(os.Getenv("NO_COLOR")) != "" {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}
