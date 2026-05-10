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

func cmdLogs(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("logs", flag.ContinueOnError)
	var (
		path     string
		follow   bool
		lastN    int
		raw      bool
		noColour bool
	)
	fs.StringVar(&path, "audit", defaultAuditPath(), "audit log path")
	fs.BoolVar(&follow, "f", false, "follow (tail -f) the audit log")
	fs.BoolVar(&follow, "follow", false, "follow (tail -f) the audit log")
	fs.IntVar(&lastN, "n", 0, "show only the last N events before optional follow (0 = all)")
	fs.BoolVar(&raw, "json", false, "emit raw JSON instead of formatted")
	fs.BoolVar(&noColour, "no-color", false, "disable colour even if stdout is a TTY")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage: dvarapala logs [flags]

Pretty-print the Dvarapala audit log.

Flags:
`)
		fs.PrintDefaults()
		fmt.Fprint(fs.Output(), `
Examples:
  dvarapala logs                # all events, pretty
  dvarapala logs -f             # follow new events as they land
  dvarapala logs -n 20          # last 20 events
  dvarapala logs -n 20 -f       # last 20 then follow
  dvarapala logs --json -f      # raw JSON for piping into jq
`)
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	p := expandHome(path)
	f, err := os.Open(p)
	if err != nil {
		if os.IsNotExist(err) && follow {
			// Wait for the file to appear when in follow mode.
			f, err = waitForFile(ctx, p)
		}
		if err != nil {
			return fmt.Errorf("open %s: %w", p, err)
		}
	}
	defer f.Close()

	pretty := !raw && (!noColour && isTerminal(os.Stdout))
	emit := func(line []byte) {
		if raw {
			os.Stdout.Write(line)
			os.Stdout.Write([]byte{'\n'})
			return
		}
		formatLine(os.Stdout, line, pretty)
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

	// Phase 2: follow mode — keep reading; sleep on EOF; cooperate with ctx.
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

func formatLine(w io.Writer, line []byte, colour bool) {
	var e struct {
		TS        string          `json:"ts"`
		Direction string          `json:"direction"`
		Kind      string          `json:"kind"`
		Method    string          `json:"method,omitempty"`
		ID        json.RawMessage `json:"id,omitempty"`
		Action    string          `json:"action"`
		Reason    string          `json:"reason,omitempty"`
		Rule      string          `json:"rule,omitempty"`
	}
	if err := json.Unmarshal(line, &e); err != nil {
		fmt.Fprintf(w, "? %s\n", line)
		return
	}
	method := e.Method
	if method == "" {
		method = "-"
	}
	id := "-"
	if len(e.ID) > 0 {
		id = string(e.ID)
	}
	arrow := "→"
	if e.Direction == "outbound" {
		arrow = "←"
	}
	ts := e.TS
	if len(ts) >= 19 {
		ts = ts[11:19]
	}
	if !colour {
		fmt.Fprintf(w, "%s  %s  %-13s  %-6s  %-32s  id=%s",
			ts, arrow, e.Kind, e.Action, method, id)
		if e.Reason != "" {
			fmt.Fprintf(w, "  %q", e.Reason)
		}
		fmt.Fprintln(w)
		return
	}
	fmt.Fprintf(w, "%s%s%s  %s%s%s  %s%-13s%s  %s  %s%-32s%s  %sid=%s%s",
		dim, ts, reset,
		colourArrow(e.Direction), arrow, reset,
		colourKind(e.Kind), e.Kind, reset,
		colourAction(e.Action),
		bold, method, reset,
		dim, id, reset,
	)
	if e.Reason != "" {
		fmt.Fprintf(w, "  %s%q%s", dim, e.Reason, reset)
	}
	fmt.Fprintln(w)
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

func colourArrow(dir string) string {
	if dir == "outbound" {
		return cyan
	}
	return blue
}

func colourKind(kind string) string {
	switch kind {
	case "request":
		return blue
	case "response":
		return green
	case "notification":
		return purple
	case "error":
		return red
	default:
		return ""
	}
}

func colourAction(action string) string {
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

// isTerminal reports whether f is attached to a TTY. Best-effort: checks
// the FileInfo mode bit. Avoids a dep on golang.org/x/term for a tiny CLI
// quality-of-life feature.
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
