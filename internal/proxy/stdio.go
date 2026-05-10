// Package proxy implements the transparent stdio passthrough.
//
// Phase 1: parse + audit + forward (no enforcement).
// Phase 2: a Policy engine evaluates each message; deny synthesises a
// JSON-RPC error back to the client; log_only audits with reason but
// still forwards.
// Phase 3: detectors run via the engine; redact action replaces matched
// content with [REDACTED:rule-id] before forwarding.
package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/tharvid/dvarapala/internal/audit"
	"github.com/tharvid/dvarapala/internal/detectors"
	"github.com/tharvid/dvarapala/internal/mcp"
	"github.com/tharvid/dvarapala/internal/policy"
)

// StdioOptions configures RunStdio.
type StdioOptions struct {
	Command []string
	Stdin   io.Reader
	Stdout  io.Writer
	Stderr  io.Writer
	Env     []string
	Audit   *audit.Logger
	// Server is a logical name tagged onto every audit event so a single
	// shared audit log can be filtered/grouped by which MCP the message
	// came from. Empty is fine (legacy behaviour).
	Server string
	// Engine is the policy evaluator. nil → transparent passthrough.
	Engine *policy.Engine
	// Detectors is consulted by the redact action: every named detector
	// runs on each JSON string value in the message and findings within
	// that string are replaced with [REDACTED:rule-id]. This walks the
	// JSON tree rather than treating the wire bytes as a flat string,
	// so quote/structure characters are never clobbered.
	Detectors *detectors.Registry
}

// JSON-RPC error code we use for policy denials. -32000 is reserved by
// the spec for application errors.
const denyErrorCode = -32000

// RunStdio is described in package doc.
func RunStdio(parentCtx context.Context, opts StdioOptions) (int, error) {
	ctx := parentCtx
	if len(opts.Command) == 0 {
		return -1, errors.New("proxy: no command")
	}
	if opts.Audit == nil {
		return -1, errors.New("proxy: nil audit logger")
	}
	if opts.Stdin == nil {
		opts.Stdin = os.Stdin
	}
	if opts.Stdout == nil {
		opts.Stdout = os.Stdout
	}
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}

	cmd := exec.CommandContext(ctx, opts.Command[0], opts.Command[1:]...)
	cmd.Stderr = opts.Stderr
	if opts.Env != nil {
		cmd.Env = opts.Env
	}
	cmd.Cancel = func() error {
		return cmd.Process.Signal(os.Interrupt)
	}
	cmd.WaitDelay = 5 * time.Second

	childIn, err := cmd.StdinPipe()
	if err != nil {
		return -1, fmt.Errorf("stdin pipe: %w", err)
	}
	childOut, err := cmd.StdoutPipe()
	if err != nil {
		return -1, fmt.Errorf("stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return -1, fmt.Errorf("start: %w", err)
	}

	// One mutex serialises the writer to the *client* (our stdout) so
	// deny-synthesised errors don't interleave with real upstream replies.
	var clientMu sync.Mutex

	var wg sync.WaitGroup
	wg.Add(2)

	// Inbound: client stdin → child stdin (with policy enforcement).
	go func() {
		defer wg.Done()
		defer childIn.Close()
		_ = relay(ctx, opts.Stdin, childIn, mcp.DirInbound, opts.Server, opts.Audit, opts.Engine,
			opts.Detectors, opts.Stdout, &clientMu)
	}()

	// Outbound: child stdout → client stdout.
	go func() {
		defer wg.Done()
		_ = relay(ctx, childOut, opts.Stdout, mcp.DirOutbound, opts.Server, opts.Audit, opts.Engine,
			opts.Detectors, opts.Stdout, &clientMu)
	}()

	waitErr := cmd.Wait()
	wg.Wait()

	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			return exitErr.ExitCode(), nil
		}
		return -1, waitErr
	}
	return cmd.ProcessState.ExitCode(), nil
}

// relay reads NDJSON from src, runs each message through the policy engine,
// and either forwards it to dst, drops it (notifications), or synthesises
// a deny response back to the client (requests).
//
// clientWriter is the writer that goes back to the LLM client; clientMu
// serialises all writes there so deny responses don't interleave with
// upstream replies on the outbound goroutine.
func relay(
	ctx context.Context,
	src io.Reader, dst io.Writer,
	dir mcp.Direction,
	server string,
	log *audit.Logger,
	eng *policy.Engine,
	registry *detectors.Registry,
	clientWriter io.Writer,
	clientMu *sync.Mutex,
) error {
	sc := mcp.NewScanner(src)
	for sc.Scan() {
		msg := sc.Message()
		raw := sc.Bytes()

		decision := policy.AllowDecision
		if eng != nil {
			decision = eng.Evaluate(ctx, msg, dir, raw)
		}

		auditPayload := raw
		forward := raw

		switch decision.Action {
		case policy.ActionDeny:
			if dir == mcp.DirInbound && msg.Kind() == mcp.KindRequest {
				if err := writeDeny(clientWriter, clientMu, msg.ID, decision); err != nil {
					return fmt.Errorf("deny synthesise: %w", err)
				}
				logEvent(log, server, dir, msg, decision, auditPayload)
				continue
			}
			logEvent(log, server, dir, msg, decision, auditPayload)
			continue

		case policy.ActionRedact:
			redacted, err := applyRedaction(ctx, raw, registry, decision.Replacement)
			if err == nil {
				forward = redacted
				auditPayload = redacted
			}

		case policy.ActionLogOnly, policy.ActionAllow, "":
		default:
		}

		logEvent(log, server, dir, msg, decision, auditPayload)

		// Outbound writes share clientMu with deny synthesis.
		if dir == mcp.DirOutbound {
			clientMu.Lock()
			err := mcp.WriteRaw(dst, forward)
			clientMu.Unlock()
			if err != nil {
				return fmt.Errorf("forward outbound: %w", err)
			}
		} else {
			if err := mcp.WriteRaw(dst, forward); err != nil {
				return fmt.Errorf("forward inbound: %w", err)
			}
		}
	}
	return sc.Err()
}

func logEvent(log *audit.Logger, server string, dir mcp.Direction, msg mcp.Message, d policy.Decision, payload []byte) {
	_ = log.Write(audit.Event{
		Server:    server,
		Direction: dir,
		Kind:      msg.Kind(),
		Method:    msg.Method,
		ID:        msg.ID,
		Action:    audit.Action(d.Action),
		Reason:    d.Reason,
		Rule:      d.Rule,
		Payload:   payload,
	})
}

// applyRedaction walks the JSON message and runs every detector in
// registry against each *string* value (not the wire bytes), so the JSON
// structure stays intact even when a detector's match would have crossed
// a quote or brace if applied to the raw line.
//
// template is the rule's Replacement string (with {{rule}} / {{kind}}
// placeholders). Empty falls back to "[REDACTED:{{rule}}]".
func applyRedaction(ctx context.Context, raw []byte, registry *detectors.Registry, template string) ([]byte, error) {
	if registry == nil {
		return raw, nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return raw, err
	}
	walked := redactWalk(ctx, v, registry, template)
	out, err := json.Marshal(walked)
	if err != nil {
		return raw, err
	}
	return out, nil
}

func redactWalk(ctx context.Context, v any, reg *detectors.Registry, tpl string) any {
	switch t := v.(type) {
	case string:
		return redactString(ctx, t, reg, tpl)
	case map[string]any:
		for k, vv := range t {
			t[k] = redactWalk(ctx, vv, reg, tpl)
		}
		return t
	case []any:
		for i, vv := range t {
			t[i] = redactWalk(ctx, vv, reg, tpl)
		}
		return t
	}
	return v
}

// redactString runs every detector in reg against s and returns s with
// every finding's Match substring replaced via formatRedactionMarker.
//
// Literal-string replacement (strings.ReplaceAll on h.Match) is used
// rather than byte-offset splicing because some detectors report
// column-within-line positions instead of absolute byte offsets —
// gitleaks does, for instance — and applying those columns as if they
// were offsets in multi-line content would clobber the wrong span.
func redactString(ctx context.Context, s string, reg *detectors.Registry, tpl string) string {
	var allHits []detectors.Finding
	for _, name := range reg.Names() {
		d, ok := reg.Get(name)
		if !ok {
			continue
		}
		hits, err := d.Detect(ctx, s)
		if err != nil {
			continue
		}
		allHits = append(allHits, hits...)
	}
	if len(allHits) == 0 {
		return s
	}
	// Replace longer matches first so that an outer span that contains a
	// nested match (e.g. a generic-api-key line that wraps an aws-access-
	// token) is redacted as a whole; the nested match's later replace
	// becomes a no-op (substring no longer present), which is fine — the
	// secret is still gone.
	sort.SliceStable(allHits, func(i, j int) bool {
		return len(allHits[i].Match) > len(allHits[j].Match)
	})
	out := s
	for _, h := range allHits {
		if h.Match == "" {
			continue
		}
		out = strings.ReplaceAll(out, h.Match, formatRedactionMarker(tpl, h))
	}
	return out
}

// formatRedactionMarker renders the per-rule replacement template,
// substituting {{rule}} and {{kind}} placeholders. Empty template falls
// back to the legacy "[REDACTED:rule-id]" form for backward compat.
func formatRedactionMarker(tpl string, h detectors.Finding) string {
	if tpl == "" {
		return fmt.Sprintf("[REDACTED:%s]", safeRuleID(h.RuleID))
	}
	out := strings.ReplaceAll(tpl, "{{rule}}", safeRuleID(h.RuleID))
	out = strings.ReplaceAll(out, "{{kind}}", findingKind(h))
	return out
}

// findingKind classifies a Finding's RuleID into a coarse category
// (secret / pii / prompt-injection / tool-mutation / tool-poisoning /
// generic) so {{kind}} can render usefully without the caller knowing
// the specific detector.
func findingKind(h detectors.Finding) string {
	id := strings.ToLower(h.RuleID)
	switch {
	case strings.Contains(id, "key"), strings.Contains(id, "token"), strings.Contains(id, "secret"), strings.Contains(id, "credential"):
		return "secret"
	case strings.Contains(id, "email"), strings.Contains(id, "phone"), strings.Contains(id, "ssn"), strings.Contains(id, "credit"), strings.Contains(id, "pii"):
		return "pii"
	case strings.Contains(id, "injection"), strings.Contains(id, "prompt"):
		return "prompt-injection"
	case strings.Contains(id, "mutation"), strings.Contains(id, "rugpull"):
		return "tool-mutation"
	case strings.Contains(id, "poisoning"):
		return "tool-poisoning"
	default:
		return "match"
	}
}

func safeRuleID(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

func writeDeny(w io.Writer, mu *sync.Mutex, id json.RawMessage, d policy.Decision) error {
	reason := d.Reason
	if reason == "" {
		reason = "blocked by Dvarapala policy"
	}
	resp := mcp.Message{
		JSONRPC: "2.0",
		ID:      id,
		Error: &mcp.RPCError{
			Code:    denyErrorCode,
			Message: fmt.Sprintf("[Dvarapala] %s", reason),
			Data:    denyData(d),
		},
	}
	mu.Lock()
	defer mu.Unlock()
	return mcp.WriteMessage(w, resp)
}

func denyData(d policy.Decision) json.RawMessage {
	b, _ := json.Marshal(struct {
		Rule string `json:"rule,omitempty"`
		Pack string `json:"pack,omitempty"`
	}{Rule: d.Rule, Pack: d.Pack})
	return b
}
