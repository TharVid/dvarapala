// Package proxy implements the transparent stdio passthrough.
//
// Phase 1: parse + audit + forward (no enforcement).
// Phase 2: a Policy engine evaluates each message; deny synthesises a
// JSON-RPC error back to the client; log_only audits with reason but
// still forwards.
package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/tharvid/dvarapala/internal/audit"
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
	// Engine is the policy evaluator. nil → transparent passthrough.
	Engine *policy.Engine
}

// JSON-RPC error code we use for policy denials. -32000 is reserved by
// the spec for application errors.
const denyErrorCode = -32000

// RunStdio is described in package doc.
func RunStdio(ctx context.Context, opts StdioOptions) (int, error) {
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
		_ = relay(opts.Stdin, childIn, mcp.DirInbound, opts.Audit, opts.Engine,
			opts.Stdout, &clientMu)
	}()

	// Outbound: child stdout → client stdout.
	go func() {
		defer wg.Done()
		_ = relay(childOut, opts.Stdout, mcp.DirOutbound, opts.Audit, opts.Engine,
			opts.Stdout, &clientMu)
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
	src io.Reader, dst io.Writer,
	dir mcp.Direction,
	log *audit.Logger,
	eng *policy.Engine,
	clientWriter io.Writer,
	clientMu *sync.Mutex,
) error {
	sc := mcp.NewScanner(src)
	for sc.Scan() {
		msg := sc.Message()

		decision := policy.AllowDecision
		if eng != nil {
			decision = eng.Evaluate(msg, dir)
		}

		event := audit.Event{
			Direction: dir,
			Kind:      msg.Kind(),
			Method:    msg.Method,
			ID:        msg.ID,
			Action:    audit.Action(decision.Action),
			Reason:    decision.Reason,
			Rule:      decision.Rule,
			Payload:   sc.Bytes(),
		}
		_ = log.Write(event)

		switch decision.Action {
		case policy.ActionDeny:
			if dir == mcp.DirInbound && msg.Kind() == mcp.KindRequest {
				// Synthesise a JSON-RPC error to the client; do NOT forward.
				if err := writeDeny(clientWriter, clientMu, msg.ID, decision); err != nil {
					return fmt.Errorf("deny synthesise: %w", err)
				}
				continue
			}
			// Notifications and outbound messages can't be "responded to";
			// deny just drops them silently (still audited above).
			continue

		case policy.ActionLogOnly, policy.ActionAllow, "":
			// fallthrough to forward
		default:
			// redact/rewrite/require_human_approval/llm_judge/delay are
			// parsed by the loader but not enforced in Phase 2 — log-and-allow
			// for forward compat.
		}

		// Outbound writes go through the same mutex to be safe.
		if dir == mcp.DirOutbound {
			clientMu.Lock()
			err := mcp.WriteRaw(dst, sc.Bytes())
			clientMu.Unlock()
			if err != nil {
				return fmt.Errorf("forward outbound: %w", err)
			}
		} else {
			if err := mcp.WriteRaw(dst, sc.Bytes()); err != nil {
				return fmt.Errorf("forward inbound: %w", err)
			}
		}
	}
	return sc.Err()
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
