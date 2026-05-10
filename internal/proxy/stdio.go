// Package proxy implements the transparent stdio passthrough.
//
// Phase 1: each JSON-RPC message is parsed, audited, and forwarded unchanged.
// Phase 2 will hook the policy engine in between parse and forward.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/tharvid/dvarapala/internal/audit"
	"github.com/tharvid/dvarapala/internal/mcp"
)

// StdioOptions configures RunStdio.
type StdioOptions struct {
	// Command is the upstream MCP server to spawn.
	Command []string

	// Stdin/Stdout/Stderr default to os.Std{in,out,err} when nil.
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer

	// Env is the child's environment. nil means inherit.
	Env []string

	// Audit receives one Event per message in either direction. Required.
	Audit *audit.Logger
}

// RunStdio spawns Command, pipes stdio bidirectionally, audits each
// JSON-RPC message, and returns the child's exit code on clean exit.
//
// Lifecycle:
//   - When ctx is cancelled, the child is sent SIGINT (Interrupt). If it
//     does not exit within 5s, the OS kills it.
//   - When the local stdin closes (EOF), the child's stdin is closed too,
//     allowing the child to exit gracefully.
//   - When the child exits, the function returns.
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
	// Soft-cancel: SIGINT first; SIGKILL after WaitDelay if child stalls.
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

	var wg sync.WaitGroup
	wg.Add(2)

	// Inbound: client stdin → child stdin
	go func() {
		defer wg.Done()
		defer childIn.Close()
		_ = relay(opts.Stdin, childIn, mcp.DirInbound, opts.Audit)
	}()

	// Outbound: child stdout → client stdout
	go func() {
		defer wg.Done()
		_ = relay(childOut, opts.Stdout, mcp.DirOutbound, opts.Audit)
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

func relay(src io.Reader, dst io.Writer, dir mcp.Direction, log *audit.Logger) error {
	sc := mcp.NewScanner(src)
	for sc.Scan() {
		msg := sc.Message()
		_ = log.Write(audit.Event{
			Direction: dir,
			Kind:      msg.Kind(),
			Method:    msg.Method,
			ID:        msg.ID,
			Action:    audit.ActionAllow,
			Payload:   sc.Bytes(),
		})
		if err := mcp.WriteRaw(dst, sc.Bytes()); err != nil {
			return fmt.Errorf("forward %s: %w", dir, err)
		}
	}
	return sc.Err()
}
