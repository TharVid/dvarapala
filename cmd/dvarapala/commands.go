package main

import (
	"context"
	"errors"
	"fmt"
)

// Stubs for commands not yet implemented. wrap, init, lint, test, install,
// scan, doctor, logs all live in their own files.

func cmdProxy(_ context.Context, _ []string) error {
	return fmt.Errorf("proxy: %w", errNotImplemented)
}

func cmdHub(_ context.Context, _ []string) error {
	return fmt.Errorf("hub: %w", errNotImplemented)
}

var errNotImplemented = errors.New("not yet implemented (Phase 6: HTTP/SSE proxy + multi-MCP hub modes)")
