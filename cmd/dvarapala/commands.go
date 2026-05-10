package main

import (
	"context"
	"errors"
	"fmt"
)

// cmdHub is the last stub — multi-MCP aggregator lands in the next commit.
// Every other verb is implemented in its own file.

func cmdHub(_ context.Context, _ []string) error {
	return fmt.Errorf("hub: %w", errNotImplemented)
}

var errNotImplemented = errors.New("not yet implemented (Phase 6b: multi-MCP hub mode)")
