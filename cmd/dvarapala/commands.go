package main

import (
	"context"
	"errors"
	"fmt"
)

// Stubs for commands not yet implemented. Implementations live in their
// own files (wrap.go, init.go, lint.go, test.go, logs.go).

func cmdProxy(_ context.Context, _ []string) error {
	return fmt.Errorf("proxy: %w", errNotImplemented)
}

func cmdHub(_ context.Context, _ []string) error {
	return fmt.Errorf("hub: %w", errNotImplemented)
}

func cmdInstall(_ context.Context, _ []string) error {
	return fmt.Errorf("install: %w", errNotImplemented)
}

func cmdScan(_ context.Context, _ []string) error {
	return fmt.Errorf("scan: %w", errNotImplemented)
}

func cmdDoctor(_ context.Context, _ []string) error {
	return fmt.Errorf("doctor: %w", errNotImplemented)
}

var errNotImplemented = errors.New("not yet implemented (scaffold)")
