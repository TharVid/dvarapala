package main

import (
	"context"
	"errors"
	"fmt"
)

// All command handlers below are stubs that panic-print a friendly message.
// Implementations land as the corresponding internal/* packages are filled in.
// (cmdWrap is implemented in wrap.go.)

func cmdProxy(_ context.Context, _ []string) error {
	return fmt.Errorf("proxy: %w", errNotImplemented)
}

func cmdHub(_ context.Context, _ []string) error {
	return fmt.Errorf("hub: %w", errNotImplemented)
}

func cmdInit(_ context.Context, _ []string) error {
	return fmt.Errorf("init: %w", errNotImplemented)
}

func cmdLint(_ context.Context, _ []string) error {
	return fmt.Errorf("lint: %w", errNotImplemented)
}

func cmdTest(_ context.Context, _ []string) error {
	return fmt.Errorf("test: %w", errNotImplemented)
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
