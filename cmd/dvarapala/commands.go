package main

import (
	"context"
	"errors"
	"fmt"
)

// All command handlers below are intentional skeletons for the initial
// scaffold. Implementations land in subsequent commits as the corresponding
// internal/* packages are filled in.

func cmdWrap(ctx context.Context, args []string) error {
	return fmt.Errorf("wrap: %w", errNotImplemented)
}

func cmdProxy(ctx context.Context, args []string) error {
	return fmt.Errorf("proxy: %w", errNotImplemented)
}

func cmdHub(ctx context.Context, args []string) error {
	return fmt.Errorf("hub: %w", errNotImplemented)
}

func cmdInit(ctx context.Context, args []string) error {
	return fmt.Errorf("init: %w", errNotImplemented)
}

func cmdLint(ctx context.Context, args []string) error {
	return fmt.Errorf("lint: %w", errNotImplemented)
}

func cmdTest(ctx context.Context, args []string) error {
	return fmt.Errorf("test: %w", errNotImplemented)
}

func cmdInstall(ctx context.Context, args []string) error {
	return fmt.Errorf("install: %w", errNotImplemented)
}

func cmdScan(ctx context.Context, args []string) error {
	return fmt.Errorf("scan: %w", errNotImplemented)
}

func cmdDoctor(ctx context.Context, args []string) error {
	return fmt.Errorf("doctor: %w", errNotImplemented)
}

var errNotImplemented = errors.New("not yet implemented (scaffold)")
