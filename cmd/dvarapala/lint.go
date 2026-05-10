package main

import (
	"context"
	"fmt"
	"os"

	"github.com/tharvid/dvarapala/internal/config"
	"github.com/tharvid/dvarapala/internal/policy"
)

func cmdLint(_ context.Context, args []string) error {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, `Usage: dvarapala lint <policy.yaml>`)
		return fmt.Errorf("expected exactly one argument")
	}
	path := expandHome(args[0])
	pol, err := config.Load(path)
	if err != nil {
		return err
	}
	if _, err := policy.NewEngine(pol.Rules, policy.ActionAllow); err != nil {
		return fmt.Errorf("compile: %w", err)
	}
	fmt.Fprintf(os.Stderr, "OK: %s — %d rules across %d defaults\n",
		path, len(pol.Rules), len(pol.Defaults))
	return nil
}
