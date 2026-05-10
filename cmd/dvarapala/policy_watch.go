package main

import (
	"context"

	"github.com/tharvid/dvarapala/internal/config"
	"github.com/tharvid/dvarapala/internal/policy"
)

// startPolicyWatcher launches a background goroutine that polls
// policyPath every 2 seconds and reloads engine when the file's mtime
// or size changes. Empty policyPath disables the watcher (wrap mode
// with no policy file is the transparent-passthrough case).
//
// A bad reload (parse error / regex error) is logged to stderr but
// never replaces the active rules, so the gateway never breaks under
// a half-edited policy.yaml.
func startPolicyWatcher(ctx context.Context, eng *policy.Engine, policyPath string) {
	if eng == nil || policyPath == "" {
		return
	}
	loader := &policy.FileRuleLoader{
		Path: policyPath,
		LoadFunc: func(p string) ([]policy.Rule, error) {
			pol, err := config.Load(p)
			if err != nil {
				return nil, err
			}
			return pol.Rules, nil
		},
	}
	w := &policy.Watcher{
		Engine: eng,
		Path:   policyPath,
		Loader: loader,
	}
	go func() { _ = w.Watch(ctx) }()
}
