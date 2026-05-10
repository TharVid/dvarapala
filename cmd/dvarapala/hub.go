package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/tharvid/dvarapala/internal/audit"
	"github.com/tharvid/dvarapala/internal/config"
	"github.com/tharvid/dvarapala/internal/hub"
	"github.com/tharvid/dvarapala/internal/policy"
)

func cmdHub(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("hub", flag.ContinueOnError)
	var (
		hubConfigPath string
		policyPath    string
		auditPath     string
		listen        string
		auditMaxMB    int
		auditKeep     int
	)
	fs.StringVar(&hubConfigPath, "config", "", "path to hub.yaml (required)")
	fs.StringVar(&policyPath, "policy", "", "policy YAML (overrides hub.yaml.policy)")
	fs.StringVar(&auditPath, "audit", defaultAuditPath(), "audit log path")
	fs.StringVar(&listen, "listen", "", "listen address (overrides hub.yaml.listen)")
	fs.IntVar(&auditMaxMB, "audit-max-mb", 50, "rotate audit log after this many MiB (0 disables rotation)")
	fs.IntVar(&auditKeep, "audit-keep", 5, "number of rotated audit files to retain")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage: dvarapala hub --config hub.yaml [flags]

Run as a multi-MCP aggregator: one Dvarapala process fronting many
upstream MCP servers (mix of stdio children and HTTP endpoints), routed
by URL path. Same engine + detectors as wrap/proxy modes.

Flags:
`)
		fs.PrintDefaults()
		fmt.Fprint(fs.Output(), `
Example hub.yaml:
  listen: 127.0.0.1:9000
  servers:
    filesystem:
      command: ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/data"]
    github:
      command: ["npx", "-y", "@modelcontextprotocol/server-github"]
    atlassian:
      upstream: "https://mcp.atlassian.com/v1/mcp"

Then in your MCP client config, point each server at:
  http://127.0.0.1:9000/<name>
`)
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if hubConfigPath == "" {
		return errors.New("--config hub.yaml is required")
	}

	cfg, err := hub.Load(expandHome(hubConfigPath))
	if err != nil {
		return err
	}
	if listen != "" {
		cfg.Listen = listen
	}
	effectivePolicy := policyPath
	if effectivePolicy == "" {
		effectivePolicy = cfg.PolicyPath
	}

	pol, err := config.Load(effectivePolicy)
	if err != nil {
		return fmt.Errorf("load policy: %w", err)
	}
	eng, err := policy.NewEngine(pol.Rules, policy.ActionAllow)
	if err != nil {
		return fmt.Errorf("compile policy: %w", err)
	}
	registry, err := buildDetectorRegistry()
	if err != nil {
		return fmt.Errorf("detectors: %w", err)
	}
	eng.SetRegistry(registry)

	log, err := audit.OpenWith(expandHome(auditPath), audit.RotateOptions{
		MaxBytes:  int64(auditMaxMB) * 1024 * 1024,
		KeepFiles: auditKeep,
	})
	if err != nil {
		return fmt.Errorf("audit: %w", err)
	}
	defer log.Close()

	startPolicyWatcher(ctx, eng, expandHome(effectivePolicy))

	fmt.Fprintf(os.Stderr, "dvarapala hub listening on %s with %d server(s)\n",
		cfg.Listen, len(cfg.Servers))
	for name, sc := range cfg.Servers {
		fmt.Fprintf(os.Stderr, "  • %-20s [%s] %s\n", name, sc.Type, hubBackendDesc(sc))
	}
	return hub.Run(ctx, cfg, hub.Options{
		Audit:     log,
		Engine:    eng,
		Detectors: registry,
	})
}

func hubBackendDesc(s hub.ServerConfig) string {
	if s.Upstream != "" {
		return s.Upstream
	}
	if len(s.Command) > 0 {
		first := s.Command[0]
		if len(s.Command) > 1 {
			first += " " + s.Command[1]
		}
		return first
	}
	return "(empty)"
}
