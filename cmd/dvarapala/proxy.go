package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/tharvid/dvarapala/internal/audit"
	"github.com/tharvid/dvarapala/internal/config"
	"github.com/tharvid/dvarapala/internal/policy"
	"github.com/tharvid/dvarapala/internal/proxy"
)

func cmdProxy(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("proxy", flag.ContinueOnError)
	var (
		upstream   string
		listen     string
		policyPath string
		auditPath  string
	)
	fs.StringVar(&upstream, "upstream", "", "upstream MCP HTTP URL (required)")
	fs.StringVar(&listen, "listen", "127.0.0.1:8080", "local address to listen on")
	fs.StringVar(&policyPath, "policy", "", "policy YAML (empty = transparent passthrough)")
	fs.StringVar(&auditPath, "audit", defaultAuditPath(), "audit log path")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage: dvarapala proxy --upstream URL [flags]

Run as an HTTP / Streamable-HTTP proxy in front of a remote MCP server.
The same policy engine + detectors used by 'dvarapala wrap' (stdio mode)
also run here, so deny / redact / log_only behave identically.

Flags:
`)
		fs.PrintDefaults()
		fmt.Fprint(fs.Output(), `
Examples:
  # Front Atlassian's hosted MCP locally with the default policy:
  dvarapala proxy --upstream https://mcp.atlassian.com/v1/mcp \
      --listen 127.0.0.1:8081 --policy ~/.dvarapala/policy.yaml

  # Then change the Atlassian MCP URL in your client to http://127.0.0.1:8081.
`)
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if upstream == "" {
		return errors.New("--upstream URL is required")
	}

	pol, err := config.Load(policyPath)
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

	log, err := audit.Open(expandHome(auditPath))
	if err != nil {
		return fmt.Errorf("audit: %w", err)
	}
	defer log.Close()

	fmt.Fprintf(os.Stderr, "dvarapala proxy listening on %s → upstream %s\n", listen, upstream)
	return proxy.RunHTTP(ctx, proxy.HTTPOptions{
		Upstream:  upstream,
		Listen:    listen,
		Audit:     log,
		Engine:    eng,
		Detectors: registry,
	})
}
