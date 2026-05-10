package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/tharvid/dvarapala/internal/audit"
	"github.com/tharvid/dvarapala/internal/config"
	"github.com/tharvid/dvarapala/internal/policy"
	"github.com/tharvid/dvarapala/internal/proxy"
)

func cmdWrap(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("wrap", flag.ContinueOnError)
	var (
		policyPath string
		auditPath  string
	)
	fs.StringVar(&policyPath, "policy", "", "path to policy YAML (empty = transparent passthrough)")
	fs.StringVar(&auditPath, "audit", defaultAuditPath(), "path to audit log (JSONL)")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage: dvarapala wrap [flags] -- <command> [args...]

Wrap an MCP stdio server with the Dvarapala gateway. Every JSON-RPC message
in either direction is parsed, evaluated against the policy, audited, and
forwarded (or denied with a synthesised JSON-RPC error).

Flags:
`)
		fs.PrintDefaults()
		fmt.Fprint(fs.Output(), `
Example:
  dvarapala wrap --policy ~/.dvarapala/policy.yaml -- \
    npx -y @modelcontextprotocol/server-filesystem ~/code
`)
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	cmd := fs.Args()
	if len(cmd) == 0 {
		fs.Usage()
		return errors.New("missing command after '--'")
	}

	pol, err := config.Load(policyPath)
	if err != nil {
		return fmt.Errorf("load policy: %w", err)
	}
	eng, err := policy.NewEngine(pol.Rules, policy.ActionAllow)
	if err != nil {
		return fmt.Errorf("compile policy: %w", err)
	}

	log, err := audit.Open(expandHome(auditPath))
	if err != nil {
		return fmt.Errorf("audit: %w", err)
	}
	defer log.Close()

	code, err := proxy.RunStdio(ctx, proxy.StdioOptions{
		Command: cmd,
		Audit:   log,
		Engine:  eng,
	})
	if err != nil {
		return err
	}
	if code != 0 {
		os.Exit(code)
	}
	return nil
}

func defaultAuditPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "audit.jsonl"
	}
	return filepath.Join(home, ".dvarapala", "audit.jsonl")
}

func expandHome(p string) string {
	if len(p) >= 2 && p[0] == '~' && (p[1] == '/' || p[1] == os.PathSeparator) {
		if h, err := os.UserHomeDir(); err == nil {
			return filepath.Join(h, p[2:])
		}
	}
	return p
}
