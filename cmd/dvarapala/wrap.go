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
	"github.com/tharvid/dvarapala/internal/detectors"
	"github.com/tharvid/dvarapala/internal/detectors/pii"
	"github.com/tharvid/dvarapala/internal/detectors/promptinjection"
	"github.com/tharvid/dvarapala/internal/detectors/secrets"
	"github.com/tharvid/dvarapala/internal/detectors/toolmutation"
	"github.com/tharvid/dvarapala/internal/detectors/toolpoisoning"
	"github.com/tharvid/dvarapala/internal/policy"
	"github.com/tharvid/dvarapala/internal/proxy"
)

func cmdWrap(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("wrap", flag.ContinueOnError)
	var (
		policyPath string
		auditPath  string
		serverName string
		auditMaxMB int
		auditKeep  int
	)
	fs.StringVar(&policyPath, "policy", "", "path to policy YAML (empty = transparent passthrough)")
	fs.StringVar(&auditPath, "audit", defaultAuditPath(), "path to audit log (JSONL)")
	fs.StringVar(&serverName, "server", "", "logical name for this MCP, tagged into every audit event")
	fs.IntVar(&auditMaxMB, "audit-max-mb", 50, "rotate audit log after this many MiB (0 disables rotation)")
	fs.IntVar(&auditKeep, "audit-keep", 5, "number of rotated audit files to retain")
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

	code, err := proxy.RunStdio(ctx, proxy.StdioOptions{
		Command:   cmd,
		Server:    serverName,
		Audit:     log,
		Engine:    eng,
		Detectors: registry,
	})
	if err != nil {
		return err
	}
	if code != 0 {
		os.Exit(code)
	}
	return nil
}

// buildDetectorRegistry assembles the available detectors:
//
//   - gitleaks: always on (embedded library, no network).
//   - Presidio (PII/PHI/PCI): registered if DVARAPALA_PRESIDIO_URL is set.
//   - llm-guard (prompt injection): registered if DVARAPALA_LLMGUARD_URL is set.
//
// Sidecar detectors degrade gracefully — if the sidecar can't be reached
// at runtime, Detect() returns an error and the engine treats it as "no
// match", so the gateway never blocks traffic on detector unavailability.
func buildDetectorRegistry() (*detectors.Registry, error) {
	r := detectors.NewRegistry()
	gl, err := secrets.New()
	if err != nil {
		return nil, fmt.Errorf("gitleaks: %w", err)
	}
	r.Register(gl)
	r.Register(toolpoisoning.New())
	r.Register(toolmutation.New())
	if u := os.Getenv("DVARAPALA_PRESIDIO_URL"); u != "" {
		r.Register(pii.New(u))
	}
	if u := os.Getenv("DVARAPALA_LLMGUARD_URL"); u != "" {
		r.Register(promptinjection.New(u))
	}
	return r, nil
}

func defaultAuditPath() string {
	return filepath.Join(defaultStoreDir(), "audit.jsonl")
}

func defaultStoreDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".dvarapala"
	}
	return filepath.Join(home, ".dvarapala")
}

func expandHome(p string) string {
	if len(p) >= 2 && p[0] == '~' && (p[1] == '/' || p[1] == os.PathSeparator) {
		if h, err := os.UserHomeDir(); err == nil {
			return filepath.Join(h, p[2:])
		}
	}
	return p
}
