package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/tharvid/dvarapala/internal/config"
	"github.com/tharvid/dvarapala/internal/policy"
	"github.com/tharvid/dvarapala/internal/version"
)

// cmdDoctor prints a one-screen environment + config health report.
func cmdDoctor(_ context.Context, _ []string) error {
	checks := []checkResult{}
	defer func() {
		// Final summary line so an automation can `dvarapala doctor | tail -1`.
		failed := 0
		for _, c := range checks {
			if !c.ok {
				failed++
			}
		}
		if failed == 0 {
			fmt.Fprintln(os.Stderr, "")
			fmt.Fprintln(os.Stderr, "All checks passed.")
			return
		}
		fmt.Fprintf(os.Stderr, "\n%d check(s) failed. See details above.\n", failed)
	}()

	checks = append(checks, runCheck("dvarapala version", func() (string, error) {
		return version.String(), nil
	}))

	checks = append(checks, runCheck("Go runtime", func() (string, error) {
		return fmt.Sprintf("%s %s/%s", runtime.Version(), runtime.GOOS, runtime.GOARCH), nil
	}))

	checks = append(checks, runCheck("dvarapala on PATH", func() (string, error) {
		p, err := exec.LookPath("dvarapala")
		if err != nil {
			return "", fmt.Errorf("not on PATH (try `make install` or `cp bin/dvarapala /usr/local/bin/`)")
		}
		return p, nil
	}))

	policyPath := defaultPolicyPath()
	checks = append(checks, runCheck("default policy file", func() (string, error) {
		expanded := expandHome(policyPath)
		info, err := os.Stat(expanded)
		if err != nil {
			return "", fmt.Errorf("not found at %s (run `dvarapala init`)", expanded)
		}
		return fmt.Sprintf("%s (%d bytes)", expanded, info.Size()), nil
	}))

	checks = append(checks, runCheck("policy parse + compile", func() (string, error) {
		p, err := config.Load(policyPath)
		if err != nil {
			return "", err
		}
		eng, err := policy.NewEngine(p.Rules, policy.ActionAllow)
		if err != nil {
			return "", err
		}
		_ = eng
		return fmt.Sprintf("%d rules across %d defaults", len(p.Rules), len(p.Defaults)), nil
	}))

	auditDir := filepath.Dir(expandHome(defaultAuditPath()))
	checks = append(checks, runCheck("audit log directory writable", func() (string, error) {
		if err := os.MkdirAll(auditDir, 0o755); err != nil {
			return "", err
		}
		probe := filepath.Join(auditDir, ".dvarapala-doctor-probe")
		if err := os.WriteFile(probe, []byte("probe"), 0o600); err != nil {
			return "", err
		}
		_ = os.Remove(probe)
		return auditDir, nil
	}))

	checks = append(checks, runCheck("Presidio sidecar (DVARAPALA_PRESIDIO_URL)", func() (string, error) {
		u := os.Getenv("DVARAPALA_PRESIDIO_URL")
		if u == "" {
			return "(not configured — PII detection disabled)", nil
		}
		return probeSidecar(u + "/recognizers")
	}))

	checks = append(checks, runCheck("llm-guard sidecar (DVARAPALA_LLMGUARD_URL)", func() (string, error) {
		u := os.Getenv("DVARAPALA_LLMGUARD_URL")
		if u == "" {
			return "(not configured — prompt-injection detection disabled)", nil
		}
		return probeSidecar(u + "/healthz")
	}))

	checks = append(checks, runCheck("known MCP client configs", func() (string, error) {
		var lines []string
		for _, name := range []string{"claude-code", "claude-desktop", "cursor", "cline"} {
			cfg, err := configPathFor(name)
			if err != nil {
				continue
			}
			expanded := expandHome(cfg)
			info, err := os.Stat(expanded)
			if err != nil {
				lines = append(lines, fmt.Sprintf("    %-15s : (not present)", name))
				continue
			}
			servers, perr := countMCPServers(expanded)
			perrStr := ""
			if perr != nil {
				perrStr = " — " + perr.Error()
			}
			lines = append(lines, fmt.Sprintf("    %-15s : %s (%d MCP servers%s, %d bytes)",
				name, expanded, servers, perrStr, info.Size()))
		}
		return "\n" + strings.Join(lines, "\n"), nil
	}))

	for _, c := range checks {
		c.print()
	}
	return nil
}

type checkResult struct {
	name string
	ok   bool
	msg  string
	err  error
}

func runCheck(name string, fn func() (string, error)) checkResult {
	msg, err := fn()
	return checkResult{name: name, ok: err == nil, msg: msg, err: err}
}

func (c checkResult) print() {
	mark := "✓"
	if !c.ok {
		mark = "✗"
	}
	if c.ok {
		fmt.Fprintf(os.Stderr, "  %s  %-50s %s\n", mark, c.name, c.msg)
	} else {
		fmt.Fprintf(os.Stderr, "  %s  %-50s %v\n", mark, c.name, c.err)
	}
}

func probeSidecar(url string) (string, error) {
	c := &http.Client{Timeout: 2 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		return "", fmt.Errorf("unreachable: %w", err)
	}
	defer resp.Body.Close()
	return fmt.Sprintf("reachable (HTTP %d)", resp.StatusCode), nil
}

func countMCPServers(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		return 0, errors.New("parse error")
	}
	if servers, ok := cfg["mcpServers"].(map[string]any); ok {
		return len(servers), nil
	}
	return 0, nil
}
