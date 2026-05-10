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
		// Summary line. Skips do not count as failures.
		failed, skipped := 0, 0
		for _, c := range checks {
			switch c.status {
			case statusFail:
				failed++
			case statusSkip:
				skipped++
			}
		}
		fmt.Fprintln(os.Stderr, "")
		switch {
		case failed > 0:
			fmt.Fprintf(os.Stderr, "%d check(s) failed, %d skipped. See details above.\n", failed, skipped)
		case skipped > 0:
			fmt.Fprintf(os.Stderr, "All required checks passed (%d optional skipped).\n", skipped)
		default:
			fmt.Fprintln(os.Stderr, "All checks passed.")
		}
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

	checks = append(checks, runSoftCheck("background proxy daemons", func() (string, bool, error) {
		records, err := loadDaemonRecords()
		if err != nil {
			return "", true, err
		}
		if len(records) == 0 {
			return "no daemons recorded (none spawned by --wrap-all)", false, nil
		}
		alive, dead := 0, 0
		var deadNames []string
		for _, r := range records {
			if processAlive(r.PID) {
				alive++
				continue
			}
			dead++
			deadNames = append(deadNames, r.Name)
		}
		if dead == 0 {
			return fmt.Sprintf("%d running, 0 stale", alive), true, nil
		}
		return "", true, fmt.Errorf("%d running, %d STALE (%s) — run `dvarapala daemon clean` to forget them, or `dvarapala install --wrap-all` to re-spawn",
			alive, dead, strings.Join(deadNames, ", "))
	}))

	checks = append(checks, runSoftCheck("Presidio sidecar (DVARAPALA_PRESIDIO_URL)", func() (string, bool, error) {
		u := os.Getenv("DVARAPALA_PRESIDIO_URL")
		if u == "" {
			return "skipped — set DVARAPALA_PRESIDIO_URL to enable PII detection", false, nil
		}
		s, err := probeSidecar(u + "/recognizers")
		return s, true, err
	}))

	checks = append(checks, runSoftCheck("llm-guard sidecar (DVARAPALA_LLMGUARD_URL)", func() (string, bool, error) {
		u := os.Getenv("DVARAPALA_LLMGUARD_URL")
		if u == "" {
			return "skipped — set DVARAPALA_LLMGUARD_URL to enable prompt-injection detection", false, nil
		}
		s, err := probeSidecar(u + "/healthz")
		return s, true, err
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

type checkStatus int

const (
	statusOK checkStatus = iota
	statusFail
	statusSkip // soft "not configured" — informational, not a failure
)

type checkResult struct {
	name   string
	status checkStatus
	msg    string
	err    error
}

func runCheck(name string, fn func() (string, error)) checkResult {
	msg, err := fn()
	if err != nil {
		return checkResult{name: name, status: statusFail, err: err}
	}
	return checkResult{name: name, status: statusOK, msg: msg}
}

// runSoftCheck marks "not configured" results as skip rather than ok.
func runSoftCheck(name string, fn func() (string, bool, error)) checkResult {
	msg, configured, err := fn()
	if err != nil {
		return checkResult{name: name, status: statusFail, err: err}
	}
	if !configured {
		return checkResult{name: name, status: statusSkip, msg: msg}
	}
	return checkResult{name: name, status: statusOK, msg: msg}
}

func (c checkResult) print() {
	switch c.status {
	case statusOK:
		fmt.Fprintf(os.Stderr, "  \033[32m✓\033[0m  %-50s %s\n", c.name, c.msg)
	case statusFail:
		fmt.Fprintf(os.Stderr, "  \033[31m✗\033[0m  %-50s %v\n", c.name, c.err)
	case statusSkip:
		fmt.Fprintf(os.Stderr, "  \033[2m○\033[0m  %-50s \033[2m%s\033[0m\n", c.name, c.msg)
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
