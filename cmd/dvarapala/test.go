package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/tharvid/dvarapala/internal/config"
	"github.com/tharvid/dvarapala/internal/mcp"
	"github.com/tharvid/dvarapala/internal/policy"
)

// AttackCase mirrors the attack-corpus schema (test/fixtures/attack-corpus/schema.json).
type AttackCase struct {
	ID          string            `json:"id"`
	Category    string            `json:"category"`
	Description string            `json:"description"`
	Source      string            `json:"source,omitempty"`
	Messages    []json.RawMessage `json:"messages"`
	Expected    struct {
		Action   string `json:"action"`
		Rule     string `json:"rule,omitempty"`
		Rulepack string `json:"rulepack,omitempty"`
	} `json:"expected"`
}

func cmdTest(_ context.Context, args []string) error {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	var (
		policyPath string
		casePath   string
	)
	fs.StringVar(&policyPath, "policy", defaultPolicyPath(), "path to policy YAML")
	fs.StringVar(&casePath, "case", "", "path to attack-case JSON")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage: dvarapala test --policy POLICY --case CASE.json

Run an attack-corpus case against a policy and report whether the gateway's
decision matches the case's expected action. Exit code 0 = pass, 1 = fail.

Flags:
`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if casePath == "" {
		return errors.New("--case is required")
	}

	pol, err := config.Load(policyPath)
	if err != nil {
		return err
	}
	eng, err := policy.NewEngine(pol.Rules, policy.ActionAllow)
	if err != nil {
		return err
	}

	caseBytes, err := os.ReadFile(casePath)
	if err != nil {
		return err
	}
	var c AttackCase
	if err := json.Unmarshal(caseBytes, &c); err != nil {
		return fmt.Errorf("parse case: %w", err)
	}

	got := policy.Decision{Action: policy.ActionAllow}
	for _, raw := range c.Messages {
		var m mcp.Message
		if err := json.Unmarshal(raw, &m); err != nil {
			return fmt.Errorf("case message: %w", err)
		}
		dir := mcp.DirInbound
		// Heuristic: a message with a Result is server→client (outbound).
		if len(m.Result) > 0 || m.Error != nil {
			dir = mcp.DirOutbound
		}
		d := eng.Evaluate(m, dir)
		if d.Action != policy.ActionAllow {
			got = d
			break
		}
	}

	want := c.Expected.Action
	pass := string(got.Action) == want
	if pass {
		fmt.Fprintf(os.Stderr, "PASS  %s  expected=%s got=%s rule=%s\n",
			c.ID, want, got.Action, got.Rule)
		return nil
	}
	fmt.Fprintf(os.Stderr, "FAIL  %s  expected=%s got=%s rule=%s\n",
		c.ID, want, got.Action, got.Rule)
	os.Exit(1)
	return nil
}
