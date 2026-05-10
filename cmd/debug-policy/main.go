// Command debug-policy is an ad-hoc helper that prints how a policy file
// loads and how a single attack-corpus case evaluates step-by-step.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/tharvid/dvarapala/internal/config"
	"github.com/tharvid/dvarapala/internal/detectors"
	"github.com/tharvid/dvarapala/internal/detectors/secrets"
	"github.com/tharvid/dvarapala/internal/detectors/toolmutation"
	"github.com/tharvid/dvarapala/internal/detectors/toolpoisoning"
	"github.com/tharvid/dvarapala/internal/mcp"
	"github.com/tharvid/dvarapala/internal/policy"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: debug-policy <policy.yaml> <attack-case.json>")
		os.Exit(1)
	}
	p, err := config.Load(os.Args[1])
	if err != nil {
		fmt.Println("load:", err)
		os.Exit(1)
	}
	fmt.Printf("Loaded %d rules from %d defaults:\n", len(p.Rules), len(p.Defaults))
	for i, r := range p.Rules {
		fmt.Printf("  [%d] %-40s pack=%-22s action=%s\n", i, r.Name, r.Pack, r.Action)
		if r.Match.ContentMatches != nil {
			fmt.Printf("        content_matches.detector=%q\n", r.Match.ContentMatches.Detector)
		}
	}

	reg := detectors.NewRegistry()
	gl, _ := secrets.New()
	reg.Register(gl)
	reg.Register(toolpoisoning.New())
	reg.Register(toolmutation.New())
	fmt.Printf("\nRegistered detectors: %v\n", reg.Names())

	eng, err := policy.NewEngine(p.Rules, policy.ActionAllow)
	if err != nil {
		fmt.Println("engine:", err)
		os.Exit(1)
	}
	eng.SetRegistry(reg)

	caseBytes, err := os.ReadFile(os.Args[2])
	if err != nil {
		fmt.Println("read case:", err)
		os.Exit(1)
	}
	var c struct {
		ID       string            `json:"id"`
		Messages []json.RawMessage `json:"messages"`
		Expected struct {
			Action string `json:"action"`
		} `json:"expected"`
	}
	_ = json.Unmarshal(caseBytes, &c)

	fmt.Printf("\nEvaluating case %s (expected=%s):\n", c.ID, c.Expected.Action)
	for i, raw := range c.Messages {
		var m mcp.Message
		_ = json.Unmarshal(raw, &m)
		dir := mcp.DirInbound
		if len(m.Result) > 0 || m.Error != nil {
			dir = mcp.DirOutbound
		}
		fmt.Printf("  msg[%d] method=%q kind=%s dir=%s\n", i, m.Method, m.Kind(), dir)
		d := eng.Evaluate(context.Background(), m, dir, raw)
		fmt.Printf("    decision: action=%s rule=%q reason=%q\n", d.Action, d.Rule, d.Reason)
		if len(d.Findings) > 0 {
			fmt.Printf("    findings: %d\n", len(d.Findings))
		}
	}
}
