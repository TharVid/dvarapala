package config

import (
	"strings"
	"testing"

	"github.com/tharvid/dvarapala/internal/policy"
)

func TestLoadInlineRules(t *testing.T) {
	yaml := `
version: "1"
rules:
  - name: deny-rm-rf
    match:
      tool: shell
      args.command: "/rm -rf/"
    action: deny
    reason: "destructive"
`
	p, err := LoadFromReader(strings.NewReader(yaml))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(p.Rules))
	}
	r := p.Rules[0]
	if r.Action != policy.ActionDeny {
		t.Errorf("action = %s want deny", r.Action)
	}
	if r.Match.Tool != "shell" {
		t.Errorf("tool = %s", r.Match.Tool)
	}
	if got := r.Match.Args["command"].Patterns; len(got) != 1 || got[0] != "/rm -rf/" {
		t.Errorf("args.command = %v", got)
	}
}

func TestLoadResolvesEmbeddedRulepack(t *testing.T) {
	yaml := `
version: "1"
defaults:
  - rulepack: destructive-actions
`
	p, err := LoadFromReader(strings.NewReader(yaml))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Rules) == 0 {
		t.Fatal("expected destructive-actions rules to expand")
	}
	// Tag pack origin
	for _, r := range p.Rules {
		if r.Pack != "destructive-actions" {
			t.Errorf("rule %q pack = %q", r.Name, r.Pack)
		}
	}
}

func TestLoadEmptyPathReturnsEmptyPolicy(t *testing.T) {
	p, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Rules) != 0 {
		t.Errorf("got %d rules, want 0", len(p.Rules))
	}
}

func TestLoadMissingFileErrors(t *testing.T) {
	_, err := Load("/no/such/file.yaml")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestArgListPattern(t *testing.T) {
	yaml := `
version: "1"
rules:
  - name: multi
    match:
      tool: shell
      args.command:
        - "/rm/"
        - "/dd/"
    action: deny
`
	p, err := LoadFromReader(strings.NewReader(yaml))
	if err != nil {
		t.Fatal(err)
	}
	got := p.Rules[0].Match.Args["command"].Patterns
	if len(got) != 2 {
		t.Errorf("got %d patterns, want 2: %v", len(got), got)
	}
}
