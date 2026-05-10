package policy

import (
	"encoding/json"
	"testing"

	"github.com/tharvid/dvarapala/internal/mcp"
)

func msg(method, params string) mcp.Message {
	return mcp.Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage("1"),
		Method:  method,
		Params:  json.RawMessage(params),
	}
}

func TestEngineDeniesRmRf(t *testing.T) {
	rules := []Rule{{
		Name: "block-rm-rf",
		Match: Match{
			ToolNameMatches: "/^(shell|exec|bash|sh)$/",
			Args: map[string]ArgMatcher{
				"command": {Patterns: []string{`/rm\s+-rf/`}},
			},
		},
		Action: ActionDeny,
		Reason: "destructive",
	}}
	eng, err := NewEngine(rules, ActionAllow)
	if err != nil {
		t.Fatal(err)
	}
	got := eng.Evaluate(
		msg("tools/call", `{"name":"shell","arguments":{"command":"rm -rf /"}}`),
		mcp.DirInbound,
	)
	if got.Action != ActionDeny {
		t.Errorf("got %s, want deny", got.Action)
	}
	if got.Rule != "block-rm-rf" {
		t.Errorf("got rule %q", got.Rule)
	}
}

func TestEngineAllowsBenignTool(t *testing.T) {
	rules := []Rule{{
		Name:   "block-rm-rf",
		Match:  Match{Tool: "shell", Args: map[string]ArgMatcher{"command": {Patterns: []string{`/rm\s+-rf/`}}}},
		Action: ActionDeny,
	}}
	eng, _ := NewEngine(rules, ActionAllow)
	got := eng.Evaluate(
		msg("tools/call", `{"name":"shell","arguments":{"command":"ls /tmp"}}`),
		mcp.DirInbound,
	)
	if got.Action != ActionAllow {
		t.Errorf("got %s, want allow", got.Action)
	}
}

func TestEngineDirectionFilter(t *testing.T) {
	rules := []Rule{{
		Name:   "outbound-only",
		Match:  Match{Direction: "outbound"},
		Action: ActionDeny,
	}}
	eng, _ := NewEngine(rules, ActionAllow)
	if got := eng.Evaluate(msg("tools/list", ""), mcp.DirInbound); got.Action != ActionAllow {
		t.Errorf("inbound: got %s want allow", got.Action)
	}
	if got := eng.Evaluate(msg("tools/list", ""), mcp.DirOutbound); got.Action != ActionDeny {
		t.Errorf("outbound: got %s want deny", got.Action)
	}
}

func TestEngineMethodMatch(t *testing.T) {
	rules := []Rule{{
		Name:   "deny-tools-list",
		Match:  Match{Method: "tools/list"},
		Action: ActionDeny,
	}}
	eng, _ := NewEngine(rules, ActionAllow)
	if got := eng.Evaluate(msg("tools/list", ""), mcp.DirInbound); got.Action != ActionDeny {
		t.Errorf("got %s want deny", got.Action)
	}
	if got := eng.Evaluate(msg("ping", ""), mcp.DirInbound); got.Action != ActionAllow {
		t.Errorf("ping: got %s want allow", got.Action)
	}
}

func TestEngineFirstMatchWins(t *testing.T) {
	rules := []Rule{
		{Name: "log-only-first", Match: Match{Method: "tools/list"}, Action: ActionLogOnly},
		{Name: "deny-second", Match: Match{Method: "tools/list"}, Action: ActionDeny},
	}
	eng, _ := NewEngine(rules, ActionAllow)
	got := eng.Evaluate(msg("tools/list", ""), mcp.DirInbound)
	if got.Action != ActionLogOnly || got.Rule != "log-only-first" {
		t.Errorf("got %+v want log-only-first", got)
	}
}

func TestCompilePatternForms(t *testing.T) {
	cases := []struct {
		in    string
		match string
		want  bool
	}{
		{`/abc/i`, "ABC", true},
		{`/abc/i`, "xyz", false},
		{`/abc/`, "ABC", false},
		{`*foo*`, "barfoobaz", true},
		{`*foo*`, "bar", false},
		{`exact`, "exact", true},
		{`exact`, "Exact", false},
		// Absolute-path globs must NOT be parsed as slash-regex.
		{`/etc/*`, "/etc/passwd", true},
		{`/etc/*`, "/var/log/foo", false},
		{`*/.ssh/*`, "/Users/sunilkumar/.ssh/id_rsa", true},
		{`*/.ssh/*`, "/Users/sunilkumar/code/main.go", false},
	}
	for _, c := range cases {
		re, err := compilePattern(c.in)
		if err != nil {
			t.Errorf("%q: compile: %v", c.in, err)
			continue
		}
		if got := re.MatchString(c.match); got != c.want {
			t.Errorf("%q vs %q: got %v want %v", c.in, c.match, got, c.want)
		}
	}
}
