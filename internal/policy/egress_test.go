package policy

import (
	"context"
	"testing"

	"github.com/tharvid/dvarapala/internal/mcp"
)

func TestEngineEgressAllowlistDeniesUnlistedHost(t *testing.T) {
	rules := []Rule{{
		Name: "egress-allowlist",
		Match: Match{
			Tool:         "fetch",
			URLHostNotIn: []string{"github.com", "api.example.com"},
		},
		Action: ActionDeny,
		Reason: "host not allowlisted",
	}}
	eng, err := NewEngine(rules, ActionAllow)
	if err != nil {
		t.Fatal(err)
	}
	got := eng.Evaluate(context.Background(),
		msg("tools/call", `{"name":"fetch","arguments":{"url":"https://evil.com/exfil"}}`),
		mcp.DirInbound, nil,
	)
	if got.Action != ActionDeny {
		t.Errorf("got %s, want deny for unlisted host", got.Action)
	}
}

func TestEngineEgressAllowlistAllowsListedHost(t *testing.T) {
	rules := []Rule{{
		Name: "egress-allowlist",
		Match: Match{
			Tool:         "fetch",
			URLHostNotIn: []string{"github.com", "api.example.com"},
		},
		Action: ActionDeny,
	}}
	eng, _ := NewEngine(rules, ActionAllow)
	got := eng.Evaluate(context.Background(),
		msg("tools/call", `{"name":"fetch","arguments":{"url":"https://api.example.com/v1/issues"}}`),
		mcp.DirInbound, nil,
	)
	if got.Action != ActionAllow {
		t.Errorf("got %s, want allow for allowlisted host", got.Action)
	}
}

func TestEngineEgressAllowlistIgnoresPort(t *testing.T) {
	rules := []Rule{{
		Match:  Match{URLHostNotIn: []string{"localhost"}},
		Action: ActionDeny,
	}}
	eng, _ := NewEngine(rules, ActionAllow)
	got := eng.Evaluate(context.Background(),
		msg("tools/call", `{"name":"fetch","arguments":{"url":"http://localhost:8080/x"}}`),
		mcp.DirInbound, nil,
	)
	if got.Action != ActionAllow {
		t.Errorf("port should not bypass allowlist: got %s, want allow", got.Action)
	}
}

func TestEngineEgressAllowlistCaseInsensitive(t *testing.T) {
	rules := []Rule{{
		Match:  Match{URLHostNotIn: []string{"GITHUB.com"}},
		Action: ActionDeny,
	}}
	eng, _ := NewEngine(rules, ActionAllow)
	got := eng.Evaluate(context.Background(),
		msg("tools/call", `{"name":"fetch","arguments":{"url":"https://github.com/x"}}`),
		mcp.DirInbound, nil,
	)
	if got.Action != ActionAllow {
		t.Errorf("allowlist should be case-insensitive: got %s, want allow", got.Action)
	}
}

func TestEngineEgressAllowlistSkipsArgsWithoutURLs(t *testing.T) {
	rules := []Rule{{
		Match:  Match{URLHostNotIn: []string{"github.com"}},
		Action: ActionDeny,
	}}
	eng, _ := NewEngine(rules, ActionAllow)
	got := eng.Evaluate(context.Background(),
		msg("tools/call", `{"name":"shell","arguments":{"command":"echo hello"}}`),
		mcp.DirInbound, nil,
	)
	if got.Action != ActionAllow {
		t.Errorf("rule should not fire when no URL-shaped args present: got %s", got.Action)
	}
}

func TestEngineEgressAllowlistMixedHosts(t *testing.T) {
	// One allowed URL + one disallowed in the same args → deny (any
	// non-listed host is a violation).
	rules := []Rule{{
		Match:  Match{URLHostNotIn: []string{"github.com"}},
		Action: ActionDeny,
	}}
	eng, _ := NewEngine(rules, ActionAllow)
	got := eng.Evaluate(context.Background(),
		msg("tools/call", `{"name":"fetch","arguments":{"primary":"https://github.com/a","backup":"https://evil.com/x"}}`),
		mcp.DirInbound, nil,
	)
	if got.Action != ActionDeny {
		t.Errorf("any non-allowlisted URL should fire the rule: got %s", got.Action)
	}
}

func TestEngineEgressAllowlistEmptyAllowsNoHost(t *testing.T) {
	// `url_host_not_in: []` — explicit empty list means "no host
	// allowlisted", so any URL fires.
	rules := []Rule{{
		Match:  Match{URLHostNotIn: []string{}},
		Action: ActionDeny,
	}}
	eng, _ := NewEngine(rules, ActionAllow)
	got := eng.Evaluate(context.Background(),
		msg("tools/call", `{"name":"fetch","arguments":{"url":"https://anywhere.example/x"}}`),
		mcp.DirInbound, nil,
	)
	if got.Action != ActionDeny {
		t.Errorf("empty allowlist should deny all URLs: got %s", got.Action)
	}
}

func TestEngineEgressAllowlistRejectsNonHTTPSchemes(t *testing.T) {
	// file://, ftp://, custom schemes don't count as egress to
	// allowlist against — those are handled by other rules.
	rules := []Rule{{
		Match:  Match{URLHostNotIn: []string{"github.com"}},
		Action: ActionDeny,
	}}
	eng, _ := NewEngine(rules, ActionAllow)
	got := eng.Evaluate(context.Background(),
		msg("tools/call", `{"name":"read","arguments":{"path":"file:///etc/passwd"}}`),
		mcp.DirInbound, nil,
	)
	if got.Action != ActionAllow {
		t.Errorf("non-http URL should not fire egress rule: got %s", got.Action)
	}
}
