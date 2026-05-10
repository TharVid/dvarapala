package hub

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tharvid/dvarapala/internal/audit"
	"github.com/tharvid/dvarapala/internal/policy"
)

type bufCloser struct{ *strings.Builder }

func (bufCloser) Close() error { return nil }

func nullLogger() *audit.Logger { return audit.New(bufCloser{&strings.Builder{}}) }

func TestConfigValidate(t *testing.T) {
	cases := []struct {
		name    string
		yaml    string
		wantErr bool
	}{
		{"empty servers", `listen: x`, true},
		{"command and upstream both set", `
servers:
  x:
    command: ["a"]
    upstream: "http://x"
`, true},
		{"valid stdio", `
servers:
  fs:
    command: ["echo"]
`, false},
		{"valid http", `
servers:
  api:
    upstream: "http://example.com"
`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := LoadFromReader(strings.NewReader(c.yaml))
			gotErr := err != nil
			if gotErr != c.wantErr {
				t.Errorf("err=%v want err=%v", err, c.wantErr)
			}
		})
	}
}

func TestHubRoutesToHTTPBackend(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"echo":"hi"}}`))
	}))
	defer upstream.Close()

	cfg, err := LoadFromReader(strings.NewReader(`
servers:
  api:
    upstream: ` + upstream.URL + `
`))
	if err != nil {
		t.Fatal(err)
	}
	h, err := New(context.Background(), cfg, Options{Audit: nullLogger()})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/api", "application/json",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !bytes.Contains(body, []byte(`"echo":"hi"`)) {
		t.Errorf("unexpected response: %s", body)
	}
}

func TestHubReturnsDirectoryOnGet(t *testing.T) {
	cfg, _ := LoadFromReader(strings.NewReader(`
servers:
  api:
    upstream: "http://example.com"
  fs:
    command: ["echo"]
`))
	h, err := New(context.Background(), cfg, Options{Audit: nullLogger()})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	srv := httptest.NewServer(h)
	defer srv.Close()
	resp, _ := http.Get(srv.URL + "/")
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var got struct {
		Servers []map[string]string `json:"servers"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, body)
	}
	if len(got.Servers) != 2 {
		t.Errorf("got %d servers, want 2", len(got.Servers))
	}
}

func TestHubUnknownServer404(t *testing.T) {
	cfg, _ := LoadFromReader(strings.NewReader(`
servers:
  api:
    upstream: "http://example.com"
`))
	h, _ := New(context.Background(), cfg, Options{Audit: nullLogger()})
	defer h.Close()
	srv := httptest.NewServer(h)
	defer srv.Close()
	resp, _ := http.Post(srv.URL+"/nope", "application/json", strings.NewReader(`{}`))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestHubDeniesInbound(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("upstream must NOT receive a denied request")
	}))
	defer upstream.Close()

	cfg, _ := LoadFromReader(strings.NewReader(`
servers:
  api:
    upstream: ` + upstream.URL + `
`))
	rules := []policy.Rule{{
		Name:   "deny-tools-list",
		Match:  policy.Match{Method: "tools/list"},
		Action: policy.ActionDeny,
		Reason: "denied",
	}}
	eng, _ := policy.NewEngine(rules, policy.ActionAllow)

	h, err := New(context.Background(), cfg, Options{Audit: nullLogger(), Engine: eng})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, _ := http.Post(srv.URL+"/api", "application/json",
		strings.NewReader(`{"jsonrpc":"2.0","id":42,"method":"tools/list"}`))
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !bytes.Contains(body, []byte("Dvarapala")) {
		t.Errorf("expected synthesised deny error, got: %s", body)
	}
}
