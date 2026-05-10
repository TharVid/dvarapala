package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tharvid/dvarapala/internal/audit"
	"github.com/tharvid/dvarapala/internal/detectors"
	"github.com/tharvid/dvarapala/internal/policy"
)

// nullLogger discards all events.
func nullLogger() *audit.Logger {
	return audit.New(testWriteCloser{&strings.Builder{}})
}

func TestProxyForwardsRequestUnchanged(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var msg map[string]any
		_ = json.Unmarshal(body, &msg)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":` +
			anyToJSON(msg["id"]) +
			`,"result":{"echo":"hi"}}`))
	}))
	defer upstream.Close()

	gw := startProxy(t, upstream.URL, nil, nil)
	defer gw.Close()

	resp := postJSON(t, gw.URL, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if !bytes.Contains(body, []byte(`"echo":"hi"`)) {
		t.Errorf("upstream response not forwarded: %s", body)
	}
}

func TestProxyDeniesRequest(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("upstream must NOT receive a denied request")
		w.WriteHeader(500)
	}))
	defer upstream.Close()

	rules := []policy.Rule{{
		Name:   "deny-tools-list",
		Match:  policy.Match{Method: "tools/list"},
		Action: policy.ActionDeny,
		Reason: "no listing",
	}}
	eng, _ := policy.NewEngine(rules, policy.ActionAllow)

	gw := startProxy(t, upstream.URL, eng, nil)
	defer gw.Close()

	resp := postJSON(t, gw.URL, `{"jsonrpc":"2.0","id":42,"method":"tools/list"}`)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var msg map[string]any
	if err := json.Unmarshal(body, &msg); err != nil {
		t.Fatalf("invalid JSON in response: %v", err)
	}
	errObj, ok := msg["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error object, got: %s", body)
	}
	if !strings.Contains(errObj["message"].(string), "Dvarapala") {
		t.Errorf("error not tagged Dvarapala: %v", errObj)
	}
}

func TestProxyMethodNotAllowed(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	defer upstream.Close()

	gw := startProxy(t, upstream.URL, nil, nil)
	defer gw.Close()

	req, _ := http.NewRequest(http.MethodPut, gw.URL, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", resp.StatusCode)
	}
}

func TestProxyRelaysSSE(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		_, _ = w.Write([]byte("data: " + `{"jsonrpc":"2.0","id":1,"result":{"hello":"world"}}` + "\n\n"))
		flusher.Flush()
	}))
	defer upstream.Close()

	gw := startProxy(t, upstream.URL, nil, nil)
	defer gw.Close()

	resp := postJSON(t, gw.URL, `{"jsonrpc":"2.0","id":1,"method":"x"}`)
	defer resp.Body.Close()
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		t.Errorf("Content-Type = %q", resp.Header.Get("Content-Type"))
	}
	body, _ := io.ReadAll(resp.Body)
	if !bytes.Contains(body, []byte(`"hello":"world"`)) {
		t.Errorf("SSE payload missing: %s", body)
	}
}

// startProxy spawns a RunHTTP listener on a random local port and returns
// an *httptest.Server-shaped helper for test cleanup.
func startProxy(t *testing.T, upstream string, eng *policy.Engine, reg *detectors.Registry) *fakeServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		_ = RunHTTP(ctx, HTTPOptions{
			Upstream:  upstream,
			Listen:    addr,
			Audit:     nullLogger(),
			Engine:    eng,
			Detectors: reg,
		})
	}()
	// Wait until the listener accepts.
	deadline := time.Now().Add(2 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("proxy did not start at %s: %v", addr, err)
		}
	}
	return &fakeServer{URL: "http://" + addr, cancel: cancel}
}

type fakeServer struct {
	URL    string
	cancel context.CancelFunc
}

func (f *fakeServer) Close() { f.cancel() }

func postJSON(t *testing.T, url, body string) *http.Response {
	t.Helper()
	resp, err := http.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func anyToJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
