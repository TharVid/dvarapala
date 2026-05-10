package policy

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tharvid/dvarapala/internal/mcp"
)

// TestEngineReloadSwapsRules verifies that Reload atomically replaces
// the active rule set so subsequent Evaluate calls see the new policy.
func TestEngineReloadSwapsRules(t *testing.T) {
	rule1 := Rule{
		Name:   "deny-everything",
		Match:  Match{},
		Action: ActionDeny,
		Reason: "v1",
	}
	rule2 := Rule{
		Name:   "allow-everything",
		Match:  Match{},
		Action: ActionAllow,
		Reason: "v2",
	}
	eng, err := NewEngine([]Rule{rule1}, ActionAllow)
	if err != nil {
		t.Fatal(err)
	}
	d := eng.Evaluate(context.Background(), mcp.Message{Method: "tools/call"}, mcp.DirInbound, nil)
	if d.Action != ActionDeny || d.Reason != "v1" {
		t.Fatalf("pre-reload Evaluate = %+v; want Action=deny, Reason=v1", d)
	}
	if err := eng.Reload([]Rule{rule2}); err != nil {
		t.Fatal(err)
	}
	d = eng.Evaluate(context.Background(), mcp.Message{Method: "tools/call"}, mcp.DirInbound, nil)
	if d.Action != ActionAllow || d.Reason != "v2" {
		t.Fatalf("post-reload Evaluate = %+v; want Action=allow, Reason=v2", d)
	}
}

// TestEngineReloadRejectsBadRulesAtomically verifies that a Reload with
// a malformed rule (uncompilable regex) returns an error and leaves the
// previously-active rules in place.
func TestEngineReloadRejectsBadRulesAtomically(t *testing.T) {
	good := Rule{Name: "ok", Action: ActionDeny, Reason: "good"}
	bad := Rule{Name: "bad", Action: ActionDeny, Match: Match{ToolNameMatches: "/(/"}}
	eng, err := NewEngine([]Rule{good}, ActionAllow)
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.Reload([]Rule{bad}); err == nil {
		t.Fatal("Reload with bad rule should have errored")
	}
	// Still serving the good rule.
	d := eng.Evaluate(context.Background(), mcp.Message{Method: "tools/call"}, mcp.DirInbound, nil)
	if d.Reason != "good" {
		t.Fatalf("post-failed-reload Evaluate.Reason = %q; want %q (engine should be unchanged)", d.Reason, "good")
	}
}

// stubLoader is an in-memory RuleLoader the watcher test drives.
type stubLoader struct {
	rules atomic.Pointer[[]Rule]
}

func (s *stubLoader) set(rules []Rule) { s.rules.Store(&rules) }
func (s *stubLoader) Load() ([]Rule, error) {
	if r := s.rules.Load(); r != nil {
		return *r, nil
	}
	return nil, nil
}

// TestWatcherReloadsOnFileChange touches the watched file and asserts
// the engine picks up the new rules within a couple of poll intervals.
func TestWatcherReloadsOnFileChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte("v1"), 0o644); err != nil {
		t.Fatal(err)
	}

	loader := &stubLoader{}
	loader.set([]Rule{{Name: "v1", Action: ActionDeny, Reason: "v1"}})

	eng, err := NewEngine([]Rule{{Name: "initial", Action: ActionAllow, Reason: "initial"}}, ActionAllow)
	if err != nil {
		t.Fatal(err)
	}

	w := &Watcher{
		Engine:   eng,
		Path:     path,
		Loader:   loader,
		Interval: 30 * time.Millisecond,
		ErrOut:   io.Discard,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- w.Watch(ctx) }()

	// Touch + bump mtime so the watcher detects a change.
	time.Sleep(10 * time.Millisecond)
	if err := os.WriteFile(path, []byte("v2 content longer"), 0o644); err != nil {
		t.Fatal(err)
	}
	loader.set([]Rule{{Name: "v2", Action: ActionDeny, Reason: "v2"}})

	// Poll up to 1s for the swap to take effect.
	deadline := time.Now().Add(1 * time.Second)
	var d Decision
	for time.Now().Before(deadline) {
		d = eng.Evaluate(context.Background(), mcp.Message{Method: "tools/call"}, mcp.DirInbound, nil)
		if d.Reason == "v2" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if d.Reason != "v2" {
		t.Fatalf("watcher did not pick up file change; latest Reason=%q", d.Reason)
	}

	cancel()
	<-done
}

// TestWatcherSurvivesBadReload verifies that a parse error mid-watch
// does NOT clobber the active rules; the previous good ruleset keeps
// serving traffic.
func TestWatcherSurvivesBadReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte("good"), 0o644); err != nil {
		t.Fatal(err)
	}
	loader := &stubLoader{}
	loader.set([]Rule{{Name: "good", Action: ActionDeny, Reason: "good"}})

	eng, err := NewEngine(nil, ActionAllow)
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.Reload([]Rule{{Name: "good", Action: ActionDeny, Reason: "good"}}); err != nil {
		t.Fatal(err)
	}

	// Use a thread-safe writer for ErrOut — the watcher goroutine
	// writes to it concurrently with the assertion that reads it,
	// which `go test -race` correctly flags. The mutex guards both
	// sides of that hand-off.
	errLog := &syncBuffer{}
	w := &Watcher{Engine: eng, Path: path, Loader: loader, Interval: 30 * time.Millisecond, ErrOut: errLog}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- w.Watch(ctx) }()

	// Trigger a "bad" reload: file changes, but loader.Load() returns
	// a malformed rule that won't compile.
	time.Sleep(50 * time.Millisecond)
	loader.set([]Rule{{Name: "bad", Action: ActionDeny, Match: Match{ToolNameMatches: "/(/"}}})
	if err := os.WriteFile(path, []byte("bad content longer"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Wait until the watcher has logged the skipped reload, or 1s.
	deadline := time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) {
		if bytes.Contains(errLog.Bytes(), []byte("policy reload skipped")) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Stop the watcher BEFORE reading state, so the read is not racing
	// with concurrent writes from the watcher goroutine.
	cancel()
	<-done

	d := eng.Evaluate(context.Background(), mcp.Message{Method: "tools/call"}, mcp.DirInbound, nil)
	if d.Reason != "good" {
		t.Errorf("after a bad reload, engine should keep serving 'good'; got Reason=%q", d.Reason)
	}
	if !bytes.Contains(errLog.Bytes(), []byte("policy reload skipped")) {
		t.Errorf("expected error log to mention 'policy reload skipped'; got: %s", errLog.String())
	}
}

// syncBuffer is a tiny mutex-guarded io.Writer for tests that need to
// read what a goroutine has written without racing.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) Bytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]byte, s.buf.Len())
	copy(out, s.buf.Bytes())
	return out
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}
