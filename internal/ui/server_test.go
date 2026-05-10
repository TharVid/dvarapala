package ui

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestBroadcasterFanOut verifies that a published line reaches every
// subscribed client and that unsubscribe is clean (channel closes,
// no panic on republish).
func TestBroadcasterFanOut(t *testing.T) {
	b := newBroadcaster()
	c1 := b.subscribe()
	c2 := b.subscribe()

	b.publish([]byte(`{"a":1}`))

	for i, ch := range []chan []byte{c1, c2} {
		select {
		case got := <-ch:
			if string(got) != `{"a":1}` {
				t.Errorf("client %d got %q; want JSON line", i, got)
			}
		case <-time.After(time.Second):
			t.Errorf("client %d did not receive published line", i)
		}
	}

	b.unsubscribe(c1)
	// After unsubscribe, publish must not panic, and c1 must be closed.
	b.publish([]byte(`{"b":2}`))
	if _, ok := <-c1; ok {
		t.Error("expected unsubscribed channel to be closed")
	}
	// c2 should still receive.
	select {
	case <-c2:
	case <-time.After(time.Second):
		t.Error("c2 did not receive after c1 unsubscribed")
	}
	b.unsubscribe(c2)
}

// TestBroadcasterDropsSlowClient verifies a stuck client does not
// back-pressure the tailer. The writer is non-blocking, so a slow
// client just drops events for itself.
func TestBroadcasterDropsSlowClient(t *testing.T) {
	b := newBroadcaster()
	slow := b.subscribe()
	// Don't read from slow. Fill its buffer past capacity (64) and
	// keep going — none of these calls should block.
	for i := 0; i < 200; i++ {
		b.publish([]byte(fmt.Sprintf(`{"i":%d}`, i)))
	}
	// We didn't deadlock — that's the assertion. Drain quickly.
	drained := 0
loop:
	for {
		select {
		case <-slow:
			drained++
		default:
			break loop
		}
	}
	if drained == 0 {
		t.Error("slow client buffer was empty; expected some events buffered")
	}
	b.unsubscribe(slow)
}

// TestTailLastNReturnsTail writes more than N lines to a JSONL file
// and verifies tailLastN returns exactly the last N, in order, with
// invalid JSON skipped.
func TestTailLastNReturnsTail(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		fmt.Fprintf(f, `{"i":%d}`+"\n", i)
	}
	// Throw in one malformed line — it should be skipped, not fatal.
	fmt.Fprintln(f, "definitely not json")
	for i := 20; i < 25; i++ {
		fmt.Fprintf(f, `{"i":%d}`+"\n", i)
	}
	_ = f.Close()

	got, err := tailLastN(path, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 5 {
		t.Fatalf("len = %d; want 5", len(got))
	}
	want := []string{`{"i":20}`, `{"i":21}`, `{"i":22}`, `{"i":23}`, `{"i":24}`}
	for i, line := range got {
		if string(line) != want[i] {
			t.Errorf("line %d = %q; want %q", i, line, want[i])
		}
	}
}

// TestTailAuditPicksUpAppendedLines starts the tailer against a file
// that exists, then appends a line and asserts the broadcaster
// publishes it within a short window.
func TestTailAuditPicksUpAppendedLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(path, []byte("{\"existing\":true}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	b := newBroadcaster()
	ch := b.subscribe()
	defer b.unsubscribe(ch)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = tailAudit(ctx, path, b)
	}()

	// Tailer seeks to EOF on open; the existing line should NOT come
	// through (clients get history via /api/events/recent instead).
	// Give it a moment to settle, then append.
	time.Sleep(150 * time.Millisecond)

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte(`{"appended":true}` + "\n")); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	select {
	case got := <-ch:
		if string(got) != `{"appended":true}` {
			t.Errorf("got %q; want appended line", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("tailer did not publish the appended line")
	}

	cancel()
	wg.Wait()
}

// TestServeRecentReturnsJSONArray hits /api/events/recent and asserts
// the response is a parseable JSON array of the underlying lines.
func TestServeRecentReturnsJSONArray(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(path, []byte(
		`{"i":1}`+"\n"+
			`{"i":2}`+"\n"+
			`{"i":3}`+"\n",
	), 0o644); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveRecent(w, r, path, 100)
	}))
	defer srv.Close()

	r, err := http.Get(srv.URL + "?n=2")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	body, _ := io.ReadAll(r.Body)
	got := string(body)
	want := "[" + `{"i":2}` + "," + `{"i":3}` + "]\n"
	if got != want {
		t.Errorf("body = %s; want %s", got, want)
	}
	if ct := r.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q; want application/json", ct)
	}
}

// TestServeStreamSendsBroadcasterEvents covers the SSE handler:
// an event published to the broadcaster reaches a connected HTTP
// client as a `data: …\n\n` frame.
func TestServeStreamSendsBroadcasterEvents(t *testing.T) {
	b := newBroadcaster()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveStream(w, r, b)
	}))
	defer srv.Close()

	// Use a custom client with timeout via per-request context.
	req, _ := http.NewRequest("GET", srv.URL, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req = req.WithContext(ctx)

	// Custom Dial so we can read line-by-line. http.Client buffers,
	// but for SSE the server flushes after each frame and we read
	// off the response Body directly.
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Errorf("Content-Type = %q; want text/event-stream", ct)
	}

	// Publish an event after the client is connected.
	go func() {
		time.Sleep(80 * time.Millisecond)
		b.publish([]byte(`{"hello":"world"}`))
	}()

	br := bufio.NewReader(resp.Body)
	deadline := time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(deadline) {
		line, err := br.ReadString('\n')
		if err != nil {
			break
		}
		if strings.HasPrefix(line, "data: ") {
			payload := strings.TrimPrefix(strings.TrimRight(line, "\r\n"), "data: ")
			if payload == `{"hello":"world"}` {
				return // pass
			}
		}
	}
	t.Fatal("did not receive published event over SSE within timeout")
}

// freePort is a tiny helper that picks an unused TCP port — handy
// for tests that need a real listener.
func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

// TestRunServesIndex starts the full server (Run) and verifies the
// embedded index.html is served at /. End-to-end check that the
// embed FS, mux, and listener are wired correctly.
func TestRunServesIndex(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	_ = os.WriteFile(path, nil, 0o644)
	addr := freePort(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- Run(ctx, Options{AuditPath: path, Listen: addr}) }()

	// Wait briefly for the listener to come up.
	deadline := time.Now().Add(2 * time.Second)
	var resp *http.Response
	var err error
	for time.Now().Before(deadline) {
		resp, err = http.Get("http://" + addr + "/")
		if err == nil {
			break
		}
		time.Sleep(40 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("could not reach server: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("status %d; want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if !strings.Contains(string(body), "<!doctype html>") {
		t.Error("response body does not look like the embedded index.html")
	}

	cancel()
	<-done
}
