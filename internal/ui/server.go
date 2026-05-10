// Package ui serves a read-only web view of the Dvarapala audit log.
//
// Architecture:
//
//   - A single goroutine tails the audit.jsonl file (inode-aware, so it
//     survives a rotation produced by internal/audit), emitting each new
//     line to an internal channel.
//   - A broadcaster fans the channel out to every connected SSE client.
//   - Each client also receives a one-time backlog of the last N lines
//     so a fresh page load shows recent context, not just future events.
//
// The HTTP surface is intentionally tiny:
//
//	GET /                    static page (embedded HTML/CSS/JS)
//	GET /api/events/recent   most recent N audit events (JSON array)
//	GET /api/events/stream   live SSE feed
//
// Read-only by design: there is no API to modify policy, kill daemons,
// or otherwise mutate gateway state. Same trust posture as `tail -f`
// the audit log.
package ui

import (
	"bufio"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"sync"
	"time"
)

//go:embed static
var staticFS embed.FS

// Options configures Run.
type Options struct {
	// AuditPath is the JSONL file to tail.
	AuditPath string
	// Listen is the bind address. Default 127.0.0.1:9090.
	Listen string
	// BacklogLines is how many recent events a fresh client receives
	// on page load. Default 500.
	BacklogLines int
}

// Run starts the UI server. Blocks until ctx is cancelled or the
// listener errors.
func Run(ctx context.Context, opts Options) error {
	if opts.AuditPath == "" {
		return errors.New("ui: empty audit path")
	}
	if opts.Listen == "" {
		opts.Listen = "127.0.0.1:9090"
	}
	if opts.BacklogLines <= 0 {
		opts.BacklogLines = 500
	}

	bcast := newBroadcaster()
	go func() {
		_ = tailAudit(ctx, opts.AuditPath, bcast)
	}()

	mux := http.NewServeMux()
	staticSub, _ := fs.Sub(staticFS, "static")
	mux.Handle("/", http.FileServer(http.FS(staticSub)))
	mux.HandleFunc("/api/events/recent", func(w http.ResponseWriter, r *http.Request) {
		serveRecent(w, r, opts.AuditPath, opts.BacklogLines)
	})
	mux.HandleFunc("/api/events/stream", func(w http.ResponseWriter, r *http.Request) {
		serveStream(w, r, bcast)
	})

	server := &http.Server{
		Addr:              opts.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = server.Shutdown(shCtx)
	}()

	fmt.Fprintf(os.Stderr, "dvarapala ui listening on http://%s/  (audit: %s)\n",
		opts.Listen, opts.AuditPath)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// broadcaster fans out audit events to all connected SSE clients.
// New subscribers register a channel; the tail goroutine sends each
// new event to every registered channel. A slow client that fails to
// read fast enough is dropped (channel non-blocking send) so one stuck
// browser tab can't back-pressure the whole gateway.
type broadcaster struct {
	mu      sync.Mutex
	clients map[chan []byte]struct{}
}

func newBroadcaster() *broadcaster {
	return &broadcaster{clients: map[chan []byte]struct{}{}}
}

func (b *broadcaster) subscribe() chan []byte {
	ch := make(chan []byte, 64)
	b.mu.Lock()
	b.clients[ch] = struct{}{}
	b.mu.Unlock()
	return ch
}

func (b *broadcaster) unsubscribe(ch chan []byte) {
	b.mu.Lock()
	delete(b.clients, ch)
	b.mu.Unlock()
	close(ch)
}

func (b *broadcaster) publish(line []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.clients {
		select {
		case ch <- line:
		default:
			// Slow client: drop the event for this client rather
			// than block. The browser will see a gap; a refresh
			// re-syncs from /api/events/recent.
		}
	}
}

// tailAudit follows the JSONL file at path, broadcasting each new line.
// On rotation (inode change) or truncation it reopens transparently.
// Returns when ctx is cancelled.
func tailAudit(ctx context.Context, path string, b *broadcaster) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		f, err := os.Open(path)
		if err != nil {
			// File might not exist yet — wait and retry.
			if !sleepCtx(ctx, time.Second) {
				return nil
			}
			continue
		}
		// Seek to end so we don't replay the entire history through
		// the broadcaster — clients get history via /api/events/recent
		// at connect time, then the live stream picks up from "now".
		_, _ = f.Seek(0, io.SeekEnd)
		if err := tailLoop(ctx, f, path, b); err != nil {
			_ = f.Close()
			return err
		}
		_ = f.Close()
		// Loop reopens; sleep briefly to avoid spinning in pathological
		// rotate-immediately scenarios.
		if !sleepCtx(ctx, 200*time.Millisecond) {
			return nil
		}
	}
}

func tailLoop(ctx context.Context, f *os.File, path string, b *broadcaster) error {
	rd := bufio.NewReader(f)
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		line, err := rd.ReadBytes('\n')
		if len(line) > 0 {
			// Strip trailing newline.
			if line[len(line)-1] == '\n' {
				line = line[:len(line)-1]
			}
			if len(line) > 0 {
				cp := make([]byte, len(line))
				copy(cp, line)
				b.publish(cp)
			}
		}
		if errors.Is(err, io.EOF) {
			select {
			case <-ctx.Done():
				return nil
			case <-tick.C:
			}
			if rotated := isRotated(path, f); rotated {
				return nil // outer loop will reopen
			}
			continue
		}
		if err != nil {
			return err
		}
	}
}

// isRotated reports whether the path now refers to a different inode
// than the open handle, or has been truncated below our read offset.
func isRotated(path string, f *os.File) bool {
	pathInfo, err := os.Stat(path)
	if err != nil {
		return false
	}
	openInfo, err := f.Stat()
	if err != nil {
		return false
	}
	if !os.SameFile(pathInfo, openInfo) {
		return true
	}
	pos, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		return false
	}
	return pathInfo.Size() < pos
}

// sleepCtx sleeps for d unless ctx is cancelled first. Returns true if
// the sleep completed normally, false if cancelled.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// serveRecent reads the last N lines of path and returns them as a
// JSON array. Used by the page on initial load to render some context
// instead of an empty table.
func serveRecent(w http.ResponseWriter, r *http.Request, path string, defaultN int) {
	n := defaultN
	if v := r.URL.Query().Get("n"); v != "" {
		var got int
		if _, err := fmt.Sscanf(v, "%d", &got); err == nil && got > 0 && got <= 5000 {
			n = got
		}
	}
	lines, err := tailLastN(path, n)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte("["))
	for i, l := range lines {
		if i > 0 {
			_, _ = w.Write([]byte(","))
		}
		// Each line is already a valid JSON object — pass through.
		_, _ = w.Write(l)
	}
	_, _ = w.Write([]byte("]\n"))
}

// tailLastN reads the file and returns the last n complete JSONL lines.
// Simple buffered scan — at typical audit file sizes (<= 50 MiB rotate
// cap) this is fast enough that a streaming reverse-read isn't worth
// the complexity.
func tailLastN(path string, n int) ([][]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 16<<20)

	ring := make([][]byte, 0, n)
	for sc.Scan() {
		line := append([]byte(nil), sc.Bytes()...)
		if !json.Valid(line) {
			continue
		}
		if len(ring) == n {
			ring = ring[1:]
		}
		ring = append(ring, line)
	}
	return ring, sc.Err()
}

// serveStream upgrades the connection to Server-Sent Events and pumps
// every published audit line as a `data: …\n\n` frame. A periodic ping
// (`: keep-alive`) keeps the connection healthy through proxies.
func serveStream(w http.ResponseWriter, r *http.Request, b *broadcaster) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	// Flush headers + an opening comment frame immediately so the
	// browser EventSource (and any HTTP client doing a Do() call) can
	// read response headers right away rather than waiting for the
	// first event.
	_, _ = fmt.Fprint(w, ": connected\n\n")
	flusher.Flush()

	ch := b.subscribe()
	defer b.unsubscribe(ch)

	ping := time.NewTicker(15 * time.Second)
	defer ping.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case line, ok := <-ch:
			if !ok {
				return
			}
			_, _ = fmt.Fprintf(w, "data: %s\n\n", line)
			flusher.Flush()
		case <-ping.C:
			_, _ = fmt.Fprint(w, ": keep-alive\n\n")
			flusher.Flush()
		}
	}
}
