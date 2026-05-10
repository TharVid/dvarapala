package hub

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tharvid/dvarapala/internal/mcp"
)

// backend is what the hub knows how to route to. Two impls: stdioBackend
// (persistent child process, demuxed by request id) and httpBackend
// (per-request POST to upstream).
type backend interface {
	Name() string
	// Call sends one client message upstream and returns the matching
	// response. For notifications (no id) it returns mcp.Message{}, nil.
	Call(ctx context.Context, msg mcp.Message, raw []byte) (mcp.Message, []byte, error)
	// Close releases any resources (e.g. terminates a stdio child).
	Close() error
}

// newBackend dispatches on cfg.kindOf().
func newBackend(parentCtx context.Context, name string, cfg ServerConfig) (backend, error) {
	switch cfg.kindOf() {
	case "stdio":
		return newStdioBackend(parentCtx, name, cfg)
	case "http":
		return newHTTPBackend(name, cfg)
	default:
		return nil, fmt.Errorf("server %q: unknown kind %q", name, cfg.kindOf())
	}
}

// ────────────────────────────────────────────────────────────────────────
// stdioBackend
// ────────────────────────────────────────────────────────────────────────

// stdioBackend keeps one long-lived child process per configured server
// and multiplexes hub-side HTTP requests onto its single stdin/stdout.
// Request ids from the client are remapped to internal monotonic ids so
// concurrent calls don't collide; the response demultiplexer routes each
// reply to the right caller's channel by internal id and restores the
// client id before returning.
type stdioBackend struct {
	name    string
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	nextID  atomic.Uint64
	pending sync.Map // uint64 → chan *mcp.Message
	writeMu sync.Mutex
}

func newStdioBackend(ctx context.Context, name string, cfg ServerConfig) (*stdioBackend, error) {
	if len(cfg.Command) == 0 {
		return nil, fmt.Errorf("server %q: empty command", name)
	}
	cmd := exec.CommandContext(ctx, cfg.Command[0], cfg.Command[1:]...)
	cmd.Stderr = os.Stderr
	if cfg.Env != nil {
		cmd.Env = append(os.Environ(), cfg.Env...)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Cancel = func() error { return cmd.Process.Signal(os.Interrupt) }
	cmd.WaitDelay = 5 * time.Second
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("server %q: start: %w", name, err)
	}
	b := &stdioBackend{name: name, cmd: cmd, stdin: stdin}
	go b.readLoop(stdout)
	return b, nil
}

func (b *stdioBackend) Name() string { return b.name }

func (b *stdioBackend) Close() error {
	_ = b.stdin.Close()
	if b.cmd != nil && b.cmd.Process != nil {
		_ = b.cmd.Process.Signal(os.Interrupt)
	}
	return nil
}

// readLoop demuxes responses from the child and dispatches to the
// matching pending channel by internal id.
func (b *stdioBackend) readLoop(stdout io.Reader) {
	sc := mcp.NewScanner(stdout)
	for sc.Scan() {
		m := sc.Message()
		if len(m.ID) == 0 {
			continue // server-initiated notification — Phase 7 will broadcast these
		}
		// our internal ids are bare integers; tolerate clients that quote.
		idStr := strings.Trim(string(m.ID), "\"")
		id, err := strconv.ParseUint(idStr, 10, 64)
		if err != nil {
			continue
		}
		if rawCh, ok := b.pending.LoadAndDelete(id); ok {
			if ch, isChan := rawCh.(chan mcp.Message); isChan {
				select {
				case ch <- m:
				default:
				}
			}
		}
	}
}

func (b *stdioBackend) Call(ctx context.Context, msg mcp.Message, raw []byte) (mcp.Message, []byte, error) {
	// Notifications: just write, no response expected.
	if len(msg.ID) == 0 {
		b.writeMu.Lock()
		err := mcp.WriteRaw(b.stdin, raw)
		b.writeMu.Unlock()
		return mcp.Message{}, nil, err
	}

	clientID := append(json.RawMessage(nil), msg.ID...)
	internalID := b.nextID.Add(1)
	msg.ID = json.RawMessage(strconv.FormatUint(internalID, 10))

	ch := make(chan mcp.Message, 1)
	b.pending.Store(internalID, ch)
	defer b.pending.Delete(internalID)

	b.writeMu.Lock()
	err := mcp.WriteMessage(b.stdin, msg)
	b.writeMu.Unlock()
	if err != nil {
		return mcp.Message{}, nil, err
	}

	select {
	case resp := <-ch:
		resp.ID = clientID
		out, err := json.Marshal(resp)
		return resp, out, err
	case <-ctx.Done():
		return mcp.Message{}, nil, ctx.Err()
	}
}

// ────────────────────────────────────────────────────────────────────────
// httpBackend
// ────────────────────────────────────────────────────────────────────────

// httpBackend POSTs every call to the configured upstream URL. SSE
// streaming responses aren't yet aggregated here — we read the full body
// and treat it as a single response. (The single-server proxy code in
// internal/proxy/http.go does support SSE; the hub will pick that up in a
// follow-up commit.)
type httpBackend struct {
	name     string
	upstream *url.URL
	client   *http.Client
}

func newHTTPBackend(name string, cfg ServerConfig) (*httpBackend, error) {
	if cfg.Upstream == "" {
		return nil, fmt.Errorf("server %q: empty upstream", name)
	}
	u, err := url.Parse(cfg.Upstream)
	if err != nil {
		return nil, fmt.Errorf("server %q: parse upstream: %w", name, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("server %q: upstream must be http(s), got %q", name, u.Scheme)
	}
	return &httpBackend{
		name:     name,
		upstream: u,
		client:   &http.Client{Timeout: 30 * time.Second},
	}, nil
}

func (b *httpBackend) Name() string { return b.name }
func (b *httpBackend) Close() error { return nil }

func (b *httpBackend) Call(ctx context.Context, _ mcp.Message, raw []byte) (mcp.Message, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.upstream.String(), bytes.NewReader(raw))
	if err != nil {
		return mcp.Message{}, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := b.client.Do(req)
	if err != nil {
		return mcp.Message{}, nil, fmt.Errorf("upstream %s: %w", b.upstream, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return mcp.Message{}, nil, err
	}
	if resp.StatusCode >= 400 {
		return mcp.Message{}, nil, fmt.Errorf("upstream %s: HTTP %d", b.upstream, resp.StatusCode)
	}
	var m mcp.Message
	if err := json.Unmarshal(body, &m); err != nil {
		// Tolerate non-JSON-RPC responses by emitting a synthetic error.
		return mcp.Message{}, nil, errors.New("upstream returned non-JSON body")
	}
	return m, body, nil
}
