// Package audit is a thread-safe JSONL writer for gateway events.
//
// Phase 1 emits one Event per JSON-RPC message in either direction, with
// Action="allow" because no policy enforcement runs yet. Later phases reuse
// this writer to record deny/redact/rewrite/etc.
package audit

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/tharvid/dvarapala/internal/mcp"
)

// Action is the disposition the gateway applied to a message.
type Action string

const (
	ActionAllow   Action = "allow"
	ActionDeny    Action = "deny"
	ActionRedact  Action = "redact"
	ActionRewrite Action = "rewrite"
	ActionLogOnly Action = "log_only"
)

// Event is one entry in the audit log.
type Event struct {
	Time      time.Time       `json:"ts"`
	Direction mcp.Direction   `json:"direction"`
	Kind      mcp.Kind        `json:"kind"`
	Method    string          `json:"method,omitempty"`
	ID        json.RawMessage `json:"id,omitempty"`
	Action    Action          `json:"action"`
	Reason    string          `json:"reason,omitempty"`
	Rule      string          `json:"rule,omitempty"`
	Payload   json.RawMessage `json:"payload,omitempty"`
}

// Logger writes Events as JSONL.
type Logger struct {
	mu sync.Mutex
	w  io.WriteCloser
}

// New wraps w with a serialised Logger. w is closed when (*Logger).Close runs.
func New(w io.WriteCloser) *Logger {
	return &Logger{w: w}
}

// Open opens path for append, creating parent directories as needed. If path
// is empty, audit events are silently discarded.
func Open(path string) (*Logger, error) {
	if path == "" {
		return New(nopCloser{io.Discard}), nil
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	return New(f), nil
}

// Write serialises e as a single JSONL line.
func (l *Logger) Write(e Event) error {
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	l.mu.Lock()
	defer l.mu.Unlock()
	_, err = l.w.Write(b)
	return err
}

// Close closes the underlying writer.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Close()
}

type nopCloser struct{ io.Writer }

func (nopCloser) Close() error { return nil }
