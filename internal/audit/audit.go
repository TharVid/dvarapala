// Package audit is a thread-safe JSONL writer for gateway events.
//
// Phase 1 emits one Event per JSON-RPC message in either direction, with
// Action="allow" because no policy enforcement runs yet. Later phases reuse
// this writer to record deny/redact/rewrite/etc.
package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
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
	Server    string          `json:"server,omitempty"`
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

// RotateOptions controls size-based rotation of the active audit log.
//
// Zero MaxBytes means no rotation (legacy behaviour). When MaxBytes is set,
// the writer will rename the active file to <path>.1 once a write would
// push it past the cap, shifting any pre-existing <path>.1 to <path>.2 and
// so on, dropping anything beyond <path>.<KeepFiles>.
//
// Defaults applied by Open:
//   - MaxBytes:  50 MiB
//   - KeepFiles: 5
type RotateOptions struct {
	MaxBytes  int64
	KeepFiles int
}

// DefaultRotate returns the rotation profile applied by Open when none is
// explicitly supplied. Tuned for an interactive workstation: caps at
// 50 MiB × 6 files = 300 MiB on disk, which is enough to retain weeks of
// real Claude Code traffic without growing unbounded.
func DefaultRotate() RotateOptions {
	return RotateOptions{
		MaxBytes:  50 * 1024 * 1024,
		KeepFiles: 5,
	}
}

// Open opens path for append, creating parent directories as needed. If path
// is empty, audit events are silently discarded. Rotation defaults are
// applied per DefaultRotate.
func Open(path string) (*Logger, error) {
	return OpenWith(path, DefaultRotate())
}

// OpenWith is Open with explicit rotation options. MaxBytes <= 0 disables
// rotation entirely.
func OpenWith(path string, rot RotateOptions) (*Logger, error) {
	if path == "" {
		return New(nopCloser{io.Discard}), nil
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}
	rw, err := newRotatingWriter(path, rot)
	if err != nil {
		return nil, err
	}
	return New(rw), nil
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

// rotatingWriter is an os.File-backed io.WriteCloser that performs
// size-bounded rotation in-process. A rotation renames <path> to <path>.1
// (shifting older copies one position deeper) and opens a fresh empty
// <path>. Files past KeepFiles are removed so disk usage is bounded.
//
// Rotation is decided per Write: if the current file size plus the next
// payload would exceed MaxBytes, rotate first. A single Write is never
// split across files — JSONL line atomicity is preserved.
type rotatingWriter struct {
	path      string
	maxBytes  int64
	keepFiles int
	f         *os.File
	size      int64
}

func newRotatingWriter(path string, rot RotateOptions) (*rotatingWriter, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	w := &rotatingWriter{
		path:      path,
		maxBytes:  rot.MaxBytes,
		keepFiles: rot.KeepFiles,
		f:         f,
		size:      info.Size(),
	}
	if w.keepFiles < 0 {
		w.keepFiles = 0
	}
	return w, nil
}

// Write appends b to the active file, rotating first if the write would
// push the file past maxBytes. A zero-or-negative maxBytes disables
// rotation.
func (r *rotatingWriter) Write(b []byte) (int, error) {
	if r.maxBytes > 0 && r.size > 0 && r.size+int64(len(b)) > r.maxBytes {
		if err := r.rotate(); err != nil {
			return 0, err
		}
	}
	n, err := r.f.Write(b)
	r.size += int64(n)
	return n, err
}

// rotate closes the active file, shifts <path>.N back one position
// (oldest is removed), renames <path> to <path>.1, and opens a fresh
// empty <path>.
//
// With KeepFiles=N, valid rotated files are .1 through .N. On rotation:
//   - <path>.N is deleted (oldest rolls off)
//   - <path>.{N-1} → <path>.N, ..., <path>.1 → <path>.2
//   - <path> → <path>.1 (if KeepFiles > 0; otherwise just remove)
//   - new empty <path> is opened for append
func (r *rotatingWriter) rotate() error {
	if err := r.f.Close(); err != nil {
		return fmt.Errorf("close before rotate: %w", err)
	}
	r.f = nil

	if r.keepFiles > 0 {
		// Drop the file that's about to roll off the keep horizon.
		_ = os.Remove(r.path + "." + strconv.Itoa(r.keepFiles))

		// Shift .{keepFiles-1} → .keepFiles, ..., .1 → .2.
		for i := r.keepFiles - 1; i >= 1; i-- {
			from := r.path + "." + strconv.Itoa(i)
			to := r.path + "." + strconv.Itoa(i+1)
			if _, err := os.Stat(from); err != nil {
				continue
			}
			if err := os.Rename(from, to); err != nil {
				return fmt.Errorf("rotate %s → %s: %w", from, to, err)
			}
		}

		if err := os.Rename(r.path, r.path+".1"); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("rotate active → .1: %w", err)
		}
	} else {
		// keepFiles=0: just truncate by removing the active file.
		_ = os.Remove(r.path)
	}

	f, err := os.OpenFile(r.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("reopen after rotate: %w", err)
	}
	r.f = f
	r.size = 0
	return nil
}

func (r *rotatingWriter) Close() error {
	if r.f == nil {
		return nil
	}
	err := r.f.Close()
	r.f = nil
	return err
}
