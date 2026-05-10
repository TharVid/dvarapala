package audit

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tharvid/dvarapala/internal/mcp"
)

type bufCloser struct {
	*strings.Builder
}

func (bufCloser) Close() error { return nil }

func TestLoggerWritesJSONL(t *testing.T) {
	var sb strings.Builder
	l := New(bufCloser{&sb})

	if err := l.Write(Event{
		Direction: mcp.DirInbound,
		Kind:      mcp.KindRequest,
		Method:    "tools/list",
		Action:    ActionAllow,
	}); err != nil {
		t.Fatal(err)
	}
	if err := l.Write(Event{
		Direction: mcp.DirOutbound,
		Kind:      mcp.KindResponse,
		Action:    ActionAllow,
	}); err != nil {
		t.Fatal(err)
	}

	scanner := bufio.NewScanner(strings.NewReader(sb.String()))
	var lines int
	for scanner.Scan() {
		lines++
		var e Event
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			t.Errorf("line %d not valid JSON: %v", lines, err)
		}
		if e.Time.IsZero() {
			t.Errorf("line %d has zero timestamp", lines)
		}
	}
	if lines != 2 {
		t.Fatalf("want 2 lines, got %d", lines)
	}
}

func TestOpenCreatesParentDirs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "audit.jsonl")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Write(Event{Action: ActionAllow}); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) == 0 {
		t.Fatal("audit file is empty")
	}
}

func TestOpenEmptyPathDiscards(t *testing.T) {
	l, err := Open("")
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Write(Event{Action: ActionAllow}); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestRotationShiftsFiles verifies that hitting MaxBytes on the active
// file produces .1, .2, … files in the right order and drops anything
// past KeepFiles.
func TestRotationShiftsFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	// Tiny cap so a few writes trigger rotation. Each event JSON-marshals
	// to ~80-200 bytes; cap at 200 to force rotation every 1-2 events.
	l, err := OpenWith(path, RotateOptions{MaxBytes: 200, KeepFiles: 3})
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 12; i++ {
		if err := l.Write(Event{
			Direction: mcp.DirInbound,
			Kind:      mcp.KindRequest,
			Method:    "tools/call",
			Action:    ActionAllow,
			Reason:    "rotation-padding-rotation-padding-rotation-padding",
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	// Active file must exist.
	if _, err := os.Stat(path); err != nil {
		t.Errorf("active file missing: %v", err)
	}
	// .1, .2, .3 should exist; .4 must not (KeepFiles=3 cap).
	for _, suffix := range []string{".1", ".2", ".3"} {
		if _, err := os.Stat(path + suffix); err != nil {
			t.Errorf("expected %s%s to exist after rotation: %v", path, suffix, err)
		}
	}
	if _, err := os.Stat(path + ".4"); !os.IsNotExist(err) {
		t.Errorf("expected %s.4 to be gone (over keep-cap), got err=%v", path, err)
	}
}

// TestRotationDisabledByZeroMaxBytes verifies that MaxBytes=0 leaves
// the writer in single-file append mode forever.
func TestRotationDisabledByZeroMaxBytes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	l, err := OpenWith(path, RotateOptions{MaxBytes: 0, KeepFiles: 5})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		if err := l.Write(Event{Method: "x", Action: ActionAllow}); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".1"); !os.IsNotExist(err) {
		t.Errorf("expected no .1 file with MaxBytes=0; err=%v", err)
	}
}
