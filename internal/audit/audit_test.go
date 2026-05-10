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
