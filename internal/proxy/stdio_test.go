package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/tharvid/dvarapala/internal/audit"
	"github.com/tharvid/dvarapala/internal/mcp"
)

// TestMain lets the test binary act as a tiny "echo MCP server" when
// DVARAPALA_TEST_FAKE_SERVER=1 is set in its env. RunStdio in the parent
// test then spawns os.Args[0] with that env to drive an end-to-end run.
func TestMain(m *testing.M) {
	if os.Getenv("DVARAPALA_TEST_FAKE_SERVER") == "1" {
		fakeMCPServer()
		return
	}
	os.Exit(m.Run())
}

// fakeMCPServer reads NDJSON requests from stdin, replies with a synthetic
// response, and exits when stdin closes.
func fakeMCPServer() {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 0, 64<<10), 16<<20)
	for sc.Scan() {
		var req mcp.Message
		if err := json.Unmarshal(sc.Bytes(), &req); err != nil {
			continue
		}
		if req.Method == "" || len(req.ID) == 0 {
			// notification, no response
			continue
		}
		resp := mcp.Message{JSONRPC: "2.0", ID: req.ID, Result: json.RawMessage(`{"ok":true}`)}
		_ = mcp.WriteMessage(os.Stdout, resp)
	}
}

func TestRelayForwardsAndAudits(t *testing.T) {
	in := strings.NewReader(strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"x"}}`,
	}, "\n") + "\n")

	var out bytes.Buffer
	var auditBuf strings.Builder
	log := audit.New(testWriteCloser{&auditBuf})

	if err := relay(in, &out, mcp.DirInbound, log); err != nil {
		t.Fatalf("relay: %v", err)
	}

	gotLines := strings.Count(strings.TrimRight(out.String(), "\n"), "\n") + 1
	if gotLines != 2 {
		t.Errorf("forwarded %d lines, want 2", gotLines)
	}

	auditLines := strings.Count(strings.TrimRight(auditBuf.String(), "\n"), "\n") + 1
	if auditLines != 2 {
		t.Errorf("audited %d events, want 2", auditLines)
	}

	if !strings.Contains(auditBuf.String(), `"method":"tools/list"`) {
		t.Errorf("audit missing tools/list event: %s", auditBuf.String())
	}
}

func TestRunStdioEndToEnd(t *testing.T) {
	if _, err := exec.LookPath(os.Args[0]); err != nil {
		t.Skipf("test binary not executable: %v", err)
	}

	var clientStdout bytes.Buffer
	var auditBuf strings.Builder
	log := audit.New(testWriteCloser{&auditBuf})

	clientStdin := strings.NewReader(strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"x"}}`,
	}, "\n") + "\n")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	code, err := RunStdio(ctx, StdioOptions{
		Command: []string{os.Args[0], "-test.run=^TestRunStdioNoop$"},
		Env:     append(os.Environ(), "DVARAPALA_TEST_FAKE_SERVER=1"),
		Stdin:   clientStdin,
		Stdout:  &clientStdout,
		Stderr:  io.Discard,
		Audit:   log,
	})
	if err != nil {
		t.Fatalf("RunStdio error: %v", err)
	}
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}

	out := clientStdout.String()
	if !strings.Contains(out, `"id":1`) || !strings.Contains(out, `"id":2`) {
		t.Errorf("client did not see both responses; got: %s", out)
	}

	if !strings.Contains(auditBuf.String(), `"direction":"inbound"`) ||
		!strings.Contains(auditBuf.String(), `"direction":"outbound"`) {
		t.Errorf("audit missing direction; got: %s", auditBuf.String())
	}
}

// TestRunStdioNoop is the test the child process matches on -test.run.
// It does nothing because DVARAPALA_TEST_FAKE_SERVER=1 short-circuits in TestMain.
func TestRunStdioNoop(t *testing.T) {}

type testWriteCloser struct{ *strings.Builder }

func (testWriteCloser) Close() error { return nil }
