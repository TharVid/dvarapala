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
	"sync"
	"testing"

	"github.com/tharvid/dvarapala/internal/audit"
	"github.com/tharvid/dvarapala/internal/mcp"
	"github.com/tharvid/dvarapala/internal/policy"
)

func TestMain(m *testing.M) {
	if os.Getenv("DVARAPALA_TEST_FAKE_SERVER") == "1" {
		fakeMCPServer()
		return
	}
	os.Exit(m.Run())
}

func fakeMCPServer() {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 0, 64<<10), 16<<20)
	for sc.Scan() {
		var req mcp.Message
		if err := json.Unmarshal(sc.Bytes(), &req); err != nil {
			continue
		}
		if req.Method == "" || len(req.ID) == 0 {
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
	var mu sync.Mutex

	if err := relay(context.Background(), in, &out, mcp.DirInbound, log, nil, nil, &out, &mu); err != nil {
		t.Fatalf("relay: %v", err)
	}

	gotLines := strings.Count(strings.TrimRight(out.String(), "\n"), "\n") + 1
	if gotLines != 2 {
		t.Errorf("forwarded %d lines, want 2", gotLines)
	}
	if !strings.Contains(auditBuf.String(), `"method":"tools/list"`) {
		t.Errorf("audit missing tools/list event: %s", auditBuf.String())
	}
}

func TestRelayDeniesAndSynthesisesError(t *testing.T) {
	rules := []policy.Rule{{
		Name:   "deny-rm-rf",
		Match:  policy.Match{Tool: "shell", Args: map[string]policy.ArgMatcher{"command": {Patterns: []string{`/rm\s+-rf/`}}}},
		Action: policy.ActionDeny,
		Reason: "destructive",
	}}
	eng, err := policy.NewEngine(rules, policy.ActionAllow)
	if err != nil {
		t.Fatal(err)
	}

	in := strings.NewReader(`{"jsonrpc":"2.0","id":42,"method":"tools/call","params":{"name":"shell","arguments":{"command":"rm -rf /"}}}` + "\n")

	var clientOut bytes.Buffer // simulates the LLM client
	var upstream bytes.Buffer  // simulates the upstream MCP server (should NOT see the request)
	var auditBuf strings.Builder
	log := audit.New(testWriteCloser{&auditBuf})
	var mu sync.Mutex

	if err := relay(context.Background(), in, &upstream, mcp.DirInbound, log, eng, nil, &clientOut, &mu); err != nil {
		t.Fatalf("relay: %v", err)
	}

	if upstream.Len() != 0 {
		t.Errorf("denied request leaked upstream: %s", upstream.String())
	}

	var resp mcp.Message
	if err := json.Unmarshal(bytes.TrimSpace(clientOut.Bytes()), &resp); err != nil {
		t.Fatalf("client response not valid JSON: %v\n%s", err, clientOut.String())
	}
	if resp.Error == nil {
		t.Fatal("expected JSON-RPC error response")
	}
	if string(resp.ID) != "42" {
		t.Errorf("response id = %s, want 42", resp.ID)
	}
	if !strings.Contains(resp.Error.Message, "Dvarapala") {
		t.Errorf("error message missing Dvarapala tag: %q", resp.Error.Message)
	}

	if !strings.Contains(auditBuf.String(), `"action":"deny"`) {
		t.Errorf("audit missing deny: %s", auditBuf.String())
	}
}

func TestRelayDropsDeniedNotification(t *testing.T) {
	rules := []policy.Rule{{
		Name:   "deny-notif",
		Match:  policy.Match{Method: "notifications/x"},
		Action: policy.ActionDeny,
	}}
	eng, _ := policy.NewEngine(rules, policy.ActionAllow)

	in := strings.NewReader(`{"jsonrpc":"2.0","method":"notifications/x"}` + "\n")
	var upstream, clientOut bytes.Buffer
	var auditBuf strings.Builder
	log := audit.New(testWriteCloser{&auditBuf})
	var mu sync.Mutex

	if err := relay(context.Background(), in, &upstream, mcp.DirInbound, log, eng, nil, &clientOut, &mu); err != nil {
		t.Fatalf("relay: %v", err)
	}
	if upstream.Len() != 0 {
		t.Errorf("denied notification leaked upstream: %s", upstream.String())
	}
	if clientOut.Len() != 0 {
		t.Errorf("notification cannot have a response, but got: %s", clientOut.String())
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
		t.Errorf("client missed responses; got: %s", out)
	}
}

// TestRunStdioNoop is matched by the child process via -test.run.
// DVARAPALA_TEST_FAKE_SERVER=1 short-circuits in TestMain.
func TestRunStdioNoop(t *testing.T) {}

type testWriteCloser struct{ *strings.Builder }

func (testWriteCloser) Close() error { return nil }
