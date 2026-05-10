package mcp

import (
	"bytes"
	"strings"
	"testing"
)

func TestScannerReadsNDJSON(t *testing.T) {
	in := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`,
		``, // blank lines should be skipped
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
	}, "\n") + "\n"

	sc := NewScanner(strings.NewReader(in))
	var got []Message
	for sc.Scan() {
		got = append(got, sc.Message())
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 messages, got %d", len(got))
	}

	if k := got[0].Kind(); k != KindRequest {
		t.Errorf("got[0].Kind=%s want request", k)
	}
	if k := got[1].Kind(); k != KindResponse {
		t.Errorf("got[1].Kind=%s want response", k)
	}
	if k := got[2].Kind(); k != KindNotification {
		t.Errorf("got[2].Kind=%s want notification", k)
	}
}

func TestScannerRejectsMalformed(t *testing.T) {
	sc := NewScanner(strings.NewReader("not json\n"))
	if sc.Scan() {
		t.Fatal("scan returned true on malformed input")
	}
	if sc.Err() == nil {
		t.Fatal("want error on malformed input")
	}
}

func TestKindForError(t *testing.T) {
	m := Message{JSONRPC: "2.0", ID: []byte("1"), Error: &RPCError{Code: -1, Message: "x"}}
	if m.Kind() != KindError {
		t.Errorf("Kind=%s want error", m.Kind())
	}
}

func TestWriteRawAppendsSingleNewline(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteRaw(&buf, []byte(`{"a":1}`+"\n\n")); err != nil {
		t.Fatal(err)
	}
	if got := buf.String(); got != `{"a":1}`+"\n" {
		t.Errorf("got %q", got)
	}
}

func TestRoundTripWriteThenScan(t *testing.T) {
	want := Message{JSONRPC: "2.0", ID: []byte("42"), Method: "ping"}
	var buf bytes.Buffer
	if err := WriteMessage(&buf, want); err != nil {
		t.Fatal(err)
	}
	sc := NewScanner(&buf)
	if !sc.Scan() {
		t.Fatalf("scan: %v", sc.Err())
	}
	got := sc.Message()
	if got.Method != want.Method || string(got.ID) != string(want.ID) {
		t.Errorf("round-trip mismatch: got %+v want %+v", got, want)
	}
}
