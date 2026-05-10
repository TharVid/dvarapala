// Package mcp defines minimal types and helpers for the JSON-RPC 2.0 layer
// of the Model Context Protocol stdio transport.
//
// MCP stdio framing: each message is a single JSON object on its own line,
// terminated by '\n'. There is no Content-Length header — that's only the
// HTTP/SSE transport.
package mcp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// Message is a single JSON-RPC 2.0 message — request, notification, response,
// or error. We keep ID/Params/Result/Error as RawMessage so we can forward
// bytes unchanged and avoid lossy round-trips.
type Message struct {
	JSONRPC string          `json:"jsonrpc,omitempty"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

// RPCError mirrors the JSON-RPC 2.0 error object.
type RPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// Direction describes a message's path through the gateway.
type Direction string

const (
	DirInbound  Direction = "inbound"  // client → server
	DirOutbound Direction = "outbound" // server → client
)

// Kind classifies a Message by JSON-RPC role.
type Kind string

const (
	KindRequest      Kind = "request"
	KindNotification Kind = "notification"
	KindResponse     Kind = "response"
	KindError        Kind = "error"
	KindUnknown      Kind = "unknown"
)

// Kind reports the JSON-RPC role of m.
func (m Message) Kind() Kind {
	switch {
	case m.Method != "" && len(m.ID) > 0:
		return KindRequest
	case m.Method != "" && len(m.ID) == 0:
		return KindNotification
	case m.Error != nil:
		return KindError
	case len(m.Result) > 0:
		return KindResponse
	default:
		return KindUnknown
	}
}

// DefaultMaxMessageSize bounds the largest JSON-RPC line we'll accept.
// MCP doesn't mandate a limit, but unbounded would invite OOM via a hostile
// peer. 16 MiB is generous for tool args and tool results.
const DefaultMaxMessageSize = 16 << 20

// Scanner reads newline-delimited JSON-RPC messages from r.
type Scanner struct {
	s   *bufio.Scanner
	msg Message
	raw []byte
	err error
}

// NewScanner wraps r with default buffer settings.
func NewScanner(r io.Reader) *Scanner {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 0, 64<<10), DefaultMaxMessageSize)
	return &Scanner{s: s}
}

// Scan advances to the next non-blank message. It returns true on success.
// On EOF it returns false with Err()==nil. On malformed JSON it returns
// false with Err()!=nil.
func (s *Scanner) Scan() bool {
	for s.s.Scan() {
		line := bytes.TrimSpace(s.s.Bytes())
		if len(line) == 0 {
			continue
		}
		// Copy because bufio.Scanner reuses its buffer on the next Scan.
		s.raw = append(s.raw[:0], line...)
		var msg Message
		if err := json.Unmarshal(s.raw, &msg); err != nil {
			s.err = fmt.Errorf("decode jsonrpc: %w", err)
			return false
		}
		s.msg = msg
		return true
	}
	s.err = s.s.Err()
	return false
}

// Message returns the most recently scanned Message.
func (s *Scanner) Message() Message { return s.msg }

// Bytes returns the raw line bytes (without the trailing newline) of the
// most recently scanned message.
func (s *Scanner) Bytes() []byte { return s.raw }

// Err returns the first non-nil error encountered while scanning.
func (s *Scanner) Err() error { return s.err }

// WriteRaw writes p followed by a single '\n', stripping any trailing
// newlines from p first.
func WriteRaw(w io.Writer, p []byte) error {
	p = bytes.TrimRight(p, "\r\n")
	if _, err := w.Write(p); err != nil {
		return err
	}
	_, err := w.Write([]byte{'\n'})
	return err
}

// WriteMessage marshals m and writes it as one NDJSON line.
func WriteMessage(w io.Writer, m Message) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return WriteRaw(w, b)
}
