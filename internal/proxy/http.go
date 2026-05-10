// Package proxy — HTTP / Streamable-HTTP transport (Phase 6).
//
// The MCP spec supports two HTTP-flavoured transports:
//
//  1. **HTTP+SSE (legacy)** — separate POST for client→server messages and
//     a long-lived GET with Accept: text/event-stream for server→client.
//
//  2. **Streamable HTTP (2024-11-05+)** — single endpoint; the server may
//     respond with either application/json (one response) or
//     text/event-stream (multiple responses streamed). This is the
//     simpler, modern shape and is what we implement here.
//
// RunHTTP listens on a local address and forwards every JSON-RPC message
// to an upstream MCP HTTP server, applying the same policy engine /
// detector / redaction pipeline as stdio mode.
package proxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/tharvid/dvarapala/internal/audit"
	"github.com/tharvid/dvarapala/internal/detectors"
	"github.com/tharvid/dvarapala/internal/mcp"
	"github.com/tharvid/dvarapala/internal/policy"
)

// HTTPOptions configures RunHTTP.
type HTTPOptions struct {
	// Upstream is the MCP server URL (must be http:// or https://).
	Upstream string
	// Listen is the local bind address, e.g. "127.0.0.1:8080".
	Listen string
	// Server is a logical name tagged onto every audit event so the
	// shared audit log can be filtered/grouped per MCP. Empty is fine.
	Server string
	// Audit, Engine, Detectors are the same shape as in StdioOptions.
	Audit     *audit.Logger
	Engine    *policy.Engine
	Detectors *detectors.Registry
	// Timeout caps a single upstream request. Default 30s.
	Timeout time.Duration
}

// RunHTTP starts the proxy. Blocks until ctx is cancelled or the listener
// errors out.
func RunHTTP(ctx context.Context, opts HTTPOptions) error {
	if opts.Upstream == "" {
		return errors.New("proxy: empty upstream")
	}
	upstream, err := url.Parse(opts.Upstream)
	if err != nil {
		return fmt.Errorf("parse upstream: %w", err)
	}
	if upstream.Scheme != "http" && upstream.Scheme != "https" {
		return fmt.Errorf("proxy: upstream scheme must be http(s), got %q", upstream.Scheme)
	}
	if opts.Audit == nil {
		return errors.New("proxy: nil audit logger")
	}
	if opts.Listen == "" {
		opts.Listen = "127.0.0.1:0"
	}
	if opts.Timeout == 0 {
		opts.Timeout = 30 * time.Second
	}

	mux := http.NewServeMux()
	mux.Handle("/", &httpRelay{
		upstream:  upstream,
		opts:      opts,
		client:    &http.Client{Timeout: opts.Timeout},
		userAgent: "dvarapala-proxy",
	})

	server := &http.Server{
		Addr:              opts.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	// Shut down cleanly on ctx cancellation.
	go func() {
		<-ctx.Done()
		shCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shCtx)
	}()

	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

type httpRelay struct {
	upstream  *url.URL
	opts      HTTPOptions
	client    *http.Client
	userAgent string
}

// upstreamForPOST returns the URL to forward a POST to. If the client
// path is the same as the upstream's configured path (or empty/"/"), use
// the full upstream URL. Otherwise, use the upstream's host + the
// client's path — that's where SSE-advertised endpoints live.
func (h *httpRelay) upstreamForPOST(clientPath string) string {
	cp := clientPath
	if cp == "" {
		cp = "/"
	}
	// Empty / root client path → full configured upstream URL (covers the
	// streamable-HTTP "single endpoint" shape).
	if cp == "/" {
		return h.upstream.String()
	}
	// Client posted to a specific path (e.g. /messages?sessionId=ABC) —
	// that's an SSE-advertised endpoint. Use upstream host + that path.
	return h.upstream.Scheme + "://" + h.upstream.Host + cp
}

func (h *httpRelay) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		h.servePost(w, r)
	case http.MethodGet:
		// Streamable HTTP servers may use GET for SSE-only channels; pass
		// through transparently with no per-message policy (this channel
		// carries server-initiated notifications which we still audit).
		h.serveGet(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// servePost handles a single MCP request: parse, evaluate, optionally
// deny-synthesize, otherwise forward to upstream and stream the response
// back through the same engine.
func (h *httpRelay) servePost(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Parse the inbound message (best effort — MCP requires JSON-RPC, so
	// malformed bodies are passed through and the upstream will reject).
	var msg mcp.Message
	if jerr := decodeJSON(body, &msg); jerr == nil && h.opts.Engine != nil {
		decision := h.opts.Engine.Evaluate(r.Context(), msg, mcp.DirInbound, body)
		_ = h.opts.Audit.Write(audit.Event{
			Server:    h.opts.Server,
			Direction: mcp.DirInbound,
			Kind:      msg.Kind(),
			Method:    msg.Method,
			ID:        msg.ID,
			Action:    audit.Action(decision.Action),
			Reason:    decision.Reason,
			Rule:      decision.Rule,
			Payload:   body,
		})
		if decision.Action == policy.ActionDeny {
			h.writeDenyJSON(w, msg.ID, decision)
			return
		}
	}

	// Forward to upstream. POSTs go to the upstream's HOST + the client's
	// path — NOT the upstream's configured path. The configured path
	// (e.g. /sse) is the SSE channel; POSTed messages target whatever
	// endpoint the SSE stream advertised (typically /messages or similar
	// with a sessionId query). If the client POSTs to /, fall back to the
	// upstream's full configured URL (handles non-SSE / streamable-HTTP
	// servers that use a single endpoint).
	upstreamURL := h.upstreamForPOST(r.URL.Path)
	if r.URL.RawQuery != "" {
		upstreamURL += "?" + r.URL.RawQuery
	}
	upReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, upstreamURL, bytes.NewReader(body))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	copyHeaders(upReq.Header, r.Header)
	upReq.Header.Set("User-Agent", h.userAgent)

	resp, err := h.client.Do(upReq)
	if err != nil {
		http.Error(w, "upstream: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Two response shapes per spec:
	//   - application/json   → single message; read fully, run engine, write back
	//   - text/event-stream  → SSE stream; relay event-by-event through engine
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	if strings.HasPrefix(ct, "text/event-stream") {
		h.relaySSE(w, resp)
		return
	}
	h.relaySingleJSON(w, resp)
}

// serveGet relays a long-lived SSE GET (server→client only). Each event is
// audited; deny on outbound here just drops the event.
//
// GETs are the SSE channel opener. Forward to the upstream's full
// configured URL (the SSE endpoint), regardless of which client path
// triggered the GET — there's only one SSE endpoint per proxy.
func (h *httpRelay) serveGet(w http.ResponseWriter, r *http.Request) {
	upstreamURL := h.upstream.String()
	if r.URL.RawQuery != "" {
		upstreamURL += "?" + r.URL.RawQuery
	}
	upReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, upstreamURL, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	copyHeaders(upReq.Header, r.Header)
	upReq.Header.Set("User-Agent", h.userAgent)

	resp, err := h.client.Do(upReq)
	if err != nil {
		http.Error(w, "upstream: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	h.relaySSE(w, resp)
}

// relaySingleJSON reads one JSON message from upstream, runs engine on it,
// and writes back the (possibly redacted) result.
func (h *httpRelay) relaySingleJSON(w http.ResponseWriter, resp *http.Response) {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "read upstream: "+err.Error(), http.StatusBadGateway)
		return
	}
	out := h.evaluateOutboundBytes(body)
	for k, vs := range resp.Header {
		if !hopByHop(k) {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
	}
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(out)))
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(out)
}

// relaySSE pumps every SSE `data:` line through the engine, then writes
// the resulting (possibly redacted) line back to the client. Other SSE
// fields (event:, id:, retry:, blank lines) are pass-through.
func (h *httpRelay) relaySSE(w http.ResponseWriter, resp *http.Response) {
	for k, vs := range resp.Header {
		if !hopByHop(k) {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(resp.StatusCode)
	flusher, _ := w.(http.Flusher)

	rd := bufio.NewReader(resp.Body)
	for {
		line, err := rd.ReadBytes('\n')
		if len(line) > 0 {
			if d, ok := bytes.CutPrefix(bytes.TrimRight(line, "\r\n"), []byte("data: ")); ok {
				out := h.evaluateOutboundBytes(d)
				_, _ = w.Write([]byte("data: "))
				_, _ = w.Write(out)
				_, _ = w.Write([]byte("\n"))
			} else {
				_, _ = w.Write(line)
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if err != nil {
			return
		}
	}
}

// evaluateOutboundBytes runs the policy engine on a single outbound JSON-
// RPC message and returns the bytes to forward (possibly redacted).
func (h *httpRelay) evaluateOutboundBytes(body []byte) []byte {
	if len(bytes.TrimSpace(body)) == 0 {
		return body
	}
	var msg mcp.Message
	if err := decodeJSON(body, &msg); err != nil {
		return body
	}

	decision := policy.AllowDecision
	if h.opts.Engine != nil {
		decision = h.opts.Engine.Evaluate(context.Background(), msg, mcp.DirOutbound, body)
	}
	_ = h.opts.Audit.Write(audit.Event{
		Server:    h.opts.Server,
		Direction: mcp.DirOutbound,
		Kind:      msg.Kind(),
		Method:    msg.Method,
		ID:        msg.ID,
		Action:    audit.Action(decision.Action),
		Reason:    decision.Reason,
		Rule:      decision.Rule,
		Payload:   body,
	})

	switch decision.Action {
	case policy.ActionRedact:
		out, err := applyRedaction(context.Background(), body, h.opts.Detectors, decision.Replacement)
		if err == nil {
			return out
		}
	case policy.ActionDeny:
		// Outbound deny: drop the message entirely (caller decides framing).
		return nil
	}
	return body
}

// writeDenyJSON synthesises a JSON-RPC error response for a denied request.
func (h *httpRelay) writeDenyJSON(w http.ResponseWriter, id []byte, d policy.Decision) {
	reason := d.Reason
	if reason == "" {
		reason = "blocked by Dvarapala policy"
	}
	resp := mcp.Message{
		JSONRPC: "2.0",
		ID:      id,
		Error: &mcp.RPCError{
			Code:    denyErrorCode,
			Message: fmt.Sprintf("[Dvarapala] %s", reason),
			Data:    denyData(d),
		},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = mcp.WriteMessage(w, resp)
}

func copyHeaders(dst, src http.Header) {
	for k, vs := range src {
		if hopByHop(k) {
			continue
		}
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

// hopByHop returns true for headers that must NOT be forwarded by an
// HTTP proxy (RFC 7230 §6.1).
func hopByHop(name string) bool {
	switch http.CanonicalHeaderKey(name) {
	case "Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
		"Te", "Trailer", "Transfer-Encoding", "Upgrade", "Host", "Content-Length":
		return true
	}
	return false
}

// decodeJSON tolerates surrounding whitespace and BOMs that some clients add.
func decodeJSON(b []byte, v any) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		return errors.New("empty body")
	}
	dec := newJSONDecoder(b)
	return dec.Decode(v)
}
