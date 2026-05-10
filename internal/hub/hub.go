package hub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/tharvid/dvarapala/internal/audit"
	"github.com/tharvid/dvarapala/internal/detectors"
	"github.com/tharvid/dvarapala/internal/mcp"
	"github.com/tharvid/dvarapala/internal/policy"
)

// denyErrorCode mirrors the proxy/stdio error code so audit consumers
// see identical disposition codes regardless of transport.
const denyErrorCode = -32000

// Options bundles runtime dependencies for the hub.
type Options struct {
	Audit     *audit.Logger
	Engine    *policy.Engine
	Detectors *detectors.Registry
}

// Hub fronts many MCP servers behind one HTTP listener. Routing is
// path-based: a POST to /<server-name> routes to that backend.
type Hub struct {
	cfg      *Config
	opts     Options
	backends map[string]backend
}

// New constructs a Hub from a config. Backends are spawned eagerly so
// startup failures are visible immediately rather than on first request.
func New(ctx context.Context, cfg *Config, opts Options) (*Hub, error) {
	if cfg == nil {
		return nil, errors.New("hub: nil config")
	}
	if opts.Audit == nil {
		return nil, errors.New("hub: nil audit logger")
	}
	h := &Hub{cfg: cfg, opts: opts, backends: make(map[string]backend, len(cfg.Servers))}
	for name, sc := range cfg.Servers {
		b, err := newBackend(ctx, name, sc)
		if err != nil {
			h.Close()
			return nil, err
		}
		h.backends[name] = b
	}
	return h, nil
}

// Close terminates every backend.
func (h *Hub) Close() {
	for _, b := range h.backends {
		_ = b.Close()
	}
}

// ServeHTTP routes POST /<server-name>. GET / returns a tiny JSON
// directory of registered servers — useful for smoke checks and for
// clients that want to discover what's available.
func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && (r.URL.Path == "/" || r.URL.Path == "") {
		h.writeDirectory(w)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := strings.Trim(r.URL.Path, "/")
	if name == "" {
		http.Error(w, "missing server name in path", http.StatusBadRequest)
		return
	}
	b, ok := h.backends[name]
	if !ok {
		http.Error(w, fmt.Sprintf("unknown server %q (try GET / for the list)", name), http.StatusNotFound)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var inMsg mcp.Message
	if err := json.Unmarshal(body, &inMsg); err == nil && h.opts.Engine != nil {
		decision := h.opts.Engine.Evaluate(r.Context(), inMsg, mcp.DirInbound, body)
		_ = h.opts.Audit.Write(audit.Event{
			Server:    name,
			Direction: mcp.DirInbound,
			Kind:      inMsg.Kind(),
			Method:    inMsg.Method,
			ID:        inMsg.ID,
			Action:    audit.Action(decision.Action),
			Reason:    decision.Reason,
			Rule:      decision.Rule,
			Payload:   body,
		})
		if decision.Action == policy.ActionDeny {
			h.writeDeny(w, inMsg.ID, decision)
			return
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	_, respBody, err := b.Call(ctx, inMsg, body)
	if err != nil {
		http.Error(w, "backend "+name+": "+err.Error(), http.StatusBadGateway)
		return
	}
	if respBody == nil {
		// Notification — no response expected, return 204.
		w.WriteHeader(http.StatusNoContent)
		return
	}

	respBody = h.evaluateOutbound(name, respBody)

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(respBody)
}

func (h *Hub) evaluateOutbound(server string, body []byte) []byte {
	if len(body) == 0 || h.opts.Engine == nil {
		return body
	}
	var msg mcp.Message
	if err := json.Unmarshal(body, &msg); err != nil {
		return body
	}
	decision := h.opts.Engine.Evaluate(context.Background(), msg, mcp.DirOutbound, body)
	_ = h.opts.Audit.Write(audit.Event{
		Server:    server,
		Direction: mcp.DirOutbound,
		Kind:      msg.Kind(),
		Method:    msg.Method,
		ID:        msg.ID,
		Action:    audit.Action(decision.Action),
		Reason:    decision.Reason,
		Rule:      decision.Rule,
		Payload:   body,
	})
	if decision.Action == policy.ActionRedact && h.opts.Detectors != nil {
		out, err := redactJSON(context.Background(), body, h.opts.Detectors, decision.Replacement)
		if err == nil {
			return out
		}
	}
	return body
}

func (h *Hub) writeDeny(w http.ResponseWriter, id json.RawMessage, d policy.Decision) {
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
		},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = mcp.WriteMessage(w, resp)
}

func (h *Hub) writeDirectory(w http.ResponseWriter) {
	type entry struct {
		Name string `json:"name"`
		Kind string `json:"kind"`
		URL  string `json:"url,omitempty"`
	}
	out := struct {
		Servers []entry `json:"servers"`
	}{}
	for name, sc := range h.cfg.Servers {
		out.Servers = append(out.Servers, entry{
			Name: name,
			Kind: sc.kindOf(),
			URL:  sc.Upstream,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// Run starts the hub listening on cfg.Listen and blocks until ctx is
// cancelled.
func Run(ctx context.Context, cfg *Config, opts Options) error {
	h, err := New(ctx, cfg, opts)
	if err != nil {
		return err
	}
	defer h.Close()

	server := &http.Server{
		Addr:              cfg.Listen,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
	}
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
