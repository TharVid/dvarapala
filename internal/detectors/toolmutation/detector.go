// Package toolmutation detects when an MCP tool's definition silently
// changes between sessions — the "rug-pull" attack class. A benign tool
// the user already approved gets its description, schema, or behaviour
// quietly mutated by a malicious or compromised server.
//
// This is another NATIVE Dvarapala detector with no off-the-shelf
// equivalent. It works by:
//
//  1. Watching outbound tools/list responses (server → client).
//  2. Computing a SHA-256 fingerprint over each tool's canonical
//     (name, description, inputSchema) tuple.
//  3. Comparing against a fingerprint store keyed by tool name.
//  4. Emitting a Finding the first time a known tool's fingerprint
//     diverges from what was last seen.
//
// The store is in-memory by default (per-gateway-process, sufficient for
// real-time stdio sessions), with optional JSONL persistence at
// ~/.dvarapala/tool-fingerprints.jsonl so fingerprints survive restarts.
package toolmutation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/tharvid/dvarapala/internal/detectors"
)

// Name is the identifier used in policy YAML (`detector: tool-mutation`).
const Name = "tool-mutation"

// Detector tracks tool fingerprints across calls.
type Detector struct {
	mu       sync.RWMutex
	seen     map[string]string // toolName → SHA-256 hex
	storeDir string            // empty = in-memory only
}

// fingerprintRecord is one line of the persistence JSONL.
type fingerprintRecord struct {
	Name string `json:"name"`
	Hash string `json:"hash"`
}

// New returns an in-memory Detector. Use NewPersistent to survive restarts.
func New() *Detector { return &Detector{seen: make(map[string]string)} }

// NewPersistent returns a Detector that loads any prior fingerprints from
// dir/tool-fingerprints.jsonl on startup and appends every new fingerprint
// to that file. Cross-session rug-pull detection only works with this.
//
// Errors during load are non-fatal: a missing or unreadable file is
// treated as "fresh state" so the detector still works in-memory.
func NewPersistent(dir string) *Detector {
	d := &Detector{
		seen:     make(map[string]string),
		storeDir: dir,
	}
	d.loadFromDisk()
	return d
}

// fingerprintsPath is the on-disk JSONL location.
func (d *Detector) fingerprintsPath() string {
	if d.storeDir == "" {
		return ""
	}
	return filepath.Join(d.storeDir, "tool-fingerprints.jsonl")
}

func (d *Detector) loadFromDisk() {
	p := d.fingerprintsPath()
	if p == "" {
		return
	}
	f, err := os.Open(p)
	if err != nil {
		return
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	for dec.More() {
		var r fingerprintRecord
		if err := dec.Decode(&r); err != nil {
			return
		}
		d.seen[r.Name] = r.Hash // last write wins
	}
}

// persist appends a fingerprint to the JSONL store. Non-fatal on error.
func (d *Detector) persist(name, hash string) {
	p := d.fingerprintsPath()
	if p == "" {
		return
	}
	if err := os.MkdirAll(d.storeDir, 0o755); err != nil {
		return
	}
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	b, _ := json.Marshal(fingerprintRecord{Name: name, Hash: hash})
	_, _ = f.Write(append(b, '\n'))
}

// Name implements detectors.Detector.
func (d *Detector) Name() string { return Name }

// Detect parses content as a JSON-RPC message; if it contains a
// tools/list-shaped result (`result.tools[]`), each tool is fingerprinted
// and compared against prior state. Any mismatch yields a Finding.
//
// Plain content that isn't a tools/list response simply returns no
// findings — the detector is a safe no-op on every other message.
func (d *Detector) Detect(_ context.Context, content string) ([]detectors.Finding, error) {
	if content == "" {
		return nil, nil
	}
	var env struct {
		Result struct {
			Tools []json.RawMessage `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(content), &env); err != nil {
		return nil, nil // not a JSON-RPC response — silently skip
	}
	if len(env.Result.Tools) == 0 {
		return nil, nil
	}

	var hits []detectors.Finding
	for _, raw := range env.Result.Tools {
		var t struct {
			Name        string          `json:"name"`
			Description string          `json:"description"`
			InputSchema json.RawMessage `json:"inputSchema"`
		}
		if err := json.Unmarshal(raw, &t); err != nil || t.Name == "" {
			continue
		}
		hash := fingerprint(t.Name, t.Description, t.InputSchema)
		d.mu.Lock()
		prev, exists := d.seen[t.Name]
		d.seen[t.Name] = hash
		d.mu.Unlock()
		d.persist(t.Name, hash)
		if exists && prev != hash {
			hits = append(hits, detectors.Finding{
				Detector:    Name,
				RuleID:      "tool-definition-changed",
				Type:        "tool-mutation",
				Description: fmt.Sprintf("tool %q definition changed (was %s, now %s)", t.Name, prev[:8], hash[:8]),
				Score:       1.0,
				Match:       t.Name,
			})
		}
	}
	return hits, nil
}

// Reset clears the fingerprint store. Useful for tests.
func (d *Detector) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.seen = make(map[string]string)
}

// fingerprint returns the canonical SHA-256 of a tool's identity. We
// canonicalise inputSchema by re-marshalling the parsed JSON with sorted
// keys so that semantically equivalent schemas (key order differs only)
// don't trigger spurious mutations.
func fingerprint(name, description string, schema json.RawMessage) string {
	canonical := struct {
		Name        string          `json:"name"`
		Description string          `json:"description"`
		Schema      json.RawMessage `json:"schema"`
	}{
		Name:        name,
		Description: description,
		Schema:      canonicalJSON(schema),
	}
	b, _ := json.Marshal(canonical)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// canonicalJSON re-emits arbitrary JSON with map keys in sorted order so
// fingerprint(schema_a) == fingerprint(schema_b) when schemas differ
// only in key ordering.
func canonicalJSON(in json.RawMessage) json.RawMessage {
	if len(in) == 0 {
		return in
	}
	var v any
	if err := json.Unmarshal(in, &v); err != nil {
		return in
	}
	out, err := json.Marshal(sortKeys(v))
	if err != nil {
		return in
	}
	return out
}

func sortKeys(v any) any {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		ordered := make(map[string]any, len(t))
		for _, k := range keys {
			ordered[k] = sortKeys(t[k])
		}
		return ordered
	case []any:
		for i, item := range t {
			t[i] = sortKeys(item)
		}
		return t
	}
	return v
}
