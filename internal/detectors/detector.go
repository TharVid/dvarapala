// Package detectors defines the contract every Dvarapala content detector
// implements (gitleaks for secrets, Presidio for PII, llm-guard for prompt
// injection, etc.) and a tiny registry the policy engine uses to look one
// up by name.
package detectors

import "context"

// Finding is one detector hit on a piece of content.
type Finding struct {
	Detector    string  `json:"detector"`          // "gitleaks", "presidio", "llm-guard"
	RuleID      string  `json:"rule_id,omitempty"` // detector-specific rule identifier
	Type        string  `json:"type,omitempty"`    // human-readable category (e.g. "aws-access-key")
	Description string  `json:"description,omitempty"`
	Score       float64 `json:"score,omitempty"` // 0..1; some detectors are binary (treat 1.0)
	Start       int     `json:"start"`           // byte offset (inclusive) in source content
	End         int     `json:"end"`             // byte offset (exclusive)
	Match       string  `json:"match,omitempty"` // matched substring (may be partially redacted)
}

// Detector inspects a string and returns zero or more findings.
type Detector interface {
	Name() string
	Detect(ctx context.Context, content string) ([]Finding, error)
}

// Registry maps a detector name to its implementation. The engine consults
// it for content_matches / content_score rule evaluation.
type Registry struct {
	m map[string]Detector
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{m: make(map[string]Detector)}
}

// Register adds d under d.Name(). Last write wins (so callers can swap a
// real detector for a stub in tests).
func (r *Registry) Register(d Detector) {
	r.m[d.Name()] = d
}

// Get returns the detector named name and ok=true, or nil and ok=false.
func (r *Registry) Get(name string) (Detector, bool) {
	d, ok := r.m[name]
	return d, ok
}

// Names returns the registered detector names (unsorted).
func (r *Registry) Names() []string {
	names := make([]string, 0, len(r.m))
	for n := range r.m {
		names = append(names, n)
	}
	return names
}
