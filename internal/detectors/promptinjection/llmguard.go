// Package promptinjection wraps llm-guard (https://github.com/protectai/llm-guard)
// as a Dvarapala detector. llm-guard ships only as a Python library, so we
// run it behind a tiny FastAPI sidecar (sidecars/llm-guard/server.py)
// and call it over HTTP.
//
// The sidecar exposes:
//
//	POST /scan { "text": "...", "direction": "inbound" | "outbound" }
//	  → { "is_valid": bool, "risk_score": float, "detector": string }
//
// When is_valid=false (i.e. llm-guard's scanner judges the text adversarial),
// we emit a single Finding with the reported risk score so policy rules
// using content_score with detector=llm-guard can fire.
//
// If the sidecar isn't running, Detect() returns an error; the engine
// treats this as "no match" so traffic isn't blocked on detector
// unavailability.
package promptinjection

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/tharvid/dvarapala/internal/detectors"
)

// Name is the identifier used in policy YAML (`detector: llm-guard`).
const Name = "llm-guard"

// Detector talks to the llm-guard sidecar over HTTP.
type Detector struct {
	url       string
	client    *http.Client
	direction string // "inbound" | "outbound"; passed to the sidecar
}

// Option configures the Detector.
type Option func(*Detector)

// WithHTTPClient swaps the http.Client (used by tests).
func WithHTTPClient(c *http.Client) Option { return func(d *Detector) { d.client = c } }

// WithDirection chooses which scanner the sidecar uses (inbound = prompt
// injection scanner; outbound = sensitive-output scanner). Default inbound.
func WithDirection(s string) Option { return func(d *Detector) { d.direction = s } }

// New constructs a Detector pointed at the llm-guard sidecar URL.
func New(url string, opts ...Option) *Detector {
	d := &Detector{
		url:       strings.TrimRight(url, "/"),
		client:    &http.Client{Timeout: 10 * time.Second},
		direction: "inbound",
	}
	for _, o := range opts {
		o(d)
	}
	return d
}

// Name implements detectors.Detector.
func (d *Detector) Name() string { return Name }

type scanRequest struct {
	Text      string `json:"text"`
	Direction string `json:"direction"`
}

type scanResponse struct {
	IsValid   bool    `json:"is_valid"`
	RiskScore float64 `json:"risk_score"`
	Detector  string  `json:"detector"`
}

// Detect calls the sidecar's /scan endpoint and returns one Finding when
// llm-guard reports the text as adversarial.
func (d *Detector) Detect(ctx context.Context, content string) ([]detectors.Finding, error) {
	if content == "" {
		return nil, nil
	}
	body, err := json.Marshal(scanRequest{Text: content, Direction: d.direction})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.url+"/scan", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("llm-guard scan: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("llm-guard scan: status %d", resp.StatusCode)
	}
	var sr scanResponse
	if err := json.NewDecoder(resp.Body).Decode(&sr); err != nil {
		return nil, fmt.Errorf("llm-guard decode: %w", err)
	}
	if sr.IsValid {
		return nil, nil
	}
	ruleID := sr.Detector
	if ruleID == "" {
		ruleID = "prompt-injection"
	}
	return []detectors.Finding{{
		Detector: Name,
		RuleID:   ruleID,
		Type:     ruleID,
		Score:    sr.RiskScore,
		Start:    0,
		End:      len(content),
		Match:    content,
	}}, nil
}
