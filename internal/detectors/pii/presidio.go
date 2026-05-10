// Package pii wraps Microsoft Presidio (https://github.com/microsoft/presidio)
// as a Dvarapala detector. We do not maintain our own PII regex set —
// Presidio is the industry-standard OSS PII engine, supports HIPAA/GDPR/PCI,
// and ships 50+ recognizers (emails, SSN, credit cards, phone, IBAN, etc.).
//
// Presidio runs as a sidecar HTTP service. Spin it up with the official
// container: `docker run -p 3000:3000 mcr.microsoft.com/presidio-analyzer`.
// Set DVARAPALA_PRESIDIO_URL=http://localhost:3000 (or pass to New).
//
// If the sidecar isn't running, Detect() returns no findings and a non-nil
// error; the engine treats this as "no match" so the gateway degrades
// gracefully rather than blocking traffic on detector unavailability.
package pii

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

// Name is the identifier used in policy YAML (`detector: presidio`).
const Name = "presidio"

// Detector talks to a Presidio analyzer over HTTP.
type Detector struct {
	url       string
	client    *http.Client
	threshold float64
	language  string
}

// Option configures the Detector.
type Option func(*Detector)

// WithThreshold filters out findings with score < t (default 0.5).
func WithThreshold(t float64) Option { return func(d *Detector) { d.threshold = t } }

// WithLanguage sets the analysis language code (default "en").
func WithLanguage(lang string) Option { return func(d *Detector) { d.language = lang } }

// WithHTTPClient swaps the http.Client (handy for tests).
func WithHTTPClient(c *http.Client) Option { return func(d *Detector) { d.client = c } }

// New constructs a Detector pointed at the given Presidio analyzer URL.
// url is typically http://localhost:3000 in dev or the service URL in
// Docker Compose / Kubernetes.
func New(url string, opts ...Option) *Detector {
	d := &Detector{
		url:       strings.TrimRight(url, "/"),
		client:    &http.Client{Timeout: 5 * time.Second},
		threshold: 0.5,
		language:  "en",
	}
	for _, o := range opts {
		o(d)
	}
	return d
}

// Name implements detectors.Detector.
func (d *Detector) Name() string { return Name }

// presidioRequest matches the Presidio Analyzer /analyze schema.
type presidioRequest struct {
	Text           string  `json:"text"`
	Language       string  `json:"language"`
	ScoreThreshold float64 `json:"score_threshold"`
}

// presidioFinding is one entry in the analyzer's response array.
type presidioFinding struct {
	EntityType string  `json:"entity_type"`
	Start      int     `json:"start"`
	End        int     `json:"end"`
	Score      float64 `json:"score"`
}

// Detect POSTs content to the Presidio analyzer and converts findings.
func (d *Detector) Detect(ctx context.Context, content string) ([]detectors.Finding, error) {
	if content == "" {
		return nil, nil
	}
	body, err := json.Marshal(presidioRequest{
		Text:           content,
		Language:       d.language,
		ScoreThreshold: d.threshold,
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.url+"/analyze", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("presidio analyze: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("presidio analyze: status %d", resp.StatusCode)
	}
	var raw []presidioFinding
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("presidio decode: %w", err)
	}
	out := make([]detectors.Finding, 0, len(raw))
	for _, f := range raw {
		match := ""
		if f.Start >= 0 && f.End <= len(content) && f.Start < f.End {
			match = content[f.Start:f.End]
		}
		out = append(out, detectors.Finding{
			Detector: Name,
			RuleID:   f.EntityType,
			Type:     f.EntityType,
			Score:    f.Score,
			Start:    f.Start,
			End:      f.End,
			Match:    match,
		})
	}
	return out, nil
}
