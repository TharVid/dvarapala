// Package secrets wraps gitleaks (https://github.com/gitleaks/gitleaks) as
// a Dvarapala detector. We do not maintain our own secret regex set —
// gitleaks ships 150+ rules covering AWS, GCP, Azure, GitHub, Slack,
// Stripe, JWT, private keys, .env entries, etc. and is the industry
// standard.
package secrets

import (
	"context"
	"fmt"

	"github.com/zricethezav/gitleaks/v8/detect"

	"github.com/tharvid/dvarapala/internal/detectors"
)

// Name is the identifier used in policy YAML (`detector: gitleaks`).
const Name = "gitleaks"

// Detector wraps a gitleaks Detector configured with the default rule set.
type Detector struct {
	d *detect.Detector
}

// New returns a Detector preloaded with gitleaks's default rules.
func New() (*Detector, error) {
	gd, err := detect.NewDetectorDefaultConfig()
	if err != nil {
		return nil, fmt.Errorf("gitleaks default config: %w", err)
	}
	gd.MaxTargetMegaBytes = 16
	return &Detector{d: gd}, nil
}

// Name implements detectors.Detector.
func (d *Detector) Name() string { return Name }

// Detect runs every default gitleaks rule against content and returns
// Dvarapala findings. The Finding.Score is always 1.0 because gitleaks
// matches are binary (a regex hit is a hit).
func (d *Detector) Detect(_ context.Context, content string) ([]detectors.Finding, error) {
	if d == nil || d.d == nil {
		return nil, fmt.Errorf("gitleaks detector not initialised")
	}
	hits := d.d.DetectString(content)
	out := make([]detectors.Finding, 0, len(hits))
	for _, h := range hits {
		out = append(out, detectors.Finding{
			Detector:    Name,
			RuleID:      h.RuleID,
			Type:        h.RuleID, // category mirrors RuleID (aws-access-token, github-pat, etc.)
			Description: h.Description,
			Score:       1.0,
			Start:       h.StartColumn - 1, // gitleaks uses 1-based columns
			End:         h.EndColumn,
			Match:       h.Match,
		})
	}
	return out, nil
}
