package proxy

import (
	"testing"

	"github.com/tharvid/dvarapala/internal/detectors"
)

func TestFormatRedactionMarker(t *testing.T) {
	cases := []struct {
		name     string
		template string
		finding  detectors.Finding
		want     string
	}{
		{
			name:     "empty template falls back to legacy form",
			template: "",
			finding:  detectors.Finding{RuleID: "aws-access-token"},
			want:     "[REDACTED:aws-access-token]",
		},
		{
			name:     "rule placeholder substitutes",
			template: "<redacted:{{rule}}>",
			finding:  detectors.Finding{RuleID: "github-pat"},
			want:     "<redacted:github-pat>",
		},
		{
			name:     "kind placeholder maps secret-keywords to secret",
			template: "<{{kind}}>",
			finding:  detectors.Finding{RuleID: "stripe-api-key"},
			want:     "<secret>",
		},
		{
			name:     "kind placeholder maps prompt-injection",
			template: "[{{kind}}]",
			finding:  detectors.Finding{RuleID: "prompt-injection-direct"},
			want:     "[prompt-injection]",
		},
		{
			name:     "kind placeholder maps tool-poisoning",
			template: "[{{kind}}:{{rule}}]",
			finding:  detectors.Finding{RuleID: "tool-poisoning-ignore-previous"},
			want:     "[tool-poisoning:tool-poisoning-ignore-previous]",
		},
		{
			name:     "empty rule id falls back to unknown",
			template: "<{{rule}}>",
			finding:  detectors.Finding{RuleID: ""},
			want:     "<unknown>",
		},
		{
			name:     "fixed string template ignores placeholders",
			template: "***",
			finding:  detectors.Finding{RuleID: "anything"},
			want:     "***",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := formatRedactionMarker(tc.template, tc.finding)
			if got != tc.want {
				t.Errorf("formatRedactionMarker(%q, %+v) = %q; want %q",
					tc.template, tc.finding, got, tc.want)
			}
		})
	}
}
