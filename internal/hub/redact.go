package hub

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/tharvid/dvarapala/internal/detectors"
)

// redactJSON walks the JSON body and runs every detector in registry on
// each *string* value, replacing matched substrings via the supplied
// per-rule template (or the default "[REDACTED:rule-id]" if empty).
// JSON validity is preserved because we never splice at byte offsets
// across structural characters; same shape as proxy.applyRedaction
// (kept duplicated rather than exported to avoid proxy → hub → proxy
// import cycles).
func redactJSON(ctx context.Context, raw []byte, reg *detectors.Registry, template string) ([]byte, error) {
	if reg == nil {
		return raw, nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return raw, err
	}
	walked := redactWalk(ctx, v, reg, template)
	out, err := json.Marshal(walked)
	if err != nil {
		return raw, err
	}
	return out, nil
}

func redactWalk(ctx context.Context, v any, reg *detectors.Registry, tpl string) any {
	switch t := v.(type) {
	case string:
		return redactString(ctx, t, reg, tpl)
	case map[string]any:
		for k, vv := range t {
			t[k] = redactWalk(ctx, vv, reg, tpl)
		}
		return t
	case []any:
		for i, vv := range t {
			t[i] = redactWalk(ctx, vv, reg, tpl)
		}
		return t
	}
	return v
}

func redactString(ctx context.Context, s string, reg *detectors.Registry, tpl string) string {
	var allHits []detectors.Finding
	for _, name := range reg.Names() {
		d, ok := reg.Get(name)
		if !ok {
			continue
		}
		hits, err := d.Detect(ctx, s)
		if err != nil {
			continue
		}
		allHits = append(allHits, hits...)
	}
	if len(allHits) == 0 {
		return s
	}
	// Longer matches first so an outer span swallows inner spans cleanly.
	sort.SliceStable(allHits, func(i, j int) bool {
		return len(allHits[i].Match) > len(allHits[j].Match)
	})
	out := s
	for _, h := range allHits {
		if h.Match == "" {
			continue
		}
		out = strings.ReplaceAll(out, h.Match, formatRedactionMarker(tpl, h))
	}
	return out
}

// formatRedactionMarker mirrors the proxy package's helper of the same
// name. {{rule}} → finding's rule id; {{kind}} → coarse category.
func formatRedactionMarker(tpl string, h detectors.Finding) string {
	if tpl == "" {
		return fmt.Sprintf("[REDACTED:%s]", safeRuleID(h.RuleID))
	}
	out := strings.ReplaceAll(tpl, "{{rule}}", safeRuleID(h.RuleID))
	out = strings.ReplaceAll(out, "{{kind}}", findingKind(h))
	return out
}

func findingKind(h detectors.Finding) string {
	id := strings.ToLower(h.RuleID)
	switch {
	case strings.Contains(id, "key"), strings.Contains(id, "token"), strings.Contains(id, "secret"), strings.Contains(id, "credential"):
		return "secret"
	case strings.Contains(id, "email"), strings.Contains(id, "phone"), strings.Contains(id, "ssn"), strings.Contains(id, "credit"), strings.Contains(id, "pii"):
		return "pii"
	case strings.Contains(id, "injection"), strings.Contains(id, "prompt"):
		return "prompt-injection"
	case strings.Contains(id, "mutation"), strings.Contains(id, "rugpull"):
		return "tool-mutation"
	case strings.Contains(id, "poisoning"):
		return "tool-poisoning"
	default:
		return "match"
	}
}

func safeRuleID(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}
