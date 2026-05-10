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
// each *string* value, replacing matched substrings with
// [REDACTED:rule-id]. JSON validity is preserved because we never splice
// at byte offsets across structural characters; this is the same shape
// as proxy.applyRedaction (kept duplicated rather than exported to avoid
// proxy → hub → proxy import cycles).
func redactJSON(ctx context.Context, raw []byte, reg *detectors.Registry) ([]byte, error) {
	if reg == nil {
		return raw, nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return raw, err
	}
	walked := redactWalk(ctx, v, reg)
	out, err := json.Marshal(walked)
	if err != nil {
		return raw, err
	}
	return out, nil
}

func redactWalk(ctx context.Context, v any, reg *detectors.Registry) any {
	switch t := v.(type) {
	case string:
		return redactString(ctx, t, reg)
	case map[string]any:
		for k, vv := range t {
			t[k] = redactWalk(ctx, vv, reg)
		}
		return t
	case []any:
		for i, vv := range t {
			t[i] = redactWalk(ctx, vv, reg)
		}
		return t
	}
	return v
}

func redactString(ctx context.Context, s string, reg *detectors.Registry) string {
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
		marker := fmt.Sprintf("[REDACTED:%s]", safeRuleID(h.RuleID))
		out = strings.ReplaceAll(out, h.Match, marker)
	}
	return out
}

func safeRuleID(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}
