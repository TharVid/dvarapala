// Package policy defines Dvarapala's policy schema and runtime evaluator.
//
// The schema deliberately stays close to what users write in YAML (see
// policies/*.yaml) so a YAML rule round-trips through the loader without
// surprise. Phase 2 supports the allow/deny/log_only actions and a small
// set of match conditions; phases 3+ wire detector results and add
// redact/rewrite/require_human_approval/llm_judge.
package policy

import (
	"encoding/json"
	"regexp"
)

// Policy is the top-level YAML document.
type Policy struct {
	Version  string         `yaml:"version" json:"version"`
	Defaults []DefaultEntry `yaml:"defaults,omitempty" json:"defaults,omitempty"`
	Audit    AuditConfig    `yaml:"audit,omitempty" json:"audit,omitempty"`
	LLMJudge LLMJudgeConfig `yaml:"llm_judge,omitempty" json:"llm_judge,omitempty"`
	Rules    []Rule         `yaml:"rules,omitempty" json:"rules,omitempty"`
}

// DefaultEntry references a built-in rule pack (e.g. {rulepack: pii}).
type DefaultEntry struct {
	Rulepack string `yaml:"rulepack" json:"rulepack"`
}

// AuditConfig drives the audit logger.
type AuditConfig struct {
	Format string `yaml:"format,omitempty" json:"format,omitempty"`
	Path   string `yaml:"path,omitempty" json:"path,omitempty"`
	Schema string `yaml:"schema,omitempty" json:"schema,omitempty"`
}

// LLMJudgeConfig configures the optional LLM-as-judge fallback.
type LLMJudgeConfig struct {
	Enabled   bool    `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Provider  string  `yaml:"provider,omitempty" json:"provider,omitempty"`
	Model     string  `yaml:"model,omitempty" json:"model,omitempty"`
	CacheTTL  string  `yaml:"cache_ttl,omitempty" json:"cache_ttl,omitempty"`
	Threshold float64 `yaml:"threshold,omitempty" json:"threshold,omitempty"`
}

// Action is the disposition a rule applies when its match fires.
type Action string

const (
	ActionAllow                Action = "allow"
	ActionDeny                 Action = "deny"
	ActionRedact               Action = "redact"
	ActionRewrite              Action = "rewrite"
	ActionRequireHumanApproval Action = "require_human_approval"
	ActionLogOnly              Action = "log_only"
	ActionDelay                Action = "delay"
	ActionLLMJudge             Action = "llm_judge"
)

// Rule is a single policy entry.
type Rule struct {
	Name        string   `yaml:"name" json:"name"`
	Pack        string   `yaml:"-" json:"pack,omitempty"` // populated when loaded from a rulepack
	Match       Match    `yaml:"match" json:"match"`
	Action      Action   `yaml:"action" json:"action"`
	Reason      string   `yaml:"reason,omitempty" json:"reason,omitempty"`
	Severity    string   `yaml:"severity,omitempty" json:"severity,omitempty"`
	Tags        []string `yaml:"tags,omitempty" json:"tags,omitempty"`
	Description string   `yaml:"description,omitempty" json:"description,omitempty"`
	// Action-specific config (parsed but not all enforced in Phase 2).
	RateLimit *RateLimitSpec `yaml:"rate_limit,omitempty" json:"rate_limit,omitempty"`
	Rewrite   map[string]any `yaml:"rewrite,omitempty" json:"rewrite,omitempty"`
	// Replacement is the template used by the redact action when this rule
	// matches. Two placeholders are recognised:
	//   {{rule}} → the matching detector's rule id
	//   {{kind}} → a coarse kind ("secret", "pii", "prompt-injection", …)
	// Empty falls back to "[REDACTED:{{rule}}]" so existing policies
	// behave exactly as before.
	Replacement string `yaml:"replacement,omitempty" json:"replacement,omitempty"`
}

// Match is the condition predicate. Each non-zero field is an additional
// AND constraint. Phase 2 implements direction/method/tool/tool_name_matches/
// tool_description_matches and a flat args.<key> map; richer conditions
// (content_matches, content_score, jsonpath, etc.) come in later phases.
type Match struct {
	Direction              string                `yaml:"direction,omitempty" json:"direction,omitempty"`
	Method                 string                `yaml:"method,omitempty" json:"method,omitempty"`
	Tool                   string                `yaml:"tool,omitempty" json:"tool,omitempty"`
	ToolNameMatches        string                `yaml:"tool_name_matches,omitempty" json:"tool_name_matches,omitempty"`
	ToolDescriptionMatches []string              `yaml:"tool_description_matches,omitempty" json:"tool_description_matches,omitempty"`
	Args                   map[string]ArgMatcher `yaml:"-" json:"args,omitempty"`
	// Inline placeholders for fields not yet enforced (phases 3+):
	ContentMatches *ContentMatchSpec `yaml:"content_matches,omitempty" json:"content_matches,omitempty"`
	ContentScore   *ContentScoreSpec `yaml:"content_score,omitempty" json:"content_score,omitempty"`
	URLHostNotIn   []string          `yaml:"url_host_not_in,omitempty" json:"url_host_not_in,omitempty"`
}

// ArgMatcher is a constraint on a single argument value. The wire form is
// either a string ("foo*", "/regex/i") or a list of strings (any match).
type ArgMatcher struct {
	Patterns []string `yaml:"-" json:"patterns,omitempty"`
}

// ContentMatchSpec is a placeholder so YAML files using gitleaks/presidio/
// llm-guard parse cleanly. Wired in Phase 3.
type ContentMatchSpec struct {
	Detector string `yaml:"detector,omitempty" json:"detector,omitempty"`
}

// ContentScoreSpec is a placeholder for detector score thresholds.
type ContentScoreSpec struct {
	Detector     string   `yaml:"detector,omitempty" json:"detector,omitempty"`
	Threshold    float64  `yaml:"threshold,omitempty" json:"threshold,omitempty"`
	ThresholdMin float64  `yaml:"threshold_min,omitempty" json:"threshold_min,omitempty"`
	ThresholdMax float64  `yaml:"threshold_max,omitempty" json:"threshold_max,omitempty"`
	Entities     []string `yaml:"entities,omitempty" json:"entities,omitempty"`
}

// RateLimitSpec is a placeholder for rate-limited rules. Wired in Phase 5.
type RateLimitSpec struct {
	RequestsPerSecond float64 `yaml:"requests_per_second,omitempty" json:"requests_per_second,omitempty"`
	Burst             int     `yaml:"burst,omitempty" json:"burst,omitempty"`
	Key               string  `yaml:"key,omitempty" json:"key,omitempty"`
}

// MarshalJSON for ArgMatcher: emit just the patterns slice.
func (a ArgMatcher) MarshalJSON() ([]byte, error) {
	return json.Marshal(a.Patterns)
}

// CompiledRule pairs a Rule with its precompiled regexes for fast eval.
type CompiledRule struct {
	Rule                   Rule
	ToolNameRegex          *regexp.Regexp
	ToolDescriptionRegexes []*regexp.Regexp
	ArgRegexes             map[string][]*regexp.Regexp
}
