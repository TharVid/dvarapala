package policy

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/tharvid/dvarapala/internal/mcp"
)

// Decision is the engine's verdict for one MCP message.
type Decision struct {
	Action Action
	Rule   string // rule name; empty if no rule fired
	Pack   string // rulepack the rule came from
	Reason string
}

// AllowDecision is the implicit verdict when no rule matches.
var AllowDecision = Decision{Action: ActionAllow}

// Engine evaluates compiled rules against MCP messages.
type Engine struct {
	rules         []CompiledRule
	defaultAction Action
}

// NewEngine compiles rules and returns a ready-to-evaluate engine. Rules
// are evaluated in order; first match wins. defaultAction is returned when
// no rule matches (typically allow).
func NewEngine(rules []Rule, defaultAction Action) (*Engine, error) {
	if defaultAction == "" {
		defaultAction = ActionAllow
	}
	compiled := make([]CompiledRule, 0, len(rules))
	for _, r := range rules {
		cr := CompiledRule{Rule: r}
		if r.Match.ToolNameMatches != "" {
			re, err := compilePattern(r.Match.ToolNameMatches)
			if err != nil {
				return nil, fmt.Errorf("rule %q: tool_name_matches: %w", r.Name, err)
			}
			cr.ToolNameRegex = re
		}
		for _, p := range r.Match.ToolDescriptionMatches {
			re, err := compilePattern(p)
			if err != nil {
				return nil, fmt.Errorf("rule %q: tool_description_matches: %w", r.Name, err)
			}
			cr.ToolDescriptionRegexes = append(cr.ToolDescriptionRegexes, re)
		}
		if len(r.Match.Args) > 0 {
			cr.ArgRegexes = make(map[string][]*regexp.Regexp, len(r.Match.Args))
			for key, m := range r.Match.Args {
				for _, p := range m.Patterns {
					re, err := compilePattern(p)
					if err != nil {
						return nil, fmt.Errorf("rule %q: args.%s: %w", r.Name, key, err)
					}
					cr.ArgRegexes[key] = append(cr.ArgRegexes[key], re)
				}
			}
		}
		compiled = append(compiled, cr)
	}
	return &Engine{rules: compiled, defaultAction: defaultAction}, nil
}

// Rules returns the compiled rules (for inspection / testing).
func (e *Engine) Rules() []CompiledRule { return e.rules }

// Evaluate runs the rules against m in direction dir and returns the first
// matching rule's decision, or the default decision if none match.
func (e *Engine) Evaluate(m mcp.Message, dir mcp.Direction) Decision {
	tool := extractToolName(m)
	args := extractArgs(m)
	for _, cr := range e.rules {
		if !matchDirection(cr.Rule.Match.Direction, dir) {
			continue
		}
		if cr.Rule.Match.Method != "" && cr.Rule.Match.Method != m.Method {
			continue
		}
		if cr.Rule.Match.Tool != "" && cr.Rule.Match.Tool != tool {
			continue
		}
		if cr.ToolNameRegex != nil && !cr.ToolNameRegex.MatchString(tool) {
			continue
		}
		if !matchArgs(cr.ArgRegexes, args) {
			continue
		}
		// (tool_description_matches is for tools/list inspection — phase 4.)
		return Decision{
			Action: cr.Rule.Action,
			Rule:   cr.Rule.Name,
			Pack:   cr.Rule.Pack,
			Reason: cr.Rule.Reason,
		}
	}
	return Decision{Action: e.defaultAction}
}

// extractToolName returns the tool name for tools/call requests, or "".
func extractToolName(m mcp.Message) string {
	if m.Method != "tools/call" || len(m.Params) == 0 {
		return ""
	}
	var p struct {
		Name string `json:"name"`
	}
	_ = json.Unmarshal(m.Params, &p)
	return p.Name
}

// extractArgs returns params.arguments for tools/call requests, flattened
// to top-level string values (best-effort; non-string values stringify via
// JSON encoding).
func extractArgs(m mcp.Message) map[string]string {
	if m.Method != "tools/call" || len(m.Params) == 0 {
		return nil
	}
	var p struct {
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(m.Params, &p); err != nil || len(p.Arguments) == 0 {
		return nil
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(p.Arguments, &raw); err != nil {
		return nil
	}
	out := make(map[string]string, len(raw))
	for k, v := range raw {
		var s string
		if err := json.Unmarshal(v, &s); err == nil {
			out[k] = s
			continue
		}
		out[k] = string(v) // fallback: raw JSON
	}
	return out
}

func matchDirection(want string, got mcp.Direction) bool {
	if want == "" {
		return true
	}
	return want == string(got)
}

func matchArgs(patterns map[string][]*regexp.Regexp, args map[string]string) bool {
	if len(patterns) == 0 {
		return true
	}
	for key, regs := range patterns {
		val, ok := args[key]
		if !ok {
			return false
		}
		matched := false
		for _, re := range regs {
			if re.MatchString(val) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

// compilePattern accepts three syntaxes:
//   - "/expr/i"       — slash-delimited regex with optional flags (i,m,s)
//   - "*foo*"         — glob (translated to regex)
//   - "literal"       — exact-string match (escaped)
//
// A leading '/' alone is not enough to make something a regex; any trailing
// characters after the closing '/' must be valid flags (i,m,s). This avoids
// misparsing absolute paths like "/etc/*" as a regex with flag "*".
func compilePattern(p string) (*regexp.Regexp, error) {
	if isSlashRegex(p) {
		return parseSlashRegex(p)
	}
	if strings.ContainsAny(p, "*?") {
		return regexp.Compile("^" + globToRegex(p) + "$")
	}
	return regexp.Compile("^" + regexp.QuoteMeta(p) + "$")
}

func isSlashRegex(p string) bool {
	if len(p) < 2 || p[0] != '/' {
		return false
	}
	idx := strings.LastIndexByte(p[1:], '/')
	if idx < 0 {
		return false
	}
	for _, f := range p[2+idx:] {
		if f != 'i' && f != 'm' && f != 's' {
			return false
		}
	}
	return true
}

func parseSlashRegex(p string) (*regexp.Regexp, error) {
	idx := strings.LastIndexByte(p[1:], '/')
	body := p[1 : 1+idx]
	flags := p[2+idx:]
	if flags != "" {
		body = "(?" + flags + ")" + body
	}
	return regexp.Compile(body)
}

func globToRegex(g string) string {
	var sb strings.Builder
	for i := 0; i < len(g); i++ {
		switch g[i] {
		case '*':
			sb.WriteString(".*")
		case '?':
			sb.WriteString(".")
		default:
			sb.WriteString(regexp.QuoteMeta(string(g[i])))
		}
	}
	return sb.String()
}
