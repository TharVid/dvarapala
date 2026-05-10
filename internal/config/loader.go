// Package config loads Dvarapala policy YAML files. It accepts both the
// user policy at, say, ~/.dvarapala/policy.yaml and the embedded rule
// packs in policies/*.yaml that the binary ships with.
package config

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/tharvid/dvarapala/internal/policy"
	policiesfs "github.com/tharvid/dvarapala/policies"
)

// Load reads a user policy YAML and returns a fully-resolved Policy with
// every defaults[].rulepack reference expanded into concrete rules.
func Load(path string) (*policy.Policy, error) {
	if path == "" {
		// No policy → empty policy → engine allows everything (transparent).
		return &policy.Policy{Version: "1"}, nil
	}
	expanded := expandHome(path)
	b, err := os.ReadFile(expanded)
	if err != nil {
		return nil, fmt.Errorf("read policy %s: %w", expanded, err)
	}
	return parse(b, policiesfs.FS)
}

// LoadFromReader is a Load that reads from any io.Reader. Used by tests.
func LoadFromReader(r io.Reader) (*policy.Policy, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return parse(b, policiesfs.FS)
}

func parse(b []byte, packs fs.FS) (*policy.Policy, error) {
	var p policy.Policy
	if err := unmarshalPolicy(b, &p); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	for _, d := range p.Defaults {
		pack, err := loadRulepack(packs, d.Rulepack)
		if err != nil {
			return nil, fmt.Errorf("load rulepack %q: %w", d.Rulepack, err)
		}
		for _, r := range pack {
			r.Pack = d.Rulepack
			p.Rules = append(p.Rules, r)
		}
	}
	return &p, nil
}

// loadRulepack reads the embedded YAML for the named pack and returns its
// rules with the args map normalised.
func loadRulepack(packs fs.FS, name string) ([]policy.Rule, error) {
	f, err := packs.Open(name + ".yaml")
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	var pack struct {
		Pack        string        `yaml:"pack"`
		Description string        `yaml:"description"`
		Rules       []policy.Rule `yaml:"rules"`
	}
	if err := unmarshalRulepack(b, &pack); err != nil {
		return nil, err
	}
	return pack.Rules, nil
}

// unmarshalPolicy parses a top-level Policy. Match.Args needs special
// handling because in YAML it's a flat map of strings or string-lists.
func unmarshalPolicy(b []byte, p *policy.Policy) error {
	if err := yaml.Unmarshal(b, p); err != nil {
		return err
	}
	return rehydrateArgs(b, &p.Rules, "rules")
}

func unmarshalRulepack(b []byte, pack *struct {
	Pack        string        `yaml:"pack"`
	Description string        `yaml:"description"`
	Rules       []policy.Rule `yaml:"rules"`
},
) error {
	if err := yaml.Unmarshal(b, pack); err != nil {
		return err
	}
	return rehydrateArgs(b, &pack.Rules, "rules")
}

// rehydrateArgs scans the raw YAML for rules[*].match.args.<key> entries
// (which yaml.v3 cannot map directly into our typed Match.Args) and fills
// in the ArgMatcher.Patterns slices.
func rehydrateArgs(b []byte, rules *[]policy.Rule, rulesKey string) error {
	var raw struct {
		Rules []map[string]any `yaml:"rules"`
	}
	if err := yaml.Unmarshal(b, &raw); err != nil {
		return nil // best effort
	}
	for i, rr := range raw.Rules {
		if i >= len(*rules) {
			break
		}
		match, _ := rr["match"].(map[string]any)
		if match == nil {
			continue
		}
		args, ok := flattenArgs(match)
		if !ok {
			continue
		}
		if (*rules)[i].Match.Args == nil {
			(*rules)[i].Match.Args = make(map[string]policy.ArgMatcher)
		}
		for k, v := range args {
			(*rules)[i].Match.Args[k] = policy.ArgMatcher{Patterns: v}
		}
	}
	_ = rulesKey
	return nil
}

// flattenArgs walks the match map for keys starting with "args." and
// returns {arg-name → patterns}. The YAML wire form supports two shapes:
//
//	args.command: "/rm -rf/"          # one pattern
//	args.command:
//	  - "/rm/"                        # multiple
//	  - "*delete*"
func flattenArgs(match map[string]any) (map[string][]string, bool) {
	out := map[string][]string{}
	found := false
	for k, v := range match {
		if !strings.HasPrefix(k, "args.") {
			continue
		}
		key := strings.TrimPrefix(k, "args.")
		switch vv := v.(type) {
		case string:
			out[key] = []string{vv}
			found = true
		case []any:
			for _, item := range vv {
				if s, ok := item.(string); ok {
					out[key] = append(out[key], s)
				}
			}
			if len(out[key]) > 0 {
				found = true
			}
		}
	}
	return out, found
}

func expandHome(p string) string {
	if len(p) >= 2 && p[0] == '~' && (p[1] == '/' || p[1] == os.PathSeparator) {
		if h, err := os.UserHomeDir(); err == nil {
			return filepath.Join(h, p[2:])
		}
	}
	return p
}
