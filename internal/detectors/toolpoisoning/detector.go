// Package toolpoisoning detects prompt-injection patterns embedded in MCP
// tool descriptions and (more generally) in any string content.
//
// This is one of Dvarapala's NATIVE detectors — there is no off-the-shelf
// library covering it because it's an MCP-specific attack class:
//
//  1. A malicious MCP server publishes a tool whose `description` contains
//     instructions ("ignore previous instructions, …") aimed at the LLM
//     when it reads the tool list.
//  2. The LLM is trained to follow well-formed instructions and may obey
//     the description rather than treating it as untrusted data.
//  3. By the time the user sees a tool call happen, the agent has already
//     been steered.
//
// References: HiddenLayer & Anthropic published advisories on
// tool-description injection / "line-jumping" attacks against MCP in 2024–2025.
//
// Detection here is a layered heuristic:
//   - Hand-curated regex patterns for the well-known phrasings.
//   - System-tag injection markers (<|im_start|>, <system>, etc.).
//   - Credential-prompt fragments (asking for API keys / private keys).
//
// llm-guard (Phase 3.5) covers the soft cases via its prompt-injection
// model; this detector covers the obvious patterns deterministically and
// runs in-process with no sidecar.
package toolpoisoning

import (
	"context"
	"regexp"

	"github.com/tharvid/dvarapala/internal/detectors"
)

// Name is the identifier used in policy YAML (`detector: tool-poisoning`).
const Name = "tool-poisoning"

// Pattern is a labelled regex used by the detector.
type Pattern struct {
	RuleID      string
	Description string
	Re          *regexp.Regexp
}

// DefaultPatterns covers the well-known prompt-injection phrasings seen in
// public MCP advisories.
var DefaultPatterns = []Pattern{
	mustPattern("ignore-previous-instructions",
		"phrase telling the LLM to disregard prior instructions",
		`(?i)ignore\s+(?:the\s+)?(?:previous|prior|all|above)\s+(?:instructions?|prompts?|messages?)`),
	mustPattern("disregard-system-prompt",
		"phrase asking the LLM to override its system prompt",
		`(?i)(?:disregard|ignore|forget)\s+(?:your|the)\s+system(?:\s+prompt)?`),
	mustPattern("you-are-now-different",
		"role-switch phrasing typical of jailbreaks",
		`(?i)you\s+are\s+(?:now|going\s+to\s+be)\s+(?:a|an)\s+(?:different|new|unrestricted|uncensored)`),
	mustPattern("system-tag-injection",
		"raw model role tags injected into tool description",
		`(?:<\|im_start\|>system|<system>|<\|system\|>)`),
	mustPattern("forget-everything-above",
		"classic instruction-erase phrasing",
		`(?i)forget\s+everything\s+(?:above|so\s+far|previous)`),
	mustPattern("do-anything-now",
		"DAN-style jailbreak phrasing",
		`(?i)\b(?:do\s+anything\s+now|DAN\s+mode)\b`),
	mustPattern("credential-prompt-private-key",
		"description asks the LLM to surface a private key",
		`-----BEGIN\s+(?:RSA|OPENSSH|EC|DSA|PGP)\s+PRIVATE\s+KEY-----`),
	mustPattern("credential-prompt-api-key",
		"description asks the LLM to include an API key/token",
		`(?i)(?:please\s+)?(?:include|append|attach)\s+(?:your\s+|the\s+)?(?:api[\s_-]?key|secret|token|password)`),
	mustPattern("exfiltration-instruction",
		"description tells the LLM to send data to an external endpoint",
		`(?i)\b(?:exfiltrate|send\s+(?:to|via)|POST\s+to|curl\s+https?://)\b.*(?:env|secret|credential|token)`),
}

func mustPattern(id, desc, expr string) Pattern {
	re, err := regexp.Compile(expr)
	if err != nil {
		panic("toolpoisoning: bad regex " + expr + ": " + err.Error())
	}
	return Pattern{RuleID: id, Description: desc, Re: re}
}

// Detector implements detectors.Detector for tool-description injection.
type Detector struct {
	patterns []Pattern
}

// New returns a Detector initialised with DefaultPatterns. Pass extra
// patterns to extend the rule set without forking.
func New(extra ...Pattern) *Detector {
	d := &Detector{}
	d.patterns = append(d.patterns, DefaultPatterns...)
	d.patterns = append(d.patterns, extra...)
	return d
}

// Name implements detectors.Detector.
func (d *Detector) Name() string { return Name }

// Detect scans content with every pattern and emits one Finding per match.
func (d *Detector) Detect(_ context.Context, content string) ([]detectors.Finding, error) {
	if content == "" {
		return nil, nil
	}
	var hits []detectors.Finding
	for _, p := range d.patterns {
		for _, loc := range p.Re.FindAllStringIndex(content, -1) {
			hits = append(hits, detectors.Finding{
				Detector:    Name,
				RuleID:      p.RuleID,
				Type:        "prompt-injection",
				Description: p.Description,
				Score:       1.0,
				Start:       loc[0],
				End:         loc[1],
				Match:       content[loc[0]:loc[1]],
			})
		}
	}
	return hits, nil
}
