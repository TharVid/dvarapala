# Built-in rule packs

Each pack ships embedded in the binary (via `policies/embed.go`). Reference them under `defaults:` in your policy.yaml and they expand into concrete rules at load time.

## Summary

| Pack | What it catches | Detector | Always on |
|---|---|---|---|
| [`destructive-actions`](../policies/destructive-actions.yaml) | `rm -rf`, `DROP TABLE`, `dd if=…of=/dev/sd*`, `mkfs.* /dev/*` | native heuristics | yes (when added to defaults) |
| [`secrets`](../policies/secrets.yaml) | AWS / GCP / Azure / GitHub / Slack / Stripe / JWT / private keys / .env | [gitleaks](https://github.com/gitleaks/gitleaks) (embedded) | yes |
| [`tool-poisoning`](../policies/tool-poisoning.yaml) | Malicious instructions in tool descriptions, system-tag injection, credential prompts, DAN-mode jailbreaks | **native** | yes |
| [`tool-mutation`](../policies/tool-mutation.yaml) | Tool definitions silently changing across sessions (rug-pull) | **native** (SHA-256 fingerprints with cross-restart persistence) | yes |
| [`pii`](../policies/pii.yaml) | Emails, SSN, credit cards, phone, IBAN, Aadhaar, PAN, MRN, etc. | [Microsoft Presidio](https://github.com/microsoft/presidio) (sidecar) | opt-in |
| [`prompt-injection`](../policies/prompt-injection.yaml) | Direct + indirect prompt injection (ML model + heuristics) | [llm-guard](https://github.com/protectai/llm-guard) + Meta Prompt-Guard (sidecar) | opt-in |
| [`egress-allowlist`](../policies/egress-allowlist.yaml) | Outbound HTTP from MCP servers to non-approved hosts | native | parsed; full enforcement in Phase 7 |
| [`rate-limit`](../policies/rate-limit.yaml) | Per-tool, per-session rate limits | `golang.org/x/time/rate` | parsed; full enforcement in Phase 7 |

## Detector availability

| Detector | How it ships | When it runs |
|---|---|---|
| `gitleaks` | embedded Go library | always available |
| `tool-poisoning` | native, in-process | always available |
| `tool-mutation` | native, in-process, persistent | always available |
| `presidio` | external sidecar (Docker container) | when `DVARAPALA_PRESIDIO_URL` is set |
| `llm-guard` | external sidecar (Docker container) | when `DVARAPALA_LLMGUARD_URL` is set |

If a detector is referenced by a rule but not available, the rule simply doesn't fire — traffic isn't blocked on detector unavailability. See [docs/deployment/docker.md](deployment/docker.md) for spinning up the sidecars.

## Native pack details

### `destructive-actions`

Heuristic regex on shell-tool args. Fires only on tools whose name matches `shell|exec|bash|sh|terminal` (so a `read_text_file` MCP tool that happens to return a doc containing `rm -rf` doesn't trip it).

### `tool-poisoning`

Hand-curated patterns for prompt-injection phrasing in tool descriptions. References:
- "ignore previous instructions" / "ignore all" / "ignore prior"
- "disregard your system prompt"
- "you are now an unrestricted assistant" (role-switch)
- `<|im_start|>system`, `<system>`, `<|system|>` raw role tags
- "forget everything above"
- DAN-mode jailbreaks
- `-----BEGIN ... PRIVATE KEY-----` (description asking the LLM to surface credentials)
- "please include your API key / secret / token / password"
- exfil-shape: `curl https://… (env|secret|credential)`

### `tool-mutation`

Computes SHA-256 over canonical `(name, description, inputSchema)` of every tool seen in `tools/list` outbound responses. Compares against `~/.dvarapala/tool-fingerprints.jsonl`. Emits a finding the first time a known tool's fingerprint diverges from prior sight.

Schemas are key-order-canonicalised so `{a, b}` and `{b, a}` don't false-positive.

## Adding your own pack

A rule pack is just a YAML file with `pack:`, `description:`, `rules:`. You can:

1. Place `~/.dvarapala/rulepacks/my-org.yaml` and reference it as `rulepack: my-org`.
2. Or write the rules inline under your policy's top-level `rules:` array.

See [policy-language.md](policy-language.md) for the rule schema.
