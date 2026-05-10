# Policy language

Dvarapala policies are YAML. Each rule has three parts: a **match**, an **action**, and optional **metadata** (reason, severity, tags).

## Top-level structure

```yaml
version: "1"
defaults:
  - rulepack: pii
  - rulepack: secrets
audit:
  path: ~/.dvarapala/audit.jsonl
  schema: ocsf
llm_judge:
  enabled: true
  provider: anthropic
  model: claude-haiku-4-5
rules:
  - name: my-custom-rule
    match: { ... }
    action: deny
```

## Match conditions

| Field | Meaning |
|---|---|
| `direction` | `inbound` (client → server) / `outbound` (server → client) |
| `method` | JSON-RPC method (`tools/list`, `tools/call`, `prompts/get`, …) |
| `tool` / `tool_name_matches` | Match a specific tool by name or regex |
| `args.<jsonpath>` | Match a tool argument |
| `args.<jsonpath>.<regex>` | `"/regex/i"` syntax |
| `tool_description_matches` | Match against tool description (used by tool-poisoning pack) |
| `content_matches` | Detector hit (e.g., `gitleaks`) |
| `content_score` | Detector score with threshold (e.g., `presidio`, `prompt-guard`) |
| `tool_definition_changed` | Tool def hash differs from last seen |
| `url_host_not_in` | Egress allowlist |

## Actions

| Action | Effect |
|---|---|
| `allow` | Default — pass through |
| `deny` | Return error to LLM, do not invoke tool |
| `redact` | Mask sensitive content before forwarding |
| `rewrite` | Modify args / results |
| `require_human_approval` | Pause and prompt user (HITL) |
| `log_only` | Audit but allow |
| `delay` / `rate_limit` | Token-bucket throttle |
| `quarantine` | Move to review queue |
| `llm_judge` | Send to LLM judge for ruling |

## Examples

See [`examples/custom-rules/policy.yaml`](../examples/custom-rules/policy.yaml).
