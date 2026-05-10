# Policy language

Dvarapala policies are YAML. Each rule has a **match** (predicate), an **action**, and optional metadata. First-match-wins ordering.

## Top-level

```yaml
version: "1"

defaults:
  - rulepack: destructive-actions
  - rulepack: secrets
  - rulepack: tool-poisoning

audit:
  format: jsonl
  path: ~/.dvarapala/audit.jsonl
  schema: ocsf

llm_judge:
  enabled: true
  provider: anthropic       # anthropic | openai | ollama | none
  model: claude-haiku-4-5
  threshold: 0.6

rules:
  - name: my-custom-rule
    match: { ... }
    action: deny
    reason: "..."
```

`defaults[].rulepack` references one of the [built-in rule packs](built-in-rules.md). They expand into the engine's compiled rule list at load time.

## Match conditions

Each non-empty field is an additional `AND` constraint. All listed conditions must hold for the rule to fire.

| Field | Meaning |
|---|---|
| `direction` | `inbound` (client → server) or `outbound` (server → client) |
| `method` | Exact JSON-RPC method (e.g. `tools/list`, `tools/call`) |
| `tool` | Exact tool name (for `tools/call`) |
| `tool_name_matches` | Regex on tool name. `/regex/i` syntax |
| `args.<key>` | Constraint on a single tool argument value (top-level only) |
| `tool_description_matches` | Regex(es) on tool descriptions in `tools/list` responses |
| `content_matches.detector` | Fire if the named detector returns ≥1 finding |
| `content_score.detector` + `threshold` | Fire if any finding's score ≥ threshold |
| `url_host_not_in` | Egress allowlist (Phase 7) |

### Pattern syntax for `tool_name_matches`, `args.*`, `tool_description_matches`

Three forms accepted:

| Form | Example | Meaning |
|---|---|---|
| Slash regex | `"/rm\\s+-rf/"` | Standard regex; `i`/`m`/`s` flags allowed |
| Glob | `"*foo*"` | `*` matches any chars; `?` matches one |
| Literal | `"exact-match"` | Exact string equality |

Any other characters are matched as literal text. Absolute paths like `/etc/*` are correctly handled as globs (not parsed as regex).

### Lists for OR semantics

`args.<key>` and `tool_description_matches` accept either a string (one pattern) or a list (any-of). Example:

```yaml
match:
  tool: shell_exec
  args.command:
    - "/rm\\s+-rf/"
    - "/dd\\s+if=/"
```

## Actions

| Action | Effect | Status |
|---|---|---|
| `allow` | Forward unchanged. Default if no rule matches. | ✅ live |
| `deny` | Block. For requests, synthesise a JSON-RPC `-32000` error to the client. For notifications/responses, drop silently. | ✅ live |
| `redact` | Walk the message JSON, run detectors on each string, replace findings with `[REDACTED:rule-id]`. JSON validity preserved. | ✅ live |
| `log_only` | Audit + forward. Useful for monitoring without enforcement. | ✅ live |
| `rewrite` | Modify args / results. | parsed but not yet enforced |
| `require_human_approval` | Pause and prompt. | parsed but not yet enforced (Phase 7) |
| `delay` / `rate_limit` | Token-bucket throttle. | parsed but not yet enforced (Phase 7) |
| `llm_judge` | Send borderline content to an LLM for adjudication. | parsed but not yet enforced |

Phase 7 plans to wire the remaining actions; until then, the loader accepts them so YAML stays forward-compatible.

## Examples

### Block destructive shell commands

```yaml
- name: block-rm-rf-root
  match:
    tool_name_matches: "/^(shell|exec|bash|sh|terminal)$/"
    args.command:
      - "/rm\\s+-rf\\s+/+/"
      - "/rm\\s+-rf\\s+~\\/?/"
      - "/dd\\s+if=.*\\s+of=\\/dev\\/(sd|nvme|disk)/"
  action: deny
  reason: "destructive shell command"
```

### Redact secrets in any tool output

```yaml
- name: redact-secrets-in-output
  match:
    direction: outbound
    content_matches:
      detector: gitleaks
  action: redact
  reason: "Secret detected in tool output"
```

### Deny SSH-key reads

```yaml
- name: deny-read-ssh-keys
  match:
    tool_name_matches: "/^(read_text_file|read_file|read_multiple_files)$/"
    args.path: "*/.ssh/*"
  action: deny
  reason: "reading SSH keys via MCP is blocked"
```

### Require approval for unbounded SQL DELETE

```yaml
- name: approve-unscoped-delete
  match:
    tool_name_matches: "/(sql|postgres|mysql|sqlite)/i"
    args.query: "/^\\s*DELETE\\s+FROM\\s+\\w+\\s*;?\\s*$/i"
  action: require_human_approval
  reason: "DELETE without WHERE"
```

### Tool-poisoning detection on outbound `tools/list`

```yaml
- name: deny-tool-description-injection
  match:
    direction: outbound
    content_matches:
      detector: tool-poisoning
  action: deny
  reason: "tool description contains prompt-injection pattern"
```

See [`policies/`](../policies/) for the shipped rule-pack YAMLs. Custom rules go alongside `defaults:` in your `~/.dvarapala/policy.yaml`.

## Validation

```bash
dvarapala lint ~/.dvarapala/policy.yaml
# OK: ~/.dvarapala/policy.yaml — N rules across M defaults
```

Compilation errors include the rule name and which match field is malformed.

## Testing rules against attack fixtures

Drop a fixture under `test/fixtures/attack-corpus/<category>/` (see [`schema.json`](../test/fixtures/attack-corpus/schema.json)) and run:

```bash
dvarapala test --policy ~/.dvarapala/policy.yaml --case path/to/case.json
# PASS  case-id  expected=deny got=deny rule=block-rm-rf-root
```
