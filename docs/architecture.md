# Architecture

Dvarapala has three transports (stdio, single-server HTTP, multi-server hub) sharing one engine, one detector registry, and one audit plane.

## High-level

```
┌────────────────────────────────────────────────────────────┐
│ LLM client                                                 │
│ (Claude Code, Claude Desktop, Cursor, Cline, custom agent) │
└──────────────┬─────────────────────────────────────────────┘
               │ stdio  /  HTTP+SSE  /  Streamable-HTTP
               ▼
┌────────────────────────────────────────────────────────────┐
│  Dvarapala gateway                                         │
│ ┌────────────────────────────────────────────────────────┐ │
│ │ MCP protocol layer (JSON-RPC 2.0)                      │ │
│ ├────────────────────────────────────────────────────────┤ │
│ │ Inbound inspector                                      │ │
│ │   • policy engine (YAML rules → match + action)        │ │
│ │   • content_matches → detector registry                │ │
│ │     ├─ gitleaks (secrets, embedded)                    │ │
│ │     ├─ tool-poisoning (native, regex)                  │ │
│ │     ├─ tool-mutation (native, hash store)              │ │
│ │     ├─ destructive-actions (native)                    │ │
│ │     ├─ Presidio (PII/PHI/PCI, sidecar)                 │ │
│ │     └─ llm-guard (prompt injection, sidecar)           │ │
│ ├────────────────────────────────────────────────────────┤ │
│ │ Action handler                                         │ │
│ │   allow → forward                                      │ │
│ │   deny  → synthesise JSON-RPC error to client          │ │
│ │   redact → walk JSON, replace finding strings          │ │
│ │   log_only → audit, then forward                       │ │
│ ├────────────────────────────────────────────────────────┤ │
│ │ Outbound inspector (server → client)                   │ │
│ │   • same detectors run on responses                    │ │
│ │   • redaction per JSON-string for valid output         │ │
│ ├────────────────────────────────────────────────────────┤ │
│ │ Audit log (JSONL, OCSF-friendly schema)                │ │
│ │   ~/.dvarapala/audit.jsonl                             │ │
│ └────────────────────────────────────────────────────────┘ │
└──────────────┬─────────────────────────────────────────────┘
               ▼
┌────────────────────────────────────────────────────────────┐
│ Real MCP servers                                           │
│ (filesystem, github, postgres, slack, hosted services …)   │
└────────────────────────────────────────────────────────────┘
```

## Three transports

```
wrap          stdio in  ──┐
                          ├─ engine ─→ child process (stdio)
                          
proxy         HTTP in  ───┐
                          ├─ engine ─→ upstream URL  (HTTP/SSE)

hub           HTTP in  ───┐
                          ├─ engine ─→ many backends (mix of stdio + HTTP)
                          │            routed by `/<name>` path
```

| Mode | Use it when | Process model |
|---|---|---|
| `wrap` | One stdio MCP per LLM-client entry. The default for Claude Code/Desktop/Cursor/Cline. | Spawns the child once per client session |
| `proxy` | Single hosted HTTP MCP (Atlassian, Sentry, internal API). | Long-running daemon |
| `hub` | Multiple MCPs behind one gateway. Enterprise / homelab fleet. | Long-running daemon, persistent stdio children plus HTTP upstreams |

All three are described in code under `internal/proxy/` (stdio + http) and `internal/hub/`.

## Detection responsibility

| Threat | Library used | Why this choice |
|---|---|---|
| Secrets | [gitleaks](https://github.com/gitleaks/gitleaks) | 150+ rules, embeds as a Go library, gold standard |
| PII / PHI / PCI | [Microsoft Presidio](https://github.com/microsoft/presidio) | Industry standard; HIPAA, GDPR, PCI-DSS recognisers; 50+ entities |
| Prompt injection | [ProtectAI llm-guard](https://github.com/protectai/llm-guard) + [Meta Prompt-Guard](https://huggingface.co/meta-llama/Prompt-Guard-86M) | Best OSS detector + the strongest open classifier |
| Policy evaluation | Native YAML | Our schema is small enough; OPA/Cedar would be overkill |
| Tool-poisoning | **Dvarapala native** | No off-the-shelf detector covers MCP-specific patterns |
| Tool-mutation / rug-pull | **Dvarapala native** | Stateful fingerprint store — needs MCP awareness |
| Destructive actions | **Dvarapala native** | MCP-tool-aware regex on shell / SQL / fs args |

The native detectors are the novel research contribution; everything else is integration work.

## Why Go core + sidecars

- **Go core** ships as a single static binary on every platform. `brew/scoop/apt/docker/release archives` all work. No runtime needed by the user.
- **gitleaks, mcp-go** are first-class Go libraries — embedded directly. Zero external dependency at runtime.
- **Presidio, llm-guard** are Python-native — running them as **HTTP sidecars** keeps the architecture clean. Most users never need them; the optional opt-in via env var means a vanilla `brew install dvarapala` already gets the always-on detectors.
- For minimum installs, `gitleaks + tool-poisoning + tool-mutation + destructive-actions` are live. Sidecars are opt-in.

## Audit log

Every message in either direction produces one JSONL event:

```json
{
  "ts": "2026-05-10T07:38:32.618838Z",
  "direction": "outbound",
  "kind": "response",
  "method": "tools/call",
  "id": 5,
  "action": "redact",
  "rule": "redact-secrets-in-tool-output",
  "reason": "Secret in tool output redacted (gitleaks)",
  "payload": { ... }
}
```

The `dvarapala logs` command pretty-prints (with colour) or tails (`-f`) this file. `--json` emits raw JSONL for piping into `jq` / SIEM.

## Code layout

```
cmd/dvarapala/        all command verbs (wrap, proxy, hub, init, lint, test, install, scan, doctor, logs, version)
internal/proxy/       stdio + http transport relays + JSON-aware redaction
internal/hub/         multi-MCP aggregator (config, backends, routing)
internal/policy/      YAML rule schema + first-match-wins evaluator
internal/config/      policy loader + embedded rulepack expansion
internal/detectors/   detector interface + per-detector packages
  secrets/              gitleaks adapter
  pii/                  Presidio HTTP client
  promptinjection/      llm-guard HTTP client
  toolpoisoning/        native (regex)
  toolmutation/         native (SHA-256 fingerprints, JSONL persistence)
internal/mcp/         JSON-RPC 2.0 types + NDJSON scanner
internal/audit/       JSONL writer
policies/             YAML rulepacks (embedded into the binary via go:embed)
test/fixtures/        attack-corpus (5 seed scenarios; 5/5 PASS)
sidecars/             Dockerfiles for the optional Python sidecars
```
