# Architecture

```
┌────────────────────────────┐
│  LLM Client                │
│  (Claude Desktop, Cursor,  │
│   Cline, custom agent)     │
└──────────────┬─────────────┘
               │  stdio / SSE / HTTP (MCP / JSON-RPC 2.0)
               ▼
┌─────────────────────────────────────────────────────┐
│   Dvarapala Gateway                                 │
│ ┌────────────────────────────────────────────────┐  │
│ │ MCP protocol layer (mark3labs/mcp-go)          │  │
│ ├────────────────────────────────────────────────┤  │
│ │ Inbound inspector                              │  │
│ │   • tool-poisoning (native)                    │  │
│ │   • tool-mutation (native, hash chain)         │  │
│ │   • PII / PHI / PCI  → Presidio sidecar        │  │
│ │   • secrets          → gitleaks (embedded)     │  │
│ │   • prompt-injection → llm-guard sidecar       │  │
│ │   • destructive-actions (native)               │  │
│ │   • egress-allowlist (native)                  │  │
│ │   • rate-limit (golang.org/x/time/rate)        │  │
│ ├────────────────────────────────────────────────┤  │
│ │ Policy engine (OPA / Rego — embedded)          │  │
│ ├────────────────────────────────────────────────┤  │
│ │ Outbound inspector  (tool result → LLM)        │  │
│ │   • indirect-prompt-injection (native + judge) │  │
│ │   • PII redaction → Presidio                   │  │
│ │   • secrets redaction → gitleaks               │  │
│ ├────────────────────────────────────────────────┤  │
│ │ Audit log (JSONL, OCSF schema, OTel hooks)     │  │
│ └────────────────────────────────────────────────┘  │
└──────────────────────┬──────────────────────────────┘
                       ▼
┌────────────────────────────┐
│  Real MCP Servers          │
│  (filesystem, github,      │
│   postgres, slack, …)      │
└────────────────────────────┘
```

## Detection responsibility split

| Threat class | Library used | Why |
|---|---|---|
| PII / PHI / PCI | Microsoft Presidio | Industry standard, 50+ recognizers |
| Secrets | gitleaks | 150+ rules, embeddable Go library |
| Prompt injection | llm-guard + Meta Prompt-Guard | Best OSS detectors |
| Policy evaluation | Open Policy Agent (Rego) | Industry standard |
| Tool poisoning | **Dvarapala native** | No existing tool covers this |
| Tool mutation | **Dvarapala native** | No existing tool covers this |
| Destructive actions | **Dvarapala native** | MCP-tool-aware heuristics |
| Egress allowlist | **Dvarapala native** | MCP-aware URL parsing |

## Modes

- **Wrap (stdio)** — single MCP server, drop-in
- **Proxy (HTTP/SSE)** — single hosted MCP server
- **Hub** — many MCP servers behind one Dvarapala
- **Library** — embed via Go / Python / TS SDK

## Why a Go core + Python sidecars

- Go core gives a **single static binary** for `brew/scoop/apt/docker/release-archives` — universal cross-platform distribution.
- gitleaks, mcp-go, OPA all have first-class Go libraries — embed them directly.
- Presidio and llm-guard are Python-native — running them as **sidecars over HTTP** keeps the architecture clean and avoids forcing every Dvarapala user to install Python.
- For minimal installs, the Go core ships with gitleaks-secrets + native MCP detectors. Sidecars are opt-in (Docker Compose, Helm chart).
