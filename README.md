# Dvarapala 🛡️

> *द्वारपाल — the gatekeeper.*
> A drop-in security gateway for the Model Context Protocol (MCP).

[![CI](https://github.com/tharvid/dvarapala/actions/workflows/ci.yml/badge.svg)](https://github.com/tharvid/dvarapala/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Dvarapala sits between your LLM client (Claude Desktop, Cursor, Cline, custom agents) and any MCP server. It inspects every JSON-RPC message in both directions, enforces a YAML policy, and blocks / redacts / logs anything that violates the rules — with **zero changes to the underlying MCP server**.

It does **not** reinvent detection. It composes the best open-source security libraries (Presidio, gitleaks, llm-guard, OPA, garak) into a single MCP-aware enforcement layer.

## Why

MCP is the new attack surface. Every Claude Desktop / Cursor user is one malicious tool away from a credential leak, prompt injection, or destructive action. Existing security tooling is not MCP-aware.

Dvarapala addresses MCP-specific threats that no other tool covers today:

- **Tool poisoning** — malicious instructions hidden in tool descriptions
- **Line-jumping** — tool descriptions that hijack the system prompt
- **Tool mutation / rug-pull** — tool definitions changing between sessions
- **Indirect prompt injection** via tool outputs
- **Excessive agency** — agents chaining tools into exfiltration paths
- **PII / PHI / PCI / secrets leakage** through tool calls or results
- **Destructive actions** — `rm -rf`, `DROP TABLE`, etc. on tool args

## Five-second integration

```bash
brew install tharvid/dvarapala/dvarapala
```

In your Claude Desktop config, wrap any MCP server:

```diff
 {
   "mcpServers": {
     "filesystem": {
-      "command": "npx",
-      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/data"]
+      "command": "dvarapala",
+      "args": [
+        "wrap", "--policy", "~/.dvarapala/policy.yaml", "--",
+        "npx", "-y", "@modelcontextprotocol/server-filesystem", "/data"
+      ]
     }
   }
 }
```

That's it. Every tool call is now policy-checked.

## Modes

| Mode | Use case | Command |
|---|---|---|
| **Wrap** | Drop-in stdio wrapper for any MCP server | `dvarapala wrap -- <cmd>` |
| **Proxy** | HTTP/SSE proxy for hosted MCP servers | `dvarapala proxy --upstream URL` |
| **Hub** | Aggregator: many MCP servers behind one Dvarapala | `dvarapala hub --config hub.yaml` |
| **Library** | Embed in your own Go/Python/TS MCP server | import `pkg/dvarapala` or SDK |

## Policy example

```yaml
defaults:
  - rulepack: pii
  - rulepack: secrets
  - rulepack: prompt-injection
  - rulepack: tool-poisoning

rules:
  - name: block-prod-db-writes
    match:
      tool: postgres_query
      args.dsn: "*prod*"
      args.sql: "/INSERT|UPDATE|DELETE/i"
    action: deny

  - name: redact-pii-from-tool-output
    match:
      direction: outbound
      content_matches: pii
    action: redact

  - name: human-approval-for-rm
    match:
      tool: shell_exec
      args.command: "/rm\\s+-rf/"
    action: require_human_approval
```

## What's borrowed (we don't reinvent)

| Concern | Library |
|---|---|
| Secrets detection | [gitleaks](https://github.com/gitleaks/gitleaks) (embedded as Go library) |
| PII / PHI / PCI | [Microsoft Presidio](https://github.com/microsoft/presidio) (sidecar) |
| Prompt injection | [llm-guard](https://github.com/protectai/llm-guard) + [Meta Prompt-Guard](https://huggingface.co/meta-llama/Prompt-Guard-86M) |
| Policy engine | [Open Policy Agent / Rego](https://www.openpolicyagent.org/) |
| MCP protocol | [mark3labs/mcp-go](https://github.com/mark3labs/mcp-go) |
| Schema validation | JSON Schema |
| Red-team corpus | [garak](https://github.com/NVIDIA/garak), [PyRIT](https://github.com/Azure/PyRIT) |
| Release pipeline | [GoReleaser](https://goreleaser.com) |

## What's novel (Dvarapala's contribution)

1. **MCP-specific attack taxonomy and detectors** — tool-poisoning, line-jumping, tool-mutation, IPI-via-tool-outputs, excessive-agency chain detection.
2. **MCP protocol-aware proxy** — stdio / SSE / Streamable-HTTP interception.
3. **Composition layer** — orchestrating Presidio + gitleaks + llm-guard + OPA into a single MCP enforcement plane.
4. **Benchmark dataset** — 200+ curated MCP attack scenarios.

## Distribution

| Channel | Install |
|---|---|
| Homebrew (mac, linux) | `brew install tharvid/dvarapala/dvarapala` |
| Scoop (windows) | `scoop install dvarapala` |
| Chocolatey (windows) | `choco install dvarapala` |
| APT (debian, ubuntu) | `apt install dvarapala` |
| RPM (fedora, rhel) | `dnf install dvarapala` |
| Docker | `docker pull ghcr.io/tharvid/dvarapala` |
| Python SDK | `pip install dvarapala` |
| TypeScript SDK | `npm i @dvarapala/sdk` |
| Go (binary) | `go install github.com/tharvid/dvarapala/cmd/dvarapala@latest` |

## Status

Pre-alpha. Active development. See [TODO.md](TODO.md) for the roadmap.

## License

MIT — see [LICENSE](LICENSE).
