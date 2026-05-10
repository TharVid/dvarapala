# Dvarapala

> *द्वारपाल — gatekeeper.* Drop-in security gateway for the Model Context Protocol (MCP).

[![CI](https://github.com/TharVid/dvarapala/actions/workflows/ci.yml/badge.svg)](https://github.com/TharVid/dvarapala/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/TharVid/dvarapala?sort=semver)](https://github.com/TharVid/dvarapala/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/ghcr.io-tharvid%2Fdvarapala-blue?logo=docker)](https://github.com/TharVid/dvarapala/pkgs/container/dvarapala)

Dvarapala sits between an LLM client (Claude Code, Claude Desktop, Cursor, Cline, custom agents) and any **third-party MCP server**. It parses every JSON-RPC message in both directions, enforces a YAML policy, and **denies / redacts / logs** anything that violates the rules — with **zero changes to the underlying MCP server**.

It does **not** reinvent detection. It composes battle-tested OSS — gitleaks, Microsoft Presidio, ProtectAI llm-guard, garak — into an MCP-aware enforcement layer.

## What it stops

- **Tool poisoning** — malicious instructions hidden in tool descriptions
- **Tool mutation / rug-pull** — tool definitions silently changing between sessions (cross-restart fingerprints)
- **Indirect prompt injection** through tool outputs
- **Secrets leakage** — AWS keys, GitHub tokens, private keys, JWT, etc. (gitleaks, 150+ rules)
- **PII / PHI / PCI exfiltration** through tool outputs (Presidio sidecar)
- **Destructive actions** — `rm -rf`, `DROP TABLE`, `dd if=…of=/dev/sda` etc.
- **Excessive agency** — tools chained into exfiltration paths

## Install

### macOS / Linux

```bash
brew tap tharvid/dvarapala
brew install dvarapala
```

### Windows

```bash
scoop bucket add dvarapala https://github.com/TharVid/scoop-dvarapala
scoop install dvarapala
```

### Docker

```bash
docker pull ghcr.io/tharvid/dvarapala:latest
```

### Go

```bash
go install github.com/tharvid/dvarapala/cmd/dvarapala@latest
```

### Linux packages (.deb / .rpm / .apk)

Grab the right file from the [latest release](https://github.com/TharVid/dvarapala/releases/latest) and install with `dpkg -i` / `rpm -i` / `apk add --allow-untrusted`. Real `apt install dvarapala` lands in v0.1.2.

## 5-minute first run

```bash
# 1. Scaffold a default policy
dvarapala init

# 2. Health-check
dvarapala doctor

# 3. Wrap every existing MCP server in your Claude Code config in one shot
dvarapala install --client claude-code --wrap-all

# 4. Restart Claude Code, then in another terminal watch traffic
dvarapala logs -f
```

`--wrap-all` reads `~/.claude.json`, finds every MCP server, and:

- For **stdio MCPs** (npx-based, etc.): rewrites the entry to route through `dvarapala wrap` with your policy.
- For **HTTP/SSE MCPs**: spawns a detached `dvarapala proxy` daemon in the background (invisible to you), points the client URL at the local proxy. Manage with `dvarapala daemon list | stop NAME | stop-all`.

Already-wrapped/proxied entries are left alone — the command is idempotent. Run it again whenever you `claude mcp add` a new server.

Same flag works for the other clients:

```bash
dvarapala install --client claude-desktop --wrap-all
dvarapala install --client cursor         --wrap-all
dvarapala install --client cline          --wrap-all
```

You'll see every JSON-RPC message Claude Code sends to the filesystem MCP server flow through the gateway, with `action=allow` / `deny` / `redact` per the policy. Try asking Claude to read a file containing fake AWS keys — the gateway redacts them before the LLM ever sees them.

For deeper walkthroughs see **[docs/getting-started.md](docs/getting-started.md)** and the per-client guides in **[docs/deployment/](docs/deployment/)**.

## Three deployment shapes

| Mode | Use case | Command |
|---|---|---|
| **Wrap** | One stdio MCP per process — drops into Claude Code/Desktop/Cursor/Cline configs | `dvarapala wrap -- npx ... server-filesystem` |
| **Proxy** | One hosted HTTP MCP (Atlassian, Sentry, internal microservice) | `dvarapala proxy --upstream URL` |
| **Hub** | One Dvarapala fronting many MCPs (the enterprise shape) | `dvarapala hub --config hub.yaml` |

All three share the same engine, detectors, audit log, and policy YAML. See **[docs/architecture.md](docs/architecture.md)**.

## Scope

**Dvarapala protects third-party MCP servers** — community npm packages, custom enterprise MCPs, hosted MCP services. These are the wild-west attack surface.

**Dvarapala does not replace the LLM client's own permission system** — Claude Code's built-in `Read`/`Write`/`Bash`/`Edit` are not MCP and are governed by [Anthropic's permission model](https://docs.claude.com/en/docs/claude-code/iam). Use both: client perms for built-in tools, Dvarapala for third-party MCPs. Two layers, both needed.

```
┌─────────────────────────────────────────────────┐
│ LLM Client (Claude Code, Cursor, …)             │
│ ┌──────────────────┐  ┌────────────────────────┐│
│ │ Built-in tools   │  │ Third-party MCPs       ││
│ │ Read, Write, …   │  │ github, postgres, …    ││
│ └────────┬─────────┘  └─────────┬──────────────┘│
│          │                      │                │
│   Anthropic perms        ┌──────▼──────┐         │
│                          │  Dvarapala  │ ← us    │
│                          └──────┬──────┘         │
└────────────────────────────────┬┴─────────────────┘
                                 ▼
                       Real MCP servers
```

## Detectors

Detection of well-defined classes is delegated to the best OSS — Dvarapala glues them together rather than maintaining its own regex set. The MCP-specific detectors are the novel contribution.

| Detector | Source | Status | Detects |
|---|---|---|---|
| **gitleaks** | embedded Go library | always on | secrets (AWS, GitHub, GCP, private keys, JWT, etc.) |
| **tool-poisoning** | Dvarapala native | always on | prompt-injection patterns in tool descriptions |
| **tool-mutation** | Dvarapala native (persistent SHA-256 store) | always on | rug-pull — tool defs changing across sessions |
| **destructive-actions** | Dvarapala native | always on | `rm -rf`, `DROP TABLE`, `dd if=…of=/dev/sd*` |
| **Presidio** | Microsoft, sidecar | opt-in via `DVARAPALA_PRESIDIO_URL` | PII / PHI / PCI (50+ recognizers, HIPAA, GDPR) |
| **llm-guard** | ProtectAI, sidecar | opt-in via `DVARAPALA_LLMGUARD_URL` | indirect prompt injection (ML model + heuristics) |

See **[docs/built-in-rules.md](docs/built-in-rules.md)** for rule packs and **[docs/policy-language.md](docs/policy-language.md)** for the policy schema.

## Commands

| Command | Purpose |
|---|---|
| `dvarapala wrap -- CMD` | Wrap an MCP stdio server with a security policy |
| `dvarapala proxy --upstream URL` | Run as an HTTP/SSE proxy in front of a hosted MCP |
| `dvarapala hub --config FILE` | Run as a multi-MCP aggregator |
| `dvarapala init` | Scaffold `~/.dvarapala/policy.yaml` |
| `dvarapala lint POLICY` | Validate a policy file |
| `dvarapala test --case FILE` | Run an attack-corpus case against a policy |
| `dvarapala scan --command CMD` | One-shot security audit of any MCP server |
| `dvarapala install --client CLIENT --server NAME --command CMD` | Auto-edit MCP-client config |
| `dvarapala doctor` | Diagnose installation, policy, sidecars, configs |
| `dvarapala daemon list \| stop NAME \| stop-all \| remove NAME \| clean` | Manage background HTTP-proxy daemons spawned by `--wrap-all` |
| `dvarapala logs [-f]` | Pretty-print or tail the audit log |
| `dvarapala version` | Print version info |

Full flag reference: **[docs/cli-reference.md](docs/cli-reference.md)**.

## What's borrowed

| Concern | Library |
|---|---|
| Secrets | [gitleaks](https://github.com/gitleaks/gitleaks) |
| PII / PHI / PCI | [Microsoft Presidio](https://github.com/microsoft/presidio) |
| Prompt injection | [ProtectAI llm-guard](https://github.com/protectai/llm-guard) + [Meta Prompt-Guard](https://huggingface.co/meta-llama/Prompt-Guard-86M) |
| MCP protocol | [mark3labs/mcp-go](https://github.com/mark3labs/mcp-go) |
| Red-team corpus | [garak](https://github.com/NVIDIA/garak), [PyRIT](https://github.com/Azure/PyRIT) |
| Release pipeline | [GoReleaser](https://goreleaser.com) |

## Status

- ✅ **v0.1.1** — production-grade detection for Phase 1–6 features
- ✅ **5/5 attack-corpus cases pass** end-to-end (rm -rf, indirect prompt injection, secrets exfil, tool poisoning, tool rug-pull)
- ✅ **CI green** on linux/macOS/windows
- ✅ **Three install paths live**: brew, scoop, docker
- 🚧 v0.1.2: APT repo (real `apt install dvarapala`)
- 🚧 Phase 7: rate limits, human-approval flow, OpenTelemetry, web UI

See [TODO.md](TODO.md) for the full roadmap.

## Documentation

| Doc | What's in it |
|---|---|
| **[Getting started](docs/getting-started.md)** | First-run walkthrough |
| **[Architecture](docs/architecture.md)** | How the engine, detectors, transports fit together |
| **[CLI reference](docs/cli-reference.md)** | Every command, every flag |
| **[Policy language](docs/policy-language.md)** | YAML schema, match conditions, actions |
| **[Built-in rule packs](docs/built-in-rules.md)** | What each rulepack does and why |
| **[Deploy: Claude Code](docs/deployment/claude-code.md)** | Primary use case |
| **[Deploy: Claude Desktop](docs/deployment/claude-desktop.md)** | macOS / Windows app |
| **[Deploy: Cursor](docs/deployment/cursor.md)** | Cursor IDE |
| **[Deploy: Cline](docs/deployment/cline.md)** | VSCode extension |
| **[Deploy: Docker](docs/deployment/docker.md)** | Container + sidecars (Presidio, llm-guard) |
| **[Deploy: Kubernetes](docs/deployment/kubernetes.md)** | Sidecar + hub manifests |

## Contributing

Bug reports, attack-corpus contributions, and rule-pack PRs welcome. See **[CONTRIBUTING.md](CONTRIBUTING.md)** and **[SECURITY.md](SECURITY.md)** for the security disclosure process.

## License

[MIT](LICENSE).

---

Built by [TharVid](https://tharvid.in).
