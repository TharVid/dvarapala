# Dvarapala — Roadmap

Status as of `main`. Each phase ends with a tagged release once the v0.1.0
pipeline is validated.

## ✅ Done & shipped

| Phase | What's live |
|---|---|
| **0** Scaffold | Repo, MIT license, GitHub Actions (test/vet/lint/build × mac+linux+windows), GoReleaser config, dependabot |
| **1** stdio passthrough | `dvarapala wrap` parses + audits + forwards every JSON-RPC message in both directions |
| **2** Policy engine | Native YAML rule engine, `allow`/`deny`/`log_only` actions, deny synthesises a JSON-RPC error to the client. Commands: `init`, `lint`, `test`, `logs` |
| **3** gitleaks redaction | Secrets detected in tool outputs are replaced with `[REDACTED:rule-id]` via JSON-aware per-string walk so JSON validity is preserved |
| **3.5** Sidecar clients | HTTP clients for Microsoft Presidio (PII/PHI/PCI) and ProtectAI llm-guard (prompt injection). Env-driven, opt-in, degrade gracefully |
| **4** Native MCP detectors | `tool-poisoning` (regex on injection patterns) + `tool-mutation` (SHA-256 fingerprint store with cross-restart JSONL persistence at `~/.dvarapala/tool-fingerprints.jsonl`) |
| **5** UX commands | `dvarapala install` (auto-edits Claude Code / Desktop / Cursor / Cline configs), `dvarapala doctor`, `dvarapala scan` (one-shot tool-poisoning audit of any MCP server) |

5/5 attack-corpus cases pass: destructive-001, ipi-001, secrets-exfil-001, tool-poisoning-001, tool-mutation-001.

## 🔧 Pending

| Phase | What it unlocks |
|---|---|
| **6** HTTP/SSE proxy + multi-MCP hub | `dvarapala proxy --upstream URL` (intercepts hosted MCP servers — Sentry, Atlassian, Slack, etc.), `dvarapala hub --config hub.yaml` (single Dvarapala in front of many MCPs, the enterprise deployment shape) |
| **v0.1.0 release** | First proper tag → GoReleaser publishes binaries to GitHub Releases, multi-arch image to GHCR, formula to a Homebrew tap |
| **Distribution** | After v0.1.0: create `homebrew-dvarapala` tap repo, claim PyPI / npm names, submit to Scoop / winget / Chocolatey |
| **Attack corpus expansion** | Currently 5 fixtures; aim for 200+ (drawing from garak, PyRIT, published advisories) |

## 💤 Stretch (post-Phase 6)

- Read-only web UI (event stream + metrics)
- Policy marketplace (community rule packs)
- Wasm policy modules (write detectors in any language)
- VSCode extension for the audit log
- Multi-tenant hub mode with OIDC
- mTLS for HTTP modes
- Helm chart + production k8s manifests
- `dvarapala.dev` domain + logo

## Won't reinvent

Detection of well-defined classes is delegated to existing OSS — Dvarapala glues them together rather than maintaining its own regex set:

| Concern | Library used |
|---|---|
| Secrets | gitleaks (embedded Go lib) |
| PII/PHI/PCI | Microsoft Presidio (sidecar) |
| Prompt injection | ProtectAI llm-guard + Meta Prompt-Guard (sidecar) |
| Policy evaluation | Native (YAML schema fits our needs; OPA/Cedar would be overkill) |
| MCP protocol | mark3labs/mcp-go for typed messages where useful; stdlib `bufio` for NDJSON |
| Red-team corpus | garak + PyRIT scenarios curated into our fixture format |

The novel contribution is the MCP-aware orchestration plus tool-poisoning + tool-mutation, which no off-the-shelf tool covers.
