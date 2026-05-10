# Dvarapala — Roadmap

Status as of `main`. Each feature ends with a tagged release.

## ✅ Done & shipped (v0.1.0 → v0.1.7)

| Phase | What's live |
|---|---|
| **0** Scaffold | Repo, MIT license, GitHub Actions (test/vet/lint/build × mac+linux+windows), GoReleaser, dependabot |
| **1** stdio passthrough | `dvarapala wrap` parses + audits + forwards every JSON-RPC message both directions |
| **2** Policy engine | Native YAML rule engine, `allow`/`deny`/`log_only`/`redact` actions, deny synthesises a JSON-RPC error |
| **3** gitleaks redaction | Secrets in tool outputs replaced with `[REDACTED:rule-id]` via JSON-aware per-string walk |
| **3.5** Sidecar clients | Presidio (PII/PHI/PCI) + llm-guard (prompt injection) HTTP clients, env-driven, opt-in, degrade gracefully |
| **4** Native MCP detectors | `tool-poisoning` (regex on injection patterns) + `tool-mutation` (cross-restart SHA-256 fingerprints) |
| **5** UX commands | `init`, `doctor`, `scan`, `lint`, `test`, `logs`, `version` |
| **6a** HTTP/SSE proxy | `dvarapala proxy --upstream URL` for hosted MCPs (Atlassian, Sentry, etc.) |
| **6b** Multi-MCP hub | `dvarapala hub --config hub.yaml` — single gateway fronting many MCPs |
| **6c** `--wrap-all` | One-shot protect-everything for Claude Code/Desktop/Cursor/Cline configs |
| **6d** Background daemons | Auto-spawn detached `dvarapala proxy` per HTTP MCP, daemon mgmt verbs (list/stop/remove/clean) |
| **6e** Audit attribution | Every event tagged with the MCP server name; `logs` shows it as a column |
| **Distribution** | brew tap, scoop bucket, ghcr.io multi-arch images, .deb/.rpm/.apk via GitHub Releases, signed checksums + SBOMs |

5/5 attack-corpus cases pass: destructive-001, ipi-001, secrets-exfil-001, tool-poisoning-001, tool-mutation-001.

## 🎯 Next up — bug fixes before UI

UI work is gated on a clean baseline. Fix these first:

- [x] **`dvarapala doctor`** auto-detect stale daemon records (shipped v0.1.9 — fails the check, points at `daemon clean` / `--wrap-all`)
- [x] **Audit log rotation** — shipped in v0.1.8 (50 MiB × 5 keep, configurable via `--audit-max-mb` / `--audit-keep`; follow-mode survives rotation via inode-change detection)
- [x] **Policy hot-reload** — shipped v0.1.10 (mtime polling, atomic engine swap, bad reload keeps previous rules)
- [x] **Configurable redaction string** — shipped v0.1.9 (per-rule `replacement:` field with `{{rule}}` / `{{kind}}` placeholders; empty falls back to legacy `[REDACTED:rule-id]`)
- [ ] **Egress allowlist enforcement** — listed in default rule pack as a scaffold but not actually enforced
- [ ] **Edge case** — HTTP daemons retagged via `--wrap-all` when listen port differs from record

## 🖥 Phase 7 — observability + control

| Feature | What it unlocks | Effort |
|---|---|---|
| **Read-only web UI** | Live event stream, search, filter by server/method/action, full request + response payload viewer, deny/redact stats | ~1 week |
| **Rate limits** | Per-tool, per-rule, per-session caps — runaway tool calls are both cost and DoS risks | ~2 days |
| **Human-approval flow** | Mark sensitive tools as needing user OK before execution; gateway pauses + prompts | ~3 days |
| **OpenTelemetry export** | Spans for every JSON-RPC message → Jaeger / Honeycomb / Datadog | ~1 day |

## 🔍 Detector roadmap

- [ ] **Excessive-agency / chain detection** — flag suspicious tool sequences (read_file → external_post). Novel contribution; pairs with tool-mutation as the second MCP-specific detector.
- [ ] **Tool-call graph analysis** — visualise + alert on chains crossing trust boundaries
- [ ] **Configurable redaction templates** (see bug list)
- [ ] **Egress allowlist enforcement** (see bug list)

## 🧪 Attack corpus expansion

Currently 5 fixtures. Target ~50 for a credible evaluation. Sources:

- [ ] Mine **garak** (NVIDIA) probes — prompt injection, jailbreaks, exfil
- [ ] Mine **PyRIT** (Azure) red-team scenarios
- [ ] Translate published advisories — Invariantlabs MCP injection writeups, Snyk MCP CVEs
- [ ] Per-detector minimums:
  - tool-poisoning: 10+ variants (Unicode tricks, base64 chunks, multi-message split)
  - tool-mutation: 10+ rug-pull patterns (silent description swap, schema widening, tool addition)
  - destructive-actions: 10+ (rm -rf, DROP, dd, mkfs, kubectl delete, gh repo delete)
  - secrets exfil: 10+ (AWS, GitHub, GCP, JWT, private keys, .env content, custom token formats)
  - indirect prompt injection: 10+ (in tool descriptions, tool outputs, resource contents)

## 📦 Distribution gaps

- [ ] **Real `apt install dvarapala`** — needs hosted APT repo (GitHub Pages + reprepro + GPG, or Cloudsmith free tier). Deferred since v0.1.1.
- [ ] **winget + Chocolatey** for Windows (currently only Scoop)
- [ ] **Docker compose stack** — one file bringing up dvarapala + Presidio + llm-guard sidecars together
- [ ] **Helm chart** for Kubernetes hub deployment

## 🔐 Hardening

- [ ] **mTLS for HTTP modes** — proxy / hub currently TLS-on-upstream only
- [ ] **Multi-tenant hub with OIDC**
- [ ] **JSON-RPC parser fuzz tests** — none exist today
- [ ] **Performance benchmarks** — `hyperfine` passthrough vs `dvarapala wrap`, p50/p95/p99 published in docs

## 🛠 UX polish

- [ ] **`dvarapala uninstall --client claude-code`** — undo `--wrap-all`
- [ ] **`dvarapala scan --format sarif`** — for CI integration
- [ ] **`dvarapala policy diff old.yaml new.yaml`** — see what changed
- [x] **Static site at `dvarapala.tharvid.in`** — single-page landing on GitHub Pages, served from repo root via CNAME

## 💤 Stretch

- Policy marketplace (community rule packs)
- Wasm policy modules (write detectors in any language)
- VSCode extension for the audit log

## Won't reinvent

| Concern | Library |
|---|---|
| Secrets | gitleaks (embedded Go lib) |
| PII/PHI/PCI | Microsoft Presidio (sidecar) |
| Prompt injection | ProtectAI llm-guard + Meta Prompt-Guard (sidecar) |
| Policy evaluation | Native YAML (OPA/Cedar would be overkill) |
| MCP protocol | mark3labs/mcp-go for typed messages where useful |
| Red-team corpus | garak + PyRIT scenarios curated into our fixture format |

The novel contribution is the MCP-aware orchestration plus tool-poisoning + tool-mutation, which no off-the-shelf tool covers.
