# Dvarapala — Master TODO

> Phased roadmap from scaffold to v1.0. Each phase ends with a tagged release.

## Phase 0 — Scaffold ✅ (this commit)

- [x] Repo layout: cmd / internal / pkg / sdks / examples / docs / packaging / sidecars
- [x] README, LICENSE (MIT), CONTRIBUTING, SECURITY, COC
- [x] Go module + Cobra-style CLI skeleton (no functionality yet)
- [x] GoReleaser config (mac/linux/windows × amd64/arm64)
- [x] GitHub Actions: ci, release, codeql, dependabot
- [x] Dockerfile (distroless) + docker-compose with Presidio + llm-guard sidecars
- [x] Homebrew formula template, Scoop manifest, Chocolatey nuspec, Winget manifest
- [x] Default YAML policy packs (pii, secrets, prompt-injection, tool-poisoning, tool-mutation, destructive-actions, egress-allowlist, rate-limit)
- [x] Python SDK skeleton (pyproject + decorator stub)
- [x] TypeScript SDK skeleton (package.json + wrap stub)
- [x] Examples for Claude Desktop, Cursor, Cline, k8s, custom rules
- [x] Docs: getting-started, architecture, policy-language, built-in-rules, deployment guides
- [x] Attack corpus scaffold + initial scenarios

## Phase 1 — MCP stdio passthrough proxy ✅ (this commit)

`dvarapala wrap -- <cmd>` works end-to-end as a transparent passthrough. Smoke-tested against `@modelcontextprotocol/server-filesystem` returning 14 tools.

- [x] `internal/mcp/jsonrpc.go` — JSON-RPC 2.0 Message + NDJSON Scanner (no third-party MCP lib needed for stdio framing)
- [x] `internal/audit/audit.go` — thread-safe JSONL audit logger
- [x] `internal/proxy/stdio.go` — bidirectional stdio relay with parse + audit + forward
- [x] Graceful shutdown via `cmd.Cancel` (SIGINT) + `cmd.WaitDelay` (5s SIGKILL fallback)
- [x] Unit tests + end-to-end test using the test binary as a fake MCP server
- [x] CLI flag parsing for `--policy`, `--audit`

## Phase 2 — Policy engine + audit log ✅ (this commit)

Native YAML-first policy engine (no OPA — would have been reinventing for our schema; we'll add OPA/CEL if rule complexity ever demands it). Phase 2's `destructive-001` attack-corpus case passes end-to-end.

- [x] `internal/config/loader.go` — YAML schema loader + rulepack expansion via `policies.FS` embed
- [x] `internal/policy/engine.go` — first-match-wins evaluator with regex / glob / exact match
- [x] `policies/embed.go` — embed.FS for default rule packs
- [x] `internal/proxy/stdio.go` — engine wired in: `deny` synthesises a JSON-RPC error to client; `log_only` audits-and-forwards
- [x] `dvarapala init` — writes default `~/.dvarapala/policy.yaml` (with `--with-packs` debug flag)
- [x] `dvarapala lint POLICY` — schema + rule-compile validation
- [x] `dvarapala test POLICY --case ATTACK.json` — runs an attack-corpus case
- [x] `dvarapala logs` — pretty (colourised) / `-f` follow / `-n N` last-N / `--json`
- [ ] OpenTelemetry hooks (deferred — optional)
- [ ] OCSF audit schema mapper (deferred — JSONL is sufficient for v0.2)

## Phase 3 — Detector integrations (v0.3.0)

Wire third-party detectors. **No reinvented detection.**

- [ ] `internal/detectors/secrets/gitleaks.go` — embed [gitleaks](https://github.com/gitleaks/gitleaks) detect API
- [ ] `internal/detectors/pii/presidio.go` — HTTP client for Presidio sidecar
- [ ] `internal/detectors/promptinjection/llmguard.go` — HTTP client for llm-guard sidecar
- [ ] `internal/llmjudge/` — pluggable LLM-as-judge (Anthropic, OpenAI, Ollama)
- [ ] `internal/detectors/destructive/` — native heuristics (regex + AST for shell/SQL)
- [ ] `internal/detectors/egress/` — native URL allowlist
- [ ] `internal/detectors/ratelimit/` — `golang.org/x/time/rate` per-key buckets

## Phase 4 — MCP-specific detectors ✅ (this commit)

Dvarapala's novel research contribution. 5/5 attack-corpus cases now pass end-to-end.

- [x] `internal/detectors/toolpoisoning/` — hand-curated regex set covering `ignore previous instructions`, system-tag injection (`<|im_start|>system`, `<system>`), `you are now…` jailbreaks, DAN-mode, `BEGIN PRIVATE KEY` exfil, "include your api key" credential prompts
- [x] `internal/detectors/toolmutation/` — stateful SHA-256 fingerprint store keyed by tool name, canonical JSON for schema (sorted keys), in-memory per-gateway, ready for JSONL persistence
- [x] Both wired into `wrap.go`'s registry (always on, no env config required — they're in-process and free)
- [x] Rulepacks updated: `policies/tool-poisoning.yaml` and `policies/tool-mutation.yaml` use `content_matches: { detector: ... }`
- [x] New attack fixture `test/fixtures/attack-corpus/tool-mutation/001-rugpull.json` PASSes
- [ ] Excessive-agency chain analysis (graph of tool calls in a session) — deferred
- [ ] Indirect-prompt-injection in tool outputs is now caught by tool-poisoning regexes; richer coverage will land via llm-guard sidecar (Phase 3.5 wired the client; sidecar deployment is a deployment doc, not code)

## Phase 5 — UX & client install (v0.5.0)

- [ ] `dvarapala install --client claude-desktop|cursor|cline --server NAME`
- [ ] `dvarapala doctor` — diagnose PATH, perms, sidecar reachability, MCP config
- [ ] `dvarapala scan <mcp-server>` — one-shot security scan (run a server in a sandbox, list tools, score)
- [ ] Human-approval flow (terminal prompt + file-based approval queue)
- [ ] `dvarapala completion bash|zsh|fish|powershell`

## Phase 6 — Hub + HTTP/SSE proxy (v0.6.0)

- [ ] `dvarapala proxy` — HTTP/SSE in front of remote MCP
- [ ] `dvarapala hub` — many MCP servers behind one Dvarapala
- [ ] Session-aware policy keys
- [ ] mTLS for HTTP mode
- [ ] Streamable HTTP transport (newer MCP)

## Phase 7 — SDK polish (v0.7.0)

- [ ] Python SDK: real `_check` impl (subprocess → Go binary, or HTTP → hub)
- [ ] TypeScript SDK: `wrap()` actually intercepts `@modelcontextprotocol/sdk` Server
- [ ] FastAPI / Express middleware
- [ ] PyPI auto-publish via GH Actions
- [ ] npm auto-publish via GH Actions

## Phase 8 — Attack corpus + benchmark (v0.8.0)

- [ ] Curate 200+ scenarios across all categories (drawing from garak, PyRIT, advisories)
- [ ] `make bench-detection` — detection rate + FPR
- [ ] `make bench-perf` — latency overhead, throughput vs. raw MCP
- [ ] Reproducible benchmark harness (Docker)
- [ ] Public benchmark results page in docs

## Phase 9 — Distribution polish (v0.9.0)

- [ ] Submit Homebrew formula → tap (auto-bump on release works already)
- [ ] Publish to scoop bucket
- [ ] Submit to Chocolatey + Winget
- [ ] AUR PKGBUILD (community-maintained welcomed)
- [ ] Snap / Flatpak (stretch)
- [ ] Helm chart for k8s
- [ ] PyPI + npm releases live
- [ ] Cosign-signed binaries + SBOM verified

## Phase 10 — v1.0

- [ ] All Phase 1–9 boxes ticked
- [ ] HN / Reddit / Twitter launch post
- [ ] Conference talk submission (NDSS workshop, USENIX AI Security, BlackHat Arsenal)
- [ ] Anthropic + Claude Skill integration
- [ ] First external contributor merged

## Stretch / Post-1.0

- [ ] Read-only web UI (events, metrics, blocked-call inspector)
- [ ] Policy marketplace (community rule packs)
- [ ] Wasm policy modules (write detectors in any language)
- [ ] VSCode extension to view audit log
- [ ] SaaS hosted version (commercial)
- [ ] Anthropic / OpenAI plugins
- [ ] Multi-tenant hub mode with OIDC

## Don't forget

- [ ] Logo (dvarapala figure / shield motif) — for README and brew formula
- [ ] `dvarapala.dev` domain (cheap, optional)
- [ ] Discord / Matrix / GitHub Discussions for community
