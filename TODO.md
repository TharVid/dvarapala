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

## Phase 1 — MCP stdio passthrough proxy (v0.1.0)

Goal: `dvarapala wrap -- <cmd>` works as a transparent passthrough — no policy yet, just proves the wire.

- [ ] Integrate `github.com/mark3labs/mcp-go` for protocol parsing
- [ ] `internal/proxy/stdio.go` — bidirectional stdio relay with JSON-RPC parsing
- [ ] `internal/mcp/jsonrpc.go` — typed messages
- [ ] Graceful shutdown: SIGTERM/SIGINT, close upstream cleanly
- [ ] Unit tests for stdio multiplex
- [ ] E2E: wrap `@modelcontextprotocol/server-filesystem`, run a real `tools/list` from a fake client

## Phase 2 — Policy engine + audit log (v0.2.0)

- [ ] `internal/config/policy.go` — YAML schema + loader
- [ ] `internal/policy/engine.go` — embed [Open Policy Agent](https://github.com/open-policy-agent/opa) Go SDK; compile YAML rules to Rego
- [ ] `internal/audit` — JSONL writer + OCSF mapper
- [ ] OpenTelemetry hooks (traces + metrics)
- [ ] `dvarapala lint POLICY` — schema validation
- [ ] `dvarapala test POLICY --case ATTACK.json` — run a corpus case
- [ ] `dvarapala init` — write default policy.yaml

## Phase 3 — Detector integrations (v0.3.0)

Wire third-party detectors. **No reinvented detection.**

- [ ] `internal/detectors/secrets/gitleaks.go` — embed [gitleaks](https://github.com/gitleaks/gitleaks) detect API
- [ ] `internal/detectors/pii/presidio.go` — HTTP client for Presidio sidecar
- [ ] `internal/detectors/promptinjection/llmguard.go` — HTTP client for llm-guard sidecar
- [ ] `internal/llmjudge/` — pluggable LLM-as-judge (Anthropic, OpenAI, Ollama)
- [ ] `internal/detectors/destructive/` — native heuristics (regex + AST for shell/SQL)
- [ ] `internal/detectors/egress/` — native URL allowlist
- [ ] `internal/detectors/ratelimit/` — `golang.org/x/time/rate` per-key buckets

## Phase 4 — MCP-specific detectors (v0.4.0)

Dvarapala's novel research contribution.

- [ ] `internal/detectors/toolpoisoning/` — tool-description analysis (heuristics + Prompt-Guard)
- [ ] `internal/detectors/toolmutation/` — content-addressable tool-def store, mutation detection
- [ ] Excessive-agency chain analysis (graph of tool calls in a session)
- [ ] Indirect-prompt-injection in tool outputs (delegated to llm-guard + judge)

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

## Thesis tie-in

- [ ] Phase 1–4: implementation chapters
- [ ] Phase 8: evaluation chapter (detection rate, FPR, latency)
- [ ] Threat taxonomy: separate chapter (Phase 0 already drafted in `docs/architecture.md`)
- [ ] BTU proposal: `docs/thesis/proposal.md` (Phase 1 deliverable)

## Don't forget

- [ ] Logo (dvarapala figure / shield motif) — for README and brew formula
- [ ] `dvarapala.dev` domain (cheap, optional)
- [ ] Discord / Matrix / GitHub Discussions for community
