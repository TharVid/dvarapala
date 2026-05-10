# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.2] — 2026-05-10

### Added

- **`dvarapala install --wrap-all`** — reads the client's existing
  config, wraps every stdio MCP server in one shot, leaves
  already-wrapped entries alone (idempotent), skips HTTP/URL upstreams
  with a note pointing at `dvarapala proxy`. Preserves per-server
  `env` (e.g. `GITHUB_TOKEN`).

  After `brew install dvarapala`, the natural one-liner is:

  ```
  dvarapala install --client claude-code --wrap-all
  ```

  Same flag works for `claude-desktop`, `cursor`, `cline`.

### Docs

- Full overhaul of README, getting-started, architecture, policy
  language, built-in rules, plus new docs/cli-reference.md and
  per-client deployment guides (Claude Code, Claude Desktop, Cursor,
  Cline). Zero broken cross-links.

## [0.1.1] — 2026-05-10

### Added

- **Homebrew tap** at https://github.com/TharVid/homebrew-dvarapala —
  `brew tap tharvid/dvarapala && brew install dvarapala`.
- **Scoop bucket** at https://github.com/TharVid/scoop-dvarapala —
  `scoop bucket add dvarapala https://github.com/TharVid/scoop-dvarapala
  && scoop install dvarapala`.

### Notes

- `apt install dvarapala` deferred to 0.1.2 — needs a hosted APT repo
  (GitHub Pages + reprepro + GPG, or Cloudsmith OSS). Until then,
  download the `.deb` from the v0.1.x release page and `sudo dpkg -i`.
- PyPI + npm SDK publishing intentionally skipped — the SDKs are stubs
  and there's no real consumer yet; squatting on package names with
  non-functional code is bad form.

## [0.1.0] — 2026-05-10

First public release. The full enforcement stack — three transports
(stdio wrap, single-server HTTP proxy, multi-server hub), all sharing
the same policy engine, detector registry, and audit log.

### Added

- **`dvarapala wrap`** — transparent stdio passthrough with parse + audit
  + JSON-RPC deny synthesis.
- **`dvarapala proxy`** — HTTP / Streamable-HTTP / SSE relay for hosted
  MCP servers.
- **`dvarapala hub`** — one gateway fronting many MCP servers (mix of
  stdio and HTTP backends), path-based routing, single audit plane.
- **Policy engine** — native YAML-first rule evaluator (no OPA needed),
  first-match-wins, allow / deny / log_only / redact actions.
- **Detectors** —
  - `gitleaks` (embedded, secrets) — always on.
  - `tool-poisoning` (native, regex on injection patterns) — always on.
  - `tool-mutation` (native, persistent SHA-256 fingerprints) —
    always on, JSONL persistence at `~/.dvarapala/tool-fingerprints.jsonl`.
  - `presidio` (Microsoft, PII/PHI/PCI) — opt-in via
    `DVARAPALA_PRESIDIO_URL`.
  - `llm-guard` (ProtectAI, prompt injection) — opt-in via
    `DVARAPALA_LLMGUARD_URL`.
- **CLI verbs** — `init`, `lint`, `test`, `logs` (colourised + tail
  mode), `install` (auto-edits Claude Code / Desktop / Cursor / Cline
  configs), `doctor`, `scan` (one-shot tool-poisoning audit of any
  MCP), `version`.
- **Default rule packs** — pii, secrets, prompt-injection,
  tool-poisoning, tool-mutation, destructive-actions, egress-allowlist,
  rate-limit (the last two are scaffolds for Phase 7).
- **Attack corpus** — 5 seed scenarios covering destructive shell
  commands, indirect prompt injection, secrets exfiltration, tool
  poisoning, tool rug-pull. 5/5 pass.
- **Docker images** at `ghcr.io/tharvid/dvarapala:0.1.0` (multi-arch
  amd64 + arm64).
- **Linux packages** — `.deb`, `.rpm`, `.apk` for amd64 + arm64.
- **GitHub Releases** — signed checksums (cosign keyless via OIDC),
  CycloneDX SBOMs (syft).

### Notes

- Homebrew tap and Scoop bucket land in 0.1.1 once the tap repos exist.
- Python and TypeScript SDKs are scaffolded but not yet published to
  PyPI / npm — SDK clients land alongside Phase 7 (rate limits,
  human-approval flow, OpenTelemetry).
