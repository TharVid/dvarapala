# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.10] — 2026-05-10

### Added

- **Policy hot-reload.** `dvarapala wrap`, `dvarapala proxy`, and
  `dvarapala hub` now watch their `--policy` file and atomically swap
  in fresh rules within ~2 seconds of any save. Previously you had to
  restart the gateway (which meant restarting Claude Code, which meant
  losing context) to pick up a single rule edit.

  Watcher implementation: poll-based mtime+size comparison every 2s
  (no fsnotify dependency, works the same on macOS / Linux / Windows).
  A bad reload — YAML parse error, regex compile error, etc. — is
  printed to stderr but the previously-active rules keep evaluating
  traffic, so a half-saved policy.yaml never breaks the gateway.

  ```
  $ vim ~/.dvarapala/policy.yaml   # add a deny rule
  # In another terminal where dvarapala is running you'll see:
  dvarapala: policy reloaded — 13 rules now active (~/.dvarapala/policy.yaml)
  ```

### Changed

- `policy.Engine` now stores its compiled rules behind an
  `atomic.Pointer`, so `Reload(rules)` is safe to call concurrently
  with in-flight `Evaluate` calls. No lock-on-read on the hot path.

## [0.1.9] — 2026-05-10

### Added

- **`dvarapala doctor` now reports background-daemon health.** Counts
  alive vs stale daemons recorded under `~/.dvarapala/daemons/` and
  fails the check if any daemons are stale (process gone, record
  still on disk), with an inline pointer to `dvarapala daemon clean`
  or `dvarapala install --wrap-all` for recovery.

- **Per-rule redaction template.** Rules can now set a `replacement:`
  field whose value is the string substituted in place of detector
  matches when that rule fires the redact action. Two placeholders
  are recognised:

  ```yaml
  - name: redact-emails-in-tool-output
    match: { content_matches: { detector: presidio } }
    action: redact
    replacement: "<{{kind}}>"      # → <pii>

  - name: redact-secrets-strict
    match: { content_matches: { detector: gitleaks } }
    action: redact
    replacement: "***"             # fixed-string redaction
  ```

  `{{rule}}` expands to the detector's rule id (e.g. `aws-access-token`);
  `{{kind}}` expands to a coarse category (`secret`, `pii`,
  `prompt-injection`, `tool-mutation`, `tool-poisoning`, `match`).
  An empty `replacement` falls back to the legacy
  `[REDACTED:{{rule}}]` shape, so existing policies are untouched.
  Template is plumbed through stdio, HTTP proxy, and hub redactors.

## [0.1.8] — 2026-05-10

### Added

- **Audit log rotation.** `~/.dvarapala/audit.jsonl` no longer grows
  unbounded. Defaults: rotate when the active file passes 50 MiB, keep
  5 rotated copies (`.1`–`.5`) — total disk cap ~300 MiB. On rotation
  the active file is renamed to `<path>.1`, older copies shift down,
  and the file at the keep horizon is dropped.

- **`--audit-max-mb` / `--audit-keep` flags** on `wrap`, `proxy`, and
  `hub` commands. Pass `--audit-max-mb 0` to disable rotation entirely
  (legacy behaviour) or tune both for high-traffic deployments.

### Fixed

- **`dvarapala logs -f` survives a rotation.** Before, when the writer
  rotated the active file mid-tail, the follower kept reading the
  renamed (now-stale) file forever and missed every subsequent event.
  The follow loop now stats the path on each idle tick, detects an
  inode change (or below-offset truncation), and reopens transparently.

## [0.1.7] — 2026-05-10

### Added

- **MCP server name on every audit event.** `audit.Event` now carries a
  `server` field; `dvarapala wrap` and `dvarapala proxy` both take a
  `--server NAME` flag whose value is tagged onto every emitted event.
  `dvarapala logs` renders it as a column so a single shared
  `~/.dvarapala/audit.jsonl` is now per-MCP attributable:

  ```
  12:29:43  deepwiki      →  allow   read_wiki_structure(repoName="facebook/react")
  12:29:44  deepwiki      ←  allow   read_wiki_structure → Available pages for facebook/react: …
  12:30:01  everything    →  allow   echo(message="hi")
  ```

- **`dvarapala install --wrap-all` auto-injects `--server <name>`** for
  every entry, using the MCP key from the client config as the name.
  Existing wrapped entries from v0.1.6 and earlier are retagged
  in-place (the `--` separator is detected and `--server NAME` is
  inserted before it). Existing HTTP-proxy daemons spawned by older
  versions are detected via a new `schema_version` field in their
  daemon record, killed, and re-spawned so their event stream picks up
  the tag too.

### Fixed

- **Dead-code lint failure on the v0.1.6 release commit.**
  `internal/proxy/http.go` had an ineffectual `upPath = "/"` assignment
  that was flagged by `ineffassign` but slipped past local builds.
  Removed.

## [0.1.6] — 2026-05-10

### Changed

- **`dvarapala logs`** rewritten with a human-readable formatter. Old
  output was `request tools/call id=4` / `response - id=4` — useless
  without manual id correlation and zero idea which tool was called.
  New output extracts `(name, arguments)` from `tools/call` requests,
  tracks id → method/tool across the stream, and shows the correlated
  tool name + response excerpt on the matching outbound:

  ```
  09:35:16  →  allow   read_wiki_structure(repoName="facebook/react")
  09:35:17  ←  allow   read_wiki_structure → Available pages for facebook/react: …
  09:35:20  ←  redact  read_file → key=AKIAQYLPMN5HABCDEFGH
                       // Secret in tool output redacted (gitleaks)
                       [redact-secrets-in-tool-output]
  ```

  Counts `tools/list` responses (`← tools/list → 15 tools`). Always
  renders deny / redact actions regardless of filter. Default-hides
  handshake noise (`initialize`, `notifications/*`, `roots/list`,
  `prompts/list`, `resources/list`, `tools/list_changed`,
  `notifications/message`). Hides orphan responses (request scrolled
  out of `-n` window) and blank-display events. Appends
  `// reason  [rule-name]` on redacts/denies so the audit line reads
  like an explanation, not a code dump.

- New flags on `dvarapala logs`:
  - `--all` — show every event including boilerplate
  - `--deny` — show only deny / redact events
  - `--methods M,M` — whitelist (overrides `--all`)
  - `--exclude M,M` — add to the default hide list
  - `--full` — include raw payload alongside formatted line

## [0.1.5] — 2026-05-10

### Fixed

- **HTTP proxy path forwarding** for Streamable HTTP / SSE-then-POST
  shapes. v0.1.3's proxy concatenated the client's request path onto
  the full upstream URL — including the upstream's path. With an
  upstream like `https://mcp.deepwiki.com/mcp` a client `POST /` would
  target `https://mcp.deepwiki.com/mcp/`, and a `POST /messages?sessionId=ABC`
  (advertised via SSE `endpoint` event) would target
  `https://mcp.deepwiki.com/mcp/messages?sessionId=ABC` — both wrong,
  both 404.

  New routing in `httpRelay.upstreamForPOST`:

  ```
  GET /<anything>          → upstream.String()  (SSE/streamable opener)
  POST /                   → upstream.String()  (single-endpoint streamable-HTTP)
  POST /<advertised-path>  → upstream.Scheme + upstream.Host + client_path
                             (the SSE-advertised endpoint)
  ```

  End-to-end verified against the live DeepWiki Streamable HTTP
  endpoint at `https://mcp.deepwiki.com/mcp`.

### Notes

- DeepWiki has deprecated the SSE endpoint at `/sse` in favour of
  Streamable HTTP at `/mcp`. Users with the old `--transport sse` URL
  should re-register:

  ```
  claude mcp remove deepwiki -s user
  claude mcp add    deepwiki --scope user --transport http \
      https://mcp.deepwiki.com/mcp
  dvarapala install --client claude-code --wrap-all
  ```

## [0.1.4] — 2026-05-10

### Fixed

- **`.bak` overwrite bug in `--wrap-all`.** `readConfigForEdit` was
  unconditionally writing `<path>.bak`. After the first run the `.bak`
  captured the user's original config (good); after the second run it
  was overwritten with a config whose URLs already pointed at local
  proxies — the original `https://…` URL was permanently lost and
  rollback became impossible.

  Fix: write `.bak` only when it doesn't exist yet (first-write-wins).
  Also write a per-run snapshot at `<path>.bak.YYYYMMDD-HHMMSS` so
  audit history is preserved without trampling the pristine `.bak`.

- **Stale local URLs are now auto-recovered.** Previously, when
  `--wrap-all` encountered an HTTP entry whose URL was already local
  (e.g. `http://127.0.0.1:18080`) but had **no** matching daemon
  record (because a prior `daemon stop-all` cleared records, or
  because of the `.bak` overwrite bug above), the entry was silently
  skipped — leaving the user with a config pointing at a dead local
  proxy.

  Fix: when the local URL has no daemon record, look in the pristine
  `.bak` for the original upstream and spawn a fresh proxy from there.
  If `.bak` is also stale (pre-fix runs), print a loud `WARNING` with
  explicit recovery instructions.

## [0.1.3] — 2026-05-10

### Added

- **`dvarapala install --wrap-all` now also auto-proxies HTTP MCPs.**
  Detached `dvarapala proxy` daemons spawn for each `url:`-based MCP
  entry, the URL is rewritten to the local proxy listen address, and
  the daemon's PID/upstream/listen are recorded under
  `~/.dvarapala/daemons/<name>.json`. Daemons survive the parent
  shell exit (Setsid on Unix, DETACHED_PROCESS on Windows) and are
  invisible to interactive users.
- **`dvarapala daemon`** subcommand: `list`, `stop NAME`, `stop-all`,
  `remove NAME`, `clean`. Stop keeps the record so `--wrap-all` can
  re-spawn at the same port using the saved upstream after a reboot.

### Fixed

- `daemon list`: PID was reported as `-1` because `cmd.Process.Pid`
  was read after `Release()`. Capture before Release.

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
