# CLI reference

Every Dvarapala verb, every flag.

## `dvarapala wrap`

Wrap a stdio MCP server. Apply policy to every JSON-RPC message in either direction; deny synthesises an error response to the client; redact replaces detector findings inline.

```bash
dvarapala wrap [flags] -- <command> [args...]
```

| Flag | Default | Purpose |
|---|---|---|
| `--policy PATH` | (empty = transparent passthrough) | Policy YAML to enforce |
| `--audit PATH` | `~/.dvarapala/audit.jsonl` | Audit log path |

```bash
dvarapala wrap --policy ~/.dvarapala/policy.yaml -- \
  npx -y @modelcontextprotocol/server-filesystem ~/code
```

## `dvarapala proxy`

Run as an HTTP / Streamable-HTTP / SSE proxy in front of a single hosted MCP server.

```bash
dvarapala proxy --upstream URL [flags]
```

| Flag | Default | Purpose |
|---|---|---|
| `--upstream URL` | (required) | Upstream MCP HTTP URL |
| `--listen ADDR` | `127.0.0.1:8080` | Local bind address |
| `--policy PATH` | (empty = transparent) | Policy YAML |
| `--audit PATH` | `~/.dvarapala/audit.jsonl` | Audit log path |

```bash
dvarapala proxy \
  --upstream https://mcp.atlassian.com/v1/mcp \
  --listen 127.0.0.1:8081 \
  --policy ~/.dvarapala/policy.yaml
```

## `dvarapala hub`

Run as a multi-MCP aggregator. One Dvarapala fronts many MCPs, mix of stdio and HTTP backends, routed by URL path.

```bash
dvarapala hub --config FILE [flags]
```

| Flag | Default | Purpose |
|---|---|---|
| `--config PATH` | (required) | hub.yaml path |
| `--policy PATH` | from hub.yaml or empty | Override policy YAML |
| `--listen ADDR` | from hub.yaml or `127.0.0.1:9000` | Override listen address |
| `--audit PATH` | `~/.dvarapala/audit.jsonl` | Audit log path |

Example `hub.yaml` lives at [`examples/hub/hub.yaml`](../examples/hub/hub.yaml). Each entry is either `command:` (stdio) or `upstream:` (HTTP).

```bash
dvarapala hub --config ~/.dvarapala/hub.yaml
```

`GET /` on the listener returns a JSON directory of registered servers. `POST /<name>` routes to backend `<name>`.

## `dvarapala init`

Scaffold a default `~/.dvarapala/policy.yaml`.

```bash
dvarapala init [flags]
```

| Flag | Default | Purpose |
|---|---|---|
| `--policy PATH` | `~/.dvarapala/policy.yaml` | Where to write |
| `--force` | false | Overwrite existing |
| `--with-packs` | false | Also write embedded rule packs alongside (debug) |

## `dvarapala lint`

Validate a policy file (parse + compile). Exits 0 on success.

```bash
dvarapala lint POLICY
```

## `dvarapala test`

Run an attack-corpus case against a policy.

```bash
dvarapala test --policy POLICY --case CASE.json
```

| Flag | Default | Purpose |
|---|---|---|
| `--policy PATH` | `~/.dvarapala/policy.yaml` | Policy YAML |
| `--case PATH` | (required) | Attack-corpus JSON case |

Exit 0 = PASS (matched expected action), 1 = FAIL.

```bash
dvarapala test \
  --policy ~/.dvarapala/policy.yaml \
  --case test/fixtures/attack-corpus/destructive-actions/001-rm-rf-root.json
```

## `dvarapala scan`

One-shot security audit of any MCP stdio server. Spawns it, lists tools, runs the native `tool-poisoning` detector against every tool description.

```bash
dvarapala scan --command "CMD ARGS..."
```

| Flag | Default | Purpose |
|---|---|---|
| `--command STR` | (required) | The MCP server command |
| `--json` | false | Emit findings as JSON (one per line) |

Exit 0 = clean, 1 = ≥1 finding.

```bash
dvarapala scan --command "npx -y @some-org/maybe-evil-mcp"
```

## `dvarapala install`

Auto-edit an MCP-client config to wrap an upstream server with `dvarapala wrap`.

```bash
dvarapala install --client CLIENT --server NAME --command "CMD ARGS..."
```

| Flag | Default | Purpose |
|---|---|---|
| `--client` | `claude-code` | One of `claude-code` / `claude-desktop` / `cursor` / `cline` |
| `--server NAME` | (required) | Name to register |
| `--command STR` | (required) | Upstream MCP command |
| `--policy PATH` | `~/.dvarapala/policy.yaml` | Policy YAML to apply |
| `--binary PATH` | this dvarapala | Dvarapala binary path |

Backs the existing config up to `<file>.bak` before editing. Idempotent — re-running with same name updates the entry.

## `dvarapala doctor`

Single-screen health check. Prints binary version, Go runtime, policy parse, audit dir writability, sidecar reachability, and a one-line summary per MCP-client config (claude-code, claude-desktop, cursor, cline).

```bash
dvarapala doctor
```

`✓` = passing required check, `○` = optional check skipped, `✗` = failure.

## `dvarapala logs`

Pretty-print or tail the audit log.

```bash
dvarapala logs [flags]
```

| Flag | Default | Purpose |
|---|---|---|
| `--audit PATH` | `~/.dvarapala/audit.jsonl` | File to read |
| `-f`, `--follow` | false | tail -f mode |
| `-n N` | 0 (all) | Show only the last N events |
| `--json` | false | Emit raw JSONL (for piping into jq) |
| `--no-color` | false | Disable colour even on a TTY |

Honours `NO_COLOR=1`.

```bash
dvarapala logs -n 20         # last 20 events, formatted
dvarapala logs -f            # tail follow
dvarapala logs --json | jq . # raw events into jq
```

## `dvarapala version`

Print version, commit, build date.

## Environment variables

| Var | Used by | Effect |
|---|---|---|
| `DVARAPALA_PRESIDIO_URL` | wrap, proxy, hub, test | Enables Presidio PII/PHI/PCI detector |
| `DVARAPALA_LLMGUARD_URL` | wrap, proxy, hub, test | Enables llm-guard prompt-injection detector |
| `NO_COLOR` | logs, doctor | Disable ANSI colour |
