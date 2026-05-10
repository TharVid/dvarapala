# Getting started

A 5-minute walkthrough from zero to "Dvarapala is enforcing policy on your live Claude Code".

## Install

Pick one — see [README › Install](../README.md#install) for the full list.

```bash
# macOS / Linux
brew tap tharvid/dvarapala
brew install dvarapala

# Verify
dvarapala version
```

## Scaffold a policy

```bash
dvarapala init
# wrote /Users/<you>/.dvarapala/policy.yaml
```

The default policy enables the `destructive-actions` rulepack so `rm -rf /` and `DROP TABLE` get denied out of the box. Inspect it:

```bash
cat ~/.dvarapala/policy.yaml
```

## Health-check the install

```bash
dvarapala doctor
```

You should see ✓ for: binary on PATH, policy file present, policy parse + compile, audit dir writable. Sidecar checks (Presidio, llm-guard) appear as ○ "skipped — set DVARAPALA_*_URL" — those are optional and add PII / prompt-injection detection ([deploy with Docker](deployment/docker.md)).

## Wire into your MCP client

If you already have MCP servers configured, **wrap them all in one shot**:

```bash
dvarapala install --client claude-code   --wrap-all
dvarapala install --client claude-desktop --wrap-all
dvarapala install --client cursor         --wrap-all
dvarapala install --client cline          --wrap-all
```

`--wrap-all` reads the client's config, finds every stdio MCP server, and rewrites each entry to route through Dvarapala. HTTP-based servers (claude.ai-managed cloud MCPs) are skipped with a note pointing at `dvarapala proxy`. Already-wrapped entries are left alone (idempotent — re-run anytime you add a new server).

If you don't have any MCPs yet, add one fresh:

```bash
dvarapala install \
  --client claude-code \
  --server filesystem \
  --command "npx -y @modelcontextprotocol/server-filesystem ~"
```

The installer backs up the existing config to `<file>.bak` before editing. Restart the client to pick up the change.

## See it work

In one terminal, tail the audit log:

```bash
dvarapala logs -f
```

In your LLM client, ask it to use the wrapped MCP tool. Each JSON-RPC message appears live with `action=allow / deny / redact / log_only` per your policy.

## Try a redaction

Create a file with fake-but-realistic AWS keys (gitleaks ignores `EXAMPLE`-tagged literals; use realistic-shaped values):

```bash
cat > ~/fake-creds.txt <<'EOF'
aws_access_key_id = AKIAQYLPMN5HABCDEFGH
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYabc123def456ghi7
EOF
```

Edit `~/.dvarapala/policy.yaml` and add the `secrets` rulepack:

```yaml
defaults:
  - rulepack: destructive-actions
  - rulepack: secrets   # ← add this
```

Restart your LLM client. Ask it to read `~/fake-creds.txt` via the filesystem MCP. The client receives the file with both keys replaced as `[REDACTED:aws-access-token]` / `[REDACTED:generic-api-key]` — the LLM never sees the originals.

## What to read next

- **[CLI reference](cli-reference.md)** — every command and flag
- **[Architecture](architecture.md)** — how parsing, policy, detectors, and redaction fit together
- **[Policy language](policy-language.md)** — write your own rules
- **[Built-in rule packs](built-in-rules.md)** — what's already covered
- **Per-client deployment guides** — [Claude Code](deployment/claude-code.md), [Claude Desktop](deployment/claude-desktop.md), [Cursor](deployment/cursor.md), [Cline](deployment/cline.md), [Docker](deployment/docker.md), [Kubernetes](deployment/kubernetes.md)
