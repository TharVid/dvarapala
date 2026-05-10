# Docker deployment

## Standalone (core only — no Presidio / llm-guard)

```bash
docker run --rm -i \
  -v ~/.dvarapala/policy.yaml:/etc/dvarapala/policy.yaml:ro \
  ghcr.io/tharvid/dvarapala:latest \
  wrap --policy /etc/dvarapala/policy.yaml -- \
  <your-mcp-server-command>
```

## Full stack (Compose, with Presidio + llm-guard sidecars)

See [examples/docker-compose/docker-compose.yml](../../examples/docker-compose/docker-compose.yml).

```bash
cd examples/docker-compose
docker compose up -d
# Hub now listens on :9000 with PII / secrets / prompt-injection / tool-poisoning enabled.
```
