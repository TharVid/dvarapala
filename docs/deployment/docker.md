# Deploy with Docker

Pre-built multi-arch image at `ghcr.io/tharvid/dvarapala`. Tags follow [semver](https://semver.org/) (`latest`, `0.1.1`, `0.1.0`, …).

## Quick run

```bash
docker run --rm ghcr.io/tharvid/dvarapala:latest version
```

## Wrap an MCP via Docker

`dvarapala wrap` can run inside a container fronting an MCP server that's also containerised:

```bash
docker run --rm -i \
  -v ~/.dvarapala/policy.yaml:/etc/dvarapala/policy.yaml:ro \
  -v ~/.dvarapala:/audit \
  ghcr.io/tharvid/dvarapala:latest \
  wrap --policy /etc/dvarapala/policy.yaml \
       --audit /audit/audit.jsonl \
       -- <upstream-mcp-command>
```

For the simple stdio case it's usually easier to install dvarapala on the host (`brew install` / `scoop install`) and let Claude Code spawn it directly.

## Hub mode + sidecars

The hub deployment is the most natural fit for Docker. Spin up Dvarapala alongside Microsoft Presidio (PII) and llm-guard (prompt injection) sidecars with one compose file. See [`examples/docker-compose/docker-compose.yml`](../../examples/docker-compose/docker-compose.yml):

```yaml
services:
  dvarapala:
    image: ghcr.io/tharvid/dvarapala:latest
    command: ["hub", "--config", "/etc/dvarapala/hub.yaml"]
    ports:
      - "9000:9000"
    volumes:
      - ./hub.yaml:/etc/dvarapala/hub.yaml:ro
      - ./policy.yaml:/etc/dvarapala/policy.yaml:ro
    environment:
      DVARAPALA_PRESIDIO_URL: http://presidio-analyzer:3000
      DVARAPALA_LLMGUARD_URL: http://llm-guard:8000

  presidio-analyzer:
    image: mcr.microsoft.com/presidio-analyzer:latest
    ports: ["3000:3000"]

  llm-guard:
    build: ../../sidecars/llm-guard
    ports: ["8000:8000"]
```

Run:

```bash
cd examples/docker-compose
docker compose up -d
dvarapala doctor   # sidecars now show ✓ instead of ○
```

Clients then point at `http://127.0.0.1:9000/<server-name>` for any of the MCPs declared in `hub.yaml` ([example](../../examples/hub/hub.yaml)).

## Image details

| Tag | Built from | Size |
|---|---|---|
| `:latest` | distroless `static-debian12:nonroot` | ~10 MB |
| `:0.1.1` | same, version-pinned | same |
| `:0.1.1-amd64`, `:0.1.1-arm64` | per-arch (the manifest list above resolves to these) | same |

Runs as `nonroot` user. No shell, no package manager, no extras.

## See also

- [Architecture](../architecture.md) — three transport modes
- [Kubernetes](kubernetes.md) — sidecar + hub manifests
