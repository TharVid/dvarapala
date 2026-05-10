# Deploy on Kubernetes

Two patterns covered: **sidecar** (one Dvarapala per MCP server) and **hub** (one Dvarapala for many MCPs in the cluster).

## Sidecar pattern

Run Dvarapala in the same pod as an MCP server, fronting it on a different port. Manifest example: [`examples/kubernetes/dvarapala-sidecar.yaml`](../../examples/kubernetes/dvarapala-sidecar.yaml).

```yaml
spec:
  containers:
    - name: dvarapala
      image: ghcr.io/tharvid/dvarapala:latest
      args:
        - proxy
        - --policy=/etc/dvarapala/policy.yaml
        - --upstream=http://localhost:7000
        - --listen=0.0.0.0:9000
      ports: [{ containerPort: 9000 }]
      volumeMounts:
        - { name: policy, mountPath: /etc/dvarapala, readOnly: true }
    - name: mcp-server
      image: <your-mcp-image>
      ports: [{ containerPort: 7000 }]
```

Clients in the cluster point at `http://<service>:9000`. Useful when each MCP team ships their own pod and wants gateway enforcement out of the box.

## Hub pattern

One Dvarapala Deployment fronts many MCPs across the cluster. Drop the hub config into a `ConfigMap`, the policy into a `Secret`, and have Dvarapala mount both:

```yaml
apiVersion: v1
kind: ConfigMap
metadata: { name: dvarapala-hub }
data:
  hub.yaml: |
    listen: 0.0.0.0:9000
    servers:
      filesystem:
        command: ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/data"]
      atlassian:
        upstream: "https://mcp.atlassian.com/v1/mcp"
---
apiVersion: v1
kind: Secret
metadata: { name: dvarapala-policy }
stringData:
  policy.yaml: |
    version: "1"
    defaults:
      - rulepack: secrets
      - rulepack: tool-poisoning
      - rulepack: tool-mutation
---
apiVersion: apps/v1
kind: Deployment
metadata: { name: dvarapala-hub }
spec:
  replicas: 1
  selector: { matchLabels: { app: dvarapala-hub } }
  template:
    metadata: { labels: { app: dvarapala-hub } }
    spec:
      containers:
        - name: dvarapala
          image: ghcr.io/tharvid/dvarapala:latest
          args: [hub, --config=/etc/dvarapala/hub.yaml, --policy=/etc/dvarapala/policy.yaml]
          ports: [{ containerPort: 9000 }]
          volumeMounts:
            - { name: hub, mountPath: /etc/dvarapala/hub.yaml, subPath: hub.yaml, readOnly: true }
            - { name: policy, mountPath: /etc/dvarapala/policy.yaml, subPath: policy.yaml, readOnly: true }
      volumes:
        - name: hub
          configMap: { name: dvarapala-hub }
        - name: policy
          secret: { secretName: dvarapala-policy }
---
apiVersion: v1
kind: Service
metadata: { name: dvarapala-hub }
spec:
  selector: { app: dvarapala-hub }
  ports: [{ port: 9000, targetPort: 9000 }]
```

Clients point at `http://dvarapala-hub:9000/<server-name>`.

## Helm chart

A first-party Helm chart ships in v0.2.x. Track [the issue](https://github.com/TharVid/dvarapala/issues) until then.

## Sidecars (Presidio, llm-guard)

Add them as additional Deployments + Services in the same namespace, then set:

```yaml
env:
  - name: DVARAPALA_PRESIDIO_URL
    value: "http://presidio-analyzer:3000"
  - name: DVARAPALA_LLMGUARD_URL
    value: "http://llm-guard:8000"
```

on the Dvarapala container. The detectors degrade gracefully if a sidecar is unreachable (the rule simply doesn't fire).

## Resource expectations

| Container | Request | Limit |
|---|---|---|
| `dvarapala` (proxy / hub) | 50m CPU / 64Mi RAM | 200m CPU / 256Mi RAM |
| `presidio-analyzer` | 200m CPU / 512Mi RAM (model load) | 500m / 1Gi |
| `llm-guard` | 200m CPU / 1Gi RAM | 500m / 2Gi (Prompt-Guard model is ~340MB) |

## See also

- [Architecture](../architecture.md)
- [Docker](docker.md) — same shape, single host
