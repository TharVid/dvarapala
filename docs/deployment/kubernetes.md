# Kubernetes deployment

Two patterns:

## 1. Sidecar (recommended)

Run Dvarapala in the same pod as the MCP server, fronting it on a different port. Manifest: [examples/kubernetes/dvarapala-sidecar.yaml](../../examples/kubernetes/dvarapala-sidecar.yaml).

## 2. Hub (centralised)

A single Dvarapala Deployment fronts many MCP servers across the cluster. Use a ConfigMap for the hub config, mount the policy as a Secret.

## Helm chart

A Helm chart is on the roadmap. Track [#1](https://github.com/tharvid/dvarapala/issues/1).
