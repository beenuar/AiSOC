---
sidebar_position: 2
---

# Kubernetes Deployment

The supported way to run AiSOC on Kubernetes is the Helm chart shipped at [`infra/helm/aisoc/`](https://github.com/beenuar/AiSOC/tree/main/infra/helm/aisoc) in the repo. It deploys every service (api, agents, realtime, mcp, ingest, enrichment, web) plus optional bundled Postgres, Redis, NATS, and OpenSearch via subcharts.

## Helm chart (in-repo)

```bash
git clone https://github.com/beenuar/AiSOC.git
cd AiSOC

helm dependency update infra/helm/aisoc

helm install aisoc infra/helm/aisoc \
  --namespace aisoc --create-namespace \
  --set api.image.tag=v5.2.0 \
  --set agents.image.tag=v5.2.0 \
  --set realtime.image.tag=v5.2.0 \
  --set mcp.image.tag=v5.2.0 \
  --set web.image.tag=v5.2.0 \
  --set secrets.openai.apiKey=sk-... \
  --set postgresql.auth.password=changeme
```

Override any of the defaults in [`infra/helm/aisoc/values.yaml`](https://github.com/beenuar/AiSOC/blob/main/infra/helm/aisoc/values.yaml). For production deployments, walk through the [Hardening Runbook](https://github.com/beenuar/AiSOC/blob/main/docs/runbooks/HARDENING.md) before exposing the platform on the public internet.

## Container images

All images are published to GHCR and Cosign-signed:

```
ghcr.io/beenuar/aisoc-api:v5.2.0
ghcr.io/beenuar/aisoc-agents:v5.2.0
ghcr.io/beenuar/aisoc-realtime:v5.2.0
ghcr.io/beenuar/aisoc-mcp:v5.2.0
ghcr.io/beenuar/aisoc-ingest:v5.2.0
ghcr.io/beenuar/aisoc-enrichment:v5.2.0
ghcr.io/beenuar/aisoc-web:v5.2.0
```

Verify a signature before deploying:

```bash
cosign verify \
  --certificate-identity-regexp '^https://github.com/beenuar/AiSOC' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/beenuar/aisoc-api:v5.2.0
```

## Scaling

```bash
kubectl scale deployment aisoc-agents --replicas=3 -n aisoc
kubectl scale deployment aisoc-api --replicas=2 -n aisoc
kubectl scale deployment aisoc-mcp --replicas=2 -n aisoc
```

Horizontal Pod Autoscaler manifests are included in the chart — enable them with `--set api.autoscaling.enabled=true` (and similarly for `agents`, `realtime`, `mcp`).

## Ingress

The chart ships an Ingress template. Configure your hostnames via values:

```yaml
ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
  hosts:
    - host: aisoc.example.com         # web (Next.js, port 3000)
      paths: [ "/" ]
    - host: api.aisoc.example.com     # api (FastAPI, port 8000)
      paths: [ "/api", "/healthz" ]
    - host: ws.aisoc.example.com      # realtime (WebSocket + push, port 8002)
      paths: [ "/ws" ]
    - host: mcp.aisoc.example.com     # MCP server (port 8003) — optional
      paths: [ "/mcp" ]
  tls:
    - secretName: aisoc-tls
      hosts:
        - aisoc.example.com
        - api.aisoc.example.com
        - ws.aisoc.example.com
        - mcp.aisoc.example.com
```

## Network policies

The chart includes opinionated `NetworkPolicy` resources that restrict each service to only the dependencies it needs (for example, `agents` can reach Postgres, NATS, and OpenSearch but not the public internet). Enable them with `--set networkPolicies.enabled=true`. They are off by default to keep first-time installs frictionless, and on for any environment that holds real telemetry.
