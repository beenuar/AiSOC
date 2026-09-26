---
sidebar_position: 2
---

# Kubernetes Deployment

The supported way to run AiSOC on Kubernetes is the Helm chart shipped at [`infra/helm/aisoc/`](https://github.com/beenuar/AiSOC/tree/main/infra/helm/aisoc) in the repo. It deploys every service (api, agents, realtime, mcp, ingest, enrichment, web) plus optional bundled Postgres, Redis, NATS, and OpenSearch via subcharts.

## Helm chart (in-repo)

```bash
git clone https://github.com/beenuar/AiSOC.git
cd AiSOC

# The chart depends on the Bitnami postgresql and redis charts. A clean
# machine has no repository definitions, so `helm dependency update` fails
# with "no repository definition for https://charts.bitnami.com/bitnami"
# before it starts. This line was missing, which meant the documented
# Kubernetes path failed at its first command.
helm repo add bitnami https://charts.bitnami.com/bitnami
helm repo update

helm dependency update infra/helm/aisoc

helm install aisoc infra/helm/aisoc \
  --namespace aisoc --create-namespace \
  --set secrets.openai.apiKey=sk-... \
  --set postgresql.auth.password=changeme
```

The image tags come from the chart's `appVersion`, so there is nothing to
override for a working install. To pin a different release, note that every
service lives under `services.<name>` — `--set api.image.tag=...` addresses a
path no template reads and silently changes nothing:

```bash
  --set services.api.image.tag=v11.0.0 \
  --set services.web.image.tag=v11.0.0
```

Override any of the defaults in [`infra/helm/aisoc/values.yaml`](https://github.com/beenuar/AiSOC/blob/main/infra/helm/aisoc/values.yaml). For production deployments, walk through the [Hardening Runbook](https://github.com/beenuar/AiSOC/blob/main/docs/runbooks/HARDENING.md) before exposing the platform on the public internet.

## Container images

All images are published to GHCR and Cosign-signed:

```
ghcr.io/beenuar/aisoc-core-api:v11.0.0
ghcr.io/beenuar/aisoc-agents:v11.0.0
ghcr.io/beenuar/aisoc-realtime:v11.0.0
ghcr.io/beenuar/aisoc-ingest:v11.0.0
ghcr.io/beenuar/aisoc-enrichment:v11.0.0
ghcr.io/beenuar/aisoc-web:v11.0.0
```

`scripts/check_published_images.py` resolves every one of these against GHCR
daily, so a name or tag that stops existing fails a build rather than a
`helm install`. This list read `v5.2.0` until v11.1.0 — a tag no image has
ever carried — and two of the names, `aisoc-api` and `aisoc-mcp`, have never
been published at all. The API image is `aisoc-core-api`; the MCP server ships
inside it rather than as its own image.

Verify a signature before deploying:

```bash
cosign verify \
  --certificate-identity-regexp '^https://github.com/beenuar/AiSOC' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/beenuar/aisoc-core-api:v11.0.0
```

## Scaling

The chart deploys `api`, `ingest`, `enrichment`, `alert-fusion`, `agents`,
`web` and `realtime`; `ueba`, `honeytokens` and `purpleTeam` are off by
default. There is no `mcp` deployment — the MCP server runs inside the API.

```bash
kubectl scale deployment aisoc-agents --replicas=3 -n aisoc
kubectl scale deployment aisoc-api --replicas=2 -n aisoc
```

Horizontal Pod Autoscaler manifests are included in the chart — enable them
with `--set services.api.autoscaling.enabled=true` (and similarly for
`agents`, `realtime`). As above, the `services.` prefix is load-bearing.

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
