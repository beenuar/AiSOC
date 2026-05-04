---
sidebar_position: 1
---

# Docker Deployment

AiSOC ships three Compose flavors. Pick the one that matches what you are doing.

| File | Purpose | When to use |
|------|---------|-------------|
| `docker-compose.demo.yml` | Streamlined demo with seeded data | Trying AiSOC for the first time |
| `docker-compose.yml` | Full developer stack | Active development against real source |
| `docker-compose.prod.yml` | Production-leaning stack | Self-hosting on a single VM |

## Streamlined demo

The fastest path is the demo orchestrator. It pulls prebuilt images, runs the full stack, seeds an alert, and prints the URL of the resulting case in under five minutes.

```bash
pnpm aisoc:demo
```

Behind the scenes this runs `docker compose -f docker-compose.demo.yml up -d` against `ghcr.io/beenuar/aisoc-*` images. Stop it with:

```bash
pnpm aisoc:demo:down
```

If GHCR is unreachable on your network the orchestrator transparently falls back to a local build.

## Development

```bash
docker compose up -d
```

This starts the full developer stack:

- `api` (FastAPI) on port `8000`
- `agents` (LangGraph runtime) on port `8001`
- `realtime` (Node + WebSocket + VAPID Web Push) on port `8002`
- `mcp` (Model Context Protocol server) on port `8003`
- `ingest` (Go) on port `8010`
- `enrichment` (Go) on port `8011`
- `web` (Next.js) on port `3000`
- `postgres` on port `5432`
- `nats` on port `4222`
- `opensearch` on port `9200`
- `redis` on port `6379`

## Production

Use the production compose file:

```bash
docker compose -f docker-compose.prod.yml up -d
```

Before going live, walk through the [Hardening Runbook](https://github.com/beenuar/AiSOC/blob/main/docs/runbooks/HARDENING.md) — TLS termination, secret rotation, network policies, and audit log forwarding all need to be in place.

### Environment variables

Copy `.env.example` to `.env` and fill in every required value before starting. See [Environment Variables](./env-vars) for the full reference.

## Building images

```bash
# Build all service images
docker compose build

# Build a single service
docker compose build agents
```

For releases, prebuilt and signed images are published to GHCR:

```
ghcr.io/beenuar/aisoc-api:v5.2.0
ghcr.io/beenuar/aisoc-agents:v5.2.0
ghcr.io/beenuar/aisoc-realtime:v5.2.0
ghcr.io/beenuar/aisoc-mcp:v5.2.0
ghcr.io/beenuar/aisoc-ingest:v5.2.0
ghcr.io/beenuar/aisoc-enrichment:v5.2.0
ghcr.io/beenuar/aisoc-web:v5.2.0
```

Each image is signed with Cosign — verify with `cosign verify --certificate-identity-regexp '^https://github.com/beenuar/AiSOC' --certificate-oidc-issuer https://token.actions.githubusercontent.com <image>`.

## Health checks

```bash
curl http://localhost:8000/healthz
# {"status": "ok", "version": "5.2.0"}
```

Each service exposes the same shape on its own port (`8001`, `8002`, `8003`, `8010`, `8011`).

## Logs

```bash
docker compose logs -f agents
docker compose logs -f api
docker compose logs -f mcp
```
