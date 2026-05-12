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

> If you don't already have Docker installed, the simplest path is the
> [one-click installer](../installation) — it installs Docker (Engine + Compose
> v2 on Linux, Docker Desktop on macOS/Windows), Node, pnpm, and git
> idempotently, then runs the streamlined demo for you.

## Streamlined demo

The fastest path is the demo orchestrator. It pulls prebuilt, signed images,
runs the slim stack, seeds an alert, kicks off an investigation, and prints the
URL of the resulting case in roughly 3-4 minutes on a warm Docker daemon.

```bash
pnpm aisoc:demo
```

Behind the scenes this runs `docker compose -f docker-compose.demo.yml up -d`
against `ghcr.io/beenuar/aisoc-*` images (with `pull_policy: missing`, so
re-runs don't re-pull). Stop it with:

```bash
pnpm aisoc:demo:down
```

If GHCR is unreachable on your network the orchestrator transparently falls
back to a local build of every service.

To uninstall everything later (stack + volumes, optionally images, optionally
node\_modules and the repo clone), use the bundled
[uninstaller](../installation#uninstall).

## Development

```bash
docker compose up -d
```

This starts the full developer stack. Host-side ports are bound to
`127.0.0.1` only by default (i.e. localhost-only) — adjust your reverse proxy
or compose override if you need LAN access.

### Application services

| Service | Host port | Container port | Notes |
|---------|-----------|----------------|-------|
| `api` (FastAPI Core API) | 8000 | 8000 | OpenAPI at `/docs` |
| `agents` (LangGraph investigator) | 8001 | 8084 | |
| `actions` (SOAR executor) | 8002 | 8085 | |
| `fusion` (alert fusion + ML) | 8003 | 8003 | |
| `threatintel` | 8005 | 8005 | |
| `purple-team` (adversary emulation) | 8006 | 8006 | |
| `ueba` (user behavior analytics) | 8007 | 8004 | |
| `honeytokens` (deception platform) | 8008 | 8005 | |
| `slack-bot` (ChatOps) | 8009 | 8089 | `profiles: [slack]` |
| `ingest-worker` (Go OCSF normaliser) | 8081 / 9090 | 8080 / 9090 | HTTP + Prometheus metrics |
| `enrichment` (Go enrichment fan-out) | 8080 | 8082 | |
| `realtime` (Node WS + Web Push) | 8086 | 4000 | |
| `connectors` (50-vendor poller) | 8088 | 8003 | `profiles: [connectors]` |
| `osquery-tls` (host telemetry server) | 8091 | 8007 | `profiles: [osquery]` |
| `web` (Next.js console + Responder PWA) | 3000 | 3000 | |

`mcp` (the Model Context Protocol stdio server) runs without a port — it is
launched on demand by IDE-side agents (Claude Code, Cursor, Continue, Cody)
over stdio.

### Profile-gated services

`connectors`, `osquery-tls`, and `slack-bot` live behind Docker Compose
profiles so the default dev stack stays light. Enable them with:

```bash
COMPOSE_PROFILES=connectors,osquery,slack docker compose up -d
```

### Data-plane services

| Service | Host port | Notes |
|---------|-----------|-------|
| `postgres` | 5432 | Cases, alerts, RBAC, vault |
| `redis` | 6379 | Sessions, rate limiting, agent cache |
| `kafka` | 9092 | Event spine |
| `kafka-ui` | 8090 | Web UI for the Kafka cluster |
| `clickhouse` | 8123 / 9000 | Analytical telemetry store |
| `opensearch` | 9200 | Full-text + log search |
| `qdrant` | 6333 | Vector store (RAG over runbooks + ATT&CK) |
| `neo4j` | 7474 / 7687 | Investigation graph |
| `prometheus` | 9091 | Metrics scraper |
| `grafana` | 3001 | Pre-wired dashboards (`admin` / `admin`) |

## Production

Use the production compose file:

```bash
docker compose -f docker-compose.prod.yml up -d
```

Before going live, walk through the
[Hardening Runbook](https://github.com/beenuar/AiSOC/blob/main/docs/runbooks/HARDENING.md)
— TLS termination, secret rotation, network policies, audit log forwarding,
and tenant-scoped backups all need to be in place.

### Environment variables

Copy `.env.example` to `.env` and fill in every required value before starting.
See [Environment Variables](./env-vars) for the full reference.

## Building images

```bash
# Build all service images
docker compose build

# Build a single service
docker compose build agents
```

For releases, prebuilt and signed images are published to GHCR:

```
ghcr.io/beenuar/aisoc-api:<version>
ghcr.io/beenuar/aisoc-agents:<version>
ghcr.io/beenuar/aisoc-actions:<version>
ghcr.io/beenuar/aisoc-fusion:<version>
ghcr.io/beenuar/aisoc-threatintel:<version>
ghcr.io/beenuar/aisoc-ueba:<version>
ghcr.io/beenuar/aisoc-honeytokens:<version>
ghcr.io/beenuar/aisoc-purple-team:<version>
ghcr.io/beenuar/aisoc-connectors:<version>
ghcr.io/beenuar/aisoc-osquery-tls:<version>
ghcr.io/beenuar/aisoc-slack-bot:<version>
ghcr.io/beenuar/aisoc-realtime:<version>
ghcr.io/beenuar/aisoc-mcp:<version>
ghcr.io/beenuar/aisoc-ingest:<version>
ghcr.io/beenuar/aisoc-enrichment:<version>
ghcr.io/beenuar/aisoc-web:<version>
```

Each image is signed with Cosign — verify with:

```bash
cosign verify \
  --certificate-identity-regexp '^https://github.com/beenuar/AiSOC' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/beenuar/aisoc-api:<version>
```

## Health checks

Every service exposes the same `GET /healthz` shape:

```bash
curl http://localhost:8000/healthz
# {"status": "ok", "version": "<version>"}
```

A quick "is everything up" sweep across the application tier:

```bash
for port in 8000 8001 8002 8003 8005 8006 8007 8008 8081 8080 8086; do
  printf "%-5s " "$port"
  curl -fsS "http://localhost:${port}/healthz" || echo "FAIL"
done
```

## Logs

```bash
docker compose logs -f agents
docker compose logs -f api
docker compose logs -f realtime
docker compose logs -f ingest-worker
```

## Reference

The canonical service inventory is in
[`docker-compose.yml`](https://github.com/beenuar/AiSOC/blob/main/docker-compose.yml).
The deeper architectural picture — what each service owns, how the data plane
fits together, and where ITSM / Slack / osquery bolt in — lives in
[Architecture](../architecture) and the
[System Design doc](https://github.com/beenuar/AiSOC/blob/main/docs/architecture/SYSTEM_DESIGN.md).
