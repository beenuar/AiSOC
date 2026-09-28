---
sidebar_position: 1
---

# Docker Deployment

AiSOC ships three Compose flavors. Pick the one that matches what you are doing.

| File | Purpose | When to use |
|------|---------|-------------|
| `infra/compose/docker-compose.demo.yml` | Streamlined demo with seeded data | Trying AiSOC for the first time |
| `docker-compose.yml` | Full developer stack | Active development against real source |
| `docker-compose.prod.yml` | Production stack | Self-hosting on a single VM |

:::warning The development stack has no effective authentication

`docker-compose.yml` defaults `ENVIRONMENT` to `development`, and in a
development-class environment `services/api/app/api/v1/dev_auth.py` resolves a
request that arrives without a bearer token to a demo user whose role is
`admin`. That is deliberate for a laptop and unsafe for anything else.

Use `docker-compose.prod.yml` for anything network-reachable. It fixes
`ENVIRONMENT` to `production` so the bypass cannot be switched back on by
configuration.

:::

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

Behind the scenes this runs `docker compose -f infra/compose/docker-compose.demo.yml up -d`
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
| `litellm` (LLM gateway) | 4000 | 4000 | CORE — resolves every `aisoc-<role>` alias |
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

```bash
make env                                      # generates the six service secrets
docker compose -f docker-compose.prod.yml up -d
```

The production file `include`s `docker-compose.yml` and overrides what
production changes, so there is one definition of every service and the two
cannot drift apart. It differs from the development stack in three ways that
matter:

- **The auth bypass is unreachable.** `ENVIRONMENT` and `AISOC_DEV_MODE` are
  fixed values, not interpolated, so no `.env` can re-enable the demo-admin
  shim described above.
- **Nothing starts on a default credential.** Every secret is declared
  `${VAR:?...}`, so Compose refuses to start and names the variable rather than
  booting on a literal published in this repository and looking healthy.
- **Only the console and the ingest endpoint are reachable.** `web` on `:3000`
  and `ingest-worker` on `:8081`, and nothing else — not the datastores, not
  the internal services, not Prometheus or Grafana. The console proxies every
  upstream server-side, so a browser never needs to reach them; use
  `docker compose exec` if you need one for debugging. `kafka-ui` browses every
  topic with no authentication of its own, so `--profile full` does not start
  it — ask for it by name with `--profile debug-ui`.

CORE is 16 long-running services here, the same as development. `--profile full`
is 21 rather than 22, the difference being `kafka-ui`.

### Required variables

`make env` generates the first six. The rest are yours to choose, and
`docker compose ... config` will name any you miss before anything starts.

| Variable | Generated by `make env` | Used for |
|---|---|---|
| `SECRET_KEY` | yes | Console session signing |
| `AISOC_CREDENTIAL_KEY` | yes | Connector credential vault |
| `AISOC_SERVICE_TOKEN` | yes | Service-to-service calls |
| `AISOC_ACTIONS_SERVICE_TOKEN` | yes | Response actions |
| `AISOC_REALTIME_JWT_SECRET` | yes | Realtime WebSocket/SSE tickets |
| `REALTIME_INTERNAL_TOKEN` | yes | Realtime `/internal/*` fan-out |
| `POSTGRES_PASSWORD` | no | Postgres owner |
| `AISOC_APP_DB_PASSWORD` | no | DML-only runtime role |
| `REDIS_PASSWORD` | no | Redis |
| `JWT_SECRET` | no | Ingest token signing, and SAML/OIDC session issuance in the API |
| `METRICS_TOKEN` | no | Bearer required to scrape `/metrics` outside development |
| `NEO4J_PASSWORD`, `CLICKHOUSE_PASSWORD` | no | `full` profile stores |
| `GRAFANA_ADMIN_PASSWORD` | no | `monitoring` profile dashboard |

All of them are required even if you only run CORE, where the last three are
unused: Compose interpolates the whole file before it decides which profile is
active, so it cannot ask for a variable conditionally. Setting them to any
value is fine if you never enable those profiles — the alternative is Grafana
starting on `admin`/`admin` the day somebody adds `--profile monitoring`.

Put a TLS-terminating reverse proxy in front: the console and ingest bind to
loopback unless you set `AISOC_BIND_ADDR` deliberately.

Before going live, walk through the
[Hardening Runbook](https://github.com/beenuar/AiSOC/blob/main/docs/runbooks/HARDENING.md)
— TLS termination, secret rotation, network policies, audit log forwarding,
and tenant-scoped backups are not things a compose file can do for you.
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
ghcr.io/beenuar/aisoc-core-api:<version>
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
ghcr.io/beenuar/aisoc-ingest:<version>
ghcr.io/beenuar/aisoc-enrichment:<version>
ghcr.io/beenuar/aisoc-web:<version>
```

### Image tags

| Tag | What it is | Who pulls it |
|---|---|---|
| `vX.Y.Z` | A pinned release. | `AISOC_VERSION` in `.env`, the Helm chart |
| `latest` | The newest release. | `docker-compose.yml`, so `make up` |
| `main` | The newest commit on `main`. | Anyone tracking the tip |
| `vX.Y.Z-demo`, `demo` | `aisoc-web` only: the console built for a public demo. | `infra/compose/docker-compose.demo.yml` |

### Upgrading

```bash
git pull
make up
```

`make up` refreshes the images **when the tag they name can move**. Compose's
`pull_policy: missing` is right for a pinned release — `v12.0.0` is immutable,
so once it is local there is nothing to fetch — and wrong for `latest`, which
is republished on every merge. Until this was wired, `git pull && make up` ran
brand-new compose configuration against whatever images the machine already
had, and nothing in the output said so: a stack whose images were pulled at
08:14 UTC stayed on them while `ghcr.io/beenuar/aisoc-web:latest` had been
republished at 15:29 UTC, seven commits later.

What that means in practice:

- **A first run costs nothing extra.** There are no images yet, so the same
  bytes are downloaded either way.
- **A warm run on `latest` spends a few seconds** on manifest checks and then
  runs the code you just pulled.
- **A pinned `AISOC_VERSION` skips it** and says so — there is nothing to
  refresh behind an immutable tag.
- **`AISOC_PULL_POLICY=never` skips it too**, and is also honoured by Compose
  itself, so an air-gapped host never reaches a registry.

`make pull` does the refresh on its own, for fetching now and starting later.

To see what is actually running:

```bash
docker image inspect ghcr.io/beenuar/aisoc-web:latest \
  --format '{{index .Config.Labels "org.opencontainers.image.revision"}}'
```

That is the commit the image was built from. If it does not match the commit
you have checked out, the console is not running your code.

The demo tags exist because the console's demo mode is a **build-time** choice,
not a runtime one: Next.js inlines `NEXT_PUBLIC_*` values into the client
bundle during `next build`, so an image built for a demo cannot be turned back
into a product image by changing an environment variable.

`latest` used to be that demo build, which meant a self-hosted console
announced that its data was demo data, disabled every write control and
offered a link to self-host an install that was already self-hosted, with no
way out short of rebuilding the image. Only `aisoc-web` is affected — the
other services gate demo behaviour at runtime through `AISOC_DEMO_MODE`.

### Image provenance

Each image is signed with [Cosign](https://docs.sigstore.dev/cosign/overview/)
using keyless OIDC signatures issued through GitHub Actions. Verify any
release artifact before deploying it into a sensitive environment:

```bash
cosign verify \
  --certificate-identity-regexp '^https://github.com/beenuar/AiSOC' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/beenuar/aisoc-core-api:<version>
```

The certificate identity is bound to this repository's workflow, so a
successful verification proves the image was produced by the official
release pipeline and has not been tampered with in transit.

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
