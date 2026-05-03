---
sidebar_position: 1
---

# Docker Deployment

## Development

```bash
docker compose up -d
```

This starts:
- `api` on port 8000
- `agents` on port 8001
- `realtime` on port 8002
- `postgres` on port 5432
- `redis` on port 6379

## Production

Use the production compose file:

```bash
docker compose -f docker-compose.prod.yml up -d
```

### Environment Variables

Copy `.env.example` to `.env` and fill in all required values before starting.

See [Environment Variables](./env-vars) for the full reference.

## Building Images

```bash
# Build all service images
docker compose build

# Build a single service
docker compose build agents
```

## Health Checks

```bash
curl http://localhost:8000/healthz
# {"status": "ok", "version": "4.0.0"}
```

## Logs

```bash
docker compose logs -f agents
docker compose logs -f api
```
