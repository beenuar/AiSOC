---
sidebar_position: 2
---

# Quick Start

Get AiSOC running locally in under 5 minutes.

## Prerequisites

| Tool | Minimum version |
|------|-----------------|
| Docker & Docker Compose | v2.x |
| Node.js | ≥ 18 |
| pnpm | ≥ 9 |
| Python | 3.11+ |

## 1. Clone the Repository

```bash
git clone https://github.com/beenuar/aisoc.git
cd aisoc
```

## 2. Install Frontend Dependencies

```bash
pnpm install
```

## 3. Configure Environment

```bash
cp .env.example .env
```

Open `.env` and fill in the required values:

```bash
# AI providers (at least one required)
OPENAI_API_KEY=sk-...
# or ANTHROPIC_API_KEY=sk-ant-...

# Database (auto-created by Docker Compose)
DATABASE_URL=postgresql+asyncpg://aisoc:aisoc@localhost:5432/aisoc

# JWT secret — generate with: openssl rand -hex 32
JWT_SECRET=change-me-in-production

# Optional: SAML/OIDC SSO
# SAML_IDP_METADATA_URL=https://your-idp/metadata
# OIDC_DISCOVERY_URL=https://your-idp/.well-known/openid-configuration

# Optional: Purple Team / Caldera integration
# CALDERA_URL=http://localhost:8888
# CALDERA_API_KEY=your-caldera-key

# Optional: OpenTelemetry
# OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317
```

## 4. Start Services

```bash
docker compose up -d
```

This starts:
- **PostgreSQL** (port 5432) — main datastore
- **Redis** (port 6379) — cache and rate-limiting
- **Kafka** (port 9092) — event streaming spine
- **FastAPI** (port 8000) — core API
- **UEBA service** (port 8005) — user behavior analytics
- **Honeytokens service** (port 8004) — deception platform
- **Purple Team service** (port 8006) — adversary emulation
- **Next.js** (port 3000) — web console

## 5. Run Database Migrations

```bash
docker compose exec api alembic upgrade head
docker compose exec ueba alembic upgrade head
docker compose exec honeytokens alembic upgrade head
docker compose exec purple-team alembic upgrade head
```

## 6. Seed Demo Data

```bash
python3 scripts/seed_demo.py
```

This loads demo cases, alerts, detections, playbooks, and a sample UEBA baseline.

## 7. Open the UI

Visit [http://localhost:3000](http://localhost:3000).

Log in with the demo credentials printed by the seed script (default: `admin@aisoc.local / changeme`).

### Console Tour

| Page | URL | Description |
|------|-----|-------------|
| Dashboard | `/` | Live alert stream, case queue, threat map |
| Cases | `/cases` | Unified case management |
| Alerts | `/alerts` | Raw signal feed with ML risk scores |
| Detections | `/detections` | Sigma/YARA/KQL rule catalog |
| Playbooks | `/playbooks` | Drag-and-drop automation builder |
| UEBA | `/ueba` | User behavior anomaly timeline |
| Honeytokens | `/honeytokens` | Deceptive token lifecycle |
| Purple Team | `/purple-team` | ATT&CK coverage · emulation runs · tabletop |
| Marketplace | `/marketplace` | Community plugins, rules, playbooks |
| Compliance | `/compliance` | SOC 2, ISO 27001, NIST CSF dashboards |
| Audit Log | `/audit` | Immutable activity ledger |

## Next Steps

- [Architecture deep-dive](./architecture)
- [Write your first detection rule](./concepts/detections)
- [Build a playbook](./concepts/playbooks)
- [Install a community plugin](./plugins/overview)
- [Deploy to Kubernetes](./deployment/kubernetes)
