---
sidebar_position: 1
---

# Development Setup

## Prerequisites

- Node.js ≥ 18, pnpm ≥ 9
- Python 3.11+
- Go 1.21+
- Docker & Docker Compose v2

## 1. Clone & Install

```bash
git clone https://github.com/beenuar/aisoc.git
cd aisoc
pnpm install
```

## 2. Python Services

```bash
cd services/agents
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## 3. Environment

```bash
cp .env.example .env
# Set OPENAI_API_KEY at minimum
```

## 4. Start Infrastructure

```bash
docker compose up -d postgres redis
```

## 5. Run Services Individually

```bash
# Frontend
pnpm --filter @aisoc/web dev

# API gateway
cd services/api && uvicorn app.main:app --reload --port 8000

# Agents service
cd services/agents && uvicorn app.main:app --reload --port 8001

# Realtime
cd services/realtime && uvicorn app.main:app --reload --port 8002
```

## 6. Run Tests

```bash
# Python
pytest services/agents/tests/

# Go SDK
cd packages/plugin-sdk-go && go test ./...

# Frontend
pnpm --filter @aisoc/web test
```

## Useful Scripts

| Script | Description |
|--------|-------------|
| `python3 scripts/seed_demo.py` | Seed demo cases and playbooks |
| `python3 scripts/validate_detections.py detections/` | Validate detection rules |
| `pnpm --filter @aisoc/web lint` | Lint the frontend |
