## Learned User Preferences

- Always track progress locally (e.g. in a TODO/PROGRESS file) so work can be resumed after IDE crashes or restarts.
- Complete all planned tasks without stopping mid-way; work through the full list until done.
- Do not mention competitor names (Prophet Security, Torq) anywhere in code, comments, or docs — this is an open-source project.
- Before pushing to GitHub, ensure no secrets, API keys, tokens, or sensitive data are present in any public repo files.
- Host codebase on GitHub once fully built out; keep documentation in sync.
- Never edit plan files directly — implement the plan as specified without modifying the plan document itself.

## Learned Workspace Facts

- Project: AiSOC — open-source, AI-powered Security Operations Center maintained by the AiSOC community under the MIT license.
- Monorepo managed with pnpm (pnpm@8.15.1) and Turborepo; workspaces defined in `apps/*` and `packages/*`.
- Apps: `apps/web` (Next.js frontend), `apps/docs` (documentation site).
- Backend services in `services/`: `api` (FastAPI/Python 3.11), `agents`, `alert-fusion`, `connectors`, `demo-producer`, `enrichment`, `fusion`, `ingest`, `realtime`, `threatintel`, `ocsf`.
- API service stack: FastAPI, Uvicorn, SQLAlchemy (async), asyncpg (PostgreSQL), Alembic (migrations), Redis, python-jose (JWT), Pydantic v2.
- Packages: `packages/types` (shared TypeScript types), `packages/ui`, `packages/sdk-go`, `packages/sdk-py`, `packages/sdk-ts`, `packages/plugin-sdk-go`, `packages/plugin-sdk-py`.
- Docker Compose used for local dev (`docker-compose.dev.yml`); Terraform in `infra/terraform/` for infrastructure.
- CI uses GitHub Actions (`.github/workflows/`); includes workflows for OpenAPI checks, CI, docs deployment, marketplace sync, and detection validation.
- Detection rules stored in `detections/` (YAML format, categorized by cloud/endpoint/identity/network/application).
- Marketplace plugin index at `marketplace/index.json`, synced to `apps/web/public/marketplace/` via `pnpm marketplace:sync`.
