FROM python:3.11-slim

WORKDIR /app

# System deps occasionally needed by transitive packages (qdrant fastembed,
# weasyprint, etc.). Keep the list small; expand only when poetry resolution
# proves a missing system library is required.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir poetry==2.4.1 \
    && poetry config virtualenvs.create false

COPY pyproject.toml poetry.lock ./

# Dependencies come from poetry.lock and nowhere else, so two builds of this
# commit install byte-identical versions. `poetry install` refuses a lock that
# no longer matches pyproject.toml ("changed significantly since poetry.lock
# was last generated"), so editing the manifest without re-locking is a build
# error rather than a silent re-resolution nobody reviewed. The matching
# `poetry check --lock` runs in CI, where the README the check wants is on
# disk; this layer has only the two files it installs from.
#
# There is deliberately no pip fallback here. The one this replaced carried its
# own copy of the dependency list, drifted from pyproject.toml, and pinned
# versions no test ever ran. When a transient poetry failure triggered it on
# 2026-09-24 the api image shipped FastAPI 0.111.1 and died at import. A build
# that fails is recoverable; an image that boots on untested versions is not.
RUN poetry install --no-interaction --no-ansi --only main --no-root

# Smoke-import the modules the orchestrator pulls in at module load time.
# Catches "image built but broken" cases at build time instead of runtime.
# Also assert that the langgraph version on disk exposes the ``START``
# sentinel — langgraph 0.0.x silently lacked it, which previously crashed the
# agents service at boot with ``ImportError: cannot import name 'START'``.
RUN python -c "import opentelemetry, langgraph, fastapi, sqlalchemy, asyncpg, redis, httpx, structlog, apscheduler, yaml, _cffi_backend; from cryptography.fernet import Fernet; from langgraph.graph import END, START, StateGraph"

COPY app/ ./app/

# Import the application module that first exposed the missing direct
# dependency. Keep this after COPY so the build validates the real import path.
RUN python -c "from app.security.credential_vault import CredentialVault"

EXPOSE 8084

# Dual-stack entrypoint — see app/scripts/serve.py and the matching CMD in
# services/api/Dockerfile for the full rationale (Python's asyncio forces
# IPV6_V6ONLY=1 on `::` binds, which breaks Fly's IPv4 health checks).
CMD ["python", "-m", "app.scripts.serve"]
