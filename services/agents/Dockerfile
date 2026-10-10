# ── Stage 1: turn the lock into a hash-pinned requirements file ──────────────
#
# Poetry runs here and nowhere else; nothing from this stage reaches the
# runtime image except the file it writes.
#
# Poetry's version is pinned, its dependency closure is not. Installing it into
# the runtime image under `virtualenvs.create false` put the ~35 packages
# poetry itself depends on into the same site-packages as the application's, so
# they shipped, and each of them moved whenever PyPI published a release. Two
# builds of one commit straddling such a release were therefore different
# images: issue #1217 was `platformdirs` 4.12.3 against 4.12.4.
#
# `poetry export` reads pyproject.toml and poetry.lock and nothing else, so
# what it writes is the same whatever poetry's own closure resolved to. It
# still refuses a lock that no longer matches the manifest ("changed
# significantly since poetry.lock was last generated"), so editing the manifest
# without re-locking remains a build error rather than a silent re-resolution
# nobody reviewed.
FROM python:3.11-slim AS deps

# `export` left poetry's core in 2.x, so the plugin that provides it is pinned
# beside poetry rather than resolved at build time.
RUN pip install --no-cache-dir poetry==2.4.1 poetry-plugin-export==1.9.0

WORKDIR /app
COPY pyproject.toml poetry.lock ./

# `--only main` is exactly what `poetry install --only main --no-root`
# installed: the main group, and not the project itself.
RUN poetry export --only main --format requirements.txt --output /requirements.txt


# ── Stage 2: the runtime image ───────────────────────────────────────────────
FROM python:3.11-slim

WORKDIR /app

# System deps occasionally needed by transitive packages (qdrant fastembed,
# weasyprint, etc.). Keep the list small; expand only when poetry resolution
# proves a missing system library is required.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY --from=deps /requirements.txt /requirements.txt

# Every version in this image comes from poetry.lock by way of the stage above,
# and `--require-hashes` makes that deterministic by construction rather than
# by the timing of the build: pip refuses any requirement that is not pinned
# with `==` and carrying a matching hash, so a re-published or substituted
# artefact fails the build instead of shipping. Poetry is not installed here,
# so its dependency closure is not in the image and cannot drift between two
# builds of this commit.
#
# There is deliberately no pip fallback here. The one this replaced carried its
# own copy of the dependency list, drifted from pyproject.toml, and pinned
# versions no test ever ran. When a transient poetry failure triggered it on
# 2026-09-24 the api image shipped FastAPI 0.111.1 and died at import. A build
# that fails is recoverable; an image that boots on untested versions is not.
RUN pip install --no-cache-dir --require-hashes -r /requirements.txt

# The manifest and the lock stay in the image as the record of what it was
# built from. The dependency layer above no longer reads them, so metadata
# edits that change no resolved version no longer rebuild it.
COPY pyproject.toml poetry.lock ./

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
