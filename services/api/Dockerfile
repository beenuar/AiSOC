FROM python:3.11-slim AS base

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    # WeasyPrint (WS-G2 exec digest PDF) — Pango/Cairo text + rendering stack
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libcairo2 \
    libgdk-pixbuf-2.0-0 \
    shared-mime-info \
    && rm -rf /var/lib/apt/lists/*

RUN pip install poetry==1.8.2 && \
    poetry config virtualenvs.create false

COPY pyproject.toml poetry.lock* ./

# Run poetry without swallowing errors. If resolution fails (transient
# registry timeout, proxy hiccup, etc.) we fall through to a pip install
# that mirrors pyproject.toml so the image still ships a working api
# service. The fallback list MUST stay in lockstep with
# services/api/pyproject.toml — missing a dep there means the image
# builds but crashes on import.
RUN set -eux; \
    if poetry install --no-interaction --no-ansi --without dev --no-root; then \
        echo "[api] poetry install succeeded"; \
    else \
        echo "[api] poetry install failed; using pip fallback"; \
        pip install --no-cache-dir \
            "fastapi>=0.111,<0.112" \
            "uvicorn[standard]>=0.29,<0.30" \
            "pydantic>=2.7,<2.11" \
            "pydantic-settings>=2.2,<3" \
            "sqlalchemy[asyncio]>=2.0.30,<3" \
            "asyncpg>=0.29,<0.32" \
            "alembic>=1.13,<2" \
            "redis[hiredis]>=5.0.4,<8.0.0" \
            "httpx>=0.27,<0.29" \
            "python-jose[cryptography]>=3.3,<4" \
            "PyJWT>=2.8,<3" \
            "cryptography>=42,<43" \
            "bcrypt>=4.1,<5" \
            "python-multipart>=0.0.9,<0.1" \
            "tenacity>=8.3,<10" \
            "structlog>=24.1,<25" \
            "prometheus-client>=0.20,<0.26" \
            "opentelemetry-sdk>=1.24,<2" \
            "opentelemetry-instrumentation-fastapi>=0.45b0" \
            "opentelemetry-instrumentation-sqlalchemy>=0.45b0" \
            "clickhouse-driver>=0.2.8,<0.3" \
            "sqlglot>=23,<27" \
            "boto3>=1.34,<2" \
            "neo4j>=5.19,<7" \
            "pysigma>=0.11,<0.12" \
            "pysigma-backend-opensearch>=1.0,<2" \
            "yara-python>=4.5,<5" \
            "pyyaml>=6.0.1,<7" \
            "strawberry-graphql[fastapi]>=0.236,<0.237" \
            "webauthn>=2.2,<3" \
            "weasyprint>=62,<63" ; \
    fi

COPY . .

EXPOSE 8000

# Use a tiny Python wrapper (app.scripts.serve) that pre-binds a dual-stack
# IPv6 socket with IPV6_V6ONLY=0 and hands the fd to uvicorn via --fd.
#
# Why not just `uvicorn --host ::`? Python's asyncio explicitly sets
# IPV6_V6ONLY=1 on IPv6 sockets it creates, so binding to "::" only accepts
# IPv6 connections. On Fly we need BOTH: IPv6 for 6PN private traffic
# (aisoc-demo-api.internal from the web app) AND IPv4 for fly-proxy's public
# /health checks against api.tryaisoc.com (which speak IPv4 to 127.0.0.1).
# Pre-binding lets us turn IPV6_V6ONLY off so a single socket serves both.
CMD ["python", "-m", "app.scripts.serve"]
