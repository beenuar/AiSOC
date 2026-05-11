FROM python:3.11-slim AS base

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

RUN pip install poetry==1.8.2 && \
    poetry config virtualenvs.create false

COPY pyproject.toml poetry.lock* ./

# Run poetry without swallowing errors. Falls back to a complete pip
# install mirroring pyproject.toml so a transient registry timeout
# doesn't fail the whole image build. Keep the fallback list in lockstep
# with services/osquery-tls/pyproject.toml.
RUN set -eux; \
    if poetry install --no-interaction --no-ansi --without dev --no-root; then \
        echo "[osquery-tls] poetry install succeeded"; \
    else \
        echo "[osquery-tls] poetry install failed; using pip fallback"; \
        pip install --no-cache-dir \
            "fastapi>=0.111,<0.112" \
            "uvicorn[standard]>=0.29,<0.30" \
            "pydantic>=2.7,<2.11" \
            "pydantic-settings>=2.2,<3" \
            "sqlalchemy[asyncio]>=2.0.30,<3" \
            "asyncpg>=0.29,<0.32" \
            "alembic>=1.13,<2" \
            "httpx>=0.27,<0.29" \
            "structlog>=24.1,<25" \
            "prometheus-client>=0.20,<0.26" \
            "cryptography>=42,<43" ; \
    fi

COPY . .

EXPOSE 9001

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "9001"]
