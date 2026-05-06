FROM python:3.11-slim

WORKDIR /app

# System deps occasionally needed by transitive packages (qdrant fastembed,
# weasyprint, etc.). Keep the list small; expand only when poetry resolution
# proves a missing system library is required.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir poetry==1.7.1 \
    && poetry config virtualenvs.create false

COPY pyproject.toml poetry.lock* ./

# Run poetry without swallowing errors. If resolution fails for any reason
# (network blip, transient registry timeout, etc.) we fall through to a
# complete pip install that mirrors pyproject.toml so the image still ships
# a working agents service. The previous fallback omitted opentelemetry-*
# and a handful of other deps, producing images that crashed on import.
RUN set -eux; \
    if poetry install --no-interaction --no-ansi --without dev --no-root; then \
        echo "[agents] poetry install succeeded"; \
    else \
        echo "[agents] poetry install failed; using pip fallback"; \
        pip install --no-cache-dir \
            "fastapi>=0.109,<0.110" \
            "uvicorn[standard]>=0.27,<0.28" \
            "pydantic>=2.5,<3" \
            "pydantic-settings>=2.1,<3" \
            "langchain>=0.1,<0.2" \
            "langchain-core>=0.1,<0.2" \
            "langchain-openai>=0.0.5,<0.1" \
            "langchain-community>=0.0.20,<0.1" \
            "langgraph>=0.0.30,<0.1" \
            "openai>=1.12,<2" \
            "redis[hiredis]>=5.0,<6" \
            "httpx>=0.26,<0.27" \
            "structlog>=24,<25" \
            "prometheus-client>=0.19,<0.20" \
            "python-dateutil>=2.8,<3" \
            "aiokafka>=0.10,<0.11" \
            "qdrant-client[fastembed]>=1.9,<2" \
            "markdown>=3.5,<4" \
            "opentelemetry-sdk>=1.24,<2" \
            "opentelemetry-instrumentation-fastapi>=0.45b0" \
            "opentelemetry-instrumentation-httpx>=0.45b0" \
            "asyncpg>=0.29,<0.30" \
            "sqlalchemy[asyncio]>=2.0.25,<3" \
            "apscheduler>=3.10.4,<4" \
            "pyyaml>=6.0.1,<7" ; \
    fi

# Smoke-import the modules the orchestrator pulls in at module load time.
# Catches "image built but broken" cases at build time instead of runtime.
RUN python -c "import opentelemetry, langgraph, fastapi, sqlalchemy, asyncpg, redis, httpx, structlog, apscheduler, yaml"

COPY app/ ./app/

EXPOSE 8084

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8084"]
