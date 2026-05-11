FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential curl \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir poetry==1.8.2 \
    && poetry config virtualenvs.create false

COPY pyproject.toml poetry.lock* ./

# Run poetry without swallowing errors. Falls back to a complete pip
# install mirroring pyproject.toml so a transient registry timeout
# doesn't fail the whole image build. Keep the fallback list in lockstep
# with services/threatintel/pyproject.toml.
RUN set -eux; \
    if poetry install --no-interaction --no-ansi --only main; then \
        echo "[threatintel] poetry install succeeded"; \
    else \
        echo "[threatintel] poetry install failed; using pip fallback"; \
        pip install --no-cache-dir \
            "fastapi>=0.109,<0.110" \
            "uvicorn[standard]>=0.27,<0.28" \
            "pydantic>=2.5,<3" \
            "pydantic-settings>=2.1,<3" \
            "httpx>=0.26,<0.27" \
            "redis[hiredis]>=5.0.1,<6" \
            "taxii2-client>=2.3,<3" \
            "stix2>=3.0.1,<4" \
            "apscheduler>=3.10.4,<4" \
            "opensearch-py[async]>=2.7,<3" \
            "qdrant-client[fastembed]>=1.9,<2" \
            "neo4j>=5.19,<6" \
            "structlog>=24.1,<25" \
            "prometheus-client>=0.19,<0.20" \
            "python-dateutil>=2.8.2,<3" \
            "aiokafka>=0.10,<0.11" \
            "mmh3>=4.1,<5" ; \
    fi

COPY app ./app

EXPOSE 8005

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8005"]
