FROM python:3.11-slim

WORKDIR /app

RUN pip install poetry==1.7.1 && \
    poetry config virtualenvs.create false

COPY pyproject.toml poetry.lock* ./

# Run poetry without swallowing errors. Falls back to a complete pip
# install mirroring pyproject.toml so a transient registry timeout
# doesn't fail the whole image build. The previous fallback used
# ``2>/dev/null ||`` which hid the real reason poetry failed and shipped
# an incomplete dep set (missing simhash + scikit-learn + lightgbm + numpy
# — i.e. the entire ML correlation engine, which would crash the fusion
# service on the first incoming alert). Keep the fallback list in lockstep
# with services/fusion/pyproject.toml.
RUN set -eux; \
    if poetry install --no-interaction --no-ansi --without dev --no-root; then \
        echo "[fusion] poetry install succeeded"; \
    else \
        echo "[fusion] poetry install failed; using pip fallback"; \
        pip install --no-cache-dir \
            "fastapi>=0.109,<0.110" \
            "uvicorn[standard]>=0.27,<0.28" \
            "pydantic>=2.5,<3" \
            "pydantic-settings>=2.1,<3" \
            "aiokafka>=0.10,<0.11" \
            "aioredis>=2.0.1,<3" \
            "redis[hiredis]>=5.0.1,<6" \
            "asyncpg>=0.29,<0.30" \
            "sqlalchemy[asyncio]>=2.0.25,<3" \
            "structlog>=24.1,<25" \
            "prometheus-client>=0.19,<0.20" \
            "httpx>=0.26,<0.27" \
            "python-dateutil>=2.8.2,<3" \
            "simhash>=2.1.2,<3" \
            "scikit-learn>=1.4,<2" \
            "lightgbm>=4.3,<5" \
            "numpy>=1.26,<2" \
            "clickhouse-driver>=0.2.6,<0.3" ; \
    fi

COPY app/ ./app/

EXPOSE 8003

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8003"]
