FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir poetry==1.7.1 && \
    poetry config virtualenvs.create false

COPY pyproject.toml poetry.lock* ./

# Run poetry without swallowing errors. Falls back to a complete pip
# install mirroring pyproject.toml so a transient registry timeout
# doesn't fail the whole image build. The previous fallback used
# ``2>/dev/null ||`` which hid the real reason poetry failed and shipped
# an incomplete dep set (missing cryptography, sqlalchemy, asyncpg,
# apscheduler — half the connector platform). Keep the fallback
# list in lockstep with services/connectors/pyproject.toml.
RUN set -eux; \
    if poetry install --no-interaction --no-ansi --without dev --no-root; then \
        echo "[connectors] poetry install succeeded"; \
    else \
        echo "[connectors] poetry install failed; using pip fallback"; \
        pip install --no-cache-dir \
            "fastapi>=0.109,<0.110" \
            "uvicorn[standard]>=0.27,<0.28" \
            "httpx>=0.26,<0.27" \
            "pydantic>=2.5,<3" \
            "pydantic-settings>=2.1,<3" \
            "structlog>=24.1,<25" \
            "boto3>=1.34,<2" \
            "apscheduler>=3.10,<4" \
            "sqlalchemy>=2.0,<3" \
            "asyncpg>=0.29,<0.30" \
            "cryptography>=42,<43" ; \
    fi

COPY app/ ./app/

EXPOSE 8087

# Dual-stack entrypoint (IPv6 + IPv4-mapped). See app/scripts/serve.py.
CMD ["python", "-m", "app.scripts.serve"]
