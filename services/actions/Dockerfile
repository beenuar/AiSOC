FROM python:3.11-slim

WORKDIR /app

RUN pip install poetry==1.7.1 && \
    poetry config virtualenvs.create false

COPY pyproject.toml poetry.lock* ./

# Run poetry without swallowing errors. Falls back to a complete pip
# install mirroring pyproject.toml so a transient registry timeout
# doesn't fail the whole image build. The previous fallback used
# ``2>/dev/null ||`` which hid the real reason poetry failed and shipped
# an incomplete dep set (missing cryptography, used by app.core for
# credential vault decryption). Keep the fallback list in lockstep with
# services/actions/pyproject.toml.
RUN set -eux; \
    if poetry install --no-interaction --no-ansi --without dev --no-root; then \
        echo "[actions] poetry install succeeded"; \
    else \
        echo "[actions] poetry install failed; using pip fallback"; \
        pip install --no-cache-dir \
            "fastapi>=0.109,<0.137" \
            "uvicorn[standard]>=0.27,<0.28" \
            "pydantic>=2.5,<3" \
            "pydantic-settings>=2.1,<3" \
            "redis[hiredis]>=5.0.1,<8.0.0" \
            "asyncpg>=0.29,<0.32" \
            "sqlalchemy[asyncio]>=2.0.25,<3" \
            "structlog>=24.1,<26" \
            "httpx>=0.27,<0.29" \
            "aiokafka>=0.10,<0.15" \
            "python-dateutil>=2.8.2,<3" \
            "cryptography>=42,<43" ; \
    fi

COPY app/ ./app/

EXPOSE 8085

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8085"]
