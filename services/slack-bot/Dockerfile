FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir poetry==1.7.1 && \
    poetry config virtualenvs.create false

COPY pyproject.toml poetry.lock* ./

# Run poetry without swallowing errors. Falls back to a complete pip
# install mirroring pyproject.toml so a transient registry timeout
# doesn't fail the whole image build. The previous fallback used
# ``2>/dev/null ||`` which hid the real reason poetry failed (we'd ship
# the image and only learn at runtime when /slack/events 500'd). Keep the
# fallback list in lockstep with services/slack-bot/pyproject.toml.
RUN set -eux; \
    if poetry install --no-interaction --no-ansi --without dev --no-root; then \
        echo "[slack-bot] poetry install succeeded"; \
    else \
        echo "[slack-bot] poetry install failed; using pip fallback"; \
        pip install --no-cache-dir \
            "fastapi>=0.109,<0.137" \
            "uvicorn[standard]>=0.27,<0.28" \
            "pydantic>=2.5,<3" \
            "pydantic-settings>=2.1,<3" \
            "slack-bolt>=1.18.1,<2" \
            "slack-sdk>=3.27,<4" \
            "aiohttp>=3.9,<4.0" \
            "httpx>=0.27,<0.29" \
            "structlog>=24.1,<26" \
            "asyncpg>=0.29,<0.31" ; \
    fi

COPY app/ ./app/

EXPOSE 8089

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8089"]
