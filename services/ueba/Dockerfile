FROM python:3.11-slim

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

COPY pyproject.toml .

# Install runtime deps explicitly. We deliberately don't `pip install .`
# because the hatchling backend would need the package source, but we
# don't COPY app/ until later (so this layer caches across source edits).
# numpy/scipy install from manylinux wheels on python:3.11-slim, no
# build-essential required. Keep this list in lockstep with
# pyproject.toml [project.dependencies].
RUN pip install --no-cache-dir \
    "fastapi>=0.110.0" \
    "uvicorn[standard]>=0.29.0" \
    "sqlalchemy[asyncio]>=2.0.0" \
    "asyncpg>=0.29.0" \
    "alembic>=1.13.0" \
    "pydantic>=2.0.0" \
    "pydantic-settings>=2.0.0" \
    "aiokafka>=0.10.0" \
    "numpy>=1.26.0" \
    "scipy>=1.12.0" \
    "httpx>=0.27.0" \
    "opentelemetry-sdk>=1.24.0" \
    "opentelemetry-exporter-otlp>=1.24.0" \
    "opentelemetry-instrumentation-fastapi>=0.45b0"

COPY alembic.ini .
COPY alembic/ alembic/
COPY app/ app/

EXPOSE 8004

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8004"]
