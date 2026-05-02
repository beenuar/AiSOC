FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir poetry==1.7.1 && \
    poetry config virtualenvs.create false

COPY pyproject.toml poetry.lock* ./
RUN poetry install --no-interaction --no-ansi --no-dev 2>/dev/null || \
    pip install --no-cache-dir fastapi uvicorn[standard] httpx pydantic pydantic-settings \
               structlog boto3

COPY app/ ./app/

EXPOSE 8087

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8087"]
