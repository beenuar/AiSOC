FROM python:3.11-slim

WORKDIR /app

RUN pip install poetry==1.7.1 && \
    poetry config virtualenvs.create false

COPY pyproject.toml poetry.lock* ./
RUN poetry install --no-interaction --no-ansi --no-dev 2>/dev/null || \
    pip install fastapi uvicorn[standard] langgraph langchain langchain-core \
               langchain-openai openai redis[hiredis] httpx structlog \
               prometheus-client python-dateutil aiokafka pydantic pydantic-settings

COPY app/ ./app/

EXPOSE 8084

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8084"]
