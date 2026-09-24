FROM python:3.11-slim

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN pip install --no-cache-dir poetry==2.4.1 \
    && poetry config virtualenvs.create false

COPY pyproject.toml poetry.lock ./

# Dependencies come from poetry.lock, so two builds of this commit install
# byte-identical versions. This layer deliberately copies only the manifest
# and the lock, so it still caches across source edits — the reason the
# hand-written `pip install` list it replaces existed at all. That list was a
# second copy of pyproject.toml maintained by a comment asking for lockstep,
# and every one of the four had drifted from the manifest it mirrored.
RUN poetry install --no-interaction --no-ansi --only main --no-root

COPY app/ app/

EXPOSE 8010

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8010"]
