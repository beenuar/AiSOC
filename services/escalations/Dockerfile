# ── Stage 1: turn the lock into a hash-pinned requirements file ──────────────
#
# Same shape as every other Python service here (see
# services/honeytokens/Dockerfile for the full rationale): poetry runs in this
# stage and nowhere else, so its own dependency closure never reaches the
# runtime image, and `poetry export` still refuses a lock that no longer
# matches the manifest — editing pyproject.toml without re-locking stays a
# build error rather than a silent re-resolution.
FROM python:3.11-slim AS deps

RUN pip install --no-cache-dir poetry==2.4.1 poetry-plugin-export==1.9.0

WORKDIR /app
COPY pyproject.toml poetry.lock ./

RUN poetry export --only main --format requirements.txt --output /requirements.txt


# ── Stage 2: the runtime image ───────────────────────────────────────────────
FROM python:3.11-slim

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

COPY --from=deps /requirements.txt /requirements.txt

# Every version here comes from poetry.lock by way of the stage above;
# --require-hashes refuses anything not pinned `==` with a matching hash.
RUN pip install --no-cache-dir --require-hashes -r /requirements.txt

COPY pyproject.toml poetry.lock ./
COPY app/ ./app/

USER nobody

CMD ["python", "-u", "app/bridge.py"]
