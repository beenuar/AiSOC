FROM python:3.11-slim AS base

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    # WeasyPrint (WS-G2 exec digest PDF) — Pango/Cairo text + rendering stack
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libcairo2 \
    libgdk-pixbuf-2.0-0 \
    shared-mime-info \
    && rm -rf /var/lib/apt/lists/*

RUN pip install poetry==2.4.1 && \
    poetry config virtualenvs.create false

COPY pyproject.toml poetry.lock ./

# Dependencies come from poetry.lock and nowhere else, so two builds of this
# commit install byte-identical versions. `poetry install` refuses a lock that
# no longer matches pyproject.toml ("changed significantly since poetry.lock
# was last generated"), so editing the manifest without re-locking is a build
# error rather than a silent re-resolution nobody reviewed. The matching
# `poetry check --lock` runs in CI, where the README the check wants is on
# disk; this layer has only the two files it installs from.
#
# There is deliberately no pip fallback here. The one this replaced carried its
# own copy of the dependency list, drifted from pyproject.toml, and pinned
# versions no test ever ran. When a transient poetry failure triggered it on
# 2026-09-24 the api image shipped FastAPI 0.111.1 and died at import. A build
# that fails is recoverable; an image that boots on untested versions is not.
RUN poetry install --no-interaction --no-ansi --only main --no-root

COPY . .

EXPOSE 8000

# Use a tiny Python wrapper (app.scripts.serve) that pre-binds a dual-stack
# IPv6 socket with IPV6_V6ONLY=0 and hands the fd to uvicorn via --fd.
#
# Why not just `uvicorn --host ::`? Python's asyncio explicitly sets
# IPV6_V6ONLY=1 on IPv6 sockets it creates, so binding to "::" only accepts
# IPv6 connections. On Fly we need BOTH: IPv6 for 6PN private traffic
# (aisoc-demo-api.internal from the web app) AND IPv4 for fly-proxy's public
# /health checks against api.tryaisoc.com (which speak IPv4 to 127.0.0.1).
# Pre-binding lets us turn IPV6_V6ONLY off so a single socket serves both.
CMD ["python", "-m", "app.scripts.serve"]
