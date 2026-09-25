FROM python:3.11-slim AS base

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
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

EXPOSE 9001

# The chain runs on the way up, then this process is replaced by the server.
#
# Nothing invoked these four alembic chains. This was a bare `uvicorn` line, so
# the documented quickstart booted the service against an empty schema with
# none of its row-level-security policies installed, and every command in that
# sequence reported success. `app/_migrate.py` applies the chain as the owner
# credential, verifies it reached head, and refuses to start the server if it
# did not.
#
# `sh -c` because an exec-form CMD cannot run two things. Neither shell nor
# wrapper stays in the process tree: `sh -c` with a single command execs it,
# and `_migrate` hands over with `os.execvp`, so uvicorn ends up as PID 1 and
# receives SIGTERM directly rather than through a parent that would swallow it.
CMD ["sh", "-c", "python -m app._migrate -- uvicorn app.main:app --host 0.0.0.0 --port 9001"]
