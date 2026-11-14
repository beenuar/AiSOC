# ── Stage 1: turn the lock into a hash-pinned requirements file ──────────────
#
# Poetry runs here and nowhere else; nothing from this stage reaches the
# runtime image except the file it writes.
#
# Poetry's version is pinned, its dependency closure is not. Installing it into
# the runtime image under `virtualenvs.create false` put the ~35 packages
# poetry itself depends on into the same site-packages as the application's, so
# they shipped, and each of them moved whenever PyPI published a release. Two
# builds of one commit straddling such a release were therefore different
# images: issue #1217 was `platformdirs` 4.12.3 against 4.12.4.
#
# `poetry export` reads pyproject.toml and poetry.lock and nothing else, so
# what it writes is the same whatever poetry's own closure resolved to. It
# still refuses a lock that no longer matches the manifest ("changed
# significantly since poetry.lock was last generated"), so editing the manifest
# without re-locking remains a build error rather than a silent re-resolution
# nobody reviewed.
FROM python:3.11-slim AS deps

# `export` left poetry's core in 2.x, so the plugin that provides it is pinned
# beside poetry rather than resolved at build time.
RUN pip install --no-cache-dir poetry==2.4.1 poetry-plugin-export==1.9.0

WORKDIR /app
COPY pyproject.toml poetry.lock ./

# `--only main` is exactly what `poetry install --only main --no-root`
# installed: the main group, and not the project itself.
RUN poetry export --only main --format requirements.txt --output /requirements.txt


# ── Stage 2: the runtime image ───────────────────────────────────────────────
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

COPY --from=deps /requirements.txt /requirements.txt

# Every version in this image comes from poetry.lock by way of the stage above,
# and `--require-hashes` makes that deterministic by construction rather than
# by the timing of the build: pip refuses any requirement that is not pinned
# with `==` and carrying a matching hash, so a re-published or substituted
# artefact fails the build instead of shipping. Poetry is not installed here,
# so its dependency closure is not in the image and cannot drift between two
# builds of this commit.
#
# There is deliberately no pip fallback here. The one this replaced carried its
# own copy of the dependency list, drifted from pyproject.toml, and pinned
# versions no test ever ran. When a transient poetry failure triggered it on
# 2026-09-24 the api image shipped FastAPI 0.111.1 and died at import. A build
# that fails is recoverable; an image that boots on untested versions is not.
RUN pip install --no-cache-dir --require-hashes -r /requirements.txt

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
