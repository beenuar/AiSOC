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

COPY alembic.ini .
COPY alembic/ alembic/
COPY app/ app/

EXPOSE 8006

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
CMD ["sh", "-c", "python -m app._migrate -- uvicorn app.main:app --host 0.0.0.0 --port 8006"]
