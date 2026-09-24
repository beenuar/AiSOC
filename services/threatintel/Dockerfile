FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential curl \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir poetry==2.4.1 \
    && poetry config virtualenvs.create false

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

COPY app ./app

EXPOSE 8005

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8005"]
