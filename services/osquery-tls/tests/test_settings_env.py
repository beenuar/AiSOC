"""``DATABASE_URL`` reaches this service, not just its compose block.

Every other field here is read as ``AISOC_OSQUERY_TLS_<FIELD>`` because the settings
declare ``env_prefix``. ``database_url`` used to be too — while
``docker-compose.yml`` set plain ``DATABASE_URL`` on the service, as it does on
every other. The variable was inert, so the switch to the DML-only runtime
role never reached this service at all and the default, which names the
*owner*, was what it connected as.

Both spellings are asserted, and so is the precedence between them, because
"accepts the new name" and "still accepts the old one" are different promises
and a deployment relies on both.
"""

from __future__ import annotations

import os

import pytest


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for key in list(os.environ):
        if key.startswith("AISOC_OSQUERY_TLS_") or key == "DATABASE_URL":
            monkeypatch.delenv(key, raising=False)


def test_unprefixed_env_var(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://aisoc_app:pw@db:5432/aisoc")
    from app.core.config import Settings

    assert Settings().database_url == "postgresql+asyncpg://aisoc_app:pw@db:5432/aisoc"


def test_prefixed_env_var_still_works(monkeypatch):
    monkeypatch.setenv("AISOC_OSQUERY_TLS_DATABASE_URL", "postgresql+asyncpg://legacy:pw@db:5432/legacy")
    from app.core.config import Settings

    assert Settings().database_url == "postgresql+asyncpg://legacy:pw@db:5432/legacy"


def test_unprefixed_takes_precedence(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://winner:pw@db:5432/win")
    monkeypatch.setenv("AISOC_OSQUERY_TLS_DATABASE_URL", "postgresql+asyncpg://loser:pw@db:5432/lose")
    from app.core.config import Settings

    assert Settings().database_url == "postgresql+asyncpg://winner:pw@db:5432/win"


def test_falls_back_to_default():
    from app.core.config import Settings

    assert "localhost" in Settings().database_url


def test_other_fields_keep_their_prefix(monkeypatch):
    """The alias covers one field. Widening it silently would be its own bug."""
    monkeypatch.setenv("AISOC_OSQUERY_TLS_INGEST_URL", "http://ingest.test:8080")
    from app.core.config import Settings

    assert Settings().ingest_url == "http://ingest.test:8080"
