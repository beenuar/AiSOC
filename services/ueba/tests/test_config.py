"""Verify UEBA Settings picks up env vars with and without the legacy UEBA_ prefix."""

from __future__ import annotations

import os

import pytest


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for key in list(os.environ):
        if key.startswith("UEBA_") or key in ("DATABASE_URL", "KAFKA_BOOTSTRAP_SERVERS"):
            monkeypatch.delenv(key, raising=False)


class TestDatabaseUrl:
    def test_unprefixed_env_var(self, monkeypatch):
        monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://prod:secret@db:5432/prod")
        from app.core.config import Settings

        s = Settings()
        assert s.database_url == "postgresql+asyncpg://prod:secret@db:5432/prod"

    def test_legacy_prefixed_env_var(self, monkeypatch):
        monkeypatch.setenv("UEBA_DATABASE_URL", "postgresql+asyncpg://legacy:pw@db:5432/legacy")
        from app.core.config import Settings

        s = Settings()
        assert s.database_url == "postgresql+asyncpg://legacy:pw@db:5432/legacy"

    def test_unprefixed_takes_precedence(self, monkeypatch):
        monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://winner:pw@db:5432/win")
        monkeypatch.setenv("UEBA_DATABASE_URL", "postgresql+asyncpg://loser:pw@db:5432/lose")
        from app.core.config import Settings

        s = Settings()
        assert s.database_url == "postgresql+asyncpg://winner:pw@db:5432/win"

    def test_falls_back_to_default(self):
        from app.core.config import Settings

        s = Settings()
        assert "localhost" in s.database_url


class TestKafkaBootstrapServers:
    def test_unprefixed_env_var(self, monkeypatch):
        monkeypatch.setenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:29092")
        from app.core.config import Settings

        s = Settings()
        assert s.kafka_bootstrap_servers == "kafka:29092"

    def test_legacy_prefixed_env_var(self, monkeypatch):
        monkeypatch.setenv("UEBA_KAFKA_BOOTSTRAP_SERVERS", "kafka-legacy:9092")
        from app.core.config import Settings

        s = Settings()
        assert s.kafka_bootstrap_servers == "kafka-legacy:9092"
