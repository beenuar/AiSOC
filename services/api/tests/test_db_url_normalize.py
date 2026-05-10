"""Unit tests for the asyncpg URL normalizer.

The normalizer translates libpq-style ``sslmode=`` query parameters that
asyncpg cannot parse into ``connect_args`` it accepts. Regressing this
silently breaks every database call in production, so we keep the cases
explicit here.
"""

from app.db.database import _normalize_async_pg_url


def test_postgres_scheme_rewritten_to_asyncpg():
    url, args = _normalize_async_pg_url("postgres://u:p@h:5432/db")
    assert url == "postgresql+asyncpg://u:p@h:5432/db"
    assert args == {}


def test_postgresql_scheme_rewritten_to_asyncpg():
    url, args = _normalize_async_pg_url("postgresql://u:p@h:5432/db")
    assert url == "postgresql+asyncpg://u:p@h:5432/db"
    assert args == {}


def test_explicit_driver_left_alone():
    url, args = _normalize_async_pg_url("postgresql+asyncpg://u:p@h/db")
    assert url == "postgresql+asyncpg://u:p@h/db"
    assert args == {}


def test_sslmode_require_translated_to_ssl_kwarg():
    url, args = _normalize_async_pg_url("postgresql://u:p@h/db?sslmode=require")
    assert url == "postgresql+asyncpg://u:p@h/db"
    assert args == {"ssl": "require"}


def test_sslmode_disable_translated_to_false():
    url, args = _normalize_async_pg_url("postgres://u:p@h/db?sslmode=disable")
    assert url == "postgresql+asyncpg://u:p@h/db"
    assert args == {"ssl": False}


def test_other_query_params_preserved():
    url, args = _normalize_async_pg_url("postgresql://u:p@h/db?application_name=aisoc&sslmode=verify-full")
    assert "application_name=aisoc" in url
    assert "sslmode" not in url
    assert args == {"ssl": "verify-full"}


def test_channel_binding_stripped():
    url, args = _normalize_async_pg_url("postgresql://u:p@h/db?sslmode=require&channel_binding=require")
    assert "channel_binding" not in url
    assert args == {"ssl": "require"}
