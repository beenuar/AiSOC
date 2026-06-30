"""Tests for ``app.scripts.run_migrations._connect`` retry semantics.

The migration runner is invoked by Fly's ``release_command`` the moment a new
API VM boots, which races against Postgres becoming reachable (autostop wake,
mid-failover, etc.). A single failed ``asyncpg.connect`` would crash the whole
deploy — these tests pin the retry contract that makes the runner resilient
to those transient connect errors without masking real auth/config failures.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import asyncpg
import pytest
from app.scripts import run_migrations


@pytest.mark.asyncio
async def test_connect_retries_until_success(monkeypatch):
    """Transient connect failures are retried and eventually succeed."""
    fake_conn = object()
    sleeps: list[float] = []
    attempts = [
        asyncpg.exceptions.ConnectionDoesNotExistError("connection was closed in the middle of operation"),
        OSError("Connection refused"),
        fake_conn,
    ]

    async def fake_connect(*_args, **_kwargs):
        outcome = attempts.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    async def fake_sleep(seconds):
        sleeps.append(seconds)

    monkeypatch.setattr(run_migrations.asyncpg, "connect", fake_connect)
    monkeypatch.setattr(run_migrations.asyncio, "sleep", fake_sleep)

    result = await run_migrations._connect()

    assert result is fake_conn
    assert sleeps == [1, 2], f"expected exponential back-off (1s, 2s) before the third (successful) attempt, got {sleeps}"


@pytest.mark.asyncio
async def test_connect_gives_up_after_exhausting_retries(monkeypatch):
    """A persistent transient failure ultimately propagates the last exception."""
    final_exc = asyncpg.exceptions.ConnectionDoesNotExistError("still down")

    async def always_fail(*_args, **_kwargs):
        raise final_exc

    async def fake_sleep(_seconds):
        pass

    monkeypatch.setattr(run_migrations.asyncpg, "connect", always_fail)
    monkeypatch.setattr(run_migrations.asyncio, "sleep", fake_sleep)

    with pytest.raises(asyncpg.exceptions.ConnectionDoesNotExistError):
        await run_migrations._connect()


@pytest.mark.asyncio
async def test_connect_does_not_retry_auth_failures(monkeypatch):
    """Auth/config errors are surfaced immediately — retrying them is pointless
    and would mask a real misconfiguration as a deploy hang."""

    async def auth_fail(*_args, **_kwargs):
        raise asyncpg.exceptions.InvalidPasswordError("wrong password for user")

    call_count = {"connect": 0}

    async def counting_connect(*args, **kwargs):
        call_count["connect"] += 1
        await auth_fail(*args, **kwargs)

    monkeypatch.setattr(run_migrations.asyncpg, "connect", counting_connect)
    # Make sure asyncio.sleep is never called — auth failures shouldn't retry.
    monkeypatch.setattr(
        run_migrations.asyncio,
        "sleep",
        AsyncMock(side_effect=AssertionError("auth failure must not retry")),
    )

    with pytest.raises(asyncpg.exceptions.InvalidPasswordError):
        await run_migrations._connect()

    assert call_count["connect"] == 1, "auth failures must propagate after the first attempt, no retries"


def test_migrations_required_defaults_to_true(monkeypatch):
    """Absence of the env var means the previous strict behaviour: any
    connect failure aborts the deploy. That's the safe default."""
    monkeypatch.delenv("AISOC_MIGRATIONS_REQUIRED", raising=False)
    assert run_migrations._migrations_required() is True


@pytest.mark.parametrize("value", ["0", "false", "no", "off", "FALSE", "Off"])
def test_migrations_required_recognises_opt_out(monkeypatch, value):
    """Demo-mode opt-out via the documented sentinel values."""
    monkeypatch.setenv("AISOC_MIGRATIONS_REQUIRED", value)
    assert run_migrations._migrations_required() is False


@pytest.mark.parametrize("value", ["1", "true", "yes", "on", "  1  ", ""])
def test_migrations_required_truthy_values(monkeypatch, value):
    """Anything not in the opt-out vocabulary is treated as 'required'.
    Empty string included — it's an easy footgun and the safe interpretation
    is 'I didn't mean to opt out'."""
    monkeypatch.setenv("AISOC_MIGRATIONS_REQUIRED", value)
    assert run_migrations._migrations_required() is True
