"""Unit tests for the scheduler singleton lock helper."""

from __future__ import annotations

import logging

import app.core.scheduler_lock as scheduler_lock_module
import pytest
from redis.exceptions import RedisError


class _FakeRedisClient:
    def __init__(self, *, acquire_result: bool | None = True, acquire_exc: Exception | None = None) -> None:
        self.acquire_result = acquire_result
        self.acquire_exc = acquire_exc
        self.set_calls: list[dict[str, object]] = []
        self.eval_calls: list[tuple[str, int, tuple[object, ...]]] = []

    async def set(self, name: str, value: str, *, ex: int, nx: bool) -> bool | None:
        self.set_calls.append({"name": name, "value": value, "ex": ex, "nx": nx})
        if self.acquire_exc is not None:
            raise self.acquire_exc
        return self.acquire_result

    async def eval(self, script: str, numkeys: int, *args: object) -> int:
        self.eval_calls.append((script, numkeys, args))
        return 1


@pytest.mark.asyncio
async def test_scheduler_lock_acquired_runs_job(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_redis = _FakeRedisClient(acquire_result=True)

    async def _fake_get_redis_client() -> _FakeRedisClient:
        return fake_redis

    monkeypatch.setattr(scheduler_lock_module, "_get_redis_client", _fake_get_redis_client)

    ran = False
    async with scheduler_lock_module.scheduler_lock(job_name="oauth_refresh", ttl_seconds=900) as should_run:
        if should_run:
            ran = True

    assert ran is True
    assert fake_redis.set_calls
    assert fake_redis.set_calls[0]["name"] == "scheduler_lock:oauth_refresh"
    assert fake_redis.set_calls[0]["ex"] == 900
    assert fake_redis.set_calls[0]["nx"] is True


@pytest.mark.asyncio
async def test_scheduler_lock_not_acquired_skips_job(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_redis = _FakeRedisClient(acquire_result=None)

    async def _fake_get_redis_client() -> _FakeRedisClient:
        return fake_redis

    monkeypatch.setattr(scheduler_lock_module, "_get_redis_client", _fake_get_redis_client)

    ran = False
    async with scheduler_lock_module.scheduler_lock(job_name="weekly_digest", ttl_seconds=5400) as should_run:
        if should_run:
            ran = True

    assert ran is False
    assert fake_redis.set_calls
    assert fake_redis.set_calls[0]["name"] == "scheduler_lock:weekly_digest"
    assert fake_redis.eval_calls == []


@pytest.mark.asyncio
async def test_scheduler_lock_backend_unavailable_fails_open(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    fake_redis = _FakeRedisClient(acquire_exc=RedisError("redis unavailable"))

    async def _fake_get_redis_client() -> _FakeRedisClient:
        return fake_redis

    monkeypatch.setattr(scheduler_lock_module, "_get_redis_client", _fake_get_redis_client)

    ran = False
    with caplog.at_level(logging.WARNING, logger="app.core.scheduler_lock"):
        async with scheduler_lock_module.scheduler_lock(job_name="hunt_scheduler", ttl_seconds=300) as should_run:
            if should_run:
                ran = True

    assert ran is True
    assert "scheduler_lock.backend_unavailable" in caplog.text
    assert "phase=acquire" in caplog.text
