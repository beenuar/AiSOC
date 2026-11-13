from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from app.hunt import scheduler as scheduler_module
from app.hunt.loader import HuntDefinition, HuntSchedule
from app.hunt.scheduler import HuntScheduler


class _Corpus:
    def __init__(self, hunt: HuntDefinition) -> None:
        self._hunt = hunt

    def list(self) -> list[HuntDefinition]:
        return [self._hunt]


@pytest.mark.asyncio
async def test_failed_hunt_is_retried_on_next_tick(monkeypatch: pytest.MonkeyPatch) -> None:
    hunt = HuntDefinition(
        id="retry-me",
        name="Retry me",
        schedule=HuntSchedule(enabled=True, interval_minutes=60),
    )
    scheduler = HuntScheduler(corpus=_Corpus(hunt))  # type: ignore[arg-type]
    times = iter((1_000.0, 1_030.0, 1_040.0))
    monkeypatch.setattr(scheduler_module, "time", SimpleNamespace(time=lambda: next(times)))
    monkeypatch.setattr(scheduler_module, "_load_telemetry", lambda _tenant_ref: [])

    attempts = 0

    async def fail_once(_hunt: HuntDefinition, _events: list[dict[str, Any]]) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RuntimeError("temporary persistence failure")

    monkeypatch.setattr(scheduler, "_run_hunt", fail_once)

    await scheduler._tick()
    await scheduler._tick()
    await scheduler._tick()

    assert attempts == 2
    assert scheduler._last_run[hunt.id] == 1_030.0


@pytest.mark.asyncio
async def test_tick_hands_the_lake_a_resolved_tenant_uuid(monkeypatch: pytest.MonkeyPatch) -> None:
    """A scheduled tick must resolve the tenant ref to a UUID before reading
    the lake.

    The lake's ``tenant_id`` is a ClickHouse UUID column, so the scheduler's
    ``tenant_ref`` default of ``'default'`` (a slug) is a parse error on every
    tick, not a miss — `hunt.telemetry.lake.failed: Cannot parse uuid default`.
    `store` already resolves the ref to a UUID; the lake path got the raw slug.
    """
    import uuid as _uuid

    hunt = HuntDefinition(id="noop", name="Noop", schedule=HuntSchedule(enabled=False, interval_minutes=60))
    scheduler = HuntScheduler(corpus=_Corpus(hunt), tenant_ref="default")  # type: ignore[arg-type]
    resolved = _uuid.UUID("00000000-0000-0000-0000-000000000001")

    async def fake_resolve(ref: str) -> _uuid.UUID | None:
        return resolved if ref == "default" else None

    monkeypatch.setattr(scheduler_module, "resolve_tenant_id", fake_resolve, raising=False)
    monkeypatch.setattr(scheduler_module, "time", SimpleNamespace(time=lambda: 1000.0))

    seen: dict[str, Any] = {}

    def record(tenant: str | None) -> list[dict[str, Any]]:
        seen["tenant"] = tenant
        return []

    monkeypatch.setattr(scheduler_module, "_load_telemetry", record)

    await scheduler._tick()

    assert seen.get("tenant") == str(resolved), f"lake was handed {seen.get('tenant')!r}, not the resolved tenant UUID"
