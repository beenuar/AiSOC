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
