"""Supervision of the fused-alert triage worker (#1930).

Readiness already reported a dead worker: ``app/main.py`` registers
:attr:`FusedAlertTriageWorker.attached` as a subscription probe and attaches
a done-callback, so a consume loop torn out by a broker fault dropped
``/readyz`` to 503 and logged ``auto_triage_worker.died``. What it could not
do was come back — ``start()`` bootstrapped exactly once, aiokafka's own
reconnect only applies *after* a successful bootstrap, and nothing ever
re-created the task. On the deployment that reported #1930, a broker that was
down for ~18 s at boot cost six days of untriaged alerts (1,058 of them)
while the container sat ``Up`` the whole time.

Harness mirrors ``services/fusion/tests/test_worker_supervision.py``, which
is where this supervision pattern shipped first.
"""

from __future__ import annotations

import asyncio
import contextlib
import sys
from pathlib import Path

import pytest
from aiokafka.errors import AuthenticationFailedError, KafkaConnectionError

_TESTS_DIR = Path(__file__).parent
_AGENTS_ROOT = _TESTS_DIR.parent
if str(_AGENTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_AGENTS_ROOT))

from app.workers import fused_alert_consumer as worker_module  # noqa: E402
from app.workers.fused_alert_consumer import (  # noqa: E402
    FusedAlertTriageWorker,
    permanent_failure_action,
)


class ScriptedConsumer:
    """An ``AIOKafkaConsumer`` stand-in with the two failure sites that matter.

    ``start_error`` models the broker refusing the bootstrap; ``iter_error``
    models a fault tearing the ``async for`` out mid-run. They are different
    code paths in the worker, and only one of them is covered by wrapping the
    consume loop.
    """

    def __init__(self, *, start_error: BaseException | None = None, iter_error: BaseException | None = None) -> None:
        self.start_error = start_error
        self.iter_error = iter_error
        self.starts = 0
        self.stops = 0

    async def start(self) -> None:
        self.starts += 1
        if self.start_error is not None:
            raise self.start_error

    async def stop(self) -> None:
        self.stops += 1

    def __aiter__(self) -> ScriptedConsumer:
        return self

    async def __anext__(self):  # noqa: ANN204
        if self.iter_error is not None:
            await asyncio.sleep(0)
            raise self.iter_error
        # A quiet topic: iterate forever, yield nothing.
        await asyncio.sleep(3600)
        raise AssertionError("unreachable")  # pragma: no cover

    async def commit(self, *_a, **_k) -> None:  # pragma: no cover — no messages
        return None

    async def topics(self) -> set[str]:
        return {"aisoc.alerts.fused"}


@pytest.fixture
def fast_backoff(monkeypatch: pytest.MonkeyPatch):
    """Run the real ``start()`` at test speed.

    Every recovery test drives ``start()`` rather than a supervisor helper,
    because ``start()`` is what ``app/main.py`` creates a task for — with
    supervision deleted from ``start()``, a test that invoked a helper by
    hand would still pass while the product stayed broken.
    """
    monkeypatch.setattr(worker_module, "SUPERVISOR_INITIAL_BACKOFF_SECONDS", 0.01)
    monkeypatch.setattr(worker_module, "SUPERVISOR_MAX_BACKOFF_SECONDS", 0.02)


@pytest.fixture
def kafka_doubles(monkeypatch: pytest.MonkeyPatch):
    """Patch the consumer constructor and record everything it builds."""
    built: list[ScriptedConsumer] = []
    script: list[dict] = []

    def fake_consumer(*_topics, **_kwargs):
        spec = script.pop(0) if script else {}
        made = ScriptedConsumer(**spec)
        built.append(made)
        return made

    monkeypatch.setattr(worker_module, "AIOKafkaConsumer", fake_consumer)
    return built, script


def make_worker() -> FusedAlertTriageWorker:
    return FusedAlertTriageWorker(bootstrap_servers="kafka:29092", topic="aisoc.alerts.fused")


async def run_until(predicate, timeout: float = 2.0) -> bool:
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        if predicate():
            return True
        await asyncio.sleep(0.01)
    return False


async def shut_down(worker: FusedAlertTriageWorker, task: asyncio.Task) -> None:
    """Stop the worker the way the lifespan does, and let the task settle."""
    await worker.stop()
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        _ = await task


# ────────────────────────────────────────────────────────────────────────────
# The recovery gap itself
# ────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_transient_bootstrap_failure_is_retried_until_consumption_resumes(fast_backoff, kafka_doubles) -> None:
    """The #1930 scenario: broker down at boot, back a moment later."""
    built, script = kafka_doubles
    script.extend([{"start_error": KafkaConnectionError("broker is not up yet")}, {}])

    worker = make_worker()
    task = asyncio.create_task(worker.start())
    try:
        assert await run_until(lambda: worker.attached), "worker never re-attached after a transient bootstrap failure"
        assert len(built) >= 2, "supervision never built a second consumer"
        assert built[0].starts == 1
    finally:
        await shut_down(worker, task)


@pytest.mark.asyncio
async def test_fault_tearing_out_the_running_loop_is_also_retried(fast_backoff, kafka_doubles) -> None:
    built, script = kafka_doubles
    script.extend([{"iter_error": RuntimeError("connection reset mid-consume")}, {}])

    worker = make_worker()
    task = asyncio.create_task(worker.start())
    try:
        assert await run_until(lambda: len(built) >= 2 and worker.attached)
    finally:
        await shut_down(worker, task)


@pytest.mark.asyncio
async def test_a_healthy_worker_starts_once_and_stays_attached(kafka_doubles) -> None:
    built, _script = kafka_doubles
    worker = make_worker()
    task = asyncio.create_task(worker.start())
    try:
        assert await run_until(lambda: worker.attached)
        await asyncio.sleep(0.05)
        assert len(built) == 1, "a healthy worker must not be churned by its own supervisor"
    finally:
        await shut_down(worker, task)


# ────────────────────────────────────────────────────────────────────────────
# Permanent-failure classification
# ────────────────────────────────────────────────────────────────────────────


def test_an_unrecoverable_kafka_error_is_classified_with_an_operator_action() -> None:
    action = permanent_failure_action(AuthenticationFailedError("bad credentials"))
    assert action is not None
    assert "credential" in action.lower() or "SASL" in action


def test_a_recoverable_failure_is_not_classified_as_permanent() -> None:
    assert permanent_failure_action(KafkaConnectionError("unreachable")) is None
    assert permanent_failure_action(RuntimeError("anything else")) is None


@pytest.mark.asyncio
async def test_supervision_stops_on_a_permanent_failure_instead_of_churning(fast_backoff, kafka_doubles) -> None:
    built, script = kafka_doubles
    script.append({"start_error": AuthenticationFailedError("bad credentials")})

    worker = make_worker()
    task = asyncio.create_task(worker.start())
    try:
        assert await run_until(task.done), "supervision kept retrying a failure no retry can clear"
        assert len(built) == 1
        assert not worker.attached
    finally:
        await shut_down(worker, task)


# ────────────────────────────────────────────────────────────────────────────
# Supervisor hygiene
# ────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_failed_bootstrap_leaks_no_kafka_client_across_retries(fast_backoff, kafka_doubles) -> None:
    built, script = kafka_doubles
    script.extend(
        [
            {"start_error": KafkaConnectionError("try 1")},
            {"start_error": KafkaConnectionError("try 2")},
            {},
        ]
    )
    worker = make_worker()
    task = asyncio.create_task(worker.start())
    try:
        assert await run_until(lambda: worker.attached)
        for failed in built[:2]:
            assert failed.stops >= 1, "a consumer built by a failed attempt was never stopped"
    finally:
        await shut_down(worker, task)


@pytest.mark.asyncio
async def test_stop_during_a_backoff_window_returns_promptly(kafka_doubles, monkeypatch: pytest.MonkeyPatch) -> None:
    """Shutdown must not wait out an exponential backoff."""
    monkeypatch.setattr(worker_module, "SUPERVISOR_INITIAL_BACKOFF_SECONDS", 30.0)
    monkeypatch.setattr(worker_module, "SUPERVISOR_MAX_BACKOFF_SECONDS", 30.0)
    built, script = kafka_doubles
    script.append({"start_error": KafkaConnectionError("broker down")})

    worker = make_worker()
    task = asyncio.create_task(worker.start())
    try:
        assert await run_until(lambda: len(built) == 1)
        await worker.stop()
        done = await run_until(task.done, timeout=1.0)
        assert done, "stop() during backoff did not return promptly"
    finally:
        task.cancel()
        # Bounded settle. Satisfies both static gates at once: a bare
        # `await task` is CodeQL's py/ineffectual-statement, and binding the
        # Task[None] result is mypy's func-returns-value.
        with contextlib.suppress(asyncio.CancelledError, TimeoutError):
            await asyncio.wait_for(task, timeout=2.0)
