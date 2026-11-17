"""Supervision of the UEBA Kafka consumer (#1930).

v23.x made the death *visible* (``_log_consumer_exit``, ``/readyz`` 503
"detached") and nothing made it recoverable: ``run()`` bootstrapped once,
``restart: unless-stopped`` only acts on process exit, and Compose does not
restart an unhealthy container. On the reporting deployment that was six
days of ``unhealthy`` and ~827k unscored events.

Harness mirrors ``services/fusion/tests/test_worker_supervision.py`` and the
agents twin ``test_triage_worker_supervision.py``.
"""

from __future__ import annotations

import asyncio
import contextlib

import pytest
from aiokafka.errors import AuthenticationFailedError, KafkaConnectionError
from app.services import kafka_consumer as consumer_module
from app.services.kafka_consumer import UEBAKafkaConsumer, permanent_failure_action


class ScriptedConsumer:
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
        await asyncio.sleep(3600)
        raise AssertionError("unreachable")  # pragma: no cover


class ScriptedProducer:
    def __init__(self, *, start_error: BaseException | None = None) -> None:
        self.start_error = start_error
        self.starts = 0
        self.stops = 0

    async def start(self) -> None:
        self.starts += 1
        if self.start_error is not None:
            raise self.start_error

    async def stop(self) -> None:
        self.stops += 1


@pytest.fixture
def fast_backoff(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(consumer_module, "SUPERVISOR_INITIAL_BACKOFF_SECONDS", 0.01)
    monkeypatch.setattr(consumer_module, "SUPERVISOR_MAX_BACKOFF_SECONDS", 0.02)


@pytest.fixture
def kafka_doubles(monkeypatch: pytest.MonkeyPatch):
    built: dict[str, list] = {"consumers": [], "producers": []}
    script: dict[str, list] = {"consumers": [], "producers": []}

    def fake_consumer(*_topics, **_kwargs):
        queued = script["consumers"]
        made = ScriptedConsumer(**(queued.pop(0) if queued else {}))
        built["consumers"].append(made)
        return made

    def fake_producer(**_kwargs):
        queued = script["producers"]
        made = ScriptedProducer(**(queued.pop(0) if queued else {}))
        built["producers"].append(made)
        return made

    monkeypatch.setattr(consumer_module, "AIOKafkaConsumer", fake_consumer)
    monkeypatch.setattr(consumer_module, "AIOKafkaProducer", fake_producer)
    return built, script


async def run_until(predicate, timeout: float = 2.0) -> bool:
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        if predicate():
            return True
        await asyncio.sleep(0.01)
    return False


async def shut_down(consumer: UEBAKafkaConsumer, task: asyncio.Task) -> None:
    """Stop the way app/main.py does on shutdown: cancel and settle."""
    consumer.stop()
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        _ = await task


@pytest.mark.asyncio
async def test_transient_bootstrap_failure_is_retried_until_consumption_resumes(fast_backoff, kafka_doubles) -> None:
    """The #1930 scenario: Kafka not up yet when the service starts."""
    built, script = kafka_doubles
    script["consumers"].extend([{"start_error": KafkaConnectionError("broker is not up yet")}, {}])

    consumer = UEBAKafkaConsumer()
    task = asyncio.create_task(consumer.run())
    try:
        assert await run_until(lambda: consumer.attached), "consumer never re-attached after a transient failure"
        assert len(built["consumers"]) >= 2
    finally:
        await shut_down(consumer, task)


@pytest.mark.asyncio
async def test_fault_tearing_out_the_running_loop_is_also_retried(fast_backoff, kafka_doubles) -> None:
    built, script = kafka_doubles
    script["consumers"].extend([{"iter_error": RuntimeError("connection reset mid-consume")}, {}])

    consumer = UEBAKafkaConsumer()
    task = asyncio.create_task(consumer.run())
    try:
        assert await run_until(lambda: len(built["consumers"]) >= 2 and consumer.attached)
    finally:
        await shut_down(consumer, task)


@pytest.mark.asyncio
async def test_a_healthy_consumer_starts_once_and_stays_attached(kafka_doubles) -> None:
    built, _script = kafka_doubles
    consumer = UEBAKafkaConsumer()
    task = asyncio.create_task(consumer.run())
    try:
        assert await run_until(lambda: consumer.attached)
        await asyncio.sleep(0.05)
        assert len(built["consumers"]) == 1
    finally:
        await shut_down(consumer, task)


def test_an_unrecoverable_kafka_error_is_classified_with_an_operator_action() -> None:
    assert permanent_failure_action(AuthenticationFailedError("bad credentials")) is not None
    assert permanent_failure_action(KafkaConnectionError("unreachable")) is None
    assert permanent_failure_action(RuntimeError("anything else")) is None


@pytest.mark.asyncio
async def test_supervision_stops_on_a_permanent_failure_instead_of_churning(fast_backoff, kafka_doubles) -> None:
    built, script = kafka_doubles
    script["consumers"].append({"start_error": AuthenticationFailedError("bad credentials")})

    consumer = UEBAKafkaConsumer()
    task = asyncio.create_task(consumer.run())
    try:
        assert await run_until(task.done), "supervision kept retrying a failure no retry can clear"
        assert len(built["consumers"]) == 1
        assert not consumer.attached
    finally:
        await shut_down(consumer, task)


@pytest.mark.asyncio
async def test_a_failed_producer_start_still_stops_the_started_consumer(fast_backoff, kafka_doubles) -> None:
    """The client leak the restructure fixed: the old shape started both
    clients before entering its try block, so a raise out of
    ``producer.start()`` left a started consumer nothing would ever stop."""
    built, script = kafka_doubles
    script["producers"].extend([{"start_error": KafkaConnectionError("producer refused")}, {}])

    consumer = UEBAKafkaConsumer()
    task = asyncio.create_task(consumer.run())
    try:
        assert await run_until(lambda: consumer.attached)
        assert built["consumers"][0].stops >= 1, "consumer from the failed attempt was never stopped"
    finally:
        await shut_down(consumer, task)


@pytest.mark.asyncio
async def test_stop_during_a_backoff_window_returns_promptly(kafka_doubles, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(consumer_module, "SUPERVISOR_INITIAL_BACKOFF_SECONDS", 30.0)
    monkeypatch.setattr(consumer_module, "SUPERVISOR_MAX_BACKOFF_SECONDS", 30.0)
    built, script = kafka_doubles
    script["consumers"].append({"start_error": KafkaConnectionError("broker down")})

    consumer = UEBAKafkaConsumer()
    task = asyncio.create_task(consumer.run())
    try:
        assert await run_until(lambda: len(built["consumers"]) == 1)
        consumer.stop()
        assert await run_until(task.done, timeout=1.0), "stop() during backoff did not return promptly"
    finally:
        task.cancel()
        # Bounded settle. Satisfies both static gates at once: a bare
        # `await task` is CodeQL's py/ineffectual-statement, and binding the
        # Task[None] result is mypy's func-returns-value.
        with contextlib.suppress(asyncio.CancelledError, TimeoutError):
            await asyncio.wait_for(task, timeout=2.0)
