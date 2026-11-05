"""Supervision of the fusion Kafka worker.

Readiness already reported a dead worker before any of this existed:
``app/main.py`` registers :attr:`FusionWorker.attached` as a subscription
probe, so a consume loop torn out by a broker fault drops ``/readyz`` to 503
and logs why. What it could not do was come back — the task ended and nothing
restarted it, so recovery meant an operator noticing and restarting the
container.

These tests cover the recovery, and the three ways a supervisor goes wrong:
retrying something no retry can fix, leaking a client on every attempt, and
being so busy retrying that a healthy worker never starts.
"""

from __future__ import annotations

import asyncio
import contextlib
from typing import cast

import pytest
from aiokafka.errors import AuthenticationFailedError, KafkaConnectionError
from app._health import install_health_routes, register_subscription
from app.services.alert_sink import AlertSink
from app.workers import consumer as consumer_module
from app.workers.consumer import FusionWorker, permanent_failure_action
from fastapi import FastAPI
from fastapi.testclient import TestClient


class ScriptedConsumer:
    """An ``AIOKafkaConsumer`` stand-in with the two failure sites that matter.

    ``start_error`` models the broker refusing or not answering the bootstrap;
    ``iter_error`` models a fault that tears the ``async for`` out mid-run.
    Those are different code paths in the worker and only one of them is
    covered by wrapping the consume loop, which is the distinction this file
    exists to hold.
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
        # A quiet topic: iterate forever, yield nothing. Never StopAsyncIteration,
        # which a real consumer does not raise either.
        await asyncio.sleep(3600)
        raise AssertionError("unreachable")  # pragma: no cover

    async def commit(self, *_a, **_k) -> None:  # pragma: no cover — no messages
        return None

    async def topics(self) -> set[str]:
        return {"aisoc.alerts.raw"}


class ScriptedProducer:
    def __init__(self) -> None:
        self.starts = 0
        self.stops = 0

    async def start(self) -> None:
        self.starts += 1

    async def stop(self) -> None:
        self.stops += 1


class CountingSink:
    """An ``AlertSink`` stand-in, present because ``_teardown`` does not null it.

    The Kafka handles are set to None once closed, so a second teardown skips
    them whether or not it is guarded. The sink is how a repeated teardown
    becomes visible at all.
    """

    def __init__(self) -> None:
        self.starts = 0
        self.stops = 0

    async def start(self) -> None:
        self.starts += 1

    async def stop(self) -> None:
        self.stops += 1


@pytest.fixture
def fast_backoff(monkeypatch):
    """Run the real ``start()`` at test speed.

    Every recovery test drives ``start()`` rather than ``run_forever``,
    because ``start()`` is what ``app/main.py`` creates a task for and the
    two can disagree: with supervision deleted from ``start()`` a test that
    calls ``run_forever`` itself still passes, having proved only that the
    supervisor it invoked by hand works.
    """
    monkeypatch.setattr(consumer_module, "SUPERVISOR_INITIAL_BACKOFF_SECONDS", 0.01)
    monkeypatch.setattr(consumer_module, "SUPERVISOR_MAX_BACKOFF_SECONDS", 0.02)


@pytest.fixture
def kafka_doubles(monkeypatch):
    """Patch the two client constructors and record everything they build."""
    built: dict[str, list] = {"consumers": [], "producers": []}
    script: dict[str, object] = {"consumers": []}

    def fake_consumer(*_topics, **_kwargs):
        queued = script["consumers"]
        spec = queued.pop(0) if queued else {}
        made = ScriptedConsumer(**spec)
        built["consumers"].append(made)
        return made

    def fake_producer(**_kwargs):
        made = ScriptedProducer()
        built["producers"].append(made)
        return made

    monkeypatch.setattr(consumer_module, "AIOKafkaConsumer", fake_consumer)
    monkeypatch.setattr(consumer_module, "AIOKafkaProducer", fake_producer)
    return built, script


def make_worker(sink: CountingSink | None = None) -> FusionWorker:
    """A worker with only the attributes start/stop touch.

    Built without ``__init__`` on purpose: a real one needs a FusionEngine and
    a Postgres pool, neither of which the supervision path reads.
    """
    worker = FusionWorker.__new__(FusionWorker)
    for attribute in (
        "_engine",
        "_dlq",
        "_lake",
        "_detector",
        "_windowed",
        "_first_seen",
        "_baselines",
        "_long_horizon",
        "_api_behaviour",
        "_weak_signals",
        "_ueba_cache",
        "_ai_assets",
        "_overlays",
        "_sessions",
        "_outbox",
        "_relay",
        "_consumer",
        "_producer",
        "_flush_task",
    ):
        setattr(worker, attribute, None)
    # Cast rather than subclass: the double implements the two methods
    # teardown calls and nothing else, so it cannot quietly grow more
    # capability than the real sink has. The target type is written as an
    # expression rather than a string so the import is a use at runtime —
    # inside a string only the type checker reads it, and static analysis
    # correctly reports the import as unused.
    worker._sink = cast(AlertSink | None, sink)
    worker._durable_capture = False
    worker._running = False
    worker._attached = False
    worker._attach_count = 0
    worker._torn_down = False
    worker._stop_event = asyncio.Event()
    worker._loop_done = asyncio.Event()
    worker._loop_done.set()
    worker._inflight = 0
    return worker


async def run_until(predicate, timeout: float = 2.0) -> bool:
    """Poll *predicate* rather than sleeping a guessed interval."""
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        if predicate():
            return True
        await asyncio.sleep(0.01)
    return False


async def shut_down(worker: FusionWorker, task: asyncio.Task) -> None:
    """Stop the worker the way the lifespan does, and let the task settle.

    ``stop()`` sets the stop event, so supervision returns on its own and the
    cancel is only a backstop for a task that did not. Leaving a running task
    behind leaks it into the next test.
    """
    await worker.stop()
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        _ = await task  # await the cancellation to settle; the result is unused


# --------------------------------------------------------------------------
# The recovery gap itself.
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_transient_broker_failure_is_retried_until_consumption_resumes(fast_backoff, kafka_doubles):
    """The gap this closes: the worker could report its death and not undo it.

    Drives ``start()``, so deleting supervision from it fails this test:
    unsupervised, the first ``KafkaConnectionError`` leaves ``start()``, the
    worker never attaches, and ``/readyz`` stays 503 until somebody restarts
    the container.
    """
    built, script = kafka_doubles
    # Two cold-boot failures, then the broker answers.
    script["consumers"] = [
        {"start_error": KafkaConnectionError("bootstrap: no brokers available")},
        {"start_error": KafkaConnectionError("bootstrap: no brokers available")},
        {},
    ]
    worker = make_worker()

    task = asyncio.create_task(worker.start())
    attached = await run_until(lambda: worker.attached)

    assert attached, "the worker never recovered: supervision did not retry a transient failure"
    assert len(built["consumers"]) == 3, "expected two failed attempts and one that attached"
    await shut_down(worker, task)


@pytest.mark.asyncio
async def test_readiness_recovers_on_its_own_when_a_retry_attaches(fast_backoff, kafka_doubles):
    """503 while retrying, 200 again afterwards, with no operator action.

    The probe is the one ``app/main.py`` already registers. A second probe
    reading the same flag would only restate this.
    """
    built, script = kafka_doubles
    script["consumers"] = [{"start_error": KafkaConnectionError("no brokers available")}, {}]
    worker = make_worker()

    app = FastAPI()
    mark_ready, _ = install_health_routes(app, service_name="aisoc-fusion")
    register_subscription(app, "alerts+raw_events", lambda: worker.attached)
    mark_ready()
    client = TestClient(app)

    # Held long enough that the 503 below is observed inside the backoff
    # window rather than racing the retry that ends it.
    task = asyncio.create_task(worker.run_forever(initial_backoff_seconds=0.3, max_backoff_seconds=0.3))

    assert await run_until(lambda: len(built["consumers"]) == 1)
    during_backoff = client.get("/readyz")
    assert during_backoff.status_code == 503
    assert during_backoff.json()["detached"] == ["alerts+raw_events"]

    assert await run_until(lambda: worker.attached), "the retry never attached"
    recovered = client.get("/readyz")
    assert recovered.status_code == 200
    assert recovered.json()["subscriptions"]["alerts+raw_events"]["attached"] is True

    await shut_down(worker, task)


@pytest.mark.asyncio
async def test_a_fault_that_tears_out_the_running_loop_is_also_retried(fast_backoff, kafka_doubles):
    """Bootstrap and mid-run are different code paths; both must recover."""
    built, script = kafka_doubles
    script["consumers"] = [{"iter_error": KafkaConnectionError("connection lost mid-stream")}, {}]
    worker = make_worker()

    task = asyncio.create_task(worker.start())

    assert await run_until(lambda: len(built["consumers"]) == 2 and worker.attached)
    await shut_down(worker, task)


# --------------------------------------------------------------------------
# Positive control. A supervisor stuck retrying reads as working caution.
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_healthy_worker_starts_once_and_stays_attached(kafka_doubles):
    built, _script = kafka_doubles
    worker = make_worker()

    task = asyncio.create_task(worker.start())

    assert await run_until(lambda: worker.attached), "a healthy worker did not attach"
    # Give a misbehaving supervisor room to churn before asserting it did not.
    await asyncio.sleep(0.2)
    assert worker.attached is True
    assert len(built["consumers"]) == 1, "a healthy worker was restarted for no reason"
    assert built["consumers"][0].starts == 1
    assert built["producers"][0].starts == 1

    await shut_down(worker, task)


# --------------------------------------------------------------------------
# Permanent vs transient.
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "error",
    [
        AuthenticationFailedError("SASL authentication failed"),
        consumer_module.TopicAuthorizationFailedError(),
        consumer_module.GroupAuthorizationFailedError(),
    ],
)
def test_an_unrecoverable_kafka_error_is_classified_with_an_operator_action(error):
    action = permanent_failure_action(error)
    assert action is not None, f"{type(error).__name__} would be retried forever"
    assert action.strip(), "a permanent verdict with no next move is just a louder silence"


@pytest.mark.parametrize(
    "error",
    [KafkaConnectionError("no brokers available"), OSError("[Errno -3] Temporary failure in name resolution")],
)
def test_a_recoverable_failure_is_not_classified_as_permanent(error):
    """The other direction. Calling a blip permanent keeps the service down."""
    assert permanent_failure_action(error) is None


@pytest.mark.asyncio
async def test_supervision_stops_on_a_permanent_failure_instead_of_churning(fast_backoff, kafka_doubles):
    """A bad credential retried every 60s forever is not an improvement.

    Unbounded retry is what turns a misconfiguration into churn an operator
    reads as ordinary noise, so the loop stops and the log line it stops on
    names what to change. ``asyncio.wait_for`` is the assertion: a supervisor
    that keeps retrying never returns and the test times out.
    """
    built, script = kafka_doubles
    script["consumers"] = [{"start_error": AuthenticationFailedError("SASL authentication failed")}] * 20
    worker = make_worker()

    await asyncio.wait_for(worker.start(), timeout=2.0)

    assert len(built["consumers"]) == 1, "a permanent failure was retried"
    assert worker.attached is False


# --------------------------------------------------------------------------
# Teardown: exactly once per attempt, nothing left open across a retry.
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_failed_bootstrap_leaks_no_kafka_client_across_retries(fast_backoff, kafka_doubles):
    """Every client a failed attempt built must be closed before the next one.

    The next attempt reassigns ``_consumer`` and ``_producer``, so a client
    left open here is unreachable and never closed — one more per retry, for
    as long as the broker is down, which is exactly when retries are frequent.
    """
    built, script = kafka_doubles
    script["consumers"] = [{"start_error": KafkaConnectionError("no brokers available")}] * 6
    worker = make_worker()

    task = asyncio.create_task(worker.start())
    assert await run_until(lambda: len(built["consumers"]) >= 4)
    await shut_down(worker, task)

    leaked_consumers = [c for c in built["consumers"] if c.stops == 0]
    leaked_producers = [p for p in built["producers"] if p.stops == 0]
    assert leaked_consumers == [], f"{len(leaked_consumers)} consumers were built and never closed"
    assert leaked_producers == [], f"{len(leaked_producers)} producers were built and never closed"


@pytest.mark.asyncio
async def test_a_clean_shutdown_tears_down_exactly_once(kafka_doubles):
    """``stop()`` and the attempt's own ``finally`` both run, and must not double.

    ``stop()`` closes the consumer to wake the idle ``async for``; that wakes
    the attempt, which then runs its own teardown. Both paths are wanted —
    the guard is what stops the second one stopping the sink a second time.
    """
    built, _script = kafka_doubles
    sink = CountingSink()
    worker = make_worker(sink=sink)

    task = asyncio.create_task(worker.start())
    assert await run_until(lambda: worker.attached)

    await worker.stop()
    await asyncio.sleep(0.05)  # let the woken loop run its finally
    await shut_down(worker, task)

    assert sink.stops == 1, f"teardown ran {sink.stops} times on one shutdown"
    assert built["consumers"][0].stops == 1
    assert built["producers"][0].stops == 1


@pytest.mark.asyncio
async def test_stop_during_a_backoff_window_returns_promptly(kafka_doubles):
    """Shutdown must not wait out a 60s backoff.

    A rolling restart during a broker outage would otherwise look like a hang
    and get the container killed rather than drained.
    """
    _built, script = kafka_doubles
    script["consumers"] = [{"start_error": KafkaConnectionError("no brokers available")}] * 10
    worker = make_worker()

    task = asyncio.create_task(worker.run_forever(initial_backoff_seconds=30.0, max_backoff_seconds=60.0))
    await asyncio.sleep(0.1)  # land inside the first backoff

    await worker.stop()
    await asyncio.wait_for(task, timeout=1.0)  # raises TimeoutError if it waited out the backoff
