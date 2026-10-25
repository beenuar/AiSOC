from __future__ import annotations

import asyncio
import time

from app._health import install_health_routes, register_dependency
from app.workers.consumer import FusionWorker
from fastapi import FastAPI
from fastapi.testclient import TestClient


def test_dependency_is_reported_before_startup_finishes() -> None:
    app = FastAPI()
    install_health_routes(app, service_name="test")
    register_dependency(app, "database", lambda: False)

    response = TestClient(app).get("/readyz")

    assert response.status_code == 503
    assert response.json()["status"] == "starting"
    assert response.json()["database"] is False


def test_required_dependency_failure_returns_503_and_named_key() -> None:
    app = FastAPI()
    mark_ready, _ = install_health_routes(app, service_name="test")
    register_dependency(app, "database", lambda: False)
    mark_ready()

    response = TestClient(app).get("/readyz")

    assert response.status_code == 503
    assert response.json()["database"] is False
    assert "database" in response.json()["detached"]


def test_optional_dependency_failure_reports_degraded_but_stays_ready() -> None:
    app = FastAPI()
    mark_ready, _ = install_health_routes(app, service_name="test")
    register_dependency(app, "lake_writer", lambda: False, required=False)
    mark_ready()

    response = TestClient(app).get("/readyz")

    assert response.status_code == 200
    assert response.json()["status"] == "ready_degraded"
    assert response.json()["lake_writer"] is False


def test_slow_dependency_is_bounded_and_reported_down() -> None:
    app = FastAPI()
    mark_ready, _ = install_health_routes(app, service_name="test")

    async def slow_probe() -> bool:
        await asyncio.sleep(10)
        return True

    register_dependency(app, "database", slow_probe)
    mark_ready()

    started = time.monotonic()
    response = TestClient(app).get("/readyz")

    assert time.monotonic() - started < 2.5
    assert response.status_code == 503
    assert response.json()["database"] is False
    assert response.json()["dependency_errors"]["database"] == "TimeoutError"


class _StubConsumer:
    """Stands in for ``AIOKafkaConsumer`` at exactly one method.

    Deliberately minimal. The thing under test is which *question* fusion
    asks about Kafka, not aiokafka's metadata path: a double that answered
    `topics()` cheerfully while modelling nothing else would be the "the test
    double was more capable than the real thing" trap, so this one only ever
    does what a real broker does on each side of the split -- answer, or
    raise the error the live chaos run recorded.
    """

    def __init__(self, *, error: Exception | None = None) -> None:
        self._error = error
        self.asked = 0

    async def topics(self) -> set[str]:
        self.asked += 1
        if self._error is not None:
            raise self._error
        return {"aisoc.alerts.raw", "aisoc.raw_events"}


def _worker_with(consumer: _StubConsumer | None, *, attached: bool) -> FusionWorker:
    """A worker with its Kafka state set, without building the whole engine."""
    worker = FusionWorker.__new__(FusionWorker)
    worker._consumer = consumer
    worker._attached = attached
    return worker


def test_kafka_readiness_reports_down_while_the_loop_is_still_attached() -> None:
    """The defect the weekly chaos `kafka` leg measured, pinned.

    ``attached`` answers "is the consume loop iterating", and aiokafka keeps
    it true across a broker outage because the retry lives inside
    ``__anext__``. During the outage fusion logged ``NodeNotReadyError``
    continuously while ``/readyz`` answered 200 with ``kafka: true`` -- a
    consumer attached to nothing, indistinguishable from one on a quiet
    topic. Readiness has to ask the broker.
    """
    consumer = _StubConsumer(error=RuntimeError("NodeNotReadyError: node id 1"))
    worker = _worker_with(consumer, attached=True)

    app = FastAPI()
    mark_ready, _ = install_health_routes(app, service_name="aisoc-fusion")
    register_dependency(app, "kafka", worker.broker_reachable)
    mark_ready()

    response = TestClient(app).get("/readyz")

    # The flag the old probe read is still true: without asking the broker
    # there is nothing here to notice.
    assert worker.attached is True
    assert consumer.asked == 1, "readiness did not ask the broker at all"
    assert response.status_code == 503
    assert response.json()["kafka"] is False


def test_kafka_readiness_stays_up_while_the_broker_answers() -> None:
    """The positive control: a working broker must not be reported as down.

    A fail-closed probe that is stuck closed reads as working caution, and
    would take fusion out of the load balancer on every healthy deployment.
    """
    consumer = _StubConsumer()
    worker = _worker_with(consumer, attached=True)

    app = FastAPI()
    mark_ready, _ = install_health_routes(app, service_name="aisoc-fusion")
    register_dependency(app, "kafka", worker.broker_reachable)
    mark_ready()

    response = TestClient(app).get("/readyz")

    assert consumer.asked == 1
    assert response.status_code == 200
    assert response.json()["kafka"] is True


def test_kafka_readiness_is_down_before_the_consumer_exists() -> None:
    """No consumer is not a reachable broker, and must not read as one."""
    worker = _worker_with(None, attached=False)

    app = FastAPI()
    mark_ready, _ = install_health_routes(app, service_name="aisoc-fusion")
    register_dependency(app, "kafka", worker.broker_reachable)
    mark_ready()

    assert TestClient(app).get("/readyz").json()["kafka"] is False
