"""``/readyz`` against a broker that goes away, with a real aiokafka client.

The unit suite can prove that ``/readyz`` reports whatever the probe
returns. What it cannot prove is the premise the whole fix rests on: that
``attached`` keeps answering **yes** for a consumer whose broker has gone,
because aiokafka's reconnect lives inside ``__anext__`` and the ``async for``
never exits. A double that models the broker going away models the author's
belief about aiokafka, not aiokafka.

So this suite starts a real ``AIOKafkaConsumer`` against a real broker,
takes the broker away underneath it, and asks both questions:

* the subscription flag — "am I consuming" — which stays true, and
* the bounded metadata fetch — "can I reach the broker" — which must not.

The broker is taken away with a TCP proxy rather than by stopping the
container, because that is the failure the live pass actually recorded
(``KafkaConnectionError: Connection at kafka:29092 closed``) and because a
test that has to drive Docker to make its assertion cannot run as an
ordinary test. The client's sockets are closed and nothing accepts a new
one: from the client's side that is indistinguishable from a broker that
died, which is the point.

    docker run -d --name aisoc-agents-redpanda -p 59093:9092 \\
        docker.redpanda.com/redpandadata/redpanda:v24.2.7 \\
        redpanda start --mode dev-container --smp 1 --memory 1G \\
        --kafka-addr PLAINTEXT://0.0.0.0:9092 \\
        --advertise-kafka-addr PLAINTEXT://127.0.0.1:59093

    AISOC_TEST_KAFKA=127.0.0.1:59093 pytest tests/integration/

Skips loudly rather than passing quietly when no broker is configured.
"""

from __future__ import annotations

import asyncio
import contextlib
import os

import httpx
import pytest
from app._health import install_health_routes, register_dependency, register_subscription
from app.workers.fused_alert_consumer import FusedAlertTriageWorker
from fastapi import FastAPI

#: The real broker, which the proxy forwards to.
BROKER = os.getenv("AISOC_TEST_KAFKA", "").strip()
#: The port the proxy binds. It **must** be the port the broker advertises,
#: or the client leaves the proxy behind the moment bootstrap hands it the
#: cluster's real address and the outage this suite stages never reaches it.
PROXY_PORT = os.getenv("AISOC_TEST_KAFKA_PROXY_PORT", "").strip()
pytestmark = pytest.mark.skipif(
    not BROKER or not PROXY_PORT,
    reason=(
        "set AISOC_TEST_KAFKA=host:port (the real broker) and "
        "AISOC_TEST_KAFKA_PROXY_PORT=<the port that broker advertises> "
        "to run the stopped-broker readiness proof"
    ),
)


class _BrokerProxy:
    """A TCP forwarder to the real broker that can be taken away.

    ``stop()`` closes the listener *and* every forwarded connection, which is
    what makes it a broker outage rather than a broker refusing new clients:
    an already-connected consumer has to notice too.
    """

    def __init__(self, upstream: str, port: int) -> None:
        host, _, upstream_port = upstream.rpartition(":")
        self._upstream = (host or "127.0.0.1", int(upstream_port))
        self.port = port
        self._server: asyncio.AbstractServer | None = None
        self._pipes: list[asyncio.Task[None]] = []
        self._writers: list[asyncio.StreamWriter] = []

    @property
    def address(self) -> str:
        return f"127.0.0.1:{self.port}"

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", self.port)

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            up_reader, up_writer = await asyncio.open_connection(*self._upstream)
        except OSError:
            writer.close()
            return
        self._writers.extend([writer, up_writer])
        self._pipes.append(asyncio.create_task(self._pump(reader, up_writer)))
        self._pipes.append(asyncio.create_task(self._pump(up_reader, writer)))

    @staticmethod
    async def _pump(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        with contextlib.suppress(Exception):
            while chunk := await reader.read(65536):
                writer.write(chunk)
                await writer.drain()
        with contextlib.suppress(Exception):
            writer.close()

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            with contextlib.suppress(Exception):
                await self._server.wait_closed()
            self._server = None
        for writer in self._writers:
            with contextlib.suppress(Exception):
                writer.close()
        for pipe in self._pipes:
            pipe.cancel()
        self._writers.clear()
        self._pipes.clear()


async def _drain(worker: FusedAlertTriageWorker, consume: asyncio.Task, proxy: _BrokerProxy) -> None:
    """Tear the probe down without leaving a task holding an exception.

    ``gather(..., return_exceptions=True)`` rather than a bare ``await`` on
    the cancelled task: the outcome is expected and discarded, and a bare
    await of a value nobody reads is an ineffectual statement.
    """
    consume.cancel()
    # `CancelledError` derives from `BaseException`, not `Exception`, so
    # suppressing only `Exception` lets the cancellation this teardown
    # *caused* fail the test it is tearing down.
    with contextlib.suppress(Exception, asyncio.CancelledError):
        await worker.stop()
    await asyncio.gather(consume, return_exceptions=True)
    await proxy.stop()


async def _readyz(worker: FusedAlertTriageWorker) -> tuple[int, dict]:
    """Drive the real health plumbing the service wires in ``app/main.py``.

    Over ASGI on *this* event loop rather than through ``TestClient``, which
    runs the app on a loop of its own. An aiokafka client is bound to the loop
    it was created on, so the synchronous client turns every probe into a
    ``RuntimeError`` — a probe stuck closed, which is the exact shape a
    positive control exists to catch and is a property of the harness rather
    than of the service, where the app and the worker share one loop.
    """
    app = FastAPI()
    mark_ready, _ = install_health_routes(app, service_name="aisoc-agents")
    register_subscription(app, worker.topic, lambda: worker.attached)
    register_dependency(app, "kafka", worker.broker_reachable)
    mark_ready()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://probe") as client:
        response = await client.get("/readyz")
    return response.status_code, response.json()


@pytest.mark.asyncio
async def test_readyz_degrades_when_the_broker_goes_away() -> None:
    """The live-QA reproduction: 200 with `attached` true through an outage."""
    proxy = _BrokerProxy(BROKER, int(PROXY_PORT))
    await proxy.start()
    worker = FusedAlertTriageWorker(
        bootstrap_servers=proxy.address,
        topic=f"aisoc.readyz.probe.{os.getpid()}",
        group_id=f"aisoc-readyz-probe-{os.getpid()}",
    )
    consume = asyncio.create_task(worker.start())
    try:
        for _ in range(100):
            if worker.attached:
                break
            await asyncio.sleep(0.1)
        assert worker.attached, "the worker never attached to the real broker"

        # Positive control first. A probe that is stuck closed reads as
        # working caution and would hold every healthy replica out of the
        # load balancer, so "it fails when the broker is gone" is only half
        # the claim.
        status, body = await _readyz(worker)
        assert status == 200, f"a healthy broker was reported unready: {body}"
        assert body["kafka"] is True

        await proxy.stop()
        await asyncio.sleep(0.5)

        status, body = await _readyz(worker)

        # The flag the probe used to read. It is still true, which is the
        # whole defect: nothing about the consume loop iterating says the
        # broker is there.
        assert worker.attached is True, "aiokafka exited the loop — re-check the premise, not the fix"
        assert status == 503, f"/readyz stayed green through a broker outage: {body}"
        assert body["kafka"] is False
        assert body["status"] == "degraded"
        assert "kafka" in body.get("detached", [])
        # The subscription is still attached and says so. Both facts belong in
        # the body: "consuming" and "can reach the broker" are what an
        # operator needs to tell a quiet topic from a dead one.
        assert body["subscriptions"] == {worker.topic: {"attached": True}}
    finally:
        await _drain(worker, consume, proxy)


@pytest.mark.asyncio
async def test_readyz_reports_the_subscription_state_not_just_its_name() -> None:
    """A bare topic name answers "which" and never "how".

    The live pass read ``{"subscriptions": ["aisoc.alerts.fused"]}`` beside a
    200 and could not tell from the body whether that subscription was
    attached — the one thing the key exists to say.
    """
    proxy = _BrokerProxy(BROKER, int(PROXY_PORT))
    await proxy.start()
    worker = FusedAlertTriageWorker(
        bootstrap_servers=proxy.address,
        topic=f"aisoc.readyz.state.{os.getpid()}",
        group_id=f"aisoc-readyz-state-{os.getpid()}",
    )
    consume = asyncio.create_task(worker.start())
    try:
        for _ in range(100):
            if worker.attached:
                break
            await asyncio.sleep(0.1)
        assert worker.attached

        _status, body = await _readyz(worker)
        # The shape `services/ingest` already publishes, rather than a third
        # spelling: a map from the subscription's name to its state.
        assert body["subscriptions"] == {worker.topic: {"attached": True}}
    finally:
        await _drain(worker, consume, proxy)
