"""A queue is answered only once ingest has confirmed the batch, end to end.

Phase 3, findings 4 and 5. The unit suites pin the connector's behaviour and
the scheduler's ordering against fakes. This one drives the whole path — real
``ConnectorScheduler``, real ``IngestClient``, the real Pub/Sub connector with
its real ``httpx`` client and a genuinely signed JWT assertion, a real HTTP
socket standing in for the subscription, and real Postgres holding the
connector row and its cursor.

Why the live version is not redundant
-------------------------------------
Two of the properties cannot be observed anywhere else.

**The cursor has to survive Postgres.** ``record_checkpoint`` merges the
cursor into ``connector_config`` with the JSONB ``||`` operator and
``set_checkpoint`` parses it back on the next poll. Phase 3 changed the shape
that travels through there from ``{"time", "id"}`` to ``{"seen": [...]}``. A
fake engine that records the dict it was handed proves the scheduler called
it; it cannot prove the value round-trips, that the shallow merge replaces
the old shape rather than leaving both, or that the next poll reads back what
the last one wrote.

**"Not acknowledged" has to be observed at the socket.** The guarantee is
about an HTTP request that must not be made. A stubbed method can only show
that a Python call did not happen; a server that records every request to
``:acknowledge`` shows that nothing reached the subscription.

The acknowledgement endpoint here answers 200 and records, and the ingest
stub answers whatever the test tells it to. Neither is more capable than the
real thing in the direction that matters: no stub ever acknowledges on its
own, and the subscription really does hand the same messages back until it
is told not to.

The negative control lives in the phase document and in
``scripts/`` -- reverting the ack placement makes the first test here fail
because ``:acknowledge`` is called during the fetch.
"""

from __future__ import annotations

import contextlib
import json
import os
import threading
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import pytest
import pytest_asyncio

pytestmark = [
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.skipif(
        not os.environ.get("ISOLATION_CONNECTOR_DSN", "").strip(),
        reason="ISOLATION_CONNECTOR_DSN is not set; this suite needs live infrastructure",
    ),
]

_PROJECT = "example-logging"
_SUBSCRIPTION = "aisoc-live-sub"


def _dsn() -> str:
    value = os.environ.get("ISOLATION_CONNECTOR_DSN", "").strip()
    if not value:
        pytest.skip("ISOLATION_CONNECTOR_DSN is not set; this suite needs a live Postgres")
    return value


def _entry(timestamp: str, insert_id: str) -> str:
    import base64

    return base64.b64encode(
        json.dumps(
            {
                "insertId": insert_id,
                "timestamp": timestamp,
                "severity": "NOTICE",
                "logName": f"projects/{_PROJECT}/logs/cloudaudit.googleapis.com%2Factivity",
                "resource": {"type": "gce_instance", "labels": {"project_id": "example-prod"}},
                "protoPayload": {
                    "methodName": "v1.compute.instances.insert",
                    "authenticationInfo": {"principalEmail": "svc@example.com"},
                },
            }
        ).encode()
    ).decode()


class _Subscription(BaseHTTPRequestHandler):
    """A real socket standing in for one Pub/Sub subscription.

    Holds messages until they are acknowledged, which is the property the
    whole guarantee rests on: an unacknowledged message is handed back.
    """

    #: messageId -> (ackId, publishTime, insertId)
    held: dict[str, tuple[str, str, str]] = {}
    acknowledged: list[list[str]] = []
    pulls = 0

    @classmethod
    def reset(cls, messages: dict[str, tuple[str, str, str]]) -> None:
        cls.held = dict(messages)
        cls.acknowledged = []
        cls.pulls = 0

    def _json(self, payload: dict[str, Any], status: int = 200) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b"{}"

        if self.path.endswith("/token"):
            self._json({"access_token": "ya29.live-test", "expires_in": 3599})
            return

        if self.path.endswith(":pull"):
            type(self).pulls += 1
            received = [
                {
                    "ackId": ack_id,
                    "message": {"messageId": message_id, "publishTime": published, "data": _entry(published, insert_id)},
                }
                for message_id, (ack_id, published, insert_id) in type(self).held.items()
            ]
            self._json({"receivedMessages": received})
            return

        if self.path.endswith(":acknowledge"):
            ack_ids = list(json.loads(raw.decode()).get("ackIds") or [])
            type(self).acknowledged.append(ack_ids)
            # Only now does the subscription forget them.
            for message_id, (ack_id, _published, _insert) in list(type(self).held.items()):
                if ack_id in ack_ids:
                    type(self).held.pop(message_id, None)
            self._json({})
            return

        self._json({}, status=404)

    def do_GET(self) -> None:  # noqa: N802
        self._json({"topic": f"projects/{_PROJECT}/topics/t", "ackDeadlineSeconds": 120})

    def log_message(self, *_args) -> None:  # noqa: ANN002
        """Quiet: the default handler prints to stderr on every request."""


class _Ingest(BaseHTTPRequestHandler):
    """Stands in for ``services/ingest``, answering what the test dictates."""

    received: list[dict[str, Any]] = []
    #: ``(status, accepted_of, rejected)``. ``accepted_of`` is "how many of
    #: the submitted events to report accepted"; ``None`` means all of them.
    behaviour: tuple[int, int | None, int] = (200, None, 0)

    @classmethod
    def reset(cls, behaviour: tuple[int, int | None, int] = (200, None, 0)) -> None:
        cls.received = []
        cls.behaviour = behaviour

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b"{}"
        submitted = 0
        with contextlib.suppress(Exception):
            payload = json.loads(raw.decode())
            events = payload.get("events") or []
            submitted = len(events)
            type(self).received.append({"tenant": self.headers.get("X-Tenant-ID"), "events": events})

        status, accepted_of, rejected = type(self).behaviour
        if status >= 500:
            body = b'{"error":"failed to publish events"}'
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        accepted = submitted if accepted_of is None else accepted_of
        body = json.dumps({"accepted": accepted, "rejected": rejected}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args) -> None:  # noqa: ANN002
        """Quiet."""


def _serve(handler) -> tuple[HTTPServer, str]:  # noqa: ANN001
    server = HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_port}"


@pytest.fixture(scope="module")
def subscription():
    server, url = _serve(_Subscription)
    yield url
    server.shutdown()


@pytest.fixture(scope="module")
def ingest():
    server, url = _serve(_Ingest)
    yield url
    server.shutdown()


@pytest.fixture(scope="module")
def service_account(subscription: str) -> str:
    """A real RSA key, so the JWT assertion the connector mints is really signed."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    return json.dumps(
        {
            "type": "service_account",
            "project_id": _PROJECT,
            "private_key": pem,
            "client_email": "aisoc-sink@example-logging.iam.gserviceaccount.com",
            "token_uri": f"{subscription}/token",
        }
    )


@pytest.fixture(scope="module", autouse=True)
def pubsub_root(subscription: str):
    """Point the connector's API root at the local socket.

    The base URL, not the logic: the real client, the real signing, the real
    request shapes and the real response parsing all stay on the path.
    """
    from app.connectors import gcp_pubsub as module

    previous = module._PUBSUB_ROOT
    module._PUBSUB_ROOT = f"{subscription}/v1"
    yield
    module._PUBSUB_ROOT = previous


@pytest.fixture(scope="module", autouse=True)
def allow_loopback():
    """The documented operator path for a vendor on a named internal host.

    The scheduled-poll SSRF guard refuses loopback unconditionally otherwise
    (GHSA-cq4g-g6wp-4m2w), and would correctly refuse to poll this stub.
    """
    previous = os.environ.get("AISOC_SSRF_ALLOW_HOSTS")
    os.environ["AISOC_SSRF_ALLOW_HOSTS"] = "127.0.0.1"
    yield
    if previous is None:
        os.environ.pop("AISOC_SSRF_ALLOW_HOSTS", None)
    else:
        os.environ["AISOC_SSRF_ALLOW_HOSTS"] = previous


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def engine():
    pytest.importorskip("asyncpg")
    from sqlalchemy.ext.asyncio import create_async_engine

    created = create_async_engine(_dsn(), future=True)
    yield created
    await created.dispose()


@pytest_asyncio.fixture(loop_scope="module")
async def connector_row(engine, service_account):  # noqa: ANN001
    """One enabled Pub/Sub connector, written the way the console writes it."""
    import sqlalchemy
    from app.security.credential_vault import get_vault

    tenant_id = uuid.uuid4()
    connector_id = uuid.uuid4()
    auth = get_vault().encrypt_dict(
        {
            "project_id": _PROJECT,
            "subscription_id": _SUBSCRIPTION,
            "service_account_json": service_account,
        }
    )

    async with engine.begin() as conn:
        await conn.execute(
            sqlalchemy.text("INSERT INTO tenants (id, name, slug) VALUES (:i, :n, :s) ON CONFLICT DO NOTHING"),
            {"i": tenant_id, "n": f"q-{tenant_id.hex[:8]}", "s": f"q-{tenant_id.hex[:8]}"},
        )
        await conn.execute(
            sqlalchemy.text(
                "INSERT INTO connectors "
                "(id, tenant_id, connector_type, name, is_enabled, auth_config, connector_config) "
                "VALUES (:i, :t, 'gcp_pubsub', 'live-queue-ack', true, CAST(:a AS jsonb), CAST(:c AS jsonb))"
            ),
            {"i": connector_id, "t": tenant_id, "a": json.dumps(auth), "c": json.dumps({"poll_interval_seconds": 300})},
        )

    yield {"tenant_id": str(tenant_id), "connector_id": connector_id}

    async with engine.begin() as conn:
        await conn.execute(sqlalchemy.text("DELETE FROM connectors WHERE id = :i"), {"i": connector_id})


@pytest_asyncio.fixture(loop_scope="module")
async def scheduler(engine, ingest):  # noqa: ANN001
    """The real scheduler. Polls are driven directly rather than on a timer:
    the timer is covered by ``test_connector_scheduler_live`` and what is
    under test here is the ordering within one poll."""
    from app.ingest_client import IngestClient
    from app.scheduler import ConnectorScheduler
    from app.security.credential_vault import get_vault

    instance = ConnectorScheduler(engine=engine, ingest_client=IngestClient(base_url=ingest), vault=get_vault())
    yield instance


async def _stored_checkpoint(engine, connector_id: uuid.UUID) -> dict[str, Any] | None:  # noqa: ANN001
    import sqlalchemy

    async with engine.connect() as conn:
        result = await conn.execute(
            sqlalchemy.text("SELECT connector_config -> 'checkpoint' AS cp FROM connectors WHERE id = :i"),
            {"i": connector_id},
        )
        row = result.first()
    if row is None or row.cp is None:
        return None
    return row.cp if isinstance(row.cp, dict) else json.loads(row.cp)


class TestIngestRefusesTheBatch:
    async def test_the_subscription_is_not_acknowledged_and_keeps_the_messages(self, scheduler, engine, connector_row) -> None:  # noqa: ANN001
        """Fetch succeeds, ingest answers 500. Nothing may be acknowledged,
        and the messages have to still be there."""
        _Subscription.reset({"m-1": ("ack-1", "2026-10-08T11:00:00Z", "entry-1")})
        _Ingest.reset((500, None, 0))

        await scheduler._poll_one(connector_id=connector_row["connector_id"])

        assert _Subscription.pulls >= 1, "the poll did happen"
        assert _Ingest.received, "and it reached ingest"
        assert _Subscription.acknowledged == [], "nothing may be acknowledged when ingest refused the batch"
        assert set(_Subscription.held) == {"m-1"}, "so the subscription still holds the message"
        assert await _stored_checkpoint(engine, connector_row["connector_id"]) is None

    async def test_the_next_poll_recovers_the_batch_in_full(self, scheduler, engine, connector_row) -> None:  # noqa: ANN001
        """Completeness. 'Not lost' means the events come back."""
        _Subscription.reset({"m-1": ("ack-1", "2026-10-08T11:00:00Z", "entry-1")})
        _Ingest.reset((500, None, 0))
        await scheduler._poll_one(connector_id=connector_row["connector_id"])

        _Ingest.reset((200, None, 0))
        await scheduler._poll_one(connector_id=connector_row["connector_id"])

        submitted = [event["external_id"] for entry in _Ingest.received for event in entry["events"]]
        assert submitted == ["entry-1"]
        assert _Subscription.acknowledged == [["ack-1"]]
        assert _Subscription.held == {}, "and only now does the subscription forget it"


class TestIngestAcceptsOnlyPartOfTheBatch:
    async def test_nothing_is_acknowledged(self, scheduler, engine, connector_row) -> None:  # noqa: ANN001
        """Ingest reports per-event normalization failures as HTTP 200 with
        counts, so a 200 is not on its own a guarantee."""
        _Subscription.reset(
            {
                "m-1": ("ack-1", "2026-10-08T11:00:00Z", "entry-1"),
                "m-2": ("ack-2", "2026-10-08T11:00:01Z", "entry-2"),
            }
        )
        _Ingest.reset((200, 1, 1))

        await scheduler._poll_one(connector_id=connector_row["connector_id"])

        assert _Subscription.acknowledged == []
        assert set(_Subscription.held) == {"m-1", "m-2"}
        assert await _stored_checkpoint(engine, connector_row["connector_id"]) is None


class TestPersistingACursorDoesNotCorruptTheConfig:
    """Found while building the live path above, and not a phase 3 defect —
    it shipped with the cursor itself and affects every connector that has
    one, not only the queue-backed two.

    ``record_checkpoint`` bound its patch with ``cast(json.dumps(...),
    JSONB)``, which serialises twice: Postgres received a JSON string scalar,
    ``jsonb || <scalar>`` coerced both sides to arrays, and one successful
    checkpointed poll rewrote ``connector_config`` from an object to
    ``[{...the config...}, "{\\"checkpoint\\": ...}"]``. The next poll raised
    ``AttributeError: 'list' object has no attribute 'items'`` reading it, the
    poll's broad handler filed that as a failure, and the instance went
    unhealthy permanently with its poll interval and filter rules unreadable.

    Invisible because every scheduler test patches ``record_checkpoint`` with
    a fake that records the dict it was handed, so this statement had never
    been executed by a test at all.
    """

    async def test_the_config_is_still_an_object_afterwards(self, scheduler, engine, connector_row) -> None:  # noqa: ANN001
        import sqlalchemy

        _Subscription.reset({"m-1": ("ack-1", "2026-10-08T11:00:00Z", "entry-1")})
        _Ingest.reset((200, None, 0))

        await scheduler._poll_one(connector_id=connector_row["connector_id"])

        async with engine.connect() as conn:
            result = await conn.execute(
                sqlalchemy.text("SELECT jsonb_typeof(connector_config) AS kind FROM connectors WHERE id = :i"),
                {"i": connector_row["connector_id"]},
            )
            row = result.first()

        assert row is not None
        assert row.kind == "object", (
            f"connector_config is a JSON {row.kind}; the merge coerced it, which destroys the instance's "
            "configuration and makes the next poll raise on .items()"
        )

    async def test_the_next_poll_still_runs(self, scheduler, engine, connector_row) -> None:  # noqa: ANN001
        """The consequence, stated as the thing an operator would notice."""
        _Subscription.reset({"m-1": ("ack-1", "2026-10-08T11:00:00Z", "entry-1")})
        _Ingest.reset((200, None, 0))
        await scheduler._poll_one(connector_id=connector_row["connector_id"])

        _Subscription.reset({"m-2": ("ack-2", "2026-10-08T12:00:00Z", "entry-2")})
        _Ingest.reset((200, None, 0))
        await scheduler._poll_one(connector_id=connector_row["connector_id"])

        assert [e["external_id"] for entry in _Ingest.received for e in entry["events"]] == ["entry-2"], (
            "the second poll produced nothing, so persisting the first cursor broke the instance"
        )

    async def test_the_poll_interval_survives(self, scheduler, engine, connector_row) -> None:  # noqa: ANN001
        """Not only the cursor. The array swallowed the whole config object,
        so the interval and any filter rules went with it."""
        import sqlalchemy

        _Subscription.reset({"m-1": ("ack-1", "2026-10-08T11:00:00Z", "entry-1")})
        _Ingest.reset((200, None, 0))
        await scheduler._poll_one(connector_id=connector_row["connector_id"])

        async with engine.connect() as conn:
            result = await conn.execute(
                sqlalchemy.text("SELECT connector_config -> 'poll_interval_seconds' AS interval FROM connectors WHERE id = :i"),
                {"i": connector_row["connector_id"]},
            )
            row = result.first()

        assert row is not None and row.interval is not None, "the instance's poll interval is no longer readable"


class TestACorruptedConfigIsRecoveredOnRead:
    async def test_a_connector_left_as_an_array_polls_again(self, scheduler, engine, connector_row) -> None:  # noqa: ANN001
        """Recovery for a deployment that already ran the previous release.

        The row is written into the exact shape that release produced, and the
        connector has to resume without an operator running SQL.
        """
        import sqlalchemy

        corrupted = [
            {"poll_interval_seconds": 300},
            json.dumps({"checkpoint": {"time": "2026-10-08T01:00:00Z", "id": "legacy"}}),
        ]
        async with engine.begin() as conn:
            await conn.execute(
                sqlalchemy.text("UPDATE connectors SET connector_config = CAST(:c AS jsonb) WHERE id = :i"),
                {"c": json.dumps(corrupted), "i": connector_row["connector_id"]},
            )

        _Subscription.reset({"m-1": ("ack-1", "2026-10-08T11:00:00Z", "entry-1")})
        _Ingest.reset((200, None, 0))
        await scheduler._poll_one(connector_id=connector_row["connector_id"])

        assert [e["external_id"] for entry in _Ingest.received for e in entry["events"]] == ["entry-1"], (
            "a connector corrupted by the previous release never polls again"
        )
        assert _Subscription.acknowledged == [["ack-1"]]


class TestTheCursorRoundTripsThroughPostgres:
    async def test_it_is_persisted_as_a_set_of_identities(self, scheduler, engine, connector_row) -> None:  # noqa: ANN001
        """The shape phase 3 changed, read back out of the database."""
        _Subscription.reset({"m-1": ("ack-1", "2026-10-08T11:00:00Z", "entry-1")})
        _Ingest.reset((200, None, 0))

        await scheduler._poll_one(connector_id=connector_row["connector_id"])
        stored = await _stored_checkpoint(engine, connector_row["connector_id"])

        assert stored is not None
        assert set(stored) == {"seen"}, "the old (time, id) watermark shape must not survive alongside it"
        from app.connectors.gcp_pubsub import GCPPubSubConnector

        assert stored["seen"] == GCPPubSubConnector.seen_tokens(["m-1"])

    async def test_a_redelivery_is_suppressed_by_what_the_database_holds(self, scheduler, engine, connector_row) -> None:  # noqa: ANN001
        """The whole point of keeping a cursor at all. Pub/Sub is
        at-least-once, and the suppression has to work across the process
        boundary — which means across Postgres."""
        _Subscription.reset({"m-1": ("ack-1", "2026-10-08T11:00:00Z", "entry-1")})
        _Ingest.reset((200, None, 0))
        await scheduler._poll_one(connector_id=connector_row["connector_id"])
        assert [e["external_id"] for entry in _Ingest.received for e in entry["events"]] == ["entry-1"]

        # Redelivered with a fresh ackId, exactly as the vendor does it.
        _Subscription.reset({"m-1": ("ack-1-again", "2026-10-08T11:00:00Z", "entry-1")})
        _Ingest.reset((200, None, 0))
        await scheduler._poll_one(connector_id=connector_row["connector_id"])

        assert [e["external_id"] for entry in _Ingest.received for e in entry["events"]] == [], (
            "the cursor read back from Postgres did not recognise the duplicate"
        )
        assert _Subscription.acknowledged == [["ack-1-again"]], "a duplicate is still a message that has to leave"

    async def test_an_older_entry_arriving_later_is_still_emitted(self, scheduler, engine, connector_row) -> None:  # noqa: ANN001
        """Finding 5, through the real database.

        A sink sets no ordering key, so this entry has never been seen — and
        under the watermark it replaced it would have been dropped on sight,
        after its message had already been acknowledged.
        """
        _Subscription.reset({"m-new": ("ack-new", "2026-10-08T11:00:00Z", "newer")})
        _Ingest.reset((200, None, 0))
        await scheduler._poll_one(connector_id=connector_row["connector_id"])
        assert [e["external_id"] for entry in _Ingest.received for e in entry["events"]] == ["newer"]

        _Subscription.reset({"m-old": ("ack-old", "2026-10-08T09:00:00Z", "older")})
        _Ingest.reset((200, None, 0))
        await scheduler._poll_one(connector_id=connector_row["connector_id"])

        assert [e["external_id"] for entry in _Ingest.received for e in entry["events"]] == ["older"]

    async def test_a_watermark_cursor_left_by_an_earlier_release_is_ignored(self, scheduler, engine, connector_row) -> None:  # noqa: ANN001
        """Upgrade compatibility, against the database an upgrade finds.

        A deployment running the previous release has a ``{"time", "id"}``
        cursor in this column. Reading it would reinstate the behaviour phase
        3 removed; the safe reading is to ignore it and re-emit at most one
        poll's worth.
        """
        import sqlalchemy

        async with engine.begin() as conn:
            await conn.execute(
                sqlalchemy.text("UPDATE connectors SET connector_config = connector_config || CAST(:p AS jsonb) WHERE id = :i"),
                {"p": json.dumps({"checkpoint": {"time": "2026-10-08T23:00:00Z", "id": "zzz"}}), "i": connector_row["connector_id"]},
            )

        _Subscription.reset({"m-1": ("ack-1", "2026-10-08T11:00:00Z", "entry-1")})
        _Ingest.reset((200, None, 0))
        await scheduler._poll_one(connector_id=connector_row["connector_id"])

        assert [e["external_id"] for entry in _Ingest.received for e in entry["events"]] == ["entry-1"], (
            "an event older than the stale watermark was dropped, so the watermark is still being read"
        )
