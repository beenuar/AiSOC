"""The connector scheduler, against real Postgres and a real HTTP vendor.

Maturity: the evidence that takes **Scheduled connectors** to Stable.
See `docs/audit/MATURITY_DEFINITION.md` for what the label requires.

Why a live scheduler is the only way to test this
---------------------------------------------------
The defect this suite exists for is the reason "connect a source" never
pulled data on any deployment: `reload_jobs` added every poll job with
`next_run_time=None`, which **APScheduler 3.x registers as PAUSED**. The
scheduler started, the job list looked right, `last_sync` stayed null for
every instance, and nothing logged an error — because nothing had gone
wrong, exactly. The jobs were simply never going to run.

No mock catches that. A test that asserts `add_job` was called with the
right arguments passes whether or not APScheduler will ever fire it;
only a real `AsyncIOScheduler` knows what `next_run_time=None` means.

So this suite starts the real scheduler, with real connector rows in real
Postgres and a real HTTP server standing in for the vendor, and waits for
an event to arrive. The vendor is a stub because we are not testing
Okta's API — but it is a *socket*, not a patched method, so the whole
client path runs.

The negative control
--------------------
The workflow re-injects `next_run_time=None` and requires this suite to
fail. Without that, "an event arrived" could be true because something
else polled.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import threading
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
import pytest_asyncio

# Skip as a *module*, not only in the fixture.
#
# The offline isolation job collects this directory with no stores
# running. With the skip only in the fixture, any test that does not take
# it ran anyway and failed there — which is a failure about the harness,
# reported against a capability.
pytestmark = [
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.skipif(
        not os.environ.get("ISOLATION_CONNECTOR_DSN", "").strip(),
        reason="ISOLATION_CONNECTOR_DSN is not set; this suite needs live infrastructure",
    ),
]

#: What the stub vendor returns, and what the stub ingest receives.
VENDOR_EVENTS = [
    {
        "uuid": "evt-live-0001",
        "published": "2026-10-02T12:00:00.000Z",
        "eventType": "user.session.start",
        "severity": "WARN",
        "displayMessage": "Sign-in from an unusual location",
        "actor": {"alternateId": "j.doe@example.com", "displayName": "J Doe"},
        "client": {"ipAddress": "198.51.100.24"},
        "outcome": {"result": "SUCCESS"},
    }
]


def _dsn() -> str:
    value = os.environ.get("ISOLATION_CONNECTOR_DSN", "").strip()
    if not value:
        pytest.skip("ISOLATION_CONNECTOR_DSN is not set; this suite needs a live Postgres")
    return value


class _Vendor(BaseHTTPRequestHandler):
    """A real HTTP server standing in for the vendor API.

    A socket rather than a patched method, so the connector's own client
    — its headers, its auth, its JSON handling, its pagination — is on
    the path. A patched `fetch_alerts` would skip all of it.
    """

    def do_GET(self) -> None:  # noqa: N802
        # The Okta connector appends `/api/v1/logs`; anything else this
        # stub is asked for still answers, because the point is to be a
        # socket the real client can talk to, not to model Okta.
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        body = json.dumps(VENDOR_EVENTS).encode()
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args) -> None:  # noqa: ANN002
        """Quiet: the default handler prints to stderr on every request."""


class _Ingest(BaseHTTPRequestHandler):
    """Stands in for `services/ingest`, and records what reached it."""

    received: list[dict] = []

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b"{}"
        with contextlib.suppress(Exception):
            _Ingest.received.append(
                {
                    "tenant": self.headers.get("X-Tenant-ID"),
                    "body": json.loads(raw.decode()),
                }
            )
        self.send_response(202)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *_args) -> None:  # noqa: ANN002
        """Quiet."""


def _serve(handler) -> tuple[HTTPServer, str]:  # noqa: ANN001
    server = HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_port}"


@pytest.fixture(scope="module")
def vendor():
    server, url = _serve(_Vendor)
    yield url
    server.shutdown()


@pytest.fixture(scope="module")
def ingest():
    _Ingest.received.clear()
    server, url = _serve(_Ingest)
    yield url
    server.shutdown()


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def engine():
    pytest.importorskip("asyncpg")
    from sqlalchemy.ext.asyncio import create_async_engine

    created = create_async_engine(_dsn(), future=True)
    yield created
    await created.dispose()


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def connector_row(engine, vendor):  # noqa: ANN001
    """One enabled connector instance, written the way the console writes it.

    Module-scoped on purpose. The stub ingest accumulates everything it
    receives, so a connector per test meant a later test comparing the
    accumulated events against a tenant that had only just been created
    — a failure about the fixture, not about the scheduler. One
    connector polling throughout is also closer to how a deployment runs.
    """
    import sqlalchemy
    from app.security.credential_vault import get_vault

    tenant_id = uuid.uuid4()
    connector_id = uuid.uuid4()
    # `domain` and `api_token` are the two arguments OktaConnector takes.
    # Passing anything else makes the scheduler log `bad_config` and skip
    # the poll — which is correct of it, and is why the field names here
    # come from the connector rather than from a convention.
    auth = get_vault().encrypt_dict({"api_token": "stub-token", "domain": vendor})

    async with engine.begin() as conn:
        await conn.execute(
            sqlalchemy.text("INSERT INTO tenants (id, name, slug) VALUES (:i, :n, :s) ON CONFLICT DO NOTHING"),
            {"i": tenant_id, "n": f"conn-{tenant_id.hex[:8]}", "s": f"conn-{tenant_id.hex[:8]}"},
        )
        await conn.execute(
            sqlalchemy.text(
                # `is_enabled`, which is what the table actually calls it.
                # `fetch_enabled_connectors` filters on this column, so a
                # row inserted under any other name is invisible to the
                # scheduler and the suite would fail for a reason that has
                # nothing to do with the scheduler.
                "INSERT INTO connectors "
                "(id, tenant_id, connector_type, name, is_enabled, auth_config, connector_config) "
                "VALUES (:i, :t, 'okta', 'live-sched', true, "
                "CAST(:a AS jsonb), CAST(:c AS jsonb))"
            ),
            {
                "i": connector_id,
                "t": tenant_id,
                "a": json.dumps(auth),
                # Two seconds, so the test does not sit for the five-minute
                # default. The interval is the thing under test only
                # insofar as the job must actually fire.
                "c": json.dumps({"poll_interval_seconds": 2, "domain": vendor}),
            },
        )

    yield {"tenant_id": str(tenant_id), "connector_id": str(connector_id)}

    async with engine.begin() as conn:
        await conn.execute(sqlalchemy.text("DELETE FROM connectors WHERE id = :i"), {"i": connector_id})


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def scheduler(engine, ingest, connector_row):  # noqa: ANN001
    """The real `ConnectorScheduler`, started."""
    from app.ingest_client import IngestClient
    from app.scheduler import ConnectorScheduler
    from app.security.credential_vault import get_vault

    instance = ConnectorScheduler(
        engine=engine,
        ingest_client=IngestClient(base_url=ingest),
        vault=get_vault(),
        reload_interval_seconds=1.0,
    )
    await instance.start()
    yield instance
    await instance.stop()


class TestTheJobIsScheduledToRun:
    async def test_a_job_exists_for_the_enabled_connector(self, scheduler, connector_row) -> None:  # noqa: ANN001
        await asyncio.sleep(2)
        jobs = scheduler.job_diagnostics()
        assert jobs, "the scheduler registered no jobs for an enabled connector"

    async def test_the_job_is_not_paused(self, scheduler, connector_row) -> None:  # noqa: ANN001
        """The defect, stated as a test.

        `next_run_time=None` registers a job as PAUSED. The job list
        looks correct, `last_sync` stays null forever, and nothing logs
        an error — nothing has gone wrong, the job is simply never going
        to run. A mock asserting `add_job` was called cannot tell the
        difference; a real AsyncIOScheduler can.
        """
        await asyncio.sleep(2)
        jobs = scheduler.job_diagnostics()
        paused = [j for j in jobs if j.get("next_run_time") is None]
        assert not paused, (
            f"{len(paused)} of {len(jobs)} jobs have no next_run_time, which APScheduler "
            "treats as PAUSED. This is the defect that meant connecting a source never "
            "pulled data on any deployment."
        )


class TestItActuallyPolls:
    async def test_an_event_reaches_ingest(self, scheduler, connector_row) -> None:  # noqa: ANN001
        """The end of the claim: a connector you enable produces events.

        Waits on the real clock because the thing under test is whether
        a timer fires.
        """
        for _ in range(30):
            if _Ingest.received:
                break
            await asyncio.sleep(1)

        assert _Ingest.received, (
            "no event reached ingest within 30s of enabling a connector with a 2s poll interval. The scheduler is not polling."
        )

    async def test_the_event_carries_its_tenant(self, scheduler, connector_row) -> None:  # noqa: ANN001
        """Ingest routes on `X-Tenant-ID`. Without it the event lands
        nowhere, or worse, somewhere else."""
        for _ in range(30):
            if _Ingest.received:
                break
            await asyncio.sleep(1)
        assert _Ingest.received

        tenants = {entry["tenant"] for entry in _Ingest.received}
        assert connector_row["tenant_id"] in tenants, (
            f"events arrived under {tenants!r}, not the connector's tenant {connector_row['tenant_id']!r}"
        )


class TestItRecordsThatItPolled:
    async def test_last_sync_is_written(self, engine, connector_row) -> None:  # noqa: ANN001
        """`last_sync` staying null across every instance was the symptom
        that surfaced the paused-job defect. It is a product signal, not
        just a test convenience: the console reads it."""
        import sqlalchemy

        for _ in range(30):
            async with engine.connect() as conn:
                result = await conn.execute(
                    sqlalchemy.text("SELECT last_sync FROM connectors WHERE id = CAST(:i AS uuid)"),
                    {"i": connector_row["connector_id"]},
                )
                if (row := result.first()) and row.last_sync is not None:
                    return
            await asyncio.sleep(1)

        pytest.fail("last_sync stayed null, so nothing recorded a successful poll")
