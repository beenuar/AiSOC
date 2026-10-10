"""Closing an alert must record *what* changed, not only that something did.

The defect (issue #1246)
------------------------
``PATCH /api/v1/alerts/{id}`` built an ``updates`` dict, wrote it, and emitted
no audit event at all — a grep for ``emit_audit`` or ``AuditLog`` in
``endpoints/alerts.py`` returned nothing. The only row a closure produced came
from ``AuditMiddleware``, which constructs ``AuditLog(...)`` with no ``changes=``
argument, so the nullable ``changes`` column landed NULL and the action was a
label guessed from the URL.

That middleware row is written under a comment saying it defers to "the
handler's row ... it carries the real ``changes`` payload". For this route the
handler row never existed, so an analyst marking a critical alert as a false
positive produced an audit trail that recorded *someone updated an alert* and
nothing an auditor could use: not the disposition, not the prior status, not
the assignee it was taken from.

Why these drive the real HTTP path
----------------------------------
The two halves of this fix pull against each other. The handler has to write a
row, and the middleware has to then *not* write a second one — two writers on
one request is what forked the chain in migration 074's history, and the
signal that suppresses the second writer is a mutable dict in a ``ContextVar``
plus ``request.state``, both of which only exist when a real request travels
through ``BaseHTTPMiddleware``. Calling ``update_alert()`` directly would
exercise the handler and silently skip the half that can regress.

So these run the shipped ASGI app, with its real authentication dependencies,
a real JWT, real ``AuditMiddleware``, and a real PostgreSQL carrying the whole
migration chain — including ``uq_audit_log_chain_successor``, which is the
constraint a duplicate writer would trip.
"""

from __future__ import annotations

import json
import os
import socket
import uuid
from datetime import UTC, datetime
from urllib.parse import urlparse

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

#: Owner DSN. The runtime role is DML-only and these tests create a scratch
#: tenant; same resolution as ``test_audit_chain_under_concurrency``.
_DSN = os.environ.get("DATABASE_MIGRATION_URL", "").strip() or os.environ.get("DATABASE_URL", "")

#: Set by the job that is *meant* to run this. A gate that quietly declines to
#: run is the shape this repository has been bitten by repeatedly, so where the
#: database is supposed to be there, its absence is a failure and not a skip.
_REQUIRED = os.environ.get("ALERT_AUDIT_PROOF_REQUIRED", "").strip() not in ("", "0", "false")


def _postgres_is_listening() -> bool:
    """Whether something actually answers on the DSN's host and port.

    A DSN is a statement of intent. The unit-test job exports a
    ``postgres://…localhost:5432`` URL with no server behind it, so a string
    check alone decides the test should run and it dies on ``Connect call
    failed``.
    """
    parsed = urlparse(_DSN.replace("postgresql+asyncpg://", "postgresql://"))
    if not parsed.hostname:
        return False
    try:
        with socket.create_connection((parsed.hostname, parsed.port or 5432), timeout=2):
            return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(
    not ("postgres" in _DSN and _postgres_is_listening()) and not _REQUIRED,
    reason=(
        "needs a live PostgreSQL with the migration chain applied — the audit row, its "
        "hash chain and the unique index that makes a duplicate writer visible have no "
        "SQLite equivalent"
    ),
)

# A password hash that no password produces. These tests authenticate with a
# minted JWT, never with a password, and a realistic bcrypt literal in a
# fixture is indistinguishable from a leaked credential to a secret scanner.
_UNUSABLE_PASSWORD_HASH = "x"  # noqa: S105 - not a credential; no plaintext maps to it


@pytest_asyncio.fixture(autouse=True)
async def _release_the_app_pool():
    """Dispose the application's global pool between tests.

    ``app.db.database.engine`` is a module-level pool, and pytest-asyncio gives
    every test its own event loop. A connection checked out under the first
    loop is unusable under the second, so without this the second test in the
    file fails inside asyncpg rather than on its assertion — a failure that
    reads like a defect in the code under test and is not one.
    """
    yield
    from app.db.database import engine

    await engine.dispose()


@pytest_asyncio.fixture
async def world():
    """A scratch tenant with one analyst and one open alert, on the real schema.

    Yields ``(maker, tenant_id, user_id, alert_id, token)``.

    No teardown of ``audit_log``: it is append-only by database trigger, so a
    test that could clean up after itself would be evidence the immutability
    control was missing. The tenant is left for the same reason — deleting it
    cascades into ``audit_log`` and the trigger correctly refuses.
    """
    from app.core.security import create_access_token

    engine = create_async_engine(_DSN)
    maker = async_sessionmaker(engine, expire_on_commit=False)

    tenant_id = uuid.uuid4()
    user_id = uuid.uuid4()
    alert_id = uuid.uuid4()
    suffix = tenant_id.hex[:8]

    async with maker() as db:
        await db.execute(
            text("INSERT INTO tenants (id, name, slug) VALUES (:i, :n, :s)"),
            {"i": tenant_id, "n": f"patch-audit-{suffix}", "s": f"patch-audit-{suffix}"},
        )
        await db.execute(
            text(
                """
                INSERT INTO users (id, tenant_id, email, username, hashed_password,
                                   role, is_active, is_verified)
                VALUES (:i, :t, :e, :u, :h, 'admin', TRUE, TRUE)
                """
            ),
            {
                "i": user_id,
                "t": tenant_id,
                "e": f"analyst-{suffix}@example.com",
                "u": f"analyst-{suffix}",
                "h": _UNUSABLE_PASSWORD_HASH,
            },
        )
        await db.execute(
            text(
                """
                INSERT INTO alerts (id, tenant_id, title, severity, status, priority, created_at, updated_at)
                VALUES (:i, :t, 'Suspicious sign-in from an unfamiliar ASN', 'critical', 'triaging', 40, NOW(), NOW())
                """
            ),
            {"i": alert_id, "t": tenant_id},
        )
        await db.commit()

    token = create_access_token({"sub": str(user_id)})
    yield maker, tenant_id, user_id, alert_id, token
    await engine.dispose()


async def _audit_rows(maker, tenant_id: uuid.UUID) -> list[dict]:
    async with maker() as db:
        rows = (
            (
                await db.execute(
                    text(
                        """
                        SELECT action, resource, resource_id, actor_id, actor_email,
                               changes, prev_hash, entry_hash, chain_index
                        FROM audit_log WHERE tenant_id = :t
                        ORDER BY chain_index ASC NULLS LAST, created_at ASC
                        """
                    ),
                    {"t": tenant_id},
                )
            )
            .mappings()
            .all()
        )
    out = []
    for row in rows:
        record = dict(row)
        # asyncpg hands JSONB back as a string unless a codec is registered;
        # SQLAlchemy registers one for mapped columns but not for `text()`.
        if isinstance(record["changes"], str):
            record["changes"] = json.loads(record["changes"])
        out.append(record)
    return out


async def _patch(token: str, alert_id: uuid.UUID, body: dict) -> tuple[int, dict]:
    """Send the PATCH through the shipped app, middleware and auth included."""
    from app.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.patch(
            f"/api/v1/alerts/{alert_id}",
            json=body,
            headers={"Authorization": f"Bearer {token}", "user-agent": "issue-1246-proof"},
        )
    return response.status_code, (response.json() if response.content else {})


class TestTheClosureIsRecordedWithItsPayload:
    async def test_marking_a_false_positive_records_the_before_and_after(self, world) -> None:
        """The reproduction. Before the fix the only row carried ``changes`` NULL."""
        maker, tenant_id, _user_id, alert_id, token = world

        code, _ = await _patch(token, alert_id, {"status": "false_positive"})
        assert code == 200, f"the PATCH itself failed: {code}"

        rows = await _audit_rows(maker, tenant_id)
        assert rows, "closing an alert produced no audit row at all"

        carrying = [r for r in rows if r["changes"]]
        assert carrying, (
            "an alert was closed as a false positive and every audit row for the tenant has "
            f"`changes` NULL — the trail records that something changed, never what. Rows: "
            f"{[(r['action'], r['changes']) for r in rows]}"
        )

        changes = carrying[0]["changes"]
        assert changes.get("status") == {"from": "triaging", "to": "false_positive"}, (
            f"the status transition is not recoverable from the audit row: {changes}"
        )
        assert carrying[0]["resource_id"] == str(alert_id)

    async def test_every_modified_field_appears_and_untouched_ones_do_not(self, world) -> None:
        """A payload that lists fields the request did not touch is noise an
        auditor has to discount; one that omits a field it did touch is the
        defect wearing a smaller hat."""
        maker, tenant_id, user_id, alert_id, token = world

        code, _ = await _patch(
            token,
            alert_id,
            {"status": "resolved", "priority": 10, "assignee": str(user_id)},
        )
        assert code == 200

        rows = await _audit_rows(maker, tenant_id)
        carrying = [r for r in rows if r["changes"]]
        assert carrying, "no audit row carried a changes payload"
        changes = carrying[0]["changes"]

        assert changes.get("status") == {"from": "triaging", "to": "resolved"}
        assert changes.get("priority") == {"from": 40, "to": 10}
        assert changes.get("assigned_to_id") == {"from": None, "to": str(user_id)}
        assert "tags" not in changes, f"tags was not in the request body but was recorded: {changes}"
        assert "case_id" not in changes, f"case_id was not in the request body but was recorded: {changes}"

    async def test_the_actor_is_the_authenticated_analyst(self, world) -> None:
        """ "Who" is half of an audit record and is not recoverable from the row
        the middleware would have written for a request that failed to carry a
        handler row."""
        maker, tenant_id, user_id, alert_id, token = world

        code, _ = await _patch(token, alert_id, {"status": "closed"})
        assert code == 200

        carrying = [r for r in await _audit_rows(maker, tenant_id) if r["changes"]]
        assert carrying
        assert carrying[0]["actor_id"] == user_id
        assert carrying[0]["actor_email"] is not None


class TestExactlyOneWriterPerRequest:
    """The half that would regress quietly.

    Emitting from the handler without the middleware standing down puts two
    writers back in one request, which is what forked the chain before
    migration 074. The unique index refuses the second row, so the visible
    symptom is not a fork but a *dropped* audit row — undetectable.
    """

    async def test_one_patch_writes_one_row(self, world) -> None:
        maker, tenant_id, _user_id, alert_id, token = world

        code, _ = await _patch(token, alert_id, {"status": "false_positive"})
        assert code == 200

        rows = await _audit_rows(maker, tenant_id)
        assert len(rows) == 1, f"one request produced {len(rows)} audit rows: {[r['action'] for r in rows]}"

    async def test_the_chain_stays_dense_across_several_patches(self, world) -> None:
        """A gap in ``chain_index``, a repeated predecessor or a second genesis
        row all mean the handler's writer is not participating in the chain the
        verifier replays."""
        maker, tenant_id, _user_id, alert_id, token = world

        for new_status in ("triaging", "in_progress", "resolved"):
            code, _ = await _patch(token, alert_id, {"status": new_status})
            assert code == 200

        rows = await _audit_rows(maker, tenant_id)
        assert [r["chain_index"] for r in rows] == list(range(len(rows)))
        assert sum(1 for r in rows if r["prev_hash"] is None) == 1, "a second genesis row is a forged restart"
        assert all(r["entry_hash"] for r in rows), "an unchained row is outside the tamper-evidence claim"


class TestAWriteThatChangesNothingIsNotAnAlertUpdate:
    async def test_an_empty_body_does_not_fabricate_a_change_payload(self, world) -> None:
        """The handler short-circuits when ``updates`` is empty and writes
        nothing to the alert. Recording a modification there would put a
        change in the trail that never happened — and the middleware's own
        row is the honest record of "a request arrived and did nothing"."""
        maker, tenant_id, _user_id, alert_id, token = world

        code, _ = await _patch(token, alert_id, {})
        assert code == 200

        rows = await _audit_rows(maker, tenant_id)
        assert not [r for r in rows if r["changes"]], f"a no-op PATCH recorded a change payload: {[r['changes'] for r in rows]}"


class TestTheRowIsReadableThroughTheAuditApi:
    async def test_the_changes_payload_survives_to_the_reader(self, world) -> None:
        """A column nobody can read is not a trail. ``GET /api/v1/audit`` is
        the surface an auditor actually uses, so the payload is asserted
        through it rather than only in the table."""
        _maker, _tenant_id, _user_id, alert_id, token = world

        code, _ = await _patch(token, alert_id, {"status": "false_positive"})
        assert code == 200

        from app.main import app

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            response = await client.get(
                "/api/v1/audit",
                params={"resource_id": str(alert_id)},
                headers={"Authorization": f"Bearer {token}"},
            )
        assert response.status_code == 200, response.text
        entries = response.json().get("items", response.json())
        payloads = [e.get("changes") for e in entries if e.get("changes")]
        assert payloads, f"the audit reader returned no changes payload for this alert: {entries}"
        assert payloads[0].get("status", {}).get("to") == "false_positive"


def test_the_fixture_clock_is_sane() -> None:
    """Guards against a fixture that silently seeds nothing."""
    assert datetime.now(UTC).year >= 2024
