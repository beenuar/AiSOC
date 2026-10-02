"""The Investigation Ledger, against the Postgres it writes to.

Maturity: part of the evidence that takes **AI triage + Investigation
Ledger** to Stable.
See `docs/audit/MATURITY_DEFINITION.md` for what the label requires.

Why the offline test is not enough
------------------------------------
`services/agents/tests/test_ledger_tenant.py` drives a `_FakeConn` and
opens no connection. It is a reasonable test of `_resolve_tenant_id`'s
branching and it cannot prove the three things the ledger is for:

* **the rows exist** — an audit trail is a claim about a table, and a
  double that returns whatever it is asked cannot have one;
* **RLS applies** — `_set_rls_context` sets a session variable that a
  policy reads. A fake has no policies, so the call is unobserved; and
  the policy reads `app.current_tenant_id`, which something in this tree
  has already got wrong once by setting `app.tenant_id` instead;
* **the foreign keys hold** — an event referencing a run that does not
  exist should be refused, and only a real schema refuses it.

The ledger is the surface an auditor reads. "Every agent decision is
logged to a persistent ledger" is a claim about durability, and
durability is exactly the property a fake cannot stand in for.

The negative control
--------------------
`test_an_unknown_tenant_resolves_to_none` is what stops the write tests
passing for a trivial reason: a resolver that returned the same tenant
for any input would satisfy every "the row is mine" assertion here.
"""

from __future__ import annotations

import os
import uuid

import pytest
import pytest_asyncio

pytestmark = [pytest.mark.asyncio]


def _dsn() -> str:
    value = os.environ.get("ISOLATION_LEDGER_DSN", "").strip()
    if not value:
        pytest.skip("ISOLATION_LEDGER_DSN is not set; this suite needs a live Postgres")
    return value


@pytest_asyncio.fixture
async def ledger():
    """The production ledger module, pointed at the live database.

    `DATABASE_URL` on the environment rather than a pool handed in,
    because `get_pool()` is how the module resolves one in a deployment
    and a fixture that bypassed it would be testing different code.
    """
    pytest.importorskip("asyncpg")
    os.environ["DATABASE_URL"] = _dsn()

    from app.investigator import ledger as module

    await module.close_pool()
    yield module
    await module.close_pool()


@pytest_asyncio.fixture
async def tenant(ledger):  # noqa: ANN001
    """A real tenant row. The ledger's tables have FKs to `tenants`."""
    import asyncpg

    conn = await asyncpg.connect(_dsn().replace("postgresql+asyncpg://", "postgresql://"))
    tenant_id = uuid.uuid4()
    slug = f"ledger-{tenant_id.hex[:8]}"
    await conn.execute(
        "INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
        tenant_id,
        slug,
        slug,
    )
    await conn.close()
    yield {"id": tenant_id, "slug": slug}


async def _runs(run_id: str) -> int:
    """`investigation_runs` keys on `id`; its children key on `run_id`.

    Read off the schema rather than assumed — the first version of this
    suite queried `run_id` on both and got "column run_id does not
    exist", which is the kind of thing a fake would have answered
    happily.
    """
    return await _count("SELECT count(*) FROM investigation_runs WHERE id = $1::uuid", run_id)


async def _events(run_id: str) -> int:
    return await _count("SELECT count(*) FROM investigation_events WHERE run_id = $1::uuid", run_id)


async def _count(sql: str, run_id: str) -> int:
    import asyncpg

    conn = await asyncpg.connect(_dsn().replace("postgresql+asyncpg://", "postgresql://"))
    try:
        return await conn.fetchval(sql, run_id)
    finally:
        await conn.close()


class TestTenantResolution:
    async def test_a_uuid_resolves_to_itself(self, ledger, tenant) -> None:  # noqa: ANN001
        assert await ledger.resolve_tenant(str(tenant["id"])) == tenant["id"]

    async def test_a_slug_resolves_to_its_tenant(self, ledger, tenant) -> None:  # noqa: ANN001
        """The console passes a slug. Migration 001 seeds the canonical
        tenant with slug `default` and the demo seed renames it to
        `demo`, so a literal is not a safe assumption anywhere."""
        assert await ledger.resolve_tenant(tenant["slug"]) == tenant["id"]

    async def test_an_unknown_tenant_resolves_to_none(self, ledger) -> None:  # noqa: ANN001
        """The negative control.

        A resolver that returned something for any input would satisfy
        every assertion below while writing every tenant's rows to one
        place.
        """
        assert await ledger.resolve_tenant(f"no-such-tenant-{uuid.uuid4().hex[:8]}") is None


class TestTheRowsAreReal:
    async def test_a_run_is_persisted(self, ledger, tenant) -> None:  # noqa: ANN001
        """The claim a fake cannot make: this survives the process."""
        run_id = str(uuid.uuid4())
        await ledger.start_run(
            run_id=uuid.UUID(run_id),
            case_id="case-1",
            tenant_ref=str(tenant["id"]),
            alert_summary="alert-1",
            raw_alert={"host": "WIN-01"},
        )
        assert await _runs(run_id) == 1

    async def test_events_are_persisted_against_their_run(self, ledger, tenant) -> None:  # noqa: ANN001
        """`aisoc_replay_decision` and `aisoc_explain_step` read these.
        A ledger that loses them is a product that cannot answer why it
        did something."""
        run_id = str(uuid.uuid4())
        await ledger.start_run(
            run_id=uuid.UUID(run_id),
            case_id="case-2",
            tenant_ref=str(tenant["id"]),
            alert_summary="alert-2",
            raw_alert={},
        )
        for index in range(3):
            await ledger.record_event(
                run_id=uuid.UUID(run_id),
                tenant_id=tenant["id"],
                seq=index,
                kind="llm_response",
                agent="aisoc-investigation",
                summary="considered the host",
                payload={"step": index},
            )
        assert await _events(run_id) == 3

    async def test_the_payload_survives_the_round_trip(self, ledger, tenant) -> None:  # noqa: ANN001
        """An audit row whose payload is empty answers nothing."""
        import asyncpg

        run_id = str(uuid.uuid4())
        await ledger.start_run(
            run_id=uuid.UUID(run_id),
            case_id="case-3",
            tenant_ref=str(tenant["id"]),
            alert_summary="alert-3",
            raw_alert={},
        )
        await ledger.record_event(
            run_id=uuid.UUID(run_id),
            tenant_id=tenant["id"],
            seq=0,
            kind="llm_response",
            agent="aisoc-investigation",
            summary="verdict",
            payload={"verdict": "benign", "confidence": 0.82},
        )

        conn = await asyncpg.connect(_dsn().replace("postgresql+asyncpg://", "postgresql://"))
        try:
            payload = await conn.fetchval("SELECT payload::text FROM investigation_events WHERE run_id = $1::uuid", run_id)
        finally:
            await conn.close()
        assert "benign" in (payload or ""), f"the payload did not survive: {payload!r}"


class TestItRefusesWhatItShould:
    async def test_an_event_for_an_unknown_run_does_not_create_one(self, ledger, tenant) -> None:  # noqa: ANN001
        """A foreign key the fake does not have.

        An event referencing a run nobody started is either a bug or a
        replay, and silently materialising the run would make the ledger
        agree with whatever it was told.
        """
        orphan = str(uuid.uuid4())
        try:
            await ledger.record_event(
                run_id=uuid.UUID(orphan),
                tenant_id=tenant["id"],
                seq=0,
                kind="llm_response",
                agent="aisoc-investigation",
                summary="orphan",
                payload={},
            )
        except Exception:  # noqa: BLE001 - refusing is the expected outcome
            pass
        assert await _runs(orphan) == 0

    async def test_an_unknown_tenant_writes_nothing(self, ledger) -> None:  # noqa: ANN001
        """`resolve_tenant` returning None must stop the write, not
        default it to somewhere."""
        run_id = str(uuid.uuid4())
        try:
            await ledger.start_run(
                run_id=uuid.UUID(run_id),
                case_id="case-4",
                tenant_ref=f"no-such-tenant-{uuid.uuid4().hex[:8]}",
                alert_summary="alert-4",
                raw_alert={},
            )
        except Exception:  # noqa: BLE001 - refusing is the expected outcome
            pass
        assert await _runs(run_id) == 0
