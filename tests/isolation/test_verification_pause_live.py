"""The verification pause, against real Postgres and the real SQL.

Depth plan 5.4.

Why this suite exists at all
---------------------------
``services/agents/tests/test_playbook_verification.py`` drives the whole
workflow against a double, and that double is written to honour the
predicates the real statements carry. It is still a double, and this
repository's most expensive recurring defect is a double that is more
capable than the thing it stands in for. Specifically, nothing offline can
tell you:

* whether migration 102's DDL applies at all, or whether its ``CHECK``
  constraints accept the five outcome values the code writes — a rejected
  value would surface as "the answer was not recorded" on a live
  deployment and nowhere else;
* whether the conditional ``UPDATE``s really are atomic claims. The double
  asserts the predicates by reading them out of the SQL text; Postgres
  asserts them by refusing the second writer.

So the same four functions run here against the real schema.

What is deliberately not covered
--------------------------------
The engine. This suite is about the storage layer and says so: the
branching, the escalation and the refusals are covered offline, where they
can run on every pull request without a container.
"""

from __future__ import annotations

import json
import os
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import pytest_asyncio

pytestmark = [
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.skipif(
        not os.environ.get("ISOLATION_VERIFICATION_DSN", "").strip(),
        reason="ISOLATION_VERIFICATION_DSN is not set; this suite needs a live Postgres",
    ),
]

REPO_ROOT = Path(__file__).resolve().parents[2]

#: The three migrations that own this table, applied in order. Not the whole
#: chain: `001_init` brings up the entire product schema and this suite is
#: about three columns and one constraint. The two stub tables below stand
#: in for the only foreign keys that reach outside those files.
_MIGRATIONS = (
    "081_playbook_pauses.sql",
    "096_playbook_wait_pauses.sql",
    "104_playbook_verification.sql",
)

#: Enough of `tenants`, `users` and `aisoc_scim_users` for the foreign keys
#: and the manager lookup. Written here rather than imported from
#: `001_init` so this file states exactly what it depends on, and so a
#: change to an unrelated column in the real schema cannot break it.
_STUBS = """
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TABLE IF NOT EXISTS tenants (id UUID PRIMARY KEY, name TEXT);
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS aisoc_scim_users (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    external_id TEXT
);
CREATE OR REPLACE FUNCTION current_tenant_id() RETURNS UUID AS $$
    SELECT NULLIF(current_setting('app.current_tenant_id', true), '')::uuid;
$$ LANGUAGE sql STABLE;
"""


def _dsn() -> str:
    value = os.environ.get("ISOLATION_VERIFICATION_DSN", "").strip()
    if not value:
        pytest.skip("ISOLATION_VERIFICATION_DSN is not set")
    return value


@pytest_asyncio.fixture(loop_scope="module", scope="module")
async def pool() -> AsyncIterator[object]:
    import asyncpg

    created = await asyncpg.create_pool(_dsn(), min_size=1, max_size=4)
    assert created is not None
    async with created.acquire() as conn:
        # In CI the whole chain is already applied by the job, and
        # re-running the stubs there would replace `current_tenant_id()` —
        # the function every RLS policy in the product calls — with the
        # simplified one below. So the schema is detected rather than
        # assumed, and the standalone path is the only one that writes.
        migrated = await conn.fetchval(
            "SELECT 1 FROM information_schema.columns WHERE table_name = 'aisoc_playbook_pauses' AND column_name = 'verification_stage'"
        )
        if not migrated:
            await conn.execute(_STUBS)
            for name in _MIGRATIONS:
                await conn.execute((REPO_ROOT / "services" / "api" / "migrations" / name).read_text(encoding="utf-8"))
    yield created
    await created.close()


@pytest_asyncio.fixture(loop_scope="module")
async def wired(pool: Any, monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[tuple[ModuleType, str]]:
    """Point `app.playbook.pause` at the live pool and seed one tenant."""
    import sys

    sys.path.insert(0, str(REPO_ROOT / "services" / "agents"))
    from app.playbook import pause as playbook_pause

    async def _pool() -> object:
        return pool

    monkeypatch.setattr(playbook_pause, "_pool", _pool)

    tenant_id = str(uuid.uuid4())
    async with pool.acquire() as conn:
        # `slug` is NOT NULL since 001_init; derived from the id so two
        # module-scoped runs cannot collide on the UNIQUE constraint.
        await conn.execute("INSERT INTO tenants (id, name, slug) VALUES ($1::uuid, 'live', 'live-' || left($1::text, 8))", tenant_id)
    yield playbook_pause, tenant_id


async def _suspend(playbook_pause: ModuleType, tenant_id: str, token: str) -> Any:
    return await playbook_pause.suspend(
        kind="verification",
        resume_at=datetime.now(UTC) + timedelta(minutes=30),
        resume_token=token,
        tenant_id=tenant_id,
        run_id=f"run-{uuid.uuid4().hex[:12]}",
        playbook_id="pb-live",
        playbook_name="live verification",
        step_index=0,
        step_id="ask",
        run_context={"tenant_id": tenant_id},
        step_results=[],
        verification_stage="user",
        verification_subject="alice@corp.test",
    )


async def test_the_migration_accepts_a_verification_pause(wired: tuple[ModuleType, str]) -> None:
    """`kind = 'verification'` and a stage both pass the real CHECKs."""
    playbook_pause, tenant_id = wired
    pause = await _suspend(playbook_pause, tenant_id, uuid.uuid4().hex)

    assert pause is not None
    assert pause.kind == "verification"
    assert pause.verification_stage == "user"
    assert pause.verification_subject == "alice@corp.test"


@pytest.mark.parametrize("outcome", ["acknowledged", "denied", "unsure", "timed_out", "no_manager"])
async def test_every_outcome_the_code_writes_passes_the_check(wired: tuple[ModuleType, str], outcome: str) -> None:
    """The constraint and the vocabulary must agree.

    They are written in two files — the migration's ``CHECK`` and
    ``verification.OUTCOMES`` — and a value in one and not the other is a
    row Postgres refuses at the moment somebody answers.
    """
    playbook_pause, tenant_id = wired
    pause = await _suspend(playbook_pause, tenant_id, uuid.uuid4().hex)
    assert pause is not None

    assert await playbook_pause.record_verification_outcome(  # type: ignore[attr-defined]
        pause_id=pause.id, tenant_id=tenant_id, outcome=outcome
    )


async def test_an_outcome_is_written_once(wired: tuple[ModuleType, str]) -> None:
    """Postgres refuses the second answer, not the double.

    ``verification_outcome IS NULL`` in the predicate is what makes a
    double click resolve once, and this is the only place that claim is
    tested against a real transaction.
    """
    playbook_pause, tenant_id = wired
    pause = await _suspend(playbook_pause, tenant_id, uuid.uuid4().hex)
    assert pause is not None

    assert await playbook_pause.record_verification_outcome(pause_id=pause.id, tenant_id=tenant_id, outcome="denied")  # type: ignore[attr-defined]
    assert not await playbook_pause.record_verification_outcome(  # type: ignore[attr-defined]
        pause_id=pause.id, tenant_id=tenant_id, outcome="acknowledged"
    )


async def test_a_pause_escalates_once_and_keeps_its_token(wired: tuple[ModuleType, str]) -> None:
    """Two sweeper replicas racing the same row escalate it once."""
    playbook_pause, tenant_id = wired
    token = uuid.uuid4().hex
    pause = await _suspend(playbook_pause, tenant_id, token)
    assert pause is not None
    deadline = datetime.now(UTC) + timedelta(hours=1)

    assert await playbook_pause.escalate_to_manager(  # type: ignore[attr-defined]
        pause_id=pause.id, tenant_id=tenant_id, manager="bob@corp.test", resume_at=deadline
    )
    assert not await playbook_pause.escalate_to_manager(  # type: ignore[attr-defined]
        pause_id=pause.id, tenant_id=tenant_id, manager="carol@corp.test", resume_at=deadline
    )

    found = await playbook_pause.find_verification_by_token(resume_token=token)  # type: ignore[attr-defined]
    assert found is not None
    assert found.verification_stage == "manager"
    assert found.verification_manager == "bob@corp.test"


async def test_a_wait_token_does_not_resolve_as_a_verification(wired: tuple[ModuleType, str]) -> None:
    """``kind`` is in the predicate, so the two callbacks cannot cross."""
    playbook_pause, tenant_id = wired
    token = uuid.uuid4().hex
    await playbook_pause.suspend(  # type: ignore[attr-defined]
        kind="wait",
        resume_at=None,
        resume_token=token,
        tenant_id=tenant_id,
        run_id=f"run-wait-{uuid.uuid4().hex[:12]}",
        playbook_id="pb-live",
        playbook_name="live wait",
        step_index=0,
        step_id="hold",
        run_context={},
        step_results=[],
    )

    assert await playbook_pause.find_verification_by_token(resume_token=token) is None  # type: ignore[attr-defined]
    assert await playbook_pause.find_wait_by_token(resume_token=token) is not None  # type: ignore[attr-defined]


async def test_due_verifications_sees_only_waiting_verification_rows(wired: tuple[ModuleType, str]) -> None:
    """The sweep's predicate, against the real partial index."""
    playbook_pause, tenant_id = wired
    pause = await _suspend(playbook_pause, tenant_id, uuid.uuid4().hex)
    assert pause is not None

    later = datetime.now(UTC) + timedelta(hours=2)
    due_ids = {p.id for p in await playbook_pause.due_verifications(now=later, limit=100)}  # type: ignore[attr-defined]
    assert pause.id in due_ids

    await playbook_pause.resolve(pause_id=pause.id, tenant_id=tenant_id, status="resumed", resolution="answered")  # type: ignore[attr-defined]
    due_ids = {p.id for p in await playbook_pause.due_verifications(now=later, limit=100)}  # type: ignore[attr-defined]
    assert pause.id not in due_ids


async def test_the_policy_table_is_tenant_scoped_and_default_deny(pool: object) -> None:
    """A tenant with no row opts into nothing, and cannot read another's.

    The RLS policy carries an unbound arm so the agents service — which
    reads this from a consumer that binds no tenant — is not locked out.
    That arm is exactly the thing worth checking: with a tenant bound, it
    must not leak.
    """
    import asyncpg

    tenant_a, tenant_b = str(uuid.uuid4()), str(uuid.uuid4())
    async with pool.acquire() as conn:  # type: ignore[attr-defined]
        await conn.execute(
            "INSERT INTO tenants (id, name, slug) VALUES "
            "($1::uuid, 'a', 'a-' || left($1::text, 8)), "
            "($2::uuid, 'b', 'b-' || left($2::text, 8))",
            tenant_a,
            tenant_b,
        )
        await conn.execute(
            "INSERT INTO aisoc_verification_policies (tenant_id, alert_class) VALUES ($1::uuid, 'impossible_travel')",
            tenant_a,
        )

    # A fresh connection on the suite's own DSN, which in CI is the DML-only
    # runtime role `aisoc_app`. The table is FORCE ROW LEVEL SECURITY, so the
    # only roles RLS cannot bind are superusers and BYPASSRLS holders — the
    # exact mistake that made 92 policies decorative in this repository once
    # already. That property is proved rather than assumed: a DSN quietly
    # re-pointed at a superuser would turn both assertions below into
    # tautologies, and the suite must fail loudly instead. (An earlier
    # revision created a dedicated reader role here, which needs CREATEROLE —
    # a privilege the runtime role rightly does not hold.)
    reader = await asyncpg.connect(_dsn())
    try:
        caps = await reader.fetchrow("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user")
        assert caps is not None and not caps["rolsuper"] and not caps["rolbypassrls"], (
            "the suite DSN resolves to a role RLS cannot bind (superuser or BYPASSRLS), "
            "so this test would prove nothing — point ISOLATION_VERIFICATION_DSN at a "
            "plain DML role such as aisoc_app"
        )

        await reader.execute("SELECT set_config('app.current_tenant_id', $1, false)", tenant_b)
        rows = await reader.fetch("SELECT alert_class FROM aisoc_verification_policies")
        assert rows == [], "tenant B read tenant A's verification policy"

        await reader.execute("SELECT set_config('app.current_tenant_id', $1, false)", tenant_a)
        rows = await reader.fetch("SELECT alert_class FROM aisoc_verification_policies")
        assert [r["alert_class"] for r in rows] == ["impossible_travel"]
    finally:
        await reader.close()


async def test_the_stored_context_survives_a_round_trip(wired: tuple[ModuleType, str]) -> None:
    """The escalation reads the step's params back off the pause.

    They go in as JSON and come back as a string from asyncpg, which
    ``_row_to_pause`` decodes. A change there would leave the escalation
    asking on the default channel with the default message.
    """
    playbook_pause, tenant_id = wired
    token = uuid.uuid4().hex
    await playbook_pause.suspend(  # type: ignore[attr-defined]
        kind="verification",
        resume_at=datetime.now(UTC) + timedelta(minutes=30),
        resume_token=token,
        tenant_id=tenant_id,
        run_id=f"run-ctx-{uuid.uuid4().hex[:12]}",
        playbook_id="pb-live",
        playbook_name="live verification",
        step_index=0,
        step_id="ask",
        run_context={"tenant_id": tenant_id, "_verification_step_params": {"channel": "teams"}},
        step_results=[{"step_id": "earlier", "status": "success"}],
        verification_stage="user",
        verification_subject="alice@corp.test",
    )

    found = await playbook_pause.find_verification_by_token(resume_token=token)  # type: ignore[attr-defined]
    assert found is not None
    assert found.run_context["_verification_step_params"] == {"channel": "teams"}
    assert found.step_results == [{"step_id": "earlier", "status": "success"}]
    # Proves the decode rather than a passthrough: a raw row would be a str.
    assert not isinstance(found.run_context, str)
    json.dumps(found.run_context)
