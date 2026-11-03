"""One MCP approval, one person, one call.

GHSA-xhmc-69rh-h3rr. Three defects in the approval that gates a non-read-only
MCP tool call, all three on the same row:

* **F10 — separation of duties compared the credential, not the person.**
  `requested_by` holds `api_key_prefix or email`, whichever authenticated the
  request. One human who asked through their own API key and then opened the
  console appeared as `ak_1a2b3c` and `them@corp.example`, the two strings
  differed, and `requester == actor` passed. They approved their own key's
  request.

* **F11 — the decision was a read, a test in Python, then a write.** Two
  concurrent decisions both read `pending`, both passed the guard and both
  committed, so an approve and a deny were each accepted on one request and
  the row kept whichever landed last.

* **F12 — consuming an approval was a `SELECT ... LIMIT 1` and a flush.**
  Neither statement took a lock, so two calls selected the same row and both
  were allowed: one approval authorised more than one tool call. The
  predicate was also tenant + tool + fingerprint with no requester, so an
  approval granted for one principal's call could be spent by any principal
  in the tenant holding the permission.

Why the races are two transactions and not `asyncio.gather`
------------------------------------------------------------
A test that gathers N concurrent calls through the ASGI app and asserts one
winner **stays green against a broken SELECT-then-UPDATE** -- the coroutines
share a session, so they serialise and the second sees the first's write. That
is the shape this repository has recorded shipping before.

So each race below opens **two sessions on two connections** and interleaves
them explicitly: both read before either writes, which is the interleaving a
real pair of replicas produces and the one the old code could not survive. The
negative controls remove the locking predicate and these go red; under
`gather` they would not.

`ENVIRONMENT` is `production`: `development` is in `AUTH_BYPASS_ENVIRONMENTS`
and resolves an uncredentialed request to a demo admin.
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio

pytestmark = [
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.skipif(
        not os.environ.get("ISOLATION_MCP_APPROVAL_DSN", "").strip(),
        reason="ISOLATION_MCP_APPROVAL_DSN is not set; this suite needs a live Postgres",
    ),
]

if os.environ.get("ISOLATION_REQUIRE_LIVE", "").strip() and not os.environ.get("ISOLATION_MCP_APPROVAL_DSN", "").strip():
    raise RuntimeError(
        "ISOLATION_REQUIRE_LIVE is set and ISOLATION_MCP_APPROVAL_DSN is not. The races in this "
        "suite need two real connections; skipping would report success having run nothing."
    )

TOOL = "aisoc_run_investigation"


def _dsn() -> str:
    value = os.environ.get("ISOLATION_MCP_APPROVAL_DSN", "").strip()
    if not value:
        pytest.skip("ISOLATION_MCP_APPROVAL_DSN is not set")
    return value


def _admin_dsn() -> str:
    return os.environ.get("ISOLATION_MCP_APPROVAL_ADMIN_DSN", "").strip() or _dsn()


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def env():
    import httpx
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    os.environ["DATABASE_URL"] = _dsn()
    os.environ["ENVIRONMENT"] = "production"
    os.environ.setdefault("SECRET_KEY", "isolation-mcp-approval-secret-at-least-32-characters")

    admin = create_async_engine(_admin_dsn(), future=True)
    runtime = create_async_engine(_dsn(), future=True)
    tenant = uuid.uuid4()
    people = {"owner": uuid.uuid4(), "approver": uuid.uuid4()}
    emails = {k: f"mcp-{k}-{v.hex[:8]}@example.com" for k, v in people.items()}

    async with admin.begin() as conn:
        await conn.execute(
            text("INSERT INTO tenants (id, name, slug) VALUES (CAST(:i AS uuid), :n, :s)"),
            {"i": str(tenant), "n": "mcp-gov", "s": f"mcp-gov-{tenant.hex[:8]}"},
        )
        for key, uid in people.items():
            await conn.execute(
                text(
                    "INSERT INTO users (id, tenant_id, email, username, hashed_password, role, is_active, is_verified) "
                    "VALUES (CAST(:i AS uuid), CAST(:t AS uuid), :e, :e, :h, 'admin', TRUE, TRUE)"
                ),
                {"i": str(uid), "t": str(tenant), "e": emails[key], "h": "x" * 60},
            )

    from app.core.security import create_access_token
    from app.main import create_application

    application = create_application()
    transport = httpx.ASGITransport(app=application)

    def headers(key: str) -> dict[str, str]:
        token = create_access_token({"sub": str(people[key]), "tenant_id": str(tenant), "email": emails[key], "role": "admin"})
        return {"Authorization": f"Bearer {token}"}

    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield {
            "client": client,
            "tenant": tenant,
            "ids": people,
            "emails": emails,
            "headers": headers,
            "admin": admin,
            "sessions": async_sessionmaker(runtime, expire_on_commit=False),
        }

    await admin.dispose()
    await runtime.dispose()


async def _insert_approval(env, **over) -> uuid.UUID:
    """Seed an approval row as a migration would, with full control of it."""
    from sqlalchemy import text

    approval_id = uuid.uuid4()
    values = {
        "id": str(approval_id),
        "tenant": str(env["tenant"]),
        "tool": TOOL,
        "fingerprint": over.pop("fingerprint", uuid.uuid4().hex),
        "requested_by": over.pop("requested_by", "someone-else"),
        "requester_id": over.pop("requested_by_user_id", None),
        "state": over.pop("state", "pending"),
        "decided_by": over.pop("decided_by", None),
        "expires": over.pop("expires_at", datetime.now(UTC) + timedelta(hours=1)),
    }
    async with env["admin"].begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO aisoc_mcp_tool_approvals "
                "(id, tenant_id, tool_name, argument_fingerprint, requested_by, requested_by_user_id, "
                " state, decided_by, expires_at) VALUES "
                "(CAST(:id AS uuid), CAST(:tenant AS uuid), :tool, :fingerprint, :requested_by, "
                " CAST(:requester_id AS uuid), :state, :decided_by, :expires)"
            ),
            values,
        )
    return approval_id


async def _state(env, approval_id: uuid.UUID) -> str:
    from sqlalchemy import text

    async with env["admin"].begin() as conn:
        return (
            await conn.execute(
                text("SELECT state FROM aisoc_mcp_tool_approvals WHERE id = CAST(:i AS uuid)"),
                {"i": str(approval_id)},
            )
        ).scalar_one()


# ── control ──────────────────────────────────────────────────────────────────


async def test_an_uncredentialed_decision_is_refused(env):
    """So every 403 below is about authorization and not about a bypass."""
    response = await env["client"].post(f"/api/v1/mcp/approvals/{uuid.uuid4()}/decide", json={"approve": True})
    assert response.status_code in (401, 403), response.text


# ── F10 ──────────────────────────────────────────────────────────────────────


async def test_one_person_cannot_approve_their_own_key_s_request(env):
    """The exact shape of the report: two credentials, one human."""
    approval_id = await _insert_approval(
        env,
        requested_by="ak_ownerkey",  # the label their API key authenticated under
        requested_by_user_id=str(env["ids"]["owner"]),  # the person behind it
    )
    response = await env["client"].post(
        f"/api/v1/mcp/approvals/{approval_id}/decide", headers=env["headers"]("owner"), json={"approve": True}
    )
    assert response.status_code == 403, (
        f"a human approved a tool call they had requested through their own API key: {response.status_code} {response.text}"
    )
    assert await _state(env, approval_id) == "pending", "a refused decision must not have been written"


async def test_a_different_person_can_still_decide(env):
    """Positive control for F10.

    A check that refuses everybody would satisfy the test above and make every
    gated MCP tool permanently unusable.
    """
    approval_id = await _insert_approval(env, requested_by="ak_ownerkey", requested_by_user_id=str(env["ids"]["owner"]))
    response = await env["client"].post(
        f"/api/v1/mcp/approvals/{approval_id}/decide", headers=env["headers"]("approver"), json={"approve": True}
    )
    assert response.status_code == 200, response.text
    assert response.json()["state"] == "approved"


async def test_a_legacy_row_still_refuses_the_same_credential(env):
    """Rows predating migration 158 keep the label comparison.

    It is weaker and it is not nothing: it still catches a caller approving
    under the very credential that asked. Dropping it on the way to the better
    check would have *removed* protection from exactly the oldest rows.
    """
    approval_id = await _insert_approval(env, requested_by=env["emails"]["owner"], requested_by_user_id=None)
    response = await env["client"].post(
        f"/api/v1/mcp/approvals/{approval_id}/decide", headers=env["headers"]("owner"), json={"approve": True}
    )
    assert response.status_code == 403, response.text


async def test_a_legacy_row_is_still_decidable_by_someone_else(env):
    """Positive control for the legacy path."""
    approval_id = await _insert_approval(env, requested_by="ak_someonelse", requested_by_user_id=None)
    response = await env["client"].post(
        f"/api/v1/mcp/approvals/{approval_id}/decide", headers=env["headers"]("approver"), json={"approve": True}
    )
    assert response.status_code == 200, response.text


# ── F11 — two interleaved transactions, both reading before either writes ────


async def test_an_approve_and_a_deny_cannot_both_land(env):
    """Driven through `claim_decision`, the function the route calls.

    An earlier draft of this test wrote its own `UPDATE` and asserted against
    that. It passed with the production statement's locking predicate
    reverted -- a test comparing a statement against a copy of itself can only
    agree with itself, which is the exact shape this repository has recorded
    shipping three times.
    """
    import asyncio

    from app.api.v1.endpoints.mcp_access import claim_decision

    approval_id = await _insert_approval(env)
    maker = env["sessions"]

    async with maker() as one, maker() as two:
        await _bind(one, env)
        await _bind(two, env)

        async def approve():
            return await claim_decision(one, approval_id=approval_id, tenant_id=env["tenant"], state="approved", actor="a", note="")

        async def deny():
            return await claim_decision(two, approval_id=approval_id, tenant_id=env["tenant"], state="denied", actor="b", note="")

        won_first = await approve()
        task = asyncio.create_task(deny())
        await asyncio.sleep(0.25)
        await one.commit()
        won_second = await asyncio.wait_for(task, timeout=20)
        await two.commit()

    winners = [w for w in (won_first, won_second) if w is not None]
    assert len(winners) == 1, f"both an approve and a deny were accepted on one pending request: {won_first=} {won_second=}"
    assert await _state(env, approval_id) == "approved"


async def test_a_single_decision_still_lands(env):
    """Positive control for F11.

    An `UPDATE` narrowed so tightly that it matched nothing would satisfy the
    race test and make every MCP approval permanently undecidable.
    """
    from app.api.v1.endpoints.mcp_access import claim_decision

    approval_id = await _insert_approval(env)
    async with env["sessions"]() as session:
        await _bind(session, env)
        claimed = await claim_decision(session, approval_id=approval_id, tenant_id=env["tenant"], state="approved", actor="a", note="")
        await session.commit()
    assert claimed is not None, "an uncontested decision on a pending approval was refused"
    assert await _state(env, approval_id) == "approved"


async def test_the_loser_of_a_decision_race_is_told_409(env):
    """The refusal reaches the caller rather than being silently discarded."""
    approval_id = await _insert_approval(env)
    first = await env["client"].post(
        f"/api/v1/mcp/approvals/{approval_id}/decide", headers=env["headers"]("approver"), json={"approve": True}
    )
    assert first.status_code == 200, first.text
    second = await env["client"].post(
        f"/api/v1/mcp/approvals/{approval_id}/decide", headers=env["headers"]("approver"), json={"approve": False}
    )
    assert second.status_code == 409, second.text


# ── F12 — one approval, one call ─────────────────────────────────────────────


async def _seeded_approval(env, *, owner: str = "owner") -> tuple[str, dict]:
    """An approved, unexpired approval, plus the claim arguments for its owner."""
    fingerprint = uuid.uuid4().hex
    await _insert_approval(
        env,
        fingerprint=fingerprint,
        state="approved",
        decided_by="an-approver",
        requested_by="ak_ownerkey",
        requested_by_user_id=str(env["ids"][owner]),
    )
    return fingerprint, {
        "tenant_id": env["tenant"],
        "tool_name": TOOL,
        "fingerprint": fingerprint,
        "requester_id": env["ids"][owner],
        "requested_by": "ak_ownerkey",
    }


async def _bind(session, env):
    from sqlalchemy import text

    await session.execute(text("SELECT set_config('app.current_tenant_id', :t, true)"), {"t": str(env["tenant"])})


async def test_one_approval_cannot_be_spent_twice(env):
    """Driven through `_claim_approval`, the function `authorize` calls.

    Not through a copy of its SQL: a test that re-states the statement it is
    checking can only ever agree with itself, and the negative control for
    this needs to be able to revert the real code and be felt here.
    """
    import asyncio

    from app.services import mcp_access

    _, args = await _seeded_approval(env)
    maker = env["sessions"]

    async with maker() as one, maker() as two:
        await _bind(one, env)
        await _bind(two, env)

        def claim(session):
            async def _run():
                return await mcp_access._claim_approval(
                    session,
                    args["tenant_id"],
                    args["tool_name"],
                    args["fingerprint"],
                    requester_id=args["requester_id"],
                    requested_by=args["requested_by"],
                )

            return _run

        # Call A claims and does NOT commit; call B starts into the held row
        # lock, which is what a second replica meets. The commit is released
        # while B is in flight, so a shape that merely *waits* for the lock
        # and then wins anyway is caught too -- that is the same defect with
        # a delay in front of it.
        claim_one = await claim(one)()
        task = asyncio.create_task(claim(two)())
        await asyncio.sleep(0.25)
        await one.commit()
        claim_two = await asyncio.wait_for(task, timeout=20)
        await two.commit()

    winners = [c for c in (claim_one, claim_two) if c is not None]
    assert len(winners) == 1, f"one approval authorised two calls: {claim_one=} {claim_two=}"


async def test_the_approval_is_spent_so_a_later_call_is_refused(env):
    """Positive control for F12.

    The first call must actually be allowed. A claim that matched nothing
    would pass the race test above and refuse every approved call -- the
    fail-closed shape that has shipped here before and passed its negative
    test perfectly.
    """
    from app.services import mcp_access

    _, args = await _seeded_approval(env)
    async with env["sessions"]() as session:
        await _bind(session, env)
        first = await mcp_access._claim_approval(
            session,
            args["tenant_id"],
            args["tool_name"],
            args["fingerprint"],
            requester_id=args["requester_id"],
            requested_by=args["requested_by"],
        )
        await session.commit()
        assert first is not None, "an approved, unexpired, correctly-scoped approval was not claimable"

        second = await mcp_access._claim_approval(
            session,
            args["tenant_id"],
            args["tool_name"],
            args["fingerprint"],
            requester_id=args["requester_id"],
            requested_by=args["requested_by"],
        )
        await session.commit()
        assert second is None, "the approval was spent and must not be claimable again"


async def test_another_principal_cannot_spend_an_approval_granted_to_someone_else(env):
    """The predicate carried no requester at all.

    An approval raised for one principal's call was claimable by any principal
    in the tenant that held the permission and reproduced the same arguments.
    """
    from app.services import mcp_access

    _, args = await _seeded_approval(env)
    async with env["sessions"]() as session:
        await _bind(session, env)
        stolen = await mcp_access._claim_approval(
            session,
            args["tenant_id"],
            args["tool_name"],
            args["fingerprint"],
            requester_id=env["ids"]["approver"],
            requested_by=env["emails"]["approver"],
        )
        await session.commit()
    assert stolen is None, "an approval granted for one principal's call was spent by another"


async def test_a_legacy_approval_is_still_claimable_by_its_label(env):
    """Positive control for the requester scoping.

    Rows predating migration 158 carry no requester id. Matching only on the
    id would have made every one of them unclaimable -- an approval an
    approver had already granted, refused forever.
    """
    from app.services import mcp_access

    fingerprint = uuid.uuid4().hex
    await _insert_approval(
        env,
        fingerprint=fingerprint,
        state="approved",
        decided_by="an-approver",
        requested_by="ak_legacykey",
        requested_by_user_id=None,
    )
    async with env["sessions"]() as session:
        await _bind(session, env)
        claimed = await mcp_access._claim_approval(
            session,
            env["tenant"],
            TOOL,
            fingerprint,
            requester_id=env["ids"]["owner"],
            requested_by="ak_legacykey",
        )
        await session.commit()
    assert claimed is not None, "a pre-158 approval became unclaimable"
