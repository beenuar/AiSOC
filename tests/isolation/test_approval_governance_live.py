"""Who may decide a response approval, and until when.

GHSA-q388-w896-9jr2. `decide_approval` authenticated the caller, scoped the
row to their tenant, required `cases:write` — and then flipped the row with no
further question. Three things it never asked:

* **F08 — is the decider the requester?** `create_approval` has stamped the
  originating identity onto the row as `action.requester_principal` since v9,
  from authenticated context and never from the body, precisely so separation
  of duties has something forgery-proof to compare. Nothing compared it. A
  user raised a `critical` approval to isolate a host and approved it
  themselves, 200, `decided_by_id` equal to the requester.

* **F09 — is the decider the named approver?** `required_user_id` is written
  at create time and `list_approvals(mine=true)` filters on it, so the console
  presents an approval as routed to one person. `decide` never read the
  column, so anybody holding `cases:write` in the tenant could answer an
  approval addressed to somebody else.

* **F82 — is the window still open?** `expires_at` was read by the expiry
  sweep and by nothing on the decision path. An approval that elapsed six
  hours ago was approved and dispatched.

Why the actions service was not a backstop
------------------------------------------
`_dispatch_decision` does send `requester` and `approver` on to
`services/actions`, which runs its own separation-of-duties check. That is not
a second line of defence here, for two reasons measured against the shipped
code:

1. The decision is **committed before the dispatch** — deliberately, so an
   interrupted decide is visible rather than invisible. So the row reads
   `approved` by its own requester whatever the actions service later says,
   and the 502 the operator sees says "the approval row reflects your
   decision".
2. The dispatch only happens at all when the approval carries an
   `action_type` **and** a `target`. An approval that gates a human step
   returns `not_executable` and reaches no check whatsoever.

So the question belongs here, at the layer that owns the row.

What F82 does *not* claim, and why
-----------------------------------
The advisory also reads F82 as covering "a decision on an approval that is no
longer `pending`". Measured against the tree, that half is **deliberate and
documented**: `app/workers/approval_expiry.py` stamps `expired` as a safe
marker and its own note says "nothing was dispatched, and this request can
still be decided", while `approved`/`denied` already answer 409 unless the
dispatch is unresolved — which is the recorded re-entry path that stops an
approval whose dispatch died from being stranded.

Keeping both intents is what shapes the rule below: **an elapsed approval may
still be denied, and may not be approved.** Denying is the safe default the
worker already names, so the request stays resolvable by a late approver;
approving on evidence the window has closed over is the thing that must stop.
Re-entering an already-decided row to finish its dispatch stays open
regardless of the clock, because that decision *was* taken in time.

Why this suite is live
----------------------
Every one of these is a disagreement between a handler and a row. A fake
session answers whatever the handler asks it, which is how a check that never
ran looked identical to a check that passed — and `AuthUser` here comes from a
real signed JWT through the real dependency graph, so "the requester" is the
one the application resolves rather than one a fixture declared.

`ENVIRONMENT` is `production`. `development` is in `AUTH_BYPASS_ENVIRONMENTS`
and resolves an uncredentialed request to a demo **admin**, which inside a
suite about who may decide would pass every assertion for the worst possible
reason.
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
        not os.environ.get("ISOLATION_APPROVAL_GOV_DSN", "").strip(),
        reason="ISOLATION_APPROVAL_GOV_DSN is not set; this suite needs a live Postgres",
    ),
]

# A skip in a job that exists to run live is a green report over nothing.
if os.environ.get("ISOLATION_REQUIRE_LIVE", "").strip() and not os.environ.get("ISOLATION_APPROVAL_GOV_DSN", "").strip():
    raise RuntimeError(
        "ISOLATION_REQUIRE_LIVE is set and ISOLATION_APPROVAL_GOV_DSN is not. This job exists to "
        "drive approval decisions against a real Postgres; skipping would report success having run nothing."
    )


def _dsn() -> str:
    value = os.environ.get("ISOLATION_APPROVAL_GOV_DSN", "").strip()
    if not value:
        pytest.skip("ISOLATION_APPROVAL_GOV_DSN is not set")
    return value


def _admin_dsn() -> str:
    """The owner role, for seeding only.

    Tenants and users are what a migration and a signup would have created.
    The *application* runs as the DML-only runtime role in `_dsn()`, which
    carries NOBYPASSRLS — seeding as the owner is standing in for a
    migration, and running the assertions as the owner would be void.
    """
    return os.environ.get("ISOLATION_APPROVAL_GOV_ADMIN_DSN", "").strip() or _dsn()


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def env():
    """The real application, a real tenant, and three real signed sessions."""
    import httpx
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine

    os.environ["DATABASE_URL"] = _dsn()
    os.environ["ENVIRONMENT"] = "production"
    os.environ.setdefault("SECRET_KEY", "isolation-approval-governance-secret-at-least-32-chars")

    admin = create_async_engine(_admin_dsn(), future=True)
    tenant = uuid.uuid4()
    people = {
        "requester": uuid.uuid4(),
        "approver": uuid.uuid4(),
        "bystander": uuid.uuid4(),
    }
    emails = {k: f"{k}-{v.hex[:8]}@example.com" for k, v in people.items()}

    async with admin.begin() as conn:
        await conn.execute(
            text("INSERT INTO tenants (id, name, slug) VALUES (CAST(:i AS uuid), :n, :s)"),
            {"i": str(tenant), "n": "approval-gov", "s": f"approval-gov-{tenant.hex[:8]}"},
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
        }

    await admin.dispose()


async def _raise(env, *, by: str = "requester", **extra) -> dict:
    """Open an approval as a real authenticated user."""
    payload = {
        "title": extra.pop("title", "Isolate finance-ws-01"),
        "summary": extra.pop("summary", "Beaconing to a known C2."),
        "risk_level": extra.pop("risk_level", "critical"),
        **extra,
    }
    response = await env["client"].post("/api/v1/approvals", headers=env["headers"](by), json=payload)
    assert response.status_code == 201, response.text
    return response.json()


async def _decide(env, approval_id: str, *, by: str, decision: str = "approve"):
    return await env["client"].post(
        f"/api/v1/approvals/{approval_id}/decide",
        headers=env["headers"](by),
        json={"decision": decision},
    )


# ── the control that stops every assertion below passing for the wrong reason ─


async def test_an_uncredentialed_decision_is_refused(env):
    """No auth bypass is active, so a 403 below is about authorization.

    Without this, every refusal this suite asserts would be satisfied by an
    application that refuses everybody — including the legitimate approver.
    """
    response = await env["client"].post(f"/api/v1/approvals/{uuid.uuid4()}/decide", json={"decision": "approve"})
    assert response.status_code in (401, 403), response.text


# ── F08 — separation of duties ───────────────────────────────────────────────


async def test_the_requester_cannot_decide_their_own_approval(env):
    approval = await _raise(env, by="requester")

    stamped = (approval.get("action") or {}).get("requester_principal") or {}
    assert stamped.get("user_id") == str(env["ids"]["requester"]), (
        f"the originating identity must be on the row for separation of duties to have anything to compare; got {stamped!r}"
    )

    response = await _decide(env, approval["id"], by="requester")
    assert response.status_code == 403, (
        f"the requester approved their own {approval['risk_level']} approval: {response.status_code} {response.text}"
    )

    detail = response.json().get("detail", "").lower()
    assert "separation of duties" in detail, f"the refusal must name why: {detail!r}"

    read_back = await env["client"].get(f"/api/v1/approvals/{approval['id']}", headers=env["headers"]("approver"))
    assert read_back.json()["status"] == "pending", "a refused decision must not have been written"
    assert read_back.json()["decided_by_id"] is None


async def test_somebody_else_can_still_decide_it(env):
    """Positive control for F08.

    A separation-of-duties check that refused everybody would pass the test
    above and brick the queue. This is the half that proves it narrows rather
    than closes.
    """
    approval = await _raise(env, by="requester")
    response = await _decide(env, approval["id"], by="approver")
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "approved"
    assert response.json()["decided_by_id"] == str(env["ids"]["approver"])


# ── F09 — the named approver ─────────────────────────────────────────────────


async def test_a_bystander_cannot_answer_an_approval_routed_to_someone_else(env):
    approval = await _raise(
        env,
        by="requester",
        required_user_id=str(env["ids"]["approver"]),
        title="Disable contractor account",
    )
    assert approval["required_user_id"] == str(env["ids"]["approver"])

    response = await _decide(env, approval["id"], by="bystander")
    assert response.status_code == 403, f"a user who is not the named approver decided: {response.status_code} {response.text}"

    read_back = await env["client"].get(f"/api/v1/approvals/{approval['id']}", headers=env["headers"]("approver"))
    assert read_back.json()["status"] == "pending"


async def test_the_named_approver_can_answer_it(env):
    """Positive control for F09."""
    approval = await _raise(env, by="requester", required_user_id=str(env["ids"]["approver"]))
    response = await _decide(env, approval["id"], by="approver")
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "approved"


async def test_an_approval_routed_to_nobody_is_open_to_any_permitted_non_requester(env):
    """Second positive control for F09.

    Most approvals carry no `required_user_id`. Those must stay answerable by
    whoever is on call, or enforcing the named-approver rule would have
    quietly made every unrouted approval undecidable.
    """
    approval = await _raise(env, by="requester")
    assert approval["required_user_id"] is None
    response = await _decide(env, approval["id"], by="bystander")
    assert response.status_code == 200, response.text


# ── F82 — the window ─────────────────────────────────────────────────────────


async def test_an_elapsed_approval_cannot_be_approved(env):
    approval = await _raise(
        env,
        by="requester",
        expires_at=(datetime.now(UTC) - timedelta(hours=6)).isoformat(),
        title="Containment window closed six hours ago",
    )
    response = await _decide(env, approval["id"], by="approver")
    assert response.status_code == 409, f"an approval that elapsed six hours ago was approved: {response.status_code} {response.text}"
    assert "expire" in response.json().get("detail", "").lower()


async def test_an_elapsed_approval_can_still_be_denied(env):
    """The half the expiry worker's own note requires.

    `approval_expiry` stamps `expired` and records that the request "can still
    be decided", because a forgotten approval that becomes unresolvable is a
    row somebody has to clean up by hand. Denying is the safe default it names
    and executes nothing, so the window closes over approval only.
    """
    approval = await _raise(env, by="requester", expires_at=(datetime.now(UTC) - timedelta(hours=6)).isoformat())
    response = await _decide(env, approval["id"], by="approver", decision="deny")
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "denied"


async def test_an_approval_inside_its_window_is_unaffected(env):
    """Positive control for F82."""
    approval = await _raise(env, by="requester", expires_at=(datetime.now(UTC) + timedelta(hours=2)).isoformat())
    response = await _decide(env, approval["id"], by="approver")
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "approved"


async def test_an_approval_with_no_deadline_is_unaffected(env):
    """Second positive control for F82.

    `expires_at` is nullable and most rows carry none. Reading a missing
    deadline as "elapsed" would refuse the common case — the fail-closed
    mistake this repository has shipped before, where a control withheld every
    grant on every deployment and passed its negative test perfectly.
    """
    approval = await _raise(env, by="requester")
    assert approval["expires_at"] is None
    response = await _decide(env, approval["id"], by="approver")
    assert response.status_code == 200, response.text


# ── the stamp itself ─────────────────────────────────────────────────────────


async def test_a_body_supplied_requester_cannot_defeat_separation_of_duties(env):
    """`requested_by` is a label and must never be the authorization basis.

    The actions service learned this the hard way; the same reasoning applies
    one layer up. A requester who names somebody else in the body must still
    be refused, because the comparison is against the server-stamped
    principal.
    """
    approval = await _raise(env, by="requester", requested_by=str(env["ids"]["approver"]))
    response = await _decide(env, approval["id"], by="requester")
    assert response.status_code == 403, f"a body-supplied `requested_by` defeated separation of duties: {response.text}"
