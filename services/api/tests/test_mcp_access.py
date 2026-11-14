"""Who may call an MCP tool over the network, and what the log says afterwards.

Depth plan 9.1 (parity 6.6).

The properties, each asserted by name below:

* a read is allowed and **still writes an audit row** -- reads were the whole
  gap, because the API's audit middleware only ever recorded mutating methods
  carrying a JWT, so the ten read tools produced nothing at all;
* a credential without the tool's scope is refused, through the principal's
  own ``require_permission`` rather than a second check;
* a tenant that has turned a tool off is refused even with a wildcard key,
  because a scope and a grant are different decisions by different people;
* a tool that is not read-only cannot run on a key alone, and the approval is
  bound to the exact arguments -- approving an investigation on one case does
  not authorise one on another;
* the principal that asked cannot be the principal that approves;
* an approval is spent by the call it authorised rather than left standing.

The database is a real one, on the same SQLite-compiles-Postgres-types basis
``test_mcp_registry.py`` uses, so the statements under test are the ones that
run in production rather than a double that agrees with them.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from app.api.v1.deps import CurrentUser, get_current_user
from app.api.v1.endpoints.mcp_access import router as mcp_router
from app.db.database import Base, get_db
from app.db.rls import get_tenant_db
from app.models.audit import AuditLog
from app.models.mcp_access import McpToolApproval, McpToolGrant
from app.services import mcp_access as policy
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.ext.compiler import compiles

TENANT = uuid.UUID("aaaaaaaa-0000-0000-0000-0000000000a1")
ANALYST = uuid.UUID("11111111-1111-1111-1111-111111111111")
APPROVER = uuid.UUID("22222222-2222-2222-2222-222222222222")

READ_TOOL = "aisoc_list_alerts"
WRITE_TOOL = "aisoc_run_investigation"


@compiles(JSONB, "sqlite")
def _jsonb_sqlite(_type_, _compiler_, **_kw_):
    return "TEXT"


@compiles(PgUUID, "sqlite")
def _uuid_sqlite(_type_, _compiler_, **_kw_):
    return "CHAR(36)"


@compiles(INET, "sqlite")
def _inet_sqlite(_type_, _compiler_, **_kw_):
    return "VARCHAR(45)"


@pytest_asyncio.fixture
async def session_factory():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        # Three tables, not the whole metadata: a full create_all drags in
        # models using Postgres ARRAY, which SQLite cannot render. The FKs to
        # `tenants` are not created, which is why the rows below carry bare
        # UUIDs -- what is under test is the policy's statements, not
        # referential integrity, which the migration's constraints hold.
        await conn.run_sync(
            Base.metadata.create_all,
            tables=[McpToolGrant.__table__, McpToolApproval.__table__, AuditLog.__table__],
        )
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


def _principal(*, user_id: uuid.UUID, scopes: list[str], key_prefix: str) -> CurrentUser:
    """An API-key principal, which is what an MCP client actually presents.

    Built with explicit ``scopes`` so ``require_permission`` takes the
    API-key branch -- the branch the MCP server exercises. A role-only
    principal would be checked against the static map instead, which is a
    different code path from the one in production.
    """
    return CurrentUser(
        user_id=user_id,
        tenant_id=TENANT,
        role="analyst",
        email=f"api-key:{key_prefix}",
        scopes=scopes,
        api_key_prefix=key_prefix,
    )


@pytest_asyncio.fixture
async def client(session_factory):
    """App + a swappable principal, so a test can change who is calling."""
    app = FastAPI()
    app.include_router(mcp_router, prefix="/api/v1")

    state: dict[str, CurrentUser] = {"user": _principal(user_id=ANALYST, scopes=["*"], key_prefix="aisoc_analyst")}

    async def _db():
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = _db
    app.dependency_overrides[get_tenant_db] = _db
    app.dependency_overrides[get_current_user] = lambda: state["user"]

    with TestClient(app) as c:
        c.state_holder = state  # type: ignore[attr-defined]
        yield c


async def _audit_rows(session_factory, action: str) -> list[AuditLog]:
    async with session_factory() as session:
        rows = (await session.execute(select(AuditLog).where(AuditLog.action == action))).scalars().all()
        return list(rows)


# ---------------------------------------------------------------------------
# Reads: allowed, and recorded
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_read_is_allowed_and_still_writes_an_audit_row(client, session_factory) -> None:
    res = client.post(
        "/api/v1/mcp/tool-calls/authorize",
        json={"tool_name": READ_TOOL, "arguments": {"severity": "high"}},
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["outcome"] == "allow"

    rows = await _audit_rows(session_factory, "mcp:tool_call")
    assert len(rows) == 1
    row = rows[0]
    assert row.tenant_id == TENANT
    assert row.resource_id == body["call_id"]
    assert row.changes["tool_name"] == READ_TOOL
    assert row.changes["decision"] == "allow"
    # Names, never values: the argument values carry hostnames and queries.
    assert row.changes["argument_keys"] == ["severity"]
    assert "high" not in str(row.changes)
    assert row.metadata_["api_key_prefix"] == "aisoc_analyst"


@pytest.mark.asyncio
async def test_a_refused_call_is_recorded_too(client, session_factory) -> None:
    """A call that was refused is as much a part of a key's account as one that ran."""
    client.state_holder["user"] = _principal(  # type: ignore[attr-defined]
        user_id=ANALYST, scopes=["cases:read"], key_prefix="aisoc_narrow"
    )
    res = client.post("/api/v1/mcp/tool-calls/authorize", json={"tool_name": READ_TOOL, "arguments": {}})
    assert res.status_code == 200
    assert res.json()["outcome"] == "deny"
    assert "alerts:read" in res.json()["reason"]

    rows = await _audit_rows(session_factory, "mcp:tool_call")
    assert [r.changes["decision"] for r in rows] == ["deny"]


@pytest.mark.asyncio
async def test_the_outcome_is_a_second_row_because_audit_rows_are_immutable(client, session_factory) -> None:
    authorized = client.post("/api/v1/mcp/tool-calls/authorize", json={"tool_name": READ_TOOL, "arguments": {}}).json()
    res = client.post(
        f"/api/v1/mcp/tool-calls/{authorized['call_id']}/complete",
        json={"outcome": "success", "latency_ms": 42},
    )
    assert res.status_code == 204

    results = await _audit_rows(session_factory, "mcp:tool_result")
    assert len(results) == 1
    assert results[0].resource_id == authorized["call_id"]
    assert results[0].changes == {"outcome": "success", "latency_ms": 42}


@pytest.mark.asyncio
async def test_an_outcome_cannot_be_reported_for_a_call_nobody_authorized(client) -> None:
    """The completion route is authorized against the call it reports on.

    There is no single permission every MCP caller holds, so a blanket
    dependency would be either wider than the call or exclusive of the
    callers it exists for. Resolving the authorize row instead means a
    caller cannot write an outcome for a call that was never decided here.
    """
    res = client.post(
        f"/api/v1/mcp/tool-calls/{uuid.uuid4()}/complete",
        json={"outcome": "success", "latency_ms": 1},
    )
    assert res.status_code == 404
    assert "No authorize decision was recorded" in res.text


@pytest.mark.asyncio
async def test_a_key_narrowed_after_the_call_cannot_report_its_outcome(client) -> None:
    """A scope removed between the call and the report is refused, not ignored."""
    authorized = client.post("/api/v1/mcp/tool-calls/authorize", json={"tool_name": READ_TOOL, "arguments": {}}).json()
    assert authorized["outcome"] == "allow"

    client.state_holder["user"] = _principal(  # type: ignore[attr-defined]
        user_id=ANALYST, scopes=["cases:read"], key_prefix="aisoc_analyst"
    )
    res = client.post(
        f"/api/v1/mcp/tool-calls/{authorized['call_id']}/complete",
        json={"outcome": "success", "latency_ms": 1},
    )
    assert res.status_code == 403


@pytest.mark.asyncio
async def test_an_outcome_outside_the_closed_set_is_refused(client) -> None:
    call_id = uuid.uuid4()
    res = client.post(
        f"/api/v1/mcp/tool-calls/{call_id}/complete",
        json={"outcome": "finished-ish", "latency_ms": 1},
    )
    assert res.status_code == 422
    assert "Unknown outcome" in res.text


# ---------------------------------------------------------------------------
# The tenant switch is a different decision from the key's scopes
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_tenant_can_turn_a_tool_off_against_a_wildcard_key(client, session_factory) -> None:
    assert client.post("/api/v1/mcp/tool-calls/authorize", json={"tool_name": READ_TOOL, "arguments": {}}).json()["outcome"] == "allow"

    off = client.put(f"/api/v1/mcp/tools/{READ_TOOL}", json={"enabled": False})
    assert off.status_code == 200, off.text
    assert off.json() == {
        "name": READ_TOOL,
        "read_only": True,
        "enabled": False,
        "source": "tenant",
        "required_permission": "alerts:read",
        "requires_approval": False,
        "decided_by": "aisoc_analyst",
    }

    after = client.post("/api/v1/mcp/tool-calls/authorize", json={"tool_name": READ_TOOL, "arguments": {}}).json()
    assert after["outcome"] == "deny"
    assert "disabled for this tenant" in after["reason"]


@pytest.mark.asyncio
async def test_no_row_means_default_not_denied_and_the_console_can_tell(client) -> None:
    """ "Nobody decided" and "somebody turned it off" must not render the same."""
    listed = {entry["name"]: entry for entry in client.get("/api/v1/mcp/tools").json()}
    assert listed[READ_TOOL]["source"] == "default"
    assert listed[READ_TOOL]["enabled"] is True
    assert listed[WRITE_TOOL]["source"] == "default"
    # A write tool is off out of the box, derived from readOnlyHint rather
    # than authored, so a new write tool cannot arrive switched on.
    assert listed[WRITE_TOOL]["enabled"] is False
    assert listed[WRITE_TOOL]["requires_approval"] is True

    client.put(f"/api/v1/mcp/tools/{READ_TOOL}", json={"enabled": True})
    relisted = {entry["name"]: entry for entry in client.get("/api/v1/mcp/tools").json()}
    assert relisted[READ_TOOL]["source"] == "tenant"


@pytest.mark.asyncio
async def test_an_unknown_tool_is_refused_rather_than_defaulted(client) -> None:
    res = client.post("/api/v1/mcp/tool-calls/authorize", json={"tool_name": "aisoc_delete_everything", "arguments": {}})
    assert res.json()["outcome"] == "deny"
    assert "Unknown tool" in res.json()["reason"]
    assert client.put("/api/v1/mcp/tools/aisoc_delete_everything", json={"enabled": True}).status_code == 404


# ---------------------------------------------------------------------------
# Approval for anything that is not a read
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_write_tool_needs_an_approver_even_with_a_wildcard_key(client) -> None:
    client.put(f"/api/v1/mcp/tools/{WRITE_TOOL}", json={"enabled": True})
    res = client.post(
        "/api/v1/mcp/tool-calls/authorize",
        json={"tool_name": WRITE_TOOL, "arguments": {"case_id": "case-a"}},
    ).json()
    assert res["outcome"] == "approval_required"
    assert res["approval_id"]

    queue = client.get("/api/v1/mcp/approvals").json()
    assert [row["tool_name"] for row in queue] == [WRITE_TOOL]
    assert queue[0]["requested_by"] == "aisoc_analyst"


@pytest.mark.asyncio
async def test_an_approval_is_bound_to_the_arguments_it_was_granted_for(client) -> None:
    client.put(f"/api/v1/mcp/tools/{WRITE_TOOL}", json={"enabled": True})
    first = client.post(
        "/api/v1/mcp/tool-calls/authorize",
        json={"tool_name": WRITE_TOOL, "arguments": {"case_id": "case-a"}},
    ).json()

    client.state_holder["user"] = _principal(  # type: ignore[attr-defined]
        user_id=APPROVER, scopes=["*"], key_prefix="aisoc_lead"
    )
    decided = client.post(f"/api/v1/mcp/approvals/{first['approval_id']}/decide", json={"approve": True})
    assert decided.status_code == 200, decided.text
    assert decided.json()["state"] == "approved"

    client.state_holder["user"] = _principal(  # type: ignore[attr-defined]
        user_id=ANALYST, scopes=["*"], key_prefix="aisoc_analyst"
    )
    # The approved call runs.
    same = client.post(
        "/api/v1/mcp/tool-calls/authorize",
        json={"tool_name": WRITE_TOOL, "arguments": {"case_id": "case-a"}},
    ).json()
    assert same["outcome"] == "allow"

    # A different case is a different call, and the approval does not cover it.
    other = client.post(
        "/api/v1/mcp/tool-calls/authorize",
        json={"tool_name": WRITE_TOOL, "arguments": {"case_id": "case-b"}},
    ).json()
    assert other["outcome"] == "approval_required"


@pytest.mark.asyncio
async def test_an_approval_is_spent_by_the_call_it_authorised(client) -> None:
    client.put(f"/api/v1/mcp/tools/{WRITE_TOOL}", json={"enabled": True})
    pending = client.post(
        "/api/v1/mcp/tool-calls/authorize",
        json={"tool_name": WRITE_TOOL, "arguments": {"case_id": "case-a"}},
    ).json()
    client.state_holder["user"] = _principal(  # type: ignore[attr-defined]
        user_id=APPROVER, scopes=["*"], key_prefix="aisoc_lead"
    )
    client.post(f"/api/v1/mcp/approvals/{pending['approval_id']}/decide", json={"approve": True})
    client.state_holder["user"] = _principal(  # type: ignore[attr-defined]
        user_id=ANALYST, scopes=["*"], key_prefix="aisoc_analyst"
    )

    assert (
        client.post(
            "/api/v1/mcp/tool-calls/authorize",
            json={"tool_name": WRITE_TOOL, "arguments": {"case_id": "case-a"}},
        ).json()["outcome"]
        == "allow"
    )
    # Second use of the same approval: a grant that outlives the call it was
    # given for is a permission, and nobody granted a permission.
    assert (
        client.post(
            "/api/v1/mcp/tool-calls/authorize",
            json={"tool_name": WRITE_TOOL, "arguments": {"case_id": "case-a"}},
        ).json()["outcome"]
        == "approval_required"
    )


@pytest.mark.asyncio
async def test_the_requester_cannot_approve_their_own_call(client) -> None:
    client.put(f"/api/v1/mcp/tools/{WRITE_TOOL}", json={"enabled": True})
    pending = client.post(
        "/api/v1/mcp/tool-calls/authorize",
        json={"tool_name": WRITE_TOOL, "arguments": {"case_id": "case-a"}},
    ).json()
    res = client.post(f"/api/v1/mcp/approvals/{pending['approval_id']}/decide", json={"approve": True})
    assert res.status_code == 403
    assert "cannot approve" in res.text


@pytest.mark.asyncio
async def test_a_denied_approval_does_not_let_the_call_through(client) -> None:
    client.put(f"/api/v1/mcp/tools/{WRITE_TOOL}", json={"enabled": True})
    pending = client.post(
        "/api/v1/mcp/tool-calls/authorize",
        json={"tool_name": WRITE_TOOL, "arguments": {"case_id": "case-a"}},
    ).json()
    client.state_holder["user"] = _principal(  # type: ignore[attr-defined]
        user_id=APPROVER, scopes=["*"], key_prefix="aisoc_lead"
    )
    client.post(
        f"/api/v1/mcp/approvals/{pending['approval_id']}/decide",
        json={"approve": False, "note": "not during the freeze"},
    )
    client.state_holder["user"] = _principal(  # type: ignore[attr-defined]
        user_id=ANALYST, scopes=["*"], key_prefix="aisoc_analyst"
    )
    again = client.post(
        "/api/v1/mcp/tool-calls/authorize",
        json={"tool_name": WRITE_TOOL, "arguments": {"case_id": "case-a"}},
    ).json()
    assert again["outcome"] == "approval_required"
    # A fresh row, not the denied one reopened.
    assert again["approval_id"] != pending["approval_id"]


@pytest.mark.asyncio
async def test_an_expired_approval_is_not_a_live_one(client, session_factory) -> None:
    client.put(f"/api/v1/mcp/tools/{WRITE_TOOL}", json={"enabled": True})
    pending = client.post(
        "/api/v1/mcp/tool-calls/authorize",
        json={"tool_name": WRITE_TOOL, "arguments": {"case_id": "case-a"}},
    ).json()
    client.state_holder["user"] = _principal(  # type: ignore[attr-defined]
        user_id=APPROVER, scopes=["*"], key_prefix="aisoc_lead"
    )
    client.post(f"/api/v1/mcp/approvals/{pending['approval_id']}/decide", json={"approve": True})

    async with session_factory() as session:
        row = (await session.execute(select(McpToolApproval).where(McpToolApproval.id == uuid.UUID(pending["approval_id"])))).scalar_one()
        row.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        await session.commit()

    client.state_holder["user"] = _principal(  # type: ignore[attr-defined]
        user_id=ANALYST, scopes=["*"], key_prefix="aisoc_analyst"
    )
    assert (
        client.post(
            "/api/v1/mcp/tool-calls/authorize",
            json={"tool_name": WRITE_TOOL, "arguments": {"case_id": "case-a"}},
        ).json()["outcome"]
        == "approval_required"
    )


# ---------------------------------------------------------------------------
# The catalogue is the authority, and it has to describe this deployment
# ---------------------------------------------------------------------------


def test_every_catalogued_tool_has_a_permission_mapped() -> None:
    """An unmapped tool is refused, so this failing means a tool is unreachable.

    It is a real failure rather than a style point: adding a tool to the
    TypeScript registry regenerates the catalogue, and without a line in
    ``TOOL_PERMISSIONS`` the new tool denies every call with a message about
    the mapping. Better to fail here than to ship a tool nobody can use.
    """
    policy.tool_catalogue.cache_clear()
    unmapped = sorted(name for name, spec in policy.tool_catalogue().items() if not spec.required_permission)
    assert unmapped == [], f"no permission mapped for {unmapped}"


def test_a_permission_is_one_a_key_can_actually_be_minted_with() -> None:
    """Every mapped permission must be in VALID_SCOPES, or only "*" reaches it.

    This is how ``hunts:read`` ended up reachable solely by the credential
    nobody should be using.
    """
    from app.api.v1.endpoints.api_keys import VALID_SCOPES

    policy.tool_catalogue.cache_clear()
    missing = sorted(
        {spec.required_permission for spec in policy.tool_catalogue().values() if spec.required_permission} - set(VALID_SCOPES)
    )
    assert missing == [], f"not mintable into an API key: {missing}"


def test_the_fingerprint_does_not_depend_on_key_order() -> None:
    """Two clients serialising the same call must produce the same approval."""
    assert policy.argument_fingerprint({"a": 1, "b": 2}) == policy.argument_fingerprint({"b": 2, "a": 1})
    assert policy.argument_fingerprint({"a": 1}) != policy.argument_fingerprint({"a": 2})
