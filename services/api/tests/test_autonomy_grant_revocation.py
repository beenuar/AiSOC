"""An operator can hand an earned autonomy grant back.

``DELETE /api/v1/autonomy-policy/grants`` was unreachable from the day it
shipped. ``DELETE /{action}`` is declared several hundred lines earlier in the
same router, FastAPI matches in registration order, and so the request was
taken by the threshold-reset handler with ``action="grants"``. The revocation
never ran, and the caller got a 204 saying it had: a safety control that only
worked in the direction that hands autonomy *out*.

The damage is what makes the two handlers easy to tell apart, and this drives
the real route rather than the handler function so that it can tell them
apart. A revocation issues ``UPDATE aisoc_autonomy_grants``; the reset issues
``DELETE FROM aisoc_autonomy_thresholds``. Before the fix this request quietly
did the second one, so a test that asserted only on the status code would have
passed against the defect.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

TENANT_ID = uuid.UUID("11111111-1111-4111-8111-111111111111")
USER_ID = uuid.UUID("22222222-2222-4222-8222-222222222222")

GRANT_QUERY = {"scope_kind": "action_verb", "scope_key": "close_alert", "capability": "auto_close"}


class _Result:
    """Enough of a SQLAlchemy result for the statements this route issues."""

    def __init__(self, rowcount: int = 1) -> None:
        self.rowcount = rowcount

    def mappings(self) -> _Result:
        return self

    def all(self) -> list:
        return []

    def first(self) -> None:
        return None

    def scalar_one_or_none(self) -> None:
        return None


class _RecordingSession:
    """Records what the route told the database, which is the evidence here."""

    def __init__(self, *, rowcount: int = 1) -> None:
        self.statements: list[tuple[str, dict]] = []
        self.added: list[Any] = []
        self._rowcount = rowcount
        self.committed = 0

    async def execute(self, statement: Any, params: dict | None = None) -> _Result:
        self.statements.append((str(statement), params or {}))
        return _Result(rowcount=self._rowcount)

    def add(self, instance: Any) -> None:
        self.added.append(instance)

    async def flush(self) -> None:
        return None

    async def commit(self) -> None:
        self.committed += 1

    async def rollback(self) -> None:
        return None

    def sql_touching(self, table: str) -> list[str]:
        return [sql for sql, _ in self.statements if table in sql]

    def audit_actions(self) -> list[str]:
        return [getattr(row, "action", "") for row in self.added]


class _Principal:
    """The authenticated caller. The tenant comes from here, never the request."""

    def __init__(self) -> None:
        self.tenant_id = TENANT_ID
        self.user_id = USER_ID
        self.email = "operator@example.com"

    async def require_permission_db(self, permission: str, db: Any) -> None:
        assert permission == "settings:write"


@pytest.fixture
def session() -> _RecordingSession:
    return _RecordingSession()


@pytest.fixture
def client(session: _RecordingSession) -> TestClient:
    autonomy_policy = pytest.importorskip("app.api.v1.endpoints.autonomy_policy")
    deps = pytest.importorskip("app.api.v1.deps")
    rls = pytest.importorskip("app.db.rls")

    app = FastAPI()
    app.include_router(autonomy_policy.router, prefix="/api/v1")
    app.dependency_overrides[deps.get_current_user] = _Principal
    app.dependency_overrides[rls.get_tenant_db] = lambda: session
    app.dependency_overrides[deps.get_db] = lambda: session
    return TestClient(app, raise_server_exceptions=False)


def test_revoking_a_grant_reaches_the_revocation(client: TestClient, session: _RecordingSession) -> None:
    """The regression. Asserted on what the database was told, because the
    handler that used to answer this request also returned 204."""
    response = client.request("DELETE", "/api/v1/autonomy-policy/grants", params=GRANT_QUERY)

    assert response.status_code == 204, response.text
    revocations = session.sql_touching("aisoc_autonomy_grants")
    assert revocations, (
        f"no statement touched aisoc_autonomy_grants; the request was answered by something other than the revocation: {session.statements}"
    )
    assert "UPDATE aisoc_autonomy_grants" in revocations[0]
    assert session.committed == 1


def test_the_revocation_is_audited_as_a_revocation(client: TestClient, session: _RecordingSession) -> None:
    """A human stopping and the evidence stopping them are different events.

    One word for both would make "was this taken away because the numbers
    slipped" unanswerable from the log, which is the reason the service keeps
    a separate audit action for it.
    """
    autonomy_grants = pytest.importorskip("app.services.autonomy_grants")

    client.request("DELETE", "/api/v1/autonomy-policy/grants", params=GRANT_QUERY)

    assert autonomy_grants.AUDIT_REVOKED in session.audit_actions()


def test_revoking_a_grant_does_not_reset_a_threshold(client: TestClient, session: _RecordingSession) -> None:
    """What the defect actually did, named so it cannot come back unnoticed.

    ``action="grants"`` deleted the tenant's threshold override for an action
    called "grants". Harmless only because no such action exists; the point is
    that the request reached the wrong table entirely.
    """
    client.request("DELETE", "/api/v1/autonomy-policy/grants", params=GRANT_QUERY)

    assert session.sql_touching("aisoc_autonomy_thresholds") == []


def test_resetting_a_threshold_still_works(client: TestClient, session: _RecordingSession) -> None:
    """The parameterised route keeps its own traffic.

    Constraining ``{action}`` narrows it to names that are not sub-resources,
    and nothing else.
    """
    response = client.request("DELETE", "/api/v1/autonomy-policy/close_alert")

    assert response.status_code == 204, response.text
    assert session.sql_touching("aisoc_autonomy_thresholds")
    assert session.sql_touching("aisoc_autonomy_grants") == []


def test_revoking_a_grant_nobody_holds_is_a_404(session: _RecordingSession) -> None:
    """A revocation that matched no standing grant is not a silent success."""
    autonomy_policy = pytest.importorskip("app.api.v1.endpoints.autonomy_policy")
    deps = pytest.importorskip("app.api.v1.deps")
    rls = pytest.importorskip("app.db.rls")

    empty = _RecordingSession(rowcount=0)
    app = FastAPI()
    app.include_router(autonomy_policy.router, prefix="/api/v1")
    app.dependency_overrides[deps.get_current_user] = _Principal
    app.dependency_overrides[rls.get_tenant_db] = lambda: empty

    response = TestClient(app, raise_server_exceptions=False).request("DELETE", "/api/v1/autonomy-policy/grants", params=GRANT_QUERY)

    assert response.status_code == 404
    assert empty.committed == 0


def test_a_scope_outside_the_vocabulary_is_refused(client: TestClient, session: _RecordingSession) -> None:
    """A capability no code path consults must not be revocable either."""
    response = client.request(
        "DELETE",
        "/api/v1/autonomy-policy/grants",
        params={**GRANT_QUERY, "capability": "auto_everything"},
    )

    assert response.status_code == 422
    assert session.sql_touching("aisoc_autonomy_grants") == []
