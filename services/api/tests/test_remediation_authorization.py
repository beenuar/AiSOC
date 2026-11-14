"""GHSA-wj5c-88hg-5926: the remediation router authenticated but never authorized.

`services/api/app/api/v1/endpoints/remediation.py` is the tenant's
autonomous-response control plane. `maturity_tier` and `action_overrides` are
read by `services/actions` when it grades a response action — `force_auto`
becomes `AutonomyMode.AUTO` at an L4 tier label, `block` becomes
`AutonomyMode.BLOCKED` — and a `remediation_whitelist` row is what lets L4
execute a high blast-radius verb unattended.

Every route depended on `get_current_user` and none on `require_permission`,
so a `viewer` (five read permissions, no write of any kind) could raise the
tier, pre-approve a destructive verb against every target with no expiry, or
suppress a containment verb mid-incident.

Two things these tests are careful about:

*They fail on the vulnerable tree for the defect.* Every symbol imported here
— `remediation`, `CurrentUser`, `require_permission`, `get_current_user` —
exists on both sides of the fix, so a run against the pre-fix module fails
because the write lands, not because an import is missing.

*They assert the write did not land, not merely the status code.* The handler
commits before FastAPI serialises the response, so on the vulnerable tree the
policy row was written on a request that returned 500. A test that asserted
`!= 200` would have passed against a successful attack.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.api.v1.deps import CurrentUser
from app.api.v1.endpoints import remediation
from app.api.v1.endpoints.auth import get_current_user
from app.db.database import get_db
from fastapi import FastAPI
from fastapi.testclient import TestClient

TENANT = uuid.UUID("11111111-1111-1111-1111-111111111111")

#: Every mutating route in the module, by handler name. The advisory names two
#: of these; enforcing only those would leave the third open.
WRITE_HANDLERS = ["update_maturity_config", "add_to_whitelist", "remove_from_whitelist"]
READ_HANDLERS = ["get_maturity_config", "list_gate_log", "list_whitelist"]

#: The advisory's proof-of-concept requests, in order.
POLICY_WRITES: list[tuple[str, str, str, dict[str, Any] | None]] = [
    (
        "raise the tier and force-auto a destructive verb",
        "PUT",
        "/api/v1/remediation/config",
        {"maturity_tier": 4, "action_overrides": {"isolate_host": {"force_auto": True}}},
    ),
    (
        "suppress a containment verb",
        "PUT",
        "/api/v1/remediation/config",
        {"maturity_tier": 0, "action_overrides": {"isolate_host": {"block": True}}},
    ),
    (
        "install a never-expiring high blast-radius pre-approval",
        "POST",
        "/api/v1/remediation/whitelist",
        {"action_type": "isolate_host", "blast_radius": "high", "constraints": {}, "expires_at": None},
    ),
    (
        "delete a whitelist entry",
        "DELETE",
        f"/api/v1/remediation/whitelist/{uuid.uuid4()}",
        None,
    ),
]


def _user(role: str) -> CurrentUser:
    return CurrentUser(user_id=uuid.uuid4(), tenant_id=TENANT, role=role, email=f"{role}@tenant-a.example")


def _row() -> SimpleNamespace:
    now = datetime.now(UTC)
    return SimpleNamespace(
        id=uuid.uuid4(),
        tenant_id=TENANT,
        maturity_tier=0,
        action_overrides={},
        changed_by=None,
        changed_at=now,
        created_at=now,
        action_type="isolate_host",
        blast_radius="high",
        constraints={},
        approved_by=None,
        expires_at=None,
    )


def _db() -> AsyncMock:
    result = MagicMock()
    result.scalar_one_or_none = MagicMock(return_value=_row())
    result.scalars = MagicMock(return_value=MagicMock(all=MagicMock(return_value=[])))
    db = AsyncMock()
    db.execute = AsyncMock(return_value=result)
    db.get = AsyncMock(return_value=_row())
    db.commit = AsyncMock()
    db.refresh = AsyncMock()
    db.delete = AsyncMock()
    db.add = MagicMock()
    return db


def _request(role: str, method: str, path: str, payload: dict[str, Any] | None) -> tuple[int, bool]:
    """Issue one request as *role*; return the status and whether it committed."""
    app = FastAPI()
    app.include_router(remediation.router, prefix="/api/v1")
    db = _db()
    app.dependency_overrides[get_current_user] = lambda: _user(role)
    app.dependency_overrides[get_db] = lambda: db
    client = TestClient(app, raise_server_exceptions=False)
    response = client.request(method, path, json=payload)
    return response.status_code, db.commit.await_count > 0


def _permissions_on(route: Any) -> list[str]:
    """Permissions FastAPI will actually enforce, read from the dependency tree.

    Walking the resolved tree rather than the source is deliberate: a
    dependency that is present but wired to the wrong thing satisfies a grep
    and enforces nothing. `require_permission` returns a closure named
    `_check` holding the permission string in its cell.
    """
    found: list[str] = []

    def walk(dependant: Any) -> None:
        call = getattr(dependant, "call", None)
        if getattr(call, "__name__", "") == "_check":
            for cell in getattr(call, "__closure__", None) or ():
                if isinstance(cell.cell_contents, str):
                    found.append(cell.cell_contents)
        for sub in getattr(dependant, "dependencies", []):
            walk(sub)

    walk(route.dependant)
    return found


def _route_for(handler_name: str) -> Any:
    for route in remediation.router.routes:
        if getattr(route, "endpoint", None) is getattr(remediation, handler_name):
            return route
    raise AssertionError(f"no route registered for {handler_name}")


class TestViewerCannotWriteThePolicy:
    """The advisory's proof of concept, executed."""

    @pytest.mark.parametrize(("label", "method", "path", "payload"), POLICY_WRITES, ids=[p[0] for p in POLICY_WRITES])
    def test_viewer_write_is_refused_and_does_not_commit(self, label: str, method: str, path: str, payload: dict[str, Any] | None) -> None:
        status, committed = _request("viewer", method, path, payload)
        assert not committed, f"viewer was able to {label}: the transaction committed"
        assert status == 403, f"viewer got HTTP {status} rather than 403 when trying to {label}"

    @pytest.mark.parametrize("role", ["soc_analyst", "soc_lead", "threat_hunter"])
    def test_action_dispatchers_cannot_pre_approve_their_own_actions(self, role: str) -> None:
        """`actions:execute` must not be enough to write the policy.

        `soc_lead` and `soc_analyst` hold `actions:execute`. Gating the
        whitelist on it — the other candidate permission — would let the
        principal who dispatches an action pre-approve its own future
        dispatches, which is the separation of duties the approval path
        already enforces elsewhere.
        """
        status, committed = _request(
            role,
            "POST",
            "/api/v1/remediation/whitelist",
            {"action_type": "isolate_host", "blast_radius": "high", "constraints": {}, "expires_at": None},
        )
        assert not committed
        assert status == 403


class TestAuthorizedCallersStillWork:
    """Refusing everyone would also satisfy the tests above."""

    def test_tenant_admin_can_update_the_policy(self) -> None:
        status, committed = _request(
            "tenant_admin",
            "PUT",
            "/api/v1/remediation/config",
            {"maturity_tier": 2, "action_overrides": {"isolate_host": {"force_auto": True}}},
        )
        assert status == 200, f"tenant_admin got HTTP {status}"
        assert committed

    def test_viewer_can_still_read_the_posture_it_works_under(self) -> None:
        status, _ = _request("viewer", "GET", "/api/v1/remediation/config", None)
        assert status == 200


class TestEveryRouteIsGated:
    """Read from the route table, so a new handler cannot quietly arrive ungated."""

    @pytest.mark.parametrize("handler", WRITE_HANDLERS)
    def test_write_routes_require_settings_write(self, handler: str) -> None:
        assert _permissions_on(_route_for(handler)) == ["settings:write"]

    @pytest.mark.parametrize("handler", READ_HANDLERS)
    def test_read_routes_require_a_permission(self, handler: str) -> None:
        assert _permissions_on(_route_for(handler)) == ["actions:read"]

    def test_no_state_changing_route_in_the_module_is_unguarded(self) -> None:
        """Catches a route added later that this file does not name."""
        unguarded = [
            f"{sorted(r.methods - {'HEAD', 'OPTIONS'})} {r.path}"
            for r in remediation.router.routes
            if r.methods & {"POST", "PUT", "PATCH", "DELETE"} and not _permissions_on(r)
        ]
        assert not unguarded, f"state-changing routes with no permission: {unguarded}"


class TestOverrideShape:
    """`action_overrides` was a free-form dict written straight into a security row."""

    @pytest.mark.parametrize(
        "overrides",
        [
            {"isolate_host": {"force_auto": "yes"}},  # not a boolean
            {"isolate_host": {"unknown_flag": True}},  # not a flag the gate reads
            {"isolate_host": "force_auto"},  # not an object
            {"Robert'); DROP TABLE--": {"block": True}},  # not an action type
        ],
    )
    def test_malformed_overrides_are_refused(self, overrides: dict[str, Any]) -> None:
        status, committed = _request(
            "tenant_admin", "PUT", "/api/v1/remediation/config", {"maturity_tier": 1, "action_overrides": overrides}
        )
        assert status == 422, f"expected 422, got {status}"
        assert not committed
