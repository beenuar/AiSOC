"""The MSSP write surface authenticated the caller and then checked nothing.

`test_mssp_cross_tenant_authz.py` covers the other half of this surface: whose
child a given tenant id is. That question is not this one. `_require_own_child`
establishes the *relationship* and says nothing about the caller's
*entitlement*, so a `viewer` — a role holding five read permissions and no
write of any kind — sitting in a managing tenant could push a rule pack into a
customer, grant themselves a role over one, adopt one, or delete a critical
detection from one. Same shape as GHSA-wj5c-88hg-5926, one tenant boundary
further out.

Two things these tests are careful about.

*They read the permission out of the resolved dependency tree.* A grep for
`require_permission` is satisfied by a call written where FastAPI never looks —
`Annotated[Any, require_permission("users:write")]` with no `Depends()` shipped
on eleven routes and read as gated. `_permissions_on` walks what FastAPI will
actually run, so that shape reports nothing here.

*They assert in both directions.* A test that only exercises the authorized
caller passes against an ungated route and proves nothing; a test that only
exercises the refused caller passes against a route that refuses everybody,
which is an outage rather than a fix. Every route below is asserted refused
for `viewer` with no write committed, and admitted for a role that should hold
it.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.api.v1.deps import CurrentUser
from app.api.v1.endpoints import mssp
from app.api.v1.endpoints.auth import get_current_user
from app.db.database import get_db
from fastapi import FastAPI
from fastapi.testclient import TestClient

PARENT = uuid.UUID("11111111-1111-1111-1111-111111111111")
CHILD = uuid.UUID("22222222-2222-2222-2222-222222222222")
PACK = uuid.UUID("33333333-3333-3333-3333-333333333333")
RULE = uuid.UUID("44444444-4444-4444-4444-444444444444")
ROW = uuid.UUID("55555555-5555-5555-5555-555555555555")

#: Every route this file gates, with the permission it must enforce and a
#: request that reaches the handler. Driving the parametrisation off one table
#: keeps the refused case, the admitted case and the wiring assertion in
#: agreement — three lists would drift.
GATED: list[tuple[str, str, str, str, dict[str, Any] | None]] = [
    ("onboard_child_tenant", "settings:write", "POST", f"/api/v1/mssp/children/{CHILD}/onboard", None),
    (
        "create_organization",
        "settings:write",
        "POST",
        "/api/v1/mssp/organizations",
        {"slug": "provider-a", "name": "Provider A", "kind": "mssp"},
    ),
    ("create_note", "cases:write", "POST", "/api/v1/mssp/notes", {"child_id": str(CHILD), "body": "quarterly review"}),
    (
        "create_delegation",
        "users:write",
        "POST",
        "/api/v1/mssp/delegations",
        {"child_tenant_id": str(CHILD), "granted_role": "soc_analyst"},
    ),
    ("revoke_delegation", "users:write", "DELETE", f"/api/v1/mssp/delegations/{ROW}", None),
    ("create_rule_pack", "rules:write", "POST", "/api/v1/mssp/rule-packs", {"name": "baseline"}),
    ("update_rule_pack", "rules:write", "PUT", f"/api/v1/mssp/rule-packs/{PACK}", {"name": "renamed"}),
    ("delete_rule_pack", "rules:write", "DELETE", f"/api/v1/mssp/rule-packs/{PACK}", None),
    ("add_rule_to_pack", "rules:write", "POST", f"/api/v1/mssp/rule-packs/{PACK}/rules", {"rule_id": str(RULE)}),
    ("remove_rule_from_pack", "rules:write", "DELETE", f"/api/v1/mssp/rule-packs/{PACK}/rules/{RULE}", None),
    (
        "assign_pack_to_child",
        "rules:write",
        "POST",
        f"/api/v1/mssp/rule-packs/{PACK}/assign",
        {"child_tenant_id": str(CHILD)},
    ),
    (
        "create_rule_override",
        "rules:write",
        "POST",
        "/api/v1/mssp/overrides",
        {"child_tenant_id": str(CHILD), "rule_id": str(RULE), "action": "exclude"},
    ),
    ("delete_override", "rules:write", "DELETE", f"/api/v1/mssp/overrides/{ROW}", None),
]

#: A role that holds each permission. `rules:write` deliberately names
#: `threat_hunter` rather than `tenant_admin`: a wildcard role would pass even
#: if the permission string were misspelled.
HOLDER = {
    "settings:write": "tenant_admin",
    "users:write": "tenant_admin",
    "rules:write": "threat_hunter",
    "cases:write": "soc_analyst",
}

#: The four organisation routes that authorize through `_admin_scope` — an
#: organisation `owner`/`admin` check — rather than a tenant-role permission.
#: Named here so a *new* ungated route in this module fails
#: `test_no_other_state_changing_route_is_unguarded` instead of joining them
#: silently.
ORG_SCOPED = {
    "add_tenants_to_portfolio",
    "remove_tenant_from_portfolio",
    "upsert_member",
    "set_member_tenant_grants",
}


def _user(role: str) -> CurrentUser:
    return CurrentUser(user_id=uuid.uuid4(), tenant_id=PARENT, role=role, email=f"{role}@provider.example")


def _row() -> SimpleNamespace:
    """One object that satisfies every `db.get` in the module.

    The handlers reach it through four different models, and each checks that
    its parent/tenant column is the caller's tenant. Answering every lookup
    with an owned row means a refusal can only have come from the permission
    dependency, which is what is under test.
    """
    now = datetime.now(UTC)
    return SimpleNamespace(
        id=ROW,
        parent_tenant_id=PARENT,
        child_tenant_id=CHILD,
        tenant_id=PARENT,
        # `onboard_child_tenant` reads these off a Tenant.
        parent_tenant_id_=None,
        settings={mssp._MSSP_INVITE_SETTING: str(PARENT)},
        name="Customer A",
        mssp_role="child",
        revoked_at=None,
        rule_id=RULE,
        pack_id=PACK,
        enabled=True,
        parameter_overrides={},
        created_at=now,
        expires_at=None,
    )


def _tenant_row() -> SimpleNamespace:
    """A child tenant that has invited PARENT and has no parent yet."""
    row = _row()
    row.id = CHILD
    row.parent_tenant_id = None
    return row


def _db() -> AsyncMock:
    async def _get(model: Any, pk: Any) -> Any:
        if getattr(model, "__name__", "") == "Tenant":
            return _tenant_row() if pk == CHILD else _row()
        return _row()

    result = MagicMock()
    result.scalar_one_or_none = MagicMock(return_value=_row())
    result.scalars = MagicMock(return_value=MagicMock(all=MagicMock(return_value=[])))
    db = AsyncMock()
    db.get = AsyncMock(side_effect=_get)
    db.execute = AsyncMock(return_value=result)
    db.commit = AsyncMock()
    db.refresh = AsyncMock()
    db.flush = AsyncMock()
    db.delete = AsyncMock()
    db.add = MagicMock()
    return db


def _request(role: str, method: str, path: str, payload: dict[str, Any] | None) -> tuple[int, bool]:
    """Issue one request as *role*; return the status and whether it committed.

    The commit flag matters independently of the status: a handler that writes
    before FastAPI serialises the response has already done the damage on a
    request that then returns 500, so `!= 200` is not evidence of a refusal.
    """
    app = FastAPI()
    app.include_router(mssp.router, prefix="/api/v1")
    db = _db()
    app.dependency_overrides[get_current_user] = lambda: _user(role)
    app.dependency_overrides[get_db] = lambda: db
    client = TestClient(app, raise_server_exceptions=False)
    response = client.request(method, path, json=payload)
    return response.status_code, db.commit.await_count > 0


def _permissions_on(route: Any) -> list[str]:
    """Permissions FastAPI will actually enforce, read from the dependency tree.

    `require_permission` returns a closure named `_check` holding the
    permission string in its cell.
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
    for route in mssp.router.routes:
        if getattr(route, "endpoint", None) is getattr(mssp, handler_name):
            return route
    raise AssertionError(f"no route registered for {handler_name}")


class TestViewerCannotWriteTheManagedEstate:
    """A read-only role in a managing tenant, running the whole write surface."""

    @pytest.mark.parametrize(("handler", "permission", "method", "path", "payload"), GATED, ids=[g[0] for g in GATED])
    def test_viewer_is_refused_and_nothing_commits(
        self, handler: str, permission: str, method: str, path: str, payload: dict[str, Any] | None
    ) -> None:
        status, committed = _request("viewer", method, path, payload)
        assert not committed, f"viewer's {handler} committed a write"
        assert status == 403, f"viewer got HTTP {status} from {handler}, not 403"

    def test_a_viewer_cannot_found_the_organisation_that_would_administer_it(self) -> None:
        """The escalation the structural test below found.

        Founding an organisation makes the founder its `owner`, and `owner` is
        what `_admin_scope` accepts. So while the four organisation routes
        authorized correctly, a read-only role could mint itself the role they
        check for in one request and then grant org roles and per-tenant
        scope. The bootstrap route is the control.
        """
        status, committed = _request(
            "viewer", "POST", "/api/v1/mssp/organizations", {"slug": "provider-a", "name": "Provider A", "kind": "mssp"}
        )
        assert not committed
        assert status == 403

    def test_an_analyst_cannot_grant_itself_a_role_in_a_customer_tenant(self) -> None:
        """`soc_analyst` holds `cases:write` but not `users:write`.

        The distinction is the point of using two permissions on this module:
        writing a note about a customer and granting yourself a session inside
        one are not the same act, and one permission for both would have made
        the weaker route's holders into tenant administrators.
        """
        status, committed = _request(
            "soc_analyst",
            "POST",
            "/api/v1/mssp/delegations",
            {"child_tenant_id": str(CHILD), "granted_role": "tenant_admin"},
        )
        assert not committed
        assert status == 403

    def test_an_analyst_cannot_exclude_a_detection_from_a_customers_ruleset(self) -> None:
        """The severe one. `soc_analyst` holds no `rules:write`.

        An `exclude` override is read back by the effective-rule resolver
        filtered on the child's tenant id, so it deletes a rule from the set
        their hunts run against. The victim's only symptom is a hunt that
        stops matching.
        """
        status, committed = _request(
            "soc_analyst",
            "POST",
            "/api/v1/mssp/overrides",
            {"child_tenant_id": str(CHILD), "rule_id": str(RULE), "action": "exclude"},
        )
        assert not committed
        assert status == 403


class TestEntitledCallersStillWork:
    """Refusing everybody would also satisfy the class above."""

    @pytest.mark.parametrize(("handler", "permission", "method", "path", "payload"), GATED, ids=[g[0] for g in GATED])
    def test_a_holder_of_the_permission_is_admitted(
        self, handler: str, permission: str, method: str, path: str, payload: dict[str, Any] | None
    ) -> None:
        status, _ = _request(HOLDER[permission], method, path, payload)
        assert status != 403, f"{HOLDER[permission]} holds {permission} but {handler} answered 403"

    def test_a_hunter_may_still_author_rule_packs(self) -> None:
        """`rules:write` is held by `threat_hunter`, not only by admins.

        Recorded as its own test because the tempting choice on this module
        was `settings:write` for everything, which would have taken the
        detection surface away from the role that exists to author it.
        """
        status, _ = _request("threat_hunter", "POST", "/api/v1/mssp/rule-packs", {"name": "baseline"})
        assert status != 403

    def test_a_viewer_may_still_read_the_portfolio_it_works_in(self) -> None:
        status, _ = _request("viewer", "GET", "/api/v1/mssp/children", None)
        assert status != 403


class TestWiring:
    """What FastAPI will run, not what the source says."""

    @pytest.mark.parametrize(("handler", "permission", "method", "path", "payload"), GATED, ids=[g[0] for g in GATED])
    def test_route_enforces_exactly_its_permission(
        self, handler: str, permission: str, method: str, path: str, payload: dict[str, Any] | None
    ) -> None:
        assert _permissions_on(_route_for(handler)) == [permission]

    def test_no_other_state_changing_route_is_unguarded(self) -> None:
        """A route added later must be gated or be an explicit org-scoped one."""
        gated = {g[0] for g in GATED}
        unguarded = [
            getattr(r.endpoint, "__name__", "?")
            for r in mssp.router.routes
            if r.methods & {"POST", "PUT", "PATCH", "DELETE"}
            and not _permissions_on(r)
            and getattr(r.endpoint, "__name__", "?") not in ORG_SCOPED
        ]
        assert not unguarded, f"state-changing MSSP routes with no permission and no org scope: {unguarded}"
        assert gated.isdisjoint(ORG_SCOPED), "a route cannot be both permission-gated and org-scoped-only"

    @pytest.mark.parametrize("handler", sorted(ORG_SCOPED))
    def test_org_scoped_routes_really_do_authorize(self, handler: str) -> None:
        """They are not gaps, and this is the evidence rather than a comment.

        `_admin_scope` is the dependency; it raises 403 unless the caller is an
        organisation `owner` or `admin`. If one of these ever loses it, this
        fails rather than the route quietly becoming identity-only.
        """
        route = _route_for(handler)

        def calls(dependant: Any) -> set[str]:
            names = {getattr(getattr(dependant, "call", None), "__name__", "")}
            for sub in getattr(dependant, "dependencies", []):
                names |= calls(sub)
            return names

        assert "_admin_scope" in calls(route.dependant), f"{handler} no longer resolves an administering portfolio scope"
