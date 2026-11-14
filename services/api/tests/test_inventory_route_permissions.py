"""Inventory, entity-graph and insider-threat writes authenticated and stopped.

Sixteen routes across five modules. None of them had a first-party caller, so
none of them had a reason to be reachable by a session alone, and all of them
were: a `viewer` could delete the inventory row for a tier-1 host, forge an
edge between an attacker-controlled account and a service identity, or put a
named employee on the insider-threat watchlist with a reason of its choosing.

Three permissions, chosen by what the row *is* rather than by which table it
lands in.

`settings:write` for the inventory and the correlation graph. An asset row is
CMDB data and the graph's own CMDB import already required exactly this, so
the two doors onto one class of data now agree. A graph edge is worse than a
bad row: nothing downstream re-derives it, so a forged one arrives in the next
investigation as a conclusion.

`cases:write` for insider threat. Watchlisting a subject and recording
indicators against them is investigative judgement, held by every
investigating role and withheld from `viewer`. `settings:write` was rejected
here for the opposite reason it was chosen above — it would take
insider-threat work away from the analysts the module is for.

`alerts:read` for `POST /identity-timeline/build`, which persists nothing and
reads only `aisoc_alerts`. Every human role holds it deliberately; the
refusal it makes is against a narrowly-scoped API key, which carries a scope
list rather than a role. That case is asserted below rather than assumed,
because a permission every role holds would otherwise be a fig leaf.
"""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.api.v1.deps import CurrentUser, get_current_user
from app.api.v1.endpoints import assets, graph, identity_graph, identity_timeline, insider_threat
from app.db.database import get_db
from fastapi import FastAPI
from fastapi.testclient import TestClient

TENANT = uuid.UUID("11111111-1111-1111-1111-111111111111")
ROW = uuid.UUID("22222222-2222-2222-2222-222222222222")

GATED: list[tuple[Any, str, str, str, str, dict[str, Any] | None]] = [
    (assets, "create_asset", "settings:write", "POST", "/api/v1/assets", {"name": "db-1", "asset_type": "host"}),
    (assets, "update_asset", "settings:write", "PATCH", f"/api/v1/assets/{ROW}", {"criticality": "low"}),
    (assets, "delete_asset", "settings:write", "DELETE", f"/api/v1/assets/{ROW}", None),
    (
        assets,
        "create_vulnerability",
        "settings:write",
        "POST",
        "/api/v1/assets/vulnerabilities",
        {"asset_id": str(ROW), "cve_id": "CVE-2026-0001", "severity": "high"},
    ),
    (
        identity_graph,
        "create_node",
        "settings:write",
        "POST",
        "/api/v1/identity-graph/nodes",
        {"node_type": "user", "identifier": "svc_deploy"},
    ),
    (
        identity_graph,
        "create_edge",
        "settings:write",
        "POST",
        "/api/v1/identity-graph/edges",
        {"source_id": str(ROW), "target_id": str(ROW), "edge_type": "assumes"},
    ),
    (
        identity_graph,
        "link_alert_to_identity",
        "settings:write",
        "POST",
        "/api/v1/identity-graph/alert-links",
        {"alert_id": str(ROW), "node_id": str(ROW)},
    ),
    (graph, "upsert_host", "settings:write", "POST", "/api/v1/graph/entities/host", {"host_id": "h1", "hostname": "db-1"}),
    (graph, "upsert_user", "settings:write", "POST", "/api/v1/graph/entities/user", {"user_id": "u1", "username": "svc_deploy"}),
    (
        graph,
        "upsert_alert_graph",
        "settings:write",
        "POST",
        "/api/v1/graph/entities/alert",
        {"alert_id": "a1", "title": "t", "severity": "high"},
    ),
    (
        graph,
        "upsert_case_graph",
        "settings:write",
        "POST",
        "/api/v1/graph/entities/case",
        {"case_id": "c1", "title": "t", "severity": "high"},
    ),
    (
        insider_threat,
        "update_watchlist",
        "cases:write",
        "PATCH",
        f"/api/v1/insider-threat/profiles/{ROW}/watchlist",
        {"is_watchlisted": True, "watchlist_reason": "resignation"},
    ),
    (
        insider_threat,
        "create_indicator",
        "cases:write",
        "POST",
        "/api/v1/insider-threat/indicators",
        {"profile_id": str(ROW), "indicator_type": "exfiltration", "severity": "high"},
    ),
    (
        insider_threat,
        "acknowledge_indicator",
        "cases:write",
        "POST",
        f"/api/v1/insider-threat/indicators/{ROW}/acknowledge",
        None,
    ),
    (insider_threat, "create_peer_group", "cases:write", "POST", "/api/v1/insider-threat/peer-groups", {"name": "engineering"}),
    (
        identity_timeline,
        "build_timeline",
        "alerts:read",
        "POST",
        "/api/v1/identity-timeline/build",
        {"identity_type": "user", "identity_value": "svc_deploy"},
    ),
]

#: A role that holds each permission. `soc_analyst` for `cases:write` on
#: purpose: it is the role `settings:write` would have locked out of the
#: insider-threat module.
HOLDER = {"settings:write": "tenant_admin", "cases:write": "soc_analyst", "alerts:read": "viewer"}

#: Roles that must be refused. `alerts:read` is held by every role in the
#: static map, so it has no role-based refusal — the API-key case below is its
#: proof instead, and listing none here says so rather than hiding it.
REFUSED: dict[str, list[str]] = {
    "settings:write": ["viewer", "soc_analyst", "soc_lead", "threat_hunter"],
    "cases:write": ["viewer"],
    "alerts:read": [],
}

IDS = [f"{m.__name__.rsplit('.', 1)[-1]}.{h}" for m, h, *_ in GATED]


def _user(role: str) -> CurrentUser:
    return CurrentUser(user_id=uuid.uuid4(), tenant_id=TENANT, role=role, email=f"{role}@tenant.example")


def _api_key(scopes: list[str]) -> CurrentUser:
    """An API-key principal: explicit scopes, no role-derived permissions."""
    return CurrentUser(user_id=uuid.uuid4(), tenant_id=TENANT, role="api_service", email="api-key:aisoc_abc123", scopes=scopes)


def _db() -> AsyncMock:
    result = MagicMock()
    result.fetchone = MagicMock(return_value=None)
    result.fetchall = MagicMock(return_value=[])
    result.scalar_one_or_none = MagicMock(return_value=None)
    result.scalars = MagicMock(return_value=MagicMock(all=MagicMock(return_value=[])))
    result.rowcount = 0
    db = AsyncMock()
    db.execute = AsyncMock(return_value=result)
    db.get = AsyncMock(return_value=None)
    db.commit = AsyncMock()
    db.rollback = AsyncMock()
    db.refresh = AsyncMock()
    db.flush = AsyncMock()
    db.delete = AsyncMock()
    db.add = MagicMock()
    return db


def _request(module: Any, principal: CurrentUser, method: str, path: str, payload: dict[str, Any] | None) -> tuple[int, bool]:
    app = FastAPI()
    app.include_router(module.router, prefix="/api/v1")
    db = _db()
    app.dependency_overrides[get_current_user] = lambda: principal
    app.dependency_overrides[get_db] = lambda: db
    client = TestClient(app, raise_server_exceptions=False)
    response = client.request(method, path, json=payload)
    return response.status_code, db.commit.await_count > 0


def _permissions_on(route: Any) -> list[str]:
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


def _route_for(module: Any, handler_name: str) -> Any:
    for route in module.router.routes:
        if getattr(route, "endpoint", None) is getattr(module, handler_name):
            return route
    raise AssertionError(f"no route registered for {module.__name__}.{handler_name}")


class TestUnentitledCallersAreRefused:
    @pytest.mark.parametrize(("module", "handler", "permission", "method", "path", "payload"), GATED, ids=IDS)
    def test_every_role_without_the_permission_is_refused(
        self, module: Any, handler: str, permission: str, method: str, path: str, payload: dict[str, Any] | None
    ) -> None:
        for role in REFUSED[permission]:
            status, committed = _request(module, _user(role), method, path, payload)
            assert not committed, f"{role} committed a write through {handler}"
            assert status == 403, f"{role} got HTTP {status} from {handler}, not 403"

    def test_a_viewer_cannot_delete_the_inventory_row_for_a_host(self) -> None:
        status, committed = _request(assets, _user("viewer"), "DELETE", f"/api/v1/assets/{ROW}", None)
        assert not committed
        assert status == 403

    def test_a_viewer_cannot_forge_an_identity_graph_edge(self) -> None:
        """A forged edge is not a visibly bad row, it is a wrong conclusion."""
        status, committed = _request(
            identity_graph,
            _user("viewer"),
            "POST",
            "/api/v1/identity-graph/edges",
            {"source_id": str(ROW), "target_id": str(ROW), "edge_type": "assumes"},
        )
        assert not committed
        assert status == 403

    def test_a_viewer_cannot_watchlist_an_employee(self) -> None:
        status, committed = _request(
            insider_threat,
            _user("viewer"),
            "PATCH",
            f"/api/v1/insider-threat/profiles/{ROW}/watchlist",
            {"is_watchlisted": True, "watchlist_reason": "fabricated"},
        )
        assert not committed
        assert status == 403


class TestTheApiKeyRefusalIsReal:
    """`alerts:read` is held by every role, so this is where it bites.

    Without this, gating a read-shaped POST on a permission nobody lacks
    would be a fig leaf that satisfies the ratchet and changes nothing.
    """

    def test_a_key_scoped_elsewhere_cannot_build_an_identity_timeline(self) -> None:
        status, _ = _request(
            identity_timeline,
            _api_key(["connectors:read"]),
            "POST",
            "/api/v1/identity-timeline/build",
            {"identity_type": "user", "identity_value": "svc_deploy"},
        )
        assert status == 403

    def test_a_key_scoped_for_alerts_can(self) -> None:
        status, _ = _request(
            identity_timeline,
            _api_key(["alerts:read"]),
            "POST",
            "/api/v1/identity-timeline/build",
            {"identity_type": "user", "identity_value": "svc_deploy"},
        )
        assert status != 403

    def test_a_key_scoped_for_connectors_cannot_write_the_entity_graph(self) -> None:
        status, _ = _request(
            graph, _api_key(["connectors:read"]), "POST", "/api/v1/graph/entities/host", {"host_id": "h1", "hostname": "db-1"}
        )
        assert status == 403

    def test_the_integration_key_these_routes_exist_for_still_works(self) -> None:
        """They have no first-party caller; a scoped key is the real client."""
        status, _ = _request(
            graph, _api_key(["settings:write"]), "POST", "/api/v1/graph/entities/host", {"host_id": "h1", "hostname": "db-1"}
        )
        assert status != 403


class TestEntitledCallersStillWork:
    @pytest.mark.parametrize(("module", "handler", "permission", "method", "path", "payload"), GATED, ids=IDS)
    def test_a_holder_of_the_permission_is_admitted(
        self, module: Any, handler: str, permission: str, method: str, path: str, payload: dict[str, Any] | None
    ) -> None:
        status, _ = _request(module, _user(HOLDER[permission]), method, path, payload)
        assert status != 403, f"{HOLDER[permission]} holds {permission} but {handler} answered 403"

    @pytest.mark.parametrize("role", ["soc_analyst", "soc_lead", "threat_hunter"])
    def test_every_investigating_role_may_still_work_insider_threat(self, role: str) -> None:
        """The outage `settings:write` would have caused on this module."""
        status, _ = _request(
            insider_threat,
            _user(role),
            "POST",
            "/api/v1/insider-threat/indicators",
            {"profile_id": str(ROW), "indicator_type": "exfiltration", "severity": "high"},
        )
        assert status != 403

    def test_a_viewer_may_still_read_the_asset_inventory(self) -> None:
        status, _ = _request(assets, _user("viewer"), "GET", "/api/v1/assets", None)
        assert status != 403


class TestWiring:
    @pytest.mark.parametrize(("module", "handler", "permission", "method", "path", "payload"), GATED, ids=IDS)
    def test_route_enforces_exactly_its_permission(
        self, module: Any, handler: str, permission: str, method: str, path: str, payload: dict[str, Any] | None
    ) -> None:
        assert _permissions_on(_route_for(module, handler)) == [permission]

    @pytest.mark.parametrize(
        "module",
        [assets, identity_graph, identity_timeline, insider_threat, graph],
        ids=lambda m: m.__name__.rsplit(".", 1)[-1],
    )
    def test_no_state_changing_route_in_these_modules_is_unguarded(self, module: Any) -> None:
        unguarded = [
            getattr(r.endpoint, "__name__", "?")
            for r in module.router.routes
            if r.methods & {"POST", "PUT", "PATCH", "DELETE"} and not _permissions_on(r)
        ]
        assert not unguarded, f"{module.__name__} has state-changing routes with no permission: {unguarded}"
