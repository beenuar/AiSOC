"""The hunting and detection-drafting write routes authenticated and stopped.

Thirteen routes across seven modules resolved a session and checked no
entitlement. `saved_hunts.py` said so in its own docstring — "anyone with read
access to the `/hunt` page can save and delete" — which was true of `viewer`,
a role with no write permission of any kind, in a tenant where saved hunts are
a *shared* list.

Two permissions, and the split is the point rather than a detail.

`lake:query` for the hunt surface. A hunt is a stored query; `run_hunt` and
`run_saved_hunt` execute it, `/nl-query/execute` executes it, and
`/graph/investigate/query` runs a typed primitive against the event lake and
returns rows. Being able to store or compose a query you may not run is
meaningless, so authoring and running are one entitlement. Held by every role
that hunts — including `soc_analyst`, which is why `rules:write` was rejected
for this half.

`rules:read` for the three routes that draft detection content and persist
nothing. The floor there is entitlement to read detection logic at all, which
`viewer` does not have; promoting a draft is separately gated on
`rules:write`.

The tests assert in both directions and read the permission out of the
resolved dependency tree rather than the source, so
`Annotated[Any, require_permission("x")]` with no `Depends()` — the shape that
shipped on eleven routes and read as gated — reports nothing here.
"""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.api.v1.deps import CurrentUser, get_current_user
from app.api.v1.endpoints import graph, hunts, nl_detection, nl_query, saved_hunts, translation
from app.db.database import get_db
from fastapi import FastAPI
from fastapi.testclient import TestClient

TENANT = uuid.UUID("11111111-1111-1111-1111-111111111111")
HUNT = uuid.UUID("22222222-2222-2222-2222-222222222222")

#: (module, handler, permission, method, path, payload). One table drives the
#: refused case, the admitted case and the wiring assertion so the three
#: cannot disagree.
GATED: list[tuple[Any, str, str, str, str, dict[str, Any] | None]] = [
    (hunts, "create_hunt", "lake:query", "POST", "/api/v1/hunts", {"title": "t", "hypothesis": "h"}),
    (hunts, "update_hunt", "lake:query", "PATCH", f"/api/v1/hunts/{HUNT}", {"status": "completed"}),
    (hunts, "run_hunt", "lake:query", "POST", f"/api/v1/hunts/{HUNT}/run", {"platform": "esql"}),
    (hunts, "add_findings", "lake:query", "POST", f"/api/v1/hunts/{HUNT}/findings", {"findings": [{"note": "n"}]}),
    (saved_hunts, "create_saved_hunt", "lake:query", "POST", "/api/v1/saved-hunts", {"name": "n", "nl_query": "logins from iran"}),
    (saved_hunts, "delete_saved_hunt", "lake:query", "DELETE", f"/api/v1/saved-hunts/{HUNT}", None),
    (saved_hunts, "run_saved_hunt", "lake:query", "POST", f"/api/v1/saved-hunts/{HUNT}/run", None),
    (nl_query, "translate_query", "lake:query", "POST", "/api/v1/nl-query/translate", {"question": "failed logins today"}),
    (nl_query, "execute_query", "lake:query", "POST", "/api/v1/nl-query/execute", {"question": "failed logins today"}),
    (graph, "run_investigation_tool", "lake:query", "POST", "/api/v1/graph/investigate/query", {"tool": "host_processes", "args": {}}),
    (
        nl_detection,
        "translate_detection",
        "rules:read",
        "POST",
        "/api/v1/nl-detection/translate",
        {"description": "psexec lateral movement"},
    ),
    (
        translation,
        "translate_rule",
        "rules:read",
        "POST",
        "/api/v1/translation/translate",
        {"rule": "title: x", "source_format": "sigma", "target_formats": ["spl"]},
    ),
]

#: A role holding each permission. `soc_analyst` for `lake:query` on purpose:
#: it is the role `rules:write` would have locked out, so the admitted case
#: fails if the hunt surface is ever re-gated on a detection permission.
HOLDER = {"lake:query": "soc_analyst", "rules:read": "threat_hunter"}

#: Roles that must be refused. `viewer` is the advisory shape. `api_service`
#: holds no lake permission either and is included because a machine key is
#: the credential most likely to be over-scoped by accident.
REFUSED = {"lake:query": ["viewer", "api_service"], "rules:read": ["viewer", "soc_analyst"]}


def _user(role: str) -> CurrentUser:
    return CurrentUser(user_id=uuid.uuid4(), tenant_id=TENANT, role=role, email=f"{role}@tenant.example")


def _db() -> AsyncMock:
    """A session that answers every lookup with "no such row".

    A 404 past the permission check is a pass for these tests: what is under
    test is whether the request reached the handler at all. Returning rows
    would mean maintaining seven different row shapes to prove one thing.
    """
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


def _request(module: Any, role: str, method: str, path: str, payload: dict[str, Any] | None) -> tuple[int, bool]:
    app = FastAPI()
    app.include_router(module.router, prefix="/api/v1")
    db = _db()
    app.dependency_overrides[get_current_user] = lambda: _user(role)
    app.dependency_overrides[get_db] = lambda: db
    try:
        from app.db.rls import get_tenant_db  # noqa: PLC0415 - optional per module

        app.dependency_overrides[get_tenant_db] = lambda: db
    except ImportError:  # pragma: no cover - the alias moved
        pass
    client = TestClient(app, raise_server_exceptions=False)
    response = client.request(method, path, json=payload)
    return response.status_code, db.commit.await_count > 0


def _permissions_on(route: Any) -> list[str]:
    """Permissions FastAPI will actually enforce, from the dependency tree."""
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


IDS = [f"{m.__name__.rsplit('.', 1)[-1]}.{h}" for m, h, *_ in GATED]


class TestUnentitledCallersAreRefused:
    @pytest.mark.parametrize(("module", "handler", "permission", "method", "path", "payload"), GATED, ids=IDS)
    def test_every_role_without_the_permission_is_refused(
        self, module: Any, handler: str, permission: str, method: str, path: str, payload: dict[str, Any] | None
    ) -> None:
        for role in REFUSED[permission]:
            status, committed = _request(module, role, method, path, payload)
            assert not committed, f"{role} committed a write through {handler}"
            assert status == 403, f"{role} got HTTP {status} from {handler}, not 403"

    def test_a_viewer_cannot_delete_another_teams_saved_hunt(self) -> None:
        """Saved hunts are a tenant-shared list, which is what made this bite.

        The module's own docstring used to say anyone with read access to the
        `/hunt` page could save and delete. `viewer` has read access to that
        page and no write permission anywhere.
        """
        status, committed = _request(saved_hunts, "viewer", "DELETE", f"/api/v1/saved-hunts/{HUNT}", None)
        assert not committed
        assert status == 403

    def test_a_viewer_cannot_read_raw_events_through_an_investigation_pivot(self) -> None:
        """`viewer` is given no lake permission at all, by design."""
        status, _ = _request(graph, "viewer", "POST", "/api/v1/graph/investigate/query", {"tool": "host_processes", "args": {}})
        assert status == 403


class TestEntitledCallersStillWork:
    """The half that catches a permission applied too strongly."""

    @pytest.mark.parametrize(("module", "handler", "permission", "method", "path", "payload"), GATED, ids=IDS)
    def test_a_holder_of_the_permission_is_admitted(
        self, module: Any, handler: str, permission: str, method: str, path: str, payload: dict[str, Any] | None
    ) -> None:
        status, _ = _request(module, HOLDER[permission], method, path, payload)
        assert status != 403, f"{HOLDER[permission]} holds {permission} but {handler} answered 403"

    @pytest.mark.parametrize(
        ("module", "method", "path", "payload"),
        [
            (hunts, "POST", "/api/v1/hunts", {"title": "t", "hypothesis": "h"}),
            (saved_hunts, "POST", "/api/v1/saved-hunts", {"name": "n", "nl_query": "logins from iran"}),
            (nl_query, "POST", "/api/v1/nl-query/translate", {"question": "failed logins today"}),
        ],
        ids=["hunts", "saved-hunts", "nl-query"],
    )
    def test_an_analyst_may_still_use_the_hunt_surface(self, module: Any, method: str, path: str, payload: dict[str, Any]) -> None:
        """The outage `rules:write` would have caused, asserted rather than argued.

        `soc_analyst` holds no `rules:*` permission. The `/hunt` page is the
        analyst surface and the console's own client calls these three, so
        gating the workbench on a detection permission would have broken it
        for the role that uses it most.
        """
        status, _ = _request(module, "soc_analyst", method, path, payload)
        assert status != 403

    @pytest.mark.parametrize("role", ["soc_lead", "threat_hunter", "tenant_admin"])
    def test_every_hunting_role_may_run_a_saved_hunt(self, role: str) -> None:
        status, _ = _request(saved_hunts, role, "POST", f"/api/v1/saved-hunts/{HUNT}/run", None)
        assert status != 403

    def test_a_viewer_may_still_list_hunts(self) -> None:
        """Reads are unchanged: the shared list stays readable."""
        status, _ = _request(saved_hunts, "viewer", "GET", "/api/v1/saved-hunts", None)
        assert status != 403


class TestWiring:
    @pytest.mark.parametrize(("module", "handler", "permission", "method", "path", "payload"), GATED, ids=IDS)
    def test_route_enforces_exactly_its_permission(
        self, module: Any, handler: str, permission: str, method: str, path: str, payload: dict[str, Any] | None
    ) -> None:
        assert _permissions_on(_route_for(module, handler)) == [permission]

    @pytest.mark.parametrize(
        "module", [hunts, saved_hunts, nl_query, nl_detection, translation], ids=lambda m: m.__name__.rsplit(".", 1)[-1]
    )
    def test_no_state_changing_route_in_these_modules_is_unguarded(self, module: Any) -> None:
        """These six are now fully gated, so the invariant is "all of them".

        `graph.py` is excluded: it has other state-changing routes that are
        this stack's later work, and asserting "all" there would fail for a
        reason this PR did not cause.
        """
        unguarded = [
            getattr(r.endpoint, "__name__", "?")
            for r in module.router.routes
            if r.methods & {"POST", "PUT", "PATCH", "DELETE"} and not _permissions_on(r)
        ]
        assert not unguarded, f"{module.__name__} has state-changing routes with no permission: {unguarded}"
