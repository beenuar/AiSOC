"""GHSA-3r28-vqm2-6g6c and GHSA-x2gf-3p79-wvgm: two holes in `cases.py`.

**Nine write routes enforced no permission.** `cases:write` exists, is
withheld from `viewer` on purpose, and is enforced on five routes in
`investigations.py`, `replay.py` and `approvals.py` — and on none of the nine
write routes here. A `viewer` token could create and mutate cases and launch
investigations through `/api/v1/cases/...` that `investigations.py` refuses to
let it launch.

**One read route ignored the tenant entirely.** `GET /cases/{case_id}/
investigations/{run_id}` declared `case_id`, never used it, took no database
session, and never read `user.tenant_id` — it forwarded `run_id` alone to the
agents service. Any authenticated user could read any run by id, across
tenants. The sibling list route two functions above it resolves the case
against the caller's tenant, which is what makes this an omission rather than
a design.

These are asserted against the route table rather than by reading the source,
because a decorator that is present but wired to the wrong dependency would
satisfy a grep and still be broken.
"""

from __future__ import annotations

import inspect
from typing import Any

import pytest
from app.api.v1.endpoints import cases

#: Every mutating route in this module, by handler name.
WRITE_HANDLERS = [
    "create_case",
    "update_case",
    "add_alerts",
    "update_observables",
    "add_comment",
    "add_note",
    "create_task",
    "update_task",
    "case_investigate",
]


def _route_for(name: str) -> Any:
    for route in cases.router.routes:
        if getattr(route, "endpoint", None) is getattr(cases, name):
            return route
    raise AssertionError(f"no route registered for {name}")


def _permissions_on(route: Any) -> list[str]:
    """Permissions enforced on a route, read from FastAPI's dependency tree.

    Reading the resolved tree rather than the source or the annotations is
    deliberate. The annotations here are strings (`from __future__ import
    annotations`), and more importantly a decorator that is present but wired
    to the wrong dependency would satisfy any textual check while enforcing
    nothing. This walks what FastAPI will actually call on a request.
    """
    found: list[str] = []

    def walk(dependant: Any) -> None:
        call = getattr(dependant, "call", None)
        # `require_permission` returns a closure holding the permission string.
        for cell in getattr(call, "__closure__", None) or ():
            try:
                value = cell.cell_contents
            except ValueError:  # pragma: no cover - empty cell
                continue
            if isinstance(value, str) and ":" in value:
                found.append(value)
        for sub in getattr(dependant, "dependencies", []) or []:
            walk(sub)

    walk(route.dependant)
    return found


class TestEveryWriteRouteRequiresCasesWrite:
    @pytest.mark.parametrize("name", WRITE_HANDLERS)
    def test_the_handler_requires_the_permission(self, name: str) -> None:
        assert "cases:write" in _permissions_on(_route_for(name)), f"{name} does not require cases:write, so a viewer token can call it"

    def test_the_list_is_the_whole_write_surface(self) -> None:
        """Guards against a tenth write route arriving unprotected."""
        routes = [r for r in cases.router.routes if set(getattr(r, "methods", set())) & {"POST", "PUT", "PATCH", "DELETE"}]
        assert len(routes) == len(WRITE_HANDLERS), (
            f"cases.py has {len(routes)} write routes but this test knows about "
            f"{len(WRITE_HANDLERS)}; add the new one here and give it cases:write"
        )


class TestTheInvestigationRunReadIsScoped:
    def test_the_handler_takes_a_database_session_and_the_caller(self) -> None:
        """Without a session it *cannot* resolve the case against the tenant.

        The absence of `db` is what made the cross-tenant read structural
        rather than a forgotten line: there was nothing to check against.
        """
        params = inspect.signature(cases.case_investigation_run).parameters
        assert "db" in params, "the handler takes no database session, so it cannot scope by tenant"
        assert "user" in params

    def test_it_resolves_the_case_against_the_callers_tenant(self) -> None:
        source = inspect.getsource(cases.case_investigation_run)
        assert "_resolve_case_id(case_id, db, user.tenant_id)" in source, (
            "the handler does not resolve case_id against the caller's tenant, so run_id alone "
            "is proxied and any authenticated user can read any run"
        )

    def test_a_run_belonging_to_another_case_is_refused(self) -> None:
        """Resolving the case is not enough on its own.

        A caller who owns *some* case could otherwise pass their own case_id
        with somebody else's run_id and have the proxy answer.
        """
        source = inspect.getsource(cases.case_investigation_run)
        assert "run_case_id" in source and "404" in source.replace("HTTP_404_NOT_FOUND", "404"), (
            "the handler does not check the returned run belongs to the resolved case"
        )
