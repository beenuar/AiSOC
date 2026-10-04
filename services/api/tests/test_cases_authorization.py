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
import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.api.v1.deps import CurrentUser
from app.api.v1.endpoints import cases
from fastapi import HTTPException


def _user() -> CurrentUser:
    return CurrentUser(user_id=uuid.uuid4(), tenant_id=uuid.uuid4(), role="analyst", email="analyst@example.com")


def _proxy_response(payload: dict[str, Any], status_code: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.json = MagicMock(return_value=payload)
    return resp


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
    # Reopening is a write, and a privileged one: it moves a case out of a
    # terminal state, which the forward-only PATCH deliberately cannot do.
    "reopen_case",
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

    @pytest.mark.asyncio
    async def test_it_resolves_the_case_against_the_callers_tenant(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A case the caller's tenant does not own must not reach the proxy.

        Was `assert "_resolve_case_id(case_id, db, user.tenant_id)" in source`,
        which is satisfied by the call appearing anywhere — including on a
        branch that never runs, or with its result discarded.
        """
        proxy = AsyncMock()
        monkeypatch.setattr(cases, "_agents_proxy", proxy)
        monkeypatch.setattr(cases, "_resolve_case_id", AsyncMock(side_effect=HTTPException(status_code=404, detail="Case not found")))

        with pytest.raises(HTTPException) as exc:
            await cases.case_investigation_run(case_id="c-1", run_id="r-1", db=MagicMock(), user=_user())

        assert exc.value.status_code == 404
        # The run must never have been proxied: resolving the case is what
        # proves the caller may see it.
        proxy.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_a_run_belonging_to_another_case_is_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Resolving the case is not enough on its own.

        A caller who owns *some* case could otherwise pass their own case_id
        with somebody else's run_id and have the proxy answer. The old
        assertion was `"run_case_id" in source and "404" in source` — and
        `404` appears on the `_resolve_case_id` path too, so deleting this
        check entirely would still have satisfied it.
        """
        mine, theirs = uuid.uuid4(), uuid.uuid4()
        monkeypatch.setattr(cases, "_resolve_case_id", AsyncMock(return_value=mine))
        monkeypatch.setattr(cases, "_agents_proxy", AsyncMock(return_value=_proxy_response({"id": "r-1", "case_id": str(theirs)})))

        with pytest.raises(HTTPException) as exc:
            await cases.case_investigation_run(case_id="INC-001", run_id="r-1", db=MagicMock(), user=_user())

        assert exc.value.status_code == 404

    @pytest.mark.asyncio
    async def test_a_run_belonging_to_this_case_is_returned(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The refusals above are worthless if the route refuses everything."""
        mine = uuid.uuid4()
        monkeypatch.setattr(cases, "_resolve_case_id", AsyncMock(return_value=mine))
        payload = {"id": "r-1", "case_id": str(mine), "status": "completed"}
        monkeypatch.setattr(cases, "_agents_proxy", AsyncMock(return_value=_proxy_response(payload)))

        assert await cases.case_investigation_run(case_id="INC-001", run_id="r-1", db=MagicMock(), user=_user()) == payload

    @pytest.mark.asyncio
    async def test_the_run_id_cannot_inject_url_syntax_into_the_proxied_path(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """`run_id` is caller-supplied and is interpolated into a URL path."""
        mine = uuid.uuid4()
        monkeypatch.setattr(cases, "_resolve_case_id", AsyncMock(return_value=mine))
        proxy = AsyncMock(return_value=_proxy_response({"id": "x", "case_id": str(mine)}))
        monkeypatch.setattr(cases, "_agents_proxy", proxy)

        await cases.case_investigation_run(case_id="INC-001", run_id="../../admin?x=1", db=MagicMock(), user=_user())

        assert proxy.await_args is not None, "the handler never reached the proxy"
        path = proxy.await_args.args[1]
        assert "../" not in path and "?" not in path, path
