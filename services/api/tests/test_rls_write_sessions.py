"""Writes against strict-WITH-CHECK tables must open tenant-scoped sessions.

Siblings of GHSA-898c-wxrw-hx6c, found by sweeping every endpoint module that
opens its own plain ``get_db`` session against the tables whose RLS policy
carries the strict ``WITH CHECK (tenant_id = current_tenant_id())`` (no NULL
branch). Both were reproduced live against real Postgres with the app
connected as the NOSUPERUSER ``aisoc_app`` runtime role:

* ``POST /api/v1/kill-switch/engage`` answered **500** — the emergency stop
  for autonomous closure and action dispatch could not be engaged on any
  deployment. ``/release`` shared the defect through its audit INSERT and the
  UPDATE's new-row check.
* ``POST /api/v1/taxii/collections`` answered **500** — no tenant could ever
  create a TAXII collection.

``mfa.py`` writes the same class of table and is correct — it calls
``set_rls_context`` on every write path — and ``war_rooms.py`` documents its
one deliberate ``DBSession`` route. These two were the ones missed.

Asserted on FastAPI's resolved dependency tree, as
``test_outbound_webhooks_tenant_session`` does.
"""

from __future__ import annotations

from typing import Any

import pytest
from app.api.v1.endpoints import kill_switch, taxii
from app.db.rls import get_tenant_db


def _db_dependency(route: Any) -> Any:
    for dep in route.dependant.dependencies:
        if dep.name == "db":
            return dep.call
    return None


def _route(router: Any, method: str, path: str) -> Any:
    for r in router.routes:
        if path == r.path and method in set(getattr(r, "methods", set())):
            return r
    raise AssertionError(f"no route {method} {path}")


@pytest.mark.parametrize("path", ["/kill-switch/engage", "/kill-switch/release"])
def test_kill_switch_writes_are_tenant_scoped(path: str) -> None:
    route = _route(kill_switch.router, "POST", path)
    assert _db_dependency(route) is get_tenant_db, (
        f"POST {path} writes aisoc_kill_switch/_audit (strict WITH CHECK) through a "
        "session without app.current_tenant_id, so the emergency stop 500s for every tenant"
    )


def test_taxii_collection_create_is_tenant_scoped() -> None:
    route = _route(taxii.admin_router, "POST", "/taxii/collections")
    assert _db_dependency(route) is get_tenant_db, (
        "POST /taxii/collections inserts into taxii_collections (strict WITH CHECK) "
        "through a session without app.current_tenant_id, so it 500s for every tenant"
    )
