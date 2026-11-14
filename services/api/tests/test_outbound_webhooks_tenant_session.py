"""Every outbound-webhook route must open a tenant-scoped session.

GHSA-898c-wxrw-hx6c (part 1). ``aisoc_outbound_webhooks`` and
``aisoc_outbound_deliveries`` carry the RLS policy
``WITH CHECK (tenant_id = current_tenant_id())`` (migration 097, ENABLE +
FORCE). Every route here took a plain ``get_db`` session, which never sets
``app.current_tenant_id``, so registering a destination failed for **every**
tenant with::

    asyncpg.exceptions.InsufficientPrivilegeError: new row violates
    row-level security policy for table "aisoc_outbound_webhooks"

and the API answered 500 (reproduced live against real Postgres with the app
connected as the NOSUPERUSER runtime role). Reads still worked — the USING
clause also admits a NULL tenant setting — which is why the list looked
healthy while nothing could ever be created. ``deps.py`` documents
``TenantDBSession`` for exactly this; all eight routes must use it.

Asserted on FastAPI's resolved dependency tree, the way
``test_cases_authorization`` reads permissions: a session dependency that is
present but wired to the wrong callable would satisfy a grep and still 500.
"""

from __future__ import annotations

from typing import Any

import pytest
from app.api.v1.endpoints import outbound_webhooks
from app.db.rls import get_tenant_db


def _db_dependency(route: Any) -> Any:
    """The callable behind the route's own ``db`` parameter.

    ``get_db`` appears elsewhere in every tree (``get_current_user`` loads the
    user with it), so the question is what the *handler's* session comes from.
    """
    for dep in route.dependant.dependencies:
        if dep.name == "db":
            return dep.call
    return None


ROUTES = [r for r in outbound_webhooks.router.routes if getattr(r, "dependant", None)]


def test_there_are_routes_to_check() -> None:
    assert len(ROUTES) >= 8


@pytest.mark.parametrize("route", ROUTES, ids=lambda r: f"{sorted(r.methods)[0]} {r.path}")
def test_route_uses_the_tenant_scoped_session(route: Any) -> None:
    assert _db_dependency(route) is get_tenant_db, (
        f"{route.path} opens its session through a dependency that never sets "
        "app.current_tenant_id, so every write violates the table's RLS policy (HTTP 500)"
    )
