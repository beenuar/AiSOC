"""The precondition a cross-tenant sweep depends on, asserted instead of assumed.

Three paths in this service read or write across every tenant: the retention
purge, the hunt scheduler's due-hunt sweep, and tenant deletion. All three used
to open with ``SET LOCAL row_security = off``.

That statement only ever worked because the deployment connected as a
superuser. ``migrations/061_runtime_app_role.sql`` moves the services onto a
role with neither ``SUPERUSER`` nor ``BYPASSRLS``, and for such a role Postgres
does not ignore policies when row security is off — it refuses the query::

    ERROR:  query would be affected by row-level security policy for table "alerts"

So the construct flips from "no-op dressed as a control" to "hard failure", and
the cross-tenant reads rest instead on the arm every policy in this schema
already carries::

    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)

A session that never bound a tenant sees everything. That is deliberate and
documented; ``scripts/check_rls_policy_shape.py`` fails if a policy is added
without the arm, so the schema side cannot drift.

Which leaves exactly one way for a sweep to go quiet: running on a session that
*did* bind a tenant. It would then enumerate one tenant, purge or reschedule
that tenant's rows under whatever configuration it loaded, and report success.
A worker that silently stops seeing data is a worse failure than the bypass
this change closes, so that condition raises here.

This module deliberately imports nothing from ``app.api`` — it is called from
background workers, and ``app.db.rls`` pulls in the FastAPI dependency graph.
"""

from __future__ import annotations

import logging

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger("aisoc.cross_tenant")

_BOUND_TENANT_SQL = "SELECT NULLIF(current_setting('app.current_tenant_id', true), '')"


class CrossTenantPreconditionError(RuntimeError):
    """A cross-tenant sweep was asked to run on a session bound to one tenant."""


def _safe(value: object, limit: int = 64) -> str:
    """One-line, length-capped rendering for a log record."""
    return str(value).replace("\r", "").replace("\n", " ")[:limit]


async def assert_cross_tenant_session(session: AsyncSession, what: str) -> None:
    """Raise unless ``session`` will see every tenant's rows.

    ``what`` names the sweep so the log record identifies the caller without a
    traceback.
    """
    bound = await session.scalar(text(_BOUND_TENANT_SQL))
    if not bound:
        return
    logger.error(
        "cross-tenant scan %r refused: the session is bound to tenant %s, so it would " "process one tenant's rows and report success",
        _safe(what),
        _safe(bound),
    )
    raise CrossTenantPreconditionError(
        f"{_safe(what)} must run on a session with no tenant bound; app.current_tenant_id is {_safe(bound)!r}"
    )
