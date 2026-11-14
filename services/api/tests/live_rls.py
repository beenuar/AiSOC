"""Bind a live test's session to a tenant, the way production writers do.

The wave-2 identity tables (``identity_privilege_facts``,
``identity_permission_usage``, ``access_review_findings``,
``access_review_runs``, ``identity_links``) carry the house RLS policy in its
strict form::

    USING      (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)
    WITH CHECK (tenant_id = current_tenant_id())

There is deliberately no unbound-session arm in ``WITH CHECK``. 36 of the 43
policies in the migration chain are written this way and it is the stronger
form: the arm that is missing here is the one that made RLS fail open on the
connectors engine, which never bound the GUC at all.

So a write issued on a session with no tenant bound is refused by Postgres,
and that is the policy working rather than an obstacle. Production writes
arrive either on a session ``app/db/rls.py``'s ``get_tenant_db`` has bound,
or inside a worker that calls ``set_config`` once per tenant the way
``hunt_scheduler`` and ``retro_hunt_consumer`` do. A live suite that wrote
without binding would be exercising a path no caller takes — and it cannot
even reach the property it is testing, because the insert never lands.

Two properties worth keeping in mind when using this:

* ``SET LOCAL`` ends with the transaction, so a ``commit()`` after the write
  drops back to an unbound session. Bind immediately before each write.
* Reads are deliberately left unbound. The cross-tenant assertions in these
  suites are about the tenant predicate each store puts in its *own* SQL, and
  binding the reader would let a store that forgot its predicate pass behind
  RLS — the assertion would still hold, for a reason that is not the one in
  the test's name.
"""

from __future__ import annotations

import uuid

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


async def bind_tenant(session: AsyncSession, tenant: uuid.UUID) -> None:
    """Scope the next write on ``session`` to ``tenant`` until it commits."""
    await session.execute(
        text("SELECT set_config('app.current_tenant_id', :t, TRUE)"),
        {"t": str(tenant)},
    )
