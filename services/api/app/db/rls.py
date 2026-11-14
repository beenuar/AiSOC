"""Row-Level Security (RLS) helpers for multi-tenant isolation.

Usage
-----
Replace ``get_db`` with ``get_tenant_db`` in endpoint signatures that require
tenant-scoped sessions:

    @router.get("/cases")
    async def list_cases(db: TenantDBSession, user: AuthUser):
        ...

The ``get_tenant_db`` dependency wraps ``get_db`` and issues:

    SET LOCAL app.current_tenant_id = '<uuid>';

inside the transaction, which is picked up by the Postgres RLS policies
defined in migrations/002_rls.sql.

For compatibility, ``get_current_user`` also exposes a helper
``set_rls_context(session, tenant_id)`` that can be called manually.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncGenerator
from typing import Annotated

from fastapi import Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import CurrentUser, get_current_user
from app.db.database import AsyncSessionLocal


async def set_rls_context(session: AsyncSession, tenant_id: uuid.UUID) -> None:
    """Emit SET LOCAL to scope the session to a single tenant."""
    await session.execute(
        text("SELECT set_config('app.current_tenant_id', :tid, TRUE)"),
        {"tid": str(tenant_id)},
    )


async def get_tenant_db(
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
) -> AsyncGenerator[AsyncSession, None]:
    """DB session scoped to the authenticated user's tenant via Postgres RLS.

    Yields an ``AsyncSession`` where ``app.current_tenant_id`` is set to the
    current user's tenant UUID for the duration of the transaction.
    """
    async with AsyncSessionLocal() as session:
        try:
            await set_rls_context(session, current_user.tenant_id)
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


# Convenience type alias — use this as the dependency type in route signatures
TenantDBSession = Annotated[AsyncSession, Depends(get_tenant_db)]
