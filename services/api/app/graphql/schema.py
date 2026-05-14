"""Strawberry GraphQL schema assembly and FastAPI router factory.

Usage in main.py::

    from app.graphql.schema import graphql_router
    app.include_router(graphql_router, prefix="/graphql")

Tenant isolation
----------------
The context factory uses ``get_tenant_db`` so every GraphQL transaction
runs with ``app.current_tenant_id`` set, activating Postgres RLS.
Resolvers also apply explicit ``where(tenant_id == user.tenant_id)``
filters as defense-in-depth in case a model is not yet covered by RLS.

GraphiQL exposure
-----------------
GraphiQL is enabled only in development-class environments (see
``app.core.config.DEV_ENVIRONMENTS``). In production the introspection UI
is disabled to reduce attack surface; this is checked via the canonical
``is_dev_env`` helper rather than an ad-hoc string compare so adding a
new dev alias automatically gets the right behaviour.
"""

from __future__ import annotations

from typing import Any

import strawberry
from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession
from strawberry.fastapi import GraphQLRouter

from app.api.v1.deps import CurrentUser, get_current_user
from app.core.config import is_dev_env, settings
from app.db.rls import get_tenant_db
from app.graphql.query import Query

# ─── Context factory ──────────────────────────────────────────────────────────


async def get_graphql_context(
    db: AsyncSession = Depends(get_tenant_db),
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Build the per-request context dict injected into every resolver.

    The ``db`` session is RLS-scoped to the user's tenant, and the
    authenticated ``user`` is available via ``info.context["user"]``.
    """
    return {"db": db, "user": user}


# ─── Schema ───────────────────────────────────────────────────────────────────

schema = strawberry.Schema(query=Query)

# ─── FastAPI router ───────────────────────────────────────────────────────────

# GraphiQL is only enabled in development-class environments. Production
# gets a pure JSON endpoint with no introspection UI.
#
# strawberry-graphql >= 0.231 replaced the old ``graphiql: bool`` kwarg with
# ``graphql_ide: GraphQL_IDE | None`` (where ``"graphiql"`` is the default and
# ``None`` disables the IDE entirely). We pin to that newer API.
_graphql_ide: str | None = "graphiql" if is_dev_env(settings.ENVIRONMENT) else None

graphql_router = GraphQLRouter(
    schema,
    context_getter=get_graphql_context,
    graphql_ide=_graphql_ide,
)
