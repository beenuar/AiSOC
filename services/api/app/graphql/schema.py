"""Strawberry GraphQL schema assembly and FastAPI router factory.

Usage in main.py::

    from app.graphql.schema import graphql_router
    app.include_router(graphql_router, prefix="/graphql")
"""
from __future__ import annotations

from typing import Any, Optional

import strawberry
from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession
from strawberry.fastapi import GraphQLRouter

from app.api.v1.deps import get_current_user
from app.db.database import get_db
from app.graphql.query import Query


# ─── Context factory ──────────────────────────────────────────────────────────


async def get_graphql_context(
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
) -> dict[str, Any]:
    """Build the per-request context dict injected into every resolver.

    The ``db`` session and authenticated ``user`` are available via
    ``info.context["db"]`` and ``info.context["user"]``.
    """
    return {"db": db, "user": user}


# ─── Schema ───────────────────────────────────────────────────────────────────

schema = strawberry.Schema(query=Query)

# ─── FastAPI router ───────────────────────────────────────────────────────────

graphql_router = GraphQLRouter(
    schema,
    context_getter=get_graphql_context,
    # GraphiQL is always available; disable in production by passing graphiql=False
)
