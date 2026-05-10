"""POST /api/v1/osquery/config — osquery TLS config retrieval endpoint.

osqueryd polls this to receive its schedule, packs, and options.

Reference:
  https://osquery.readthedocs.io/en/stable/deployment/remote/#config-retrieval
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import require_valid_node_key
from app.db.session import get_db
from app.models.node import OsqueryNode
from app.services.node_registry import mark_seen
from app.services.pack_resolver import resolve_config

router = APIRouter()


@router.post("/config")
async def get_config(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    node: Annotated[OsqueryNode, Depends(require_valid_node_key)],
) -> dict:
    await mark_seen(db, node)
    return resolve_config(node.tenant_id)
