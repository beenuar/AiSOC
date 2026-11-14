"""POST /api/v1/osquery/log — osquery TLS log endpoint.

osqueryd POSTs result and status logs here.  We normalise each row and
forward the batch to services/ingest.

Reference:
  https://osquery.readthedocs.io/en/stable/deployment/remote/#log-string
"""

from __future__ import annotations

import json
import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import require_valid_node_key
from app.db.session import get_db
from app.models.node import OsqueryNode
from app.services.log_forwarder import forward_events
from app.services.node_registry import mark_seen
from app.services.normalizer import normalize_row

logger = logging.getLogger(__name__)
router = APIRouter()


class LogRequest(BaseModel):
    node_key: str
    log_type: str  # "result" | "snapshot" | "status"
    data: str  # JSON-encoded string (osquery sends it as a string)


@router.post("/log")
async def log(
    body: LogRequest,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    node: Annotated[OsqueryNode, Depends(require_valid_node_key)],
) -> dict:
    await mark_seen(db, node)

    events: list[dict] = []
    try:
        payload = json.loads(body.data)
    except (json.JSONDecodeError, TypeError):
        logger.warning("Received non-JSON log data from node %s", node.host_identifier)
        return {"node_invalid": False}

    # Only result and snapshot log types carry query rows worth forwarding.
    # Status logs are osqueryd daemon diagnostics; skip them.
    if body.log_type not in ("result", "snapshot"):
        await forward_events([], node.tenant_id)
        return {"node_invalid": False}

    if isinstance(payload, list):
        rows = payload
    elif isinstance(payload, dict):
        rows = [payload]
    else:
        rows = []

    for entry in rows:
        query_name = entry.get("name", "unknown")
        raw_rows = entry.get("columns") or entry.get("snapshot") or [entry]
        if isinstance(raw_rows, dict):
            raw_rows = [raw_rows]
        for row in raw_rows:
            events.append(
                normalize_row(
                    row,
                    host_identifier=node.host_identifier,
                    tenant_id=node.tenant_id,
                    query_name=query_name,
                    log_type=body.log_type,
                )
            )

    await forward_events(events, node.tenant_id)
    return {"node_invalid": False}
