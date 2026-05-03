"""Audit log helpers.

Usage::

    from app.services.audit import emit_audit

    await emit_audit(
        db=db,
        user=current_user,
        action="cases:create",
        resource="case",
        resource_id=str(case.id),
        changes={"title": case.title},
        request=request,  # optional FastAPI Request for IP / user-agent
    )
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLog


async def emit_audit(
    *,
    db: AsyncSession,
    tenant_id: uuid.UUID,
    actor_id: uuid.UUID | None = None,
    actor_email: str | None = None,
    action: str,
    resource: str | None = None,
    resource_id: str | None = None,
    changes: dict[str, Any] | None = None,
    request: Request | None = None,
) -> AuditLog:
    """Append an immutable audit event to the log.

    Parameters
    ----------
    db:           Active async session (does NOT commit – caller controls).
    tenant_id:    The tenant this event belongs to.
    actor_id:     User UUID performing the action (optional).
    actor_email:  Email for denormalised search (optional).
    action:       Dot/colon action string, e.g. ``cases:create``.
    resource:     Resource type, e.g. ``case``.
    resource_id:  Primary key / identifier of the affected object.
    changes:      Before/after dict or delta payload.
    request:      FastAPI ``Request`` to extract IP & user-agent.
    """
    actor_ip: str | None = None
    meta: dict[str, Any] = {}

    if request is not None:
        # Respect X-Forwarded-For if behind a proxy
        forwarded = request.headers.get("x-forwarded-for")
        actor_ip = (forwarded.split(",")[0].strip() if forwarded else None) or str(request.client.host) if request.client else None
        ua = request.headers.get("user-agent")
        if ua:
            meta["user_agent"] = ua
        rid = request.headers.get("x-request-id")
        if rid:
            meta["request_id"] = rid

    event = AuditLog(
        tenant_id=tenant_id,
        actor_id=actor_id,
        actor_email=actor_email,
        actor_ip=actor_ip,
        action=action,
        resource=resource,
        resource_id=resource_id,
        changes=changes,
        metadata_=meta or None,
    )
    db.add(event)
    return event
