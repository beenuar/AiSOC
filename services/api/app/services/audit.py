"""Audit log helpers.

Usage::

    from app.services.audit import emit_audit

    await emit_audit(
        db=db,
        tenant_id=current_user.tenant_id,
        actor_id=current_user.id,
        actor_email=current_user.email,
        action="cases:create",
        resource="case",
        resource_id=str(case.id),
        changes={"title": case.title},
        request=request,  # optional FastAPI Request for IP / user-agent
    )

Hardening (BATCH 7 — H-4 + M-12)
--------------------------------

* **Source-IP attribution.** ``actor_ip`` is resolved through
  :func:`app.core.trusted_proxy.resolve_client_ip`, which only honours
  ``X-Forwarded-For`` when the direct peer is on the configured
  ``AISOC_TRUSTED_PROXIES`` allow-list. The previous version trusted
  the header unconditionally, letting any client forge their audit IP.
  It also had an operator-precedence bug
  (``A or B if C else None``) that silently broke when ``request.client``
  was ``None``.
* **Changes redaction & size cap.** The ``changes`` payload is passed
  through :func:`app.services.audit_redaction.redact_changes` so
  password/token/secret keys are masked and oversized payloads are
  reduced to a marker row. Without this we were one bad endpoint away
  from persisting raw secrets into an immutable, RLS-scoped table.
* **Tamper-evident hash chain.** Each row stores ``prev_hash`` and
  ``entry_hash`` (sha256, computed by
  :mod:`app.services.audit_hash`) so an external verifier can prove
  the chain was not truncated, reordered, or rewritten — even by an
  operator with ``DISABLE TRIGGER`` privileges. The DB-side
  immutability trigger (migration 004) still defends the normal SQL
  path; the chain catches what the trigger cannot.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.trusted_proxy import resolve_client_ip
from app.models.audit import AuditLog
from app.services.audit_hash import compute_entry_hash
from app.services.audit_redaction import redact_changes

logger = logging.getLogger("aisoc.audit")

# Hard caps on header-derived metadata that lands in the audit row.
# These exist independently of changes-payload redaction and protect
# the ``metadata`` JSONB column from arbitrary client growth.
_MAX_UA_LEN = 512
_MAX_REQUEST_ID_LEN = 128


async def _resolve_prev_hash(db: AsyncSession, tenant_id: uuid.UUID) -> str | None:
    """Return the most recent ``entry_hash`` for ``tenant_id``.

    Ordering by ``created_at DESC, id DESC`` is deliberate:
    ``created_at`` may collide at microsecond granularity for events
    emitted in a single request, so we tiebreak on ``id`` to keep the
    chain deterministic even when wall-clock time does not move.

    Returns ``None`` for the genesis (first ever audit row for this
    tenant). Legacy rows that pre-date the hash chain — where
    ``entry_hash IS NULL`` — are skipped via the partial index from
    migration 043; new chains begin from the first hashed row.
    """
    stmt = (
        select(AuditLog.entry_hash)
        .where(AuditLog.tenant_id == tenant_id)
        .where(AuditLog.entry_hash.is_not(None))
        .order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
        .limit(1)
    )
    result = await db.execute(stmt)
    return result.scalar_one_or_none()


def _safe_truncate(value: str | None, limit: int) -> str | None:
    """Trim a header value to ``limit`` characters, preserving None."""
    if value is None:
        return None
    if len(value) <= limit:
        return value
    return value[:limit]


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
    """Append an immutable, hash-chained audit event to the log.

    The caller still owns the transaction — ``db.add()`` is queued, but
    we do not commit. Callers that need a strict guarantee that the
    audit row outlives the rest of their work (i.e. a request can fail
    *after* committing audit but *before* the business write) should
    wrap their handler in a savepoint and commit the audit row first.
    The hash chain is robust either way; in-flight rows simply do not
    yet have an ``entry_hash`` reader.

    Parameters
    ----------
    db:           Active async session.
    tenant_id:    Tenant this event belongs to.
    actor_id:     User UUID performing the action (optional).
    actor_email:  Email for denormalised search (optional).
    action:       Dot/colon action string, e.g. ``cases:create``.
    resource:     Resource type, e.g. ``case``.
    resource_id:  Primary key / identifier of the affected object.
    changes:      Before/after dict or delta payload. Will be redacted
                  and size-capped before persistence.
    request:      FastAPI ``Request`` to extract IP & user-agent.
    """
    actor_ip: str | None = None
    meta: dict[str, Any] = {}

    if request is not None:
        # Trusted-proxy aware IP resolution — see services/api/app/core/trusted_proxy.py.
        try:
            actor_ip = resolve_client_ip(request)
        except Exception:  # noqa: BLE001
            # We never want audit attribution to take down a mutating
            # request. Log and fall through with no IP attached.
            logger.warning("audit: failed to resolve client IP", exc_info=True)
            actor_ip = None

        ua = _safe_truncate(request.headers.get("user-agent"), _MAX_UA_LEN)
        if ua:
            meta["user_agent"] = ua
        rid = _safe_truncate(request.headers.get("x-request-id"), _MAX_REQUEST_ID_LEN)
        if rid:
            meta["request_id"] = rid

    # Sanitize before persistence. Anything secret-shaped is masked,
    # and oversized payloads collapse to a marker row.
    safe_changes = redact_changes(changes)

    # Stable created_at — set explicitly so the hash uses the same
    # value the DB will store. Without this, default=lambda runs at
    # flush time and we'd hash one timestamp and persist another.
    created_at = datetime.now(UTC)

    event = AuditLog(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        actor_id=actor_id,
        actor_email=actor_email,
        actor_ip=actor_ip,
        action=action,
        resource=resource,
        resource_id=resource_id,
        changes=safe_changes,
        metadata_=meta or None,
        created_at=created_at,
    )

    # Chain-link this row onto the tenant's prior history. If the
    # lookup fails for any reason (e.g. transient DB blip) we still
    # write the row — falling back to an unchained entry is strictly
    # better than failing the originating mutation, and the gap is
    # detectable by the verifier.
    try:
        prev = await _resolve_prev_hash(db, tenant_id)
        event.prev_hash = prev
        event.entry_hash = compute_entry_hash(
            prev_hash=prev,
            row_id=event.id,
            tenant_id=event.tenant_id,
            actor_id=event.actor_id,
            actor_email=event.actor_email,
            actor_ip=event.actor_ip,
            action=event.action,
            resource=event.resource,
            resource_id=event.resource_id,
            changes=event.changes,
            metadata=event.metadata_,
            created_at=event.created_at,
        )
    except Exception:  # noqa: BLE001
        logger.warning(
            "audit: failed to compute hash chain for tenant=%s action=%s",
            tenant_id,
            action,
            exc_info=True,
        )
        event.prev_hash = None
        event.entry_hash = None

    db.add(event)
    return event
