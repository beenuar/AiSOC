"""Turning an enforced entitlement into an HTTP refusal.

One helper rather than a copy per handler, for the reason the matrix has
recorded twice: a second place that decides "is this tenant full" is a
second definition, and the two drift in front of the customer being
refused. `entitlements.assert_within_limit` owns the decision; this owns
only the status code and the shape of the body.

**402, not 403 and not 429.** A 403 says the caller may not do this, which
is false — they may, and will be able to again when the ceiling moves or
usage falls. A 429 says slow down and invites a retry, which will fail
identically until somebody changes a setting. 402 is the status whose
meaning is "this is a billing or plan condition, not an authorization one
and not a timing one", and the body names which limit, by how much, and
what to change.
"""

from __future__ import annotations

import uuid

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.tenant import Tenant
from app.services.entitlements import LimitExceeded, assert_within_limit


async def refuse_if_over_limit(db: AsyncSession, tenant_id: uuid.UUID, key: str) -> None:
    """Refuse with 402 if *key* is enforced for this tenant and exhausted.

    Returns silently when the key is not opted in, no ceiling is set, there
    is room, or usage could not be measured. Only the first is a policy
    decision; see `entitlements` for why an unmeasurable count allows the
    request rather than refusing it.

    The per-tenant override is read here rather than the plan default,
    because `limit_for` reads it first: checking a plan ceiling for a
    tenant whose limits were deliberately raised refuses exactly the
    customer somebody went out of their way to accommodate.
    """
    tenant_limits = await db.scalar(select(Tenant.limits).where(Tenant.id == tenant_id))
    try:
        await assert_within_limit(db, tenant_id, tenant_limits, key)
    except LimitExceeded as exc:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail={
                "error": "limit_exceeded",
                "key": exc.key,
                "label": exc.label,
                "used": exc.used,
                "limit": exc.limit,
                "message": str(exc),
            },
        ) from exc
