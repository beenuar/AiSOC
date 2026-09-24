"""FastAPI routes for the Honeytokens service."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import settings
from app.models.honeytoken import Honeytoken, HoneytokenTrigger
from app.security.service_auth import require_service_auth
from app.security.tenant_scope import (
    TenantPrincipal,
    require_console_or_service_auth,
    scoped_tenant_or_403,
)
from app.services.alerting import send_alert
from app.services.generator import TOKEN_GENERATORS, generate_token

router = APIRouter(prefix="/api/v1/honeytokens", tags=["honeytokens"], dependencies=[Depends(require_service_auth)])

#: Every token route resolves a tenant from the caller's credential. The
#: router-level ``require_service_auth`` above proves the caller is a trusted
#: service; it says nothing about *which tenant* that service is acting for,
#: and a tenant read out of the query string is a tenant the caller chose.
ScopedPrincipal = Annotated[TenantPrincipal, Depends(require_console_or_service_auth)]

# ---------------------------------------------------------------------------
# DB dependency
# ---------------------------------------------------------------------------
_engine = create_async_engine(settings.database_url)
_session_factory = async_sessionmaker(_engine, expire_on_commit=False)


async def get_db() -> AsyncSession:  # type: ignore[return]
    async with _session_factory() as session:
        yield session


DB = Annotated[AsyncSession, Depends(get_db)]


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class CreateTokenRequest(BaseModel):
    tenant_id: uuid.UUID
    name: str = Field(..., min_length=1, max_length=256)
    description: str | None = None
    token_type: str = Field(..., description=f"One of: {list(TOKEN_GENERATORS)}")
    metadata: dict[str, Any] = Field(default_factory=dict)
    ttl_days: int | None = None
    created_by: str | None = None


class TokenOut(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    name: str
    description: str | None
    token_type: str
    token_value: str
    metadata_: dict = Field(alias="metadata")
    status: str
    expires_at: datetime | None
    created_at: datetime
    updated_at: datetime
    created_by: str | None

    model_config = {"from_attributes": True, "populate_by_name": True}


class TriggerOut(BaseModel):
    id: uuid.UUID
    honeytoken_id: uuid.UUID
    tenant_id: uuid.UUID
    source_ip: str | None
    user_agent: str | None
    threat_score: float | None
    alert_sent: bool
    triggered_at: datetime

    model_config = {"from_attributes": True}


class WebhookTriggerPayload(BaseModel):
    token_id: uuid.UUID
    source_ip: str | None = None
    user_agent: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    body: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("", response_model=TokenOut, status_code=201)
async def create_token(body: CreateTokenRequest, db: DB, principal: ScopedPrincipal) -> TokenOut:
    """Generate and store a new honeytoken."""
    tenant_id = scoped_tenant_or_403(principal, body.tenant_id)
    data = generate_token(
        token_type=body.token_type,
        name=body.name,
        description=body.description,
        tenant_id=tenant_id,
        created_by=body.created_by,
        metadata=body.metadata,
        ttl_days=body.ttl_days,
    )
    token = Honeytoken(**data)
    db.add(token)
    await db.commit()
    await db.refresh(token)
    return TokenOut.model_validate(token)


@router.get("", response_model=list[TokenOut])
async def list_tokens(
    db: DB,
    principal: ScopedPrincipal,
    tenant_id: uuid.UUID | None = Query(None),
    status: str | None = Query(None),
    token_type: str | None = Query(None),
    limit: int = Query(50, ge=1, le=500),
) -> list[TokenOut]:
    scoped = scoped_tenant_or_403(principal, tenant_id)
    q = select(Honeytoken).where(Honeytoken.tenant_id == scoped).order_by(desc(Honeytoken.created_at)).limit(limit)
    if status:
        q = q.where(Honeytoken.status == status)
    if token_type:
        q = q.where(Honeytoken.token_type == token_type)
    result = await db.execute(q)
    return [TokenOut.model_validate(row) for row in result.scalars().all()]


# The four by-id routes below took no tenant at all and matched on `id`
# alone, so a caller holding the service token could read, revoke or delete
# any tenant's honeytoken by guessing or replaying its UUID. A route that
# names no tenant is not tenant-agnostic; it is unscoped. Each now filters on
# the caller's tenant as well as the id, so a foreign token is a 404 — the
# same answer as a token that does not exist, which is what it is from this
# caller's point of view.


async def _owned_token(db: AsyncSession, token_id: uuid.UUID, tenant_id: uuid.UUID) -> Honeytoken:
    result = await db.execute(select(Honeytoken).where(Honeytoken.id == token_id, Honeytoken.tenant_id == tenant_id))
    token = result.scalar_one_or_none()
    if not token:
        raise HTTPException(status_code=404, detail="Token not found")
    return token


@router.get("/{token_id}", response_model=TokenOut)
async def get_token(token_id: uuid.UUID, db: DB, principal: ScopedPrincipal) -> TokenOut:
    token = await _owned_token(db, token_id, scoped_tenant_or_403(principal))
    return TokenOut.model_validate(token)


@router.patch("/{token_id}/revoke", response_model=TokenOut)
async def revoke_token(token_id: uuid.UUID, db: DB, principal: ScopedPrincipal) -> TokenOut:
    token = await _owned_token(db, token_id, scoped_tenant_or_403(principal))
    token.status = "revoked"
    await db.commit()
    await db.refresh(token)
    return TokenOut.model_validate(token)


@router.delete("/{token_id}", status_code=204, response_model=None)
async def delete_token(token_id: uuid.UUID, db: DB, principal: ScopedPrincipal) -> None:
    token = await _owned_token(db, token_id, scoped_tenant_or_403(principal))
    await db.delete(token)
    await db.commit()


# ---------------------------------------------------------------------------
# Webhook trigger endpoint — called by canary infrastructure or canarytools
# ---------------------------------------------------------------------------


@router.post("/webhook/trigger", status_code=200)
async def webhook_trigger(body: WebhookTriggerPayload, db: DB) -> dict:
    """
    First-touch handler — receives an inbound notification that a honeytoken
    was accessed.  Creates a trigger record and fires an alert.
    """
    result = await db.execute(select(Honeytoken).where(Honeytoken.id == body.token_id))
    token = result.scalar_one_or_none()
    if not token:
        raise HTTPException(status_code=404, detail="Token not found")

    now = datetime.now(UTC)

    trigger = HoneytokenTrigger(
        honeytoken_id=token.id,
        tenant_id=token.tenant_id,
        source_ip=body.source_ip,
        user_agent=body.user_agent,
        request_headers=body.headers,
        request_body=body.body,
        triggered_at=now,
    )
    db.add(trigger)

    # Mark token as triggered on first touch
    if token.status == "active":
        token.status = "triggered"

    await db.commit()
    await db.refresh(trigger)

    # Fire alert asynchronously (best-effort)
    alert_sent = await send_alert(
        honeytoken_id=token.id,
        tenant_id=token.tenant_id,
        token_type=token.token_type,
        token_name=token.name,
        trigger_id=trigger.id,
        source_ip=body.source_ip,
        triggered_at=now,
    )

    if alert_sent:
        trigger.alert_sent = True
        trigger.alert_sent_at = datetime.now(UTC)
        await db.commit()

    return {
        "trigger_id": str(trigger.id),
        "alert_sent": alert_sent,
        "token_status": token.status,
    }


# ---------------------------------------------------------------------------
# Trigger history
# ---------------------------------------------------------------------------


@router.get("/{token_id}/triggers", response_model=list[TriggerOut])
async def list_triggers(
    token_id: uuid.UUID,
    db: DB,
    principal: ScopedPrincipal,
    limit: int = Query(50, ge=1, le=200),
) -> list[TriggerOut]:
    # Scoped on the trigger rows themselves, not only on the parent token:
    # filtering the parent alone would rely on the write path having stamped
    # every trigger with the token's tenant, and a read must not depend on a
    # write being correct.
    scoped = scoped_tenant_or_403(principal)
    result = await db.execute(
        select(HoneytokenTrigger)
        .where(
            HoneytokenTrigger.honeytoken_id == token_id,
            HoneytokenTrigger.tenant_id == scoped,
        )
        .order_by(desc(HoneytokenTrigger.triggered_at))
        .limit(limit)
    )
    return [TriggerOut.model_validate(row) for row in result.scalars().all()]
