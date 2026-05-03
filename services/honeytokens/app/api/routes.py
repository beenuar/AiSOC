"""FastAPI routes for the Honeytokens service."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select, desc, update
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker

from app.core.config import settings
from app.models.honeytoken import Honeytoken, HoneytokenTrigger
from app.services.alerting import send_alert
from app.services.generator import generate_token, TOKEN_GENERATORS

router = APIRouter(prefix="/api/v1/honeytokens", tags=["honeytokens"])

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
async def create_token(body: CreateTokenRequest, db: DB) -> TokenOut:
    """Generate and store a new honeytoken."""
    data = generate_token(
        token_type=body.token_type,
        name=body.name,
        description=body.description,
        tenant_id=body.tenant_id,
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
    tenant_id: uuid.UUID = Query(...),
    status: str | None = Query(None),
    token_type: str | None = Query(None),
    limit: int = Query(50, ge=1, le=500),
) -> list[TokenOut]:
    q = (
        select(Honeytoken)
        .where(Honeytoken.tenant_id == tenant_id)
        .order_by(desc(Honeytoken.created_at))
        .limit(limit)
    )
    if status:
        q = q.where(Honeytoken.status == status)
    if token_type:
        q = q.where(Honeytoken.token_type == token_type)
    result = await db.execute(q)
    return [TokenOut.model_validate(row) for row in result.scalars().all()]


@router.get("/{token_id}", response_model=TokenOut)
async def get_token(token_id: uuid.UUID, db: DB) -> TokenOut:
    result = await db.execute(select(Honeytoken).where(Honeytoken.id == token_id))
    token = result.scalar_one_or_none()
    if not token:
        raise HTTPException(status_code=404, detail="Token not found")
    return TokenOut.model_validate(token)


@router.patch("/{token_id}/revoke", response_model=TokenOut)
async def revoke_token(token_id: uuid.UUID, db: DB) -> TokenOut:
    result = await db.execute(select(Honeytoken).where(Honeytoken.id == token_id))
    token = result.scalar_one_or_none()
    if not token:
        raise HTTPException(status_code=404, detail="Token not found")
    token.status = "revoked"
    await db.commit()
    await db.refresh(token)
    return TokenOut.model_validate(token)


@router.delete("/{token_id}", status_code=204)
async def delete_token(token_id: uuid.UUID, db: DB) -> None:
    result = await db.execute(select(Honeytoken).where(Honeytoken.id == token_id))
    token = result.scalar_one_or_none()
    if not token:
        raise HTTPException(status_code=404, detail="Token not found")
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

    now = datetime.now(timezone.utc)

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
        trigger.alert_sent_at = datetime.now(timezone.utc)
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
    limit: int = Query(50, ge=1, le=200),
) -> list[TriggerOut]:
    result = await db.execute(
        select(HoneytokenTrigger)
        .where(HoneytokenTrigger.honeytoken_id == token_id)
        .order_by(desc(HoneytokenTrigger.triggered_at))
        .limit(limit)
    )
    return [TriggerOut.model_validate(row) for row in result.scalars().all()]
