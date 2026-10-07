"""Manage outbound event webhooks, and see the ones that failed.

The dead-letter view is the half worth defending. A retry queue nobody can
read is indistinguishable from one that is empty, and the failure mode of a
silent one is a tenant who believes their SIEM has every alert when a month
of them went to a receiver that has been answering 410 since a migration.
"""

from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import CurrentUser, require_permission
from app.db.database import get_db
from app.models.outbound_webhook import OutboundDelivery, OutboundWebhook
from app.security.credential_vault import get_vault
from app.services.outbound_webhooks import attempt_delivery

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/outbound-webhooks", tags=["integrations"])


class WebhookCreate(BaseModel):
    name: str = Field(max_length=255)
    url: str = Field(max_length=2048)
    event_types: list[str] = Field(default_factory=list, max_length=64)

    #: FALSE on creation, and not settable here. A destination that starts
    #: sending the moment somebody pastes a URL is the shape this whole
    #: wave ships off by default.
    @field_validator("url")
    @classmethod
    def _http_only(cls, value: str) -> str:
        if not value.startswith(("http://", "https://")):
            raise ValueError("url must be http or https")
        return value


class WebhookUpdate(BaseModel):
    name: str | None = Field(default=None, max_length=255)
    url: str | None = Field(default=None, max_length=2048)
    event_types: list[str] | None = Field(default=None, max_length=64)
    enabled: bool | None = None


class WebhookOut(BaseModel):
    """The public projection. ``secret`` is never in it.

    Not even decrypted, and not even to the operator who set it: rotation
    issues a new secret rather than showing the old one, the same rule the
    connector wizard follows. ``has_secret`` answers the only question a
    console needs.
    """

    id: uuid.UUID
    name: str
    url: str
    event_types: list[str]
    enabled: bool
    has_secret: bool
    created_at: datetime

    @classmethod
    def of(cls, row: OutboundWebhook) -> WebhookOut:
        return cls(
            id=row.id,
            name=row.name,
            url=row.url,
            event_types=list(row.event_types or []),
            enabled=row.enabled,
            has_secret=bool(row.secret),
            created_at=row.created_at,
        )


class DeliveryOut(BaseModel):
    id: uuid.UUID
    webhook_id: uuid.UUID
    event_type: str
    status: str
    attempts: int
    last_status_code: int | None
    last_error: str
    created_at: datetime
    delivered_at: datetime | None


async def _owned(db: AsyncSession, webhook_id: uuid.UUID, tenant_id: uuid.UUID) -> OutboundWebhook:
    row = (
        await db.execute(select(OutboundWebhook).where(OutboundWebhook.id == webhook_id).where(OutboundWebhook.tenant_id == tenant_id))
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="webhook not found")
    return row


@router.get("", response_model=list[WebhookOut])
async def list_webhooks(
    user: Annotated[CurrentUser, Depends(require_permission("integrations:read"))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> list[WebhookOut]:
    rows = (
        (await db.execute(select(OutboundWebhook).where(OutboundWebhook.tenant_id == user.tenant_id).order_by(OutboundWebhook.name)))
        .scalars()
        .all()
    )
    return [WebhookOut.of(row) for row in rows]


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_webhook(
    body: WebhookCreate,
    user: Annotated[CurrentUser, Depends(require_permission("integrations:write"))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, Any]:
    """Create a destination and mint its signing secret.

    The secret is returned **once**, here, and never again — it is stored
    vault-encrypted and the read projection carries only ``has_secret``.
    Returning it on every read would put a live credential in every console
    response and every browser cache that held one.
    """
    plaintext = secrets.token_urlsafe(32)
    row = OutboundWebhook(
        tenant_id=user.tenant_id,
        name=body.name,
        url=body.url,
        event_types=body.event_types,
        secret=get_vault().encrypt_dict({"secret": plaintext})["secret"],
        enabled=False,
        created_by=str(user.user_id),
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)
    return {
        **WebhookOut.of(row).model_dump(mode="json"),
        "secret": plaintext,
        "signature_header": "X-AiSOC-Signature",
        "signature_scheme": "t=<unix>,v1=HMAC-SHA256(secret, '<t>.' + raw body)",
        "note": "This secret is shown once. Rotate it to get a new one; it cannot be read back.",
    }


@router.patch("/{webhook_id}", response_model=WebhookOut)
async def update_webhook(
    webhook_id: uuid.UUID,
    body: WebhookUpdate,
    user: Annotated[CurrentUser, Depends(require_permission("integrations:write"))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> WebhookOut:
    row = await _owned(db, webhook_id, user.tenant_id)
    for field_name in ("name", "url", "event_types", "enabled"):
        value = getattr(body, field_name)
        if value is not None:
            setattr(row, field_name, value)
    row.updated_at = datetime.now(UTC)
    await db.commit()
    await db.refresh(row)
    return WebhookOut.of(row)


@router.delete("/{webhook_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_webhook(
    webhook_id: uuid.UUID,
    user: Annotated[CurrentUser, Depends(require_permission("integrations:write"))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> None:
    row = await _owned(db, webhook_id, user.tenant_id)
    await db.delete(row)
    await db.commit()


@router.post("/{webhook_id}/rotate-secret")
async def rotate_secret(
    webhook_id: uuid.UUID,
    user: Annotated[CurrentUser, Depends(require_permission("integrations:write"))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, Any]:
    row = await _owned(db, webhook_id, user.tenant_id)
    plaintext = secrets.token_urlsafe(32)
    row.secret = get_vault().encrypt_dict({"secret": plaintext})["secret"]
    row.updated_at = datetime.now(UTC)
    await db.commit()
    return {"id": str(row.id), "secret": plaintext, "note": "Shown once. Deliveries signed with the previous secret will now fail."}


@router.get("/deliveries", response_model=list[DeliveryOut])
async def list_deliveries(
    user: Annotated[CurrentUser, Depends(require_permission("integrations:read"))],
    db: Annotated[AsyncSession, Depends(get_db)],
    status_filter: Annotated[str | None, Query(alias="status", pattern="^(pending|delivered|failed|dead)$")] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[DeliveryOut]:
    query = select(OutboundDelivery).where(OutboundDelivery.tenant_id == user.tenant_id)
    if status_filter:
        query = query.where(OutboundDelivery.status == status_filter)
    rows = (await db.execute(query.order_by(OutboundDelivery.created_at.desc()).limit(limit))).scalars().all()
    return [DeliveryOut.model_validate(row, from_attributes=True) for row in rows]


@router.get("/dead-letters", response_model=list[DeliveryOut])
async def list_dead_letters(
    user: Annotated[CurrentUser, Depends(require_permission("integrations:read"))],
    db: Annotated[AsyncSession, Depends(get_db)],
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[DeliveryOut]:
    """Deliveries that exhausted their retries or were refused outright.

    A named route rather than ``?status=dead`` on the list above, because
    this is the one an operator is told to check and a filter nobody
    applies is a filter nobody sees.
    """
    rows = (
        (
            await db.execute(
                select(OutboundDelivery)
                .where(OutboundDelivery.tenant_id == user.tenant_id)
                .where(OutboundDelivery.status == "dead")
                .order_by(OutboundDelivery.created_at.desc())
                .limit(limit)
            )
        )
        .scalars()
        .all()
    )
    return [DeliveryOut.model_validate(row, from_attributes=True) for row in rows]


@router.post("/deliveries/{delivery_id}/replay")
async def replay_delivery(
    delivery_id: uuid.UUID,
    user: Annotated[CurrentUser, Depends(require_permission("integrations:write"))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> DeliveryOut:
    """Send a dead letter again, with the body the first attempt sent.

    Synchronous and single-attempt: an operator replaying by hand has just
    fixed something and wants to know now whether it worked, not in thirty
    seconds. The attempt counter keeps climbing, so a replay cannot be used
    to loop past the ladder.
    """
    row = (
        await db.execute(
            select(OutboundDelivery).where(OutboundDelivery.id == delivery_id).where(OutboundDelivery.tenant_id == user.tenant_id)
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="delivery not found")
    webhook = await _owned(db, row.webhook_id, user.tenant_id)

    await attempt_delivery(row, webhook)
    await db.commit()
    await db.refresh(row)
    return DeliveryOut.model_validate(row, from_attributes=True)
