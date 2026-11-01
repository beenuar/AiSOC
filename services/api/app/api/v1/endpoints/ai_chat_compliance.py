"""Enable, inspect and read enterprise AI-chat compliance collection.

Depth plan wave 2, Phase 7.1.

Off by default, enabled per tenant, through here
------------------------------------------------
There is no environment variable and no YAML knob. A tenant that has not
POSTed a key to this router has no configuration row, and the collector
therefore does not run for them. The key is the tenant's own and is
vault-encrypted before the row is written; nothing returns it, and the read
route exposes ``hasKey`` rather than a masked value, because a masked value
still tells you the length.

Two opt-ins, not one
--------------------
``enabled`` turns on the directory and activity feed. ``contentLabels`` is a
second switch covering anything derived from message text, and it defaults
off even when the first is on. A tenant that wants its activity feed and
explicitly does not want message bodies read — a common and entirely
reasonable position — gets that by default rather than by discovering a
setting.

Why reads need a permission
---------------------------
The same reason ``/ai-assets`` does. An activity feed naming who talked to
which AI assistant, and a label row saying whose conversation contained a
credential, is sensitive about people rather than about infrastructure. It
sits behind ``ai_estate:read``; the two write routes behind
``ai_estate:write``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import delete, select

from app.api.v1.deps import CurrentUser, require_permission
from app.db.rls import TenantDBSession
from app.models.ai_chat_compliance import (
    AI_CHAT_PROVIDERS,
    AiChatAuditEvent,
    AiChatComplianceConfig,
    AiChatContentLabel,
    AiChatUser,
)
from app.security.credential_vault import CredentialVaultError, get_vault
from app.services.ai_chat_compliance.collector import collect_for_tenant

logger = structlog.get_logger()

router = APIRouter(prefix="/ai-chat-compliance", tags=["ai-estate"])

_MAX_PAGE = 200


class ConfigResponse(BaseModel):
    """The tenant's configuration, without the key."""

    configured: bool
    provider: str | None = None
    enabled: bool = False
    contentLabels: bool = False
    #: Never the key, and never a masked form of it: a mask still leaks the
    #: length, and nothing in the console needs either.
    hasKey: bool = False
    lastCollectedAt: str | None = None
    #: Null means "never run", which the console renders differently from
    #: "ran and found nothing". An empty feed and an unconfigured key are
    #: not the same state, and showing a confident zero for the second is
    #: the failure this field exists to prevent.
    lastError: str | None = None


class ConfigRequest(BaseModel):
    provider: str = Field(..., description=f"One of: {', '.join(AI_CHAT_PROVIDERS)}")
    accessKey: str = Field(..., min_length=8, description="Stored vault-encrypted; never returned.")
    enabled: bool = Field(False, description="Collect the directory and the activity feed.")
    contentLabels: bool = Field(
        False,
        description=(
            "Additionally derive classification labels and one bounded snippet from message "
            "text. Off by default even when collection is on."
        ),
    )


class AuditEventModel(BaseModel):
    id: str
    eventType: str
    occurredAt: str
    actorEmail: str | None = None
    actorIp: str | None = None
    chatExternalId: str | None = None
    projectExternalId: str | None = None


class ContentLabelModel(BaseModel):
    id: str
    chatExternalId: str
    actorEmail: str | None = None
    labels: list[str] = Field(default_factory=list)
    secretKinds: list[str] = Field(default_factory=list)
    #: At most 280 characters, with every matched value already replaced by
    #: its shape name before storage.
    snippet: str | None = None
    snippetTruncated: bool = False
    messagesExamined: int
    messagesMatched: int
    occurredAt: str


class AuditEventListResponse(BaseModel):
    items: list[AuditEventModel]
    total: int
    #: Stated rather than inferred from an empty list, for the same reason
    #: `lastError` exists above.
    collectionEnabled: bool


class ContentLabelListResponse(BaseModel):
    items: list[ContentLabelModel]
    total: int
    contentLabelsEnabled: bool


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


async def _config(db: Any, tenant_id: Any) -> AiChatComplianceConfig | None:
    return (await db.execute(select(AiChatComplianceConfig).where(AiChatComplianceConfig.tenant_id == tenant_id))).scalar_one_or_none()


@router.get("/config", response_model=ConfigResponse)
async def get_config(
    db: TenantDBSession,
    current_user: Annotated[CurrentUser, Depends(require_permission("ai_estate:read"))],
) -> ConfigResponse:
    row = await _config(db, current_user.tenant_id)
    if row is None:
        return ConfigResponse(configured=False)
    return ConfigResponse(
        configured=True,
        provider=row.provider,
        enabled=row.enabled,
        contentLabels=row.content_labels_enabled,
        hasKey=bool(row.access_key_vault),
        lastCollectedAt=_iso(row.last_collected_at),
        lastError=row.last_error,
    )


@router.put("/config", response_model=ConfigResponse)
async def put_config(
    payload: ConfigRequest,
    db: TenantDBSession,
    current_user: Annotated[CurrentUser, Depends(require_permission("ai_estate:write"))],
) -> ConfigResponse:
    """Store the tenant's key and switches.

    Encryption happens before the row is written, and a vault failure is a
    503 rather than a silently-plaintext row: storing the key unencrypted
    because the vault was unavailable is the worst outcome available here.
    """
    if payload.provider not in AI_CHAT_PROVIDERS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unknown provider {payload.provider!r}. Known providers: {', '.join(AI_CHAT_PROVIDERS)}.",
        )
    try:
        ciphertext = get_vault().encrypt(payload.accessKey)
    except CredentialVaultError as exc:
        logger.error("ai_chat_compliance.vault_unavailable", error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The credential vault is unavailable, so the key was not stored. Nothing was written.",
        ) from exc

    row = await _config(db, current_user.tenant_id)
    if row is None:
        row = AiChatComplianceConfig(tenant_id=current_user.tenant_id, provider=payload.provider, access_key_vault=ciphertext)
        db.add(row)
    else:
        row.provider = payload.provider
        row.access_key_vault = ciphertext
    row.enabled = payload.enabled
    row.content_labels_enabled = payload.contentLabels
    await db.commit()

    logger.info(
        "ai_chat_compliance.configured",
        tenant_id=str(current_user.tenant_id),
        provider=payload.provider,
        enabled=payload.enabled,
        content_labels=payload.contentLabels,
        actor=str(current_user.user_id),
    )
    return ConfigResponse(
        configured=True,
        provider=row.provider,
        enabled=row.enabled,
        contentLabels=row.content_labels_enabled,
        hasKey=True,
        lastCollectedAt=_iso(row.last_collected_at),
        lastError=row.last_error,
    )


@router.delete("/config", status_code=status.HTTP_204_NO_CONTENT)
async def delete_config(
    db: TenantDBSession,
    current_user: Annotated[CurrentUser, Depends(require_permission("ai_estate:write"))],
    purge: Annotated[
        bool,
        Query(description="Also delete everything already collected for this tenant."),
    ] = False,
) -> None:
    """Stop collecting, and optionally remove what was collected.

    Disabling without purging is the default because an operator turning a
    feature off should not silently destroy evidence an investigation may
    be relying on. Purging is the explicit choice, and it is the one a
    data-subject request needs.
    """
    await db.execute(delete(AiChatComplianceConfig).where(AiChatComplianceConfig.tenant_id == current_user.tenant_id))
    if purge:
        for model in (AiChatContentLabel, AiChatAuditEvent, AiChatUser):
            await db.execute(delete(model).where(model.tenant_id == current_user.tenant_id))
    await db.commit()
    logger.info(
        "ai_chat_compliance.disabled",
        tenant_id=str(current_user.tenant_id),
        purged=purge,
        actor=str(current_user.user_id),
    )


class SyncResponse(BaseModel):
    """What one collection run did."""

    users: int
    projects: int
    events: int
    contentLabels: int
    chatsSkipped: int
    contentUnavailable: bool
    errors: list[str]


@router.post("/sync", response_model=SyncResponse)
async def sync_now(
    db: TenantDBSession,
    current_user: Annotated[CurrentUser, Depends(require_permission("ai_estate:write"))],
) -> SyncResponse:
    """Collect now, for this tenant.

    This route is the production caller the collector, client and
    classifier never had. Until it existed the four tables migration 146
    creates could only ever be empty, and the events page read "nothing
    here" on a tenant that had configured collection and switched it on --
    which reads as no AI-chat risk rather than as nothing having looked.

    Write-permissioned deliberately: a sync spends a tenant's provider
    quota and writes rows, so it is not a read.

    Partial failure is reported, never swallowed. A directory call that
    403s still leaves the activity records that were written, and the
    reason lands on both this response and the config row's ``lastError``.
    """
    result = await collect_for_tenant(db, current_user.tenant_id)
    return SyncResponse(**result.as_dict())


@router.get("/events", response_model=AuditEventListResponse)
async def list_events(
    db: TenantDBSession,
    current_user: Annotated[CurrentUser, Depends(require_permission("ai_estate:read"))],
    limit: Annotated[int, Query(ge=1, le=_MAX_PAGE)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> AuditEventListResponse:
    stmt = (
        select(AiChatAuditEvent).where(AiChatAuditEvent.tenant_id == current_user.tenant_id).order_by(AiChatAuditEvent.occurred_at.desc())
    )
    rows = (await db.execute(stmt.limit(limit).offset(offset))).scalars().all()
    # Counted independently of the page rather than from len(rows), which
    # reports the page size as the total on every page but the last.
    total = len((await db.execute(select(AiChatAuditEvent.id).where(AiChatAuditEvent.tenant_id == current_user.tenant_id))).scalars().all())
    config = await _config(db, current_user.tenant_id)
    return AuditEventListResponse(
        items=[
            AuditEventModel(
                id=str(r.id),
                eventType=r.event_type,
                occurredAt=r.occurred_at.isoformat(),
                actorEmail=r.actor_email,
                actorIp=str(r.actor_ip) if r.actor_ip else None,
                chatExternalId=r.chat_external_id,
                projectExternalId=r.project_external_id,
            )
            for r in rows
        ],
        total=total,
        collectionEnabled=bool(config and config.enabled),
    )


@router.get("/content-labels", response_model=ContentLabelListResponse)
async def list_content_labels(
    db: TenantDBSession,
    current_user: Annotated[CurrentUser, Depends(require_permission("ai_estate:read"))],
    label: Annotated[str | None, Query(description="Filter to one classification label.")] = None,
    limit: Annotated[int, Query(ge=1, le=_MAX_PAGE)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> ContentLabelListResponse:
    stmt = select(AiChatContentLabel).where(AiChatContentLabel.tenant_id == current_user.tenant_id)
    count_stmt = select(AiChatContentLabel.id).where(AiChatContentLabel.tenant_id == current_user.tenant_id)
    if label:
        stmt = stmt.where(AiChatContentLabel.labels.any(label))
        count_stmt = count_stmt.where(AiChatContentLabel.labels.any(label))

    rows = (await db.execute(stmt.order_by(AiChatContentLabel.occurred_at.desc()).limit(limit).offset(offset))).scalars().all()
    total = len((await db.execute(count_stmt)).scalars().all())
    config = await _config(db, current_user.tenant_id)
    return ContentLabelListResponse(
        items=[
            ContentLabelModel(
                id=str(r.id),
                chatExternalId=r.chat_external_id,
                actorEmail=r.actor_email,
                labels=list(r.labels or []),
                secretKinds=list(r.secret_kinds or []),
                snippet=r.snippet,
                snippetTruncated=r.snippet_truncated,
                messagesExamined=r.messages_examined,
                messagesMatched=r.messages_matched,
                occurredAt=r.occurred_at.isoformat(),
            )
            for r in rows
        ],
        total=total,
        contentLabelsEnabled=bool(config and config.content_labels_enabled),
    )
