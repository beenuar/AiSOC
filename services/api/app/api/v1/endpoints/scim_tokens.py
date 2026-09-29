"""Administering the credentials the SCIM surface accepts.

Separate from ``scim.py`` on purpose. That module is the machine-facing
surface, authenticated by the token it is about; this one is the
human-facing surface, authenticated by a console session, and the two must
not share a credential. A SCIM token that could mint SCIM tokens would be a
credential that escalates itself.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.api.v1.deps import AuthUser, DBSession, require_permission
from app.models.organization import OrganizationTenant
from app.models.scim import ScimToken
from app.services.audit import emit_audit
from app.services.scim import tokens as scim_tokens

router = APIRouter(prefix="/scim-tokens", tags=["scim"])


class CreateScimTokenRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200, description="Which identity provider this credential is for")
    expires_in_days: int | None = Field(None, ge=1, le=3650, description="Optional lifetime; omit for no expiry")


class RotateScimTokenRequest(BaseModel):
    grace_hours: int = Field(
        24,
        ge=0,
        le=168,
        description=("How long the superseded credential keeps working. Zero revokes it at once, for rotation after a disclosure."),
    )


class ScimTokenOut(BaseModel):
    id: uuid.UUID
    name: str
    prefix: str
    org_id: uuid.UUID | None
    created_at: datetime
    last_used_at: datetime | None
    expires_at: datetime | None
    revoked_at: datetime | None
    rotated_from_id: uuid.UUID | None
    active: bool


class CreatedScimTokenOut(ScimTokenOut):
    token: str = Field(..., description="The raw credential. Shown once and not recoverable.")


def _to_out(row: ScimToken) -> ScimTokenOut:
    return ScimTokenOut(
        id=row.id,
        name=row.name,
        prefix=row.token_prefix,
        org_id=row.org_id,
        created_at=row.created_at,
        last_used_at=row.last_used_at,
        expires_at=row.expires_at,
        revoked_at=row.revoked_at,
        rotated_from_id=row.rotated_from_id,
        active=row.is_usable(),
    )


async def _owning_org(db: Any, tenant_id: uuid.UUID) -> uuid.UUID | None:
    """The organisation whose portfolio holds this tenant, if any.

    Read here rather than accepted from the caller: ``organization_tenants``
    already carries a uniqueness constraint making one tenant's managing
    organisation single-valued, so there is nothing for a request field to
    usefully say and something for it to get wrong.
    """
    result = await db.execute(select(OrganizationTenant.org_id).where(OrganizationTenant.tenant_id == tenant_id))
    return result.scalar_one_or_none()


@router.get("", response_model=list[ScimTokenOut])
async def list_scim_tokens(db: DBSession, current_user: AuthUser) -> list[ScimTokenOut]:
    """List this tenant's SCIM credentials. Secrets are never returned."""
    result = await db.execute(select(ScimToken).where(ScimToken.tenant_id == current_user.tenant_id).order_by(ScimToken.created_at.desc()))
    return [_to_out(row) for row in result.scalars().all()]


@router.post("", response_model=CreatedScimTokenOut, status_code=status.HTTP_201_CREATED)
async def create_scim_token(
    body: CreateScimTokenRequest,
    db: DBSession,
    request: Request,
    current_user: Annotated[AuthUser, Depends(require_permission("settings:write"))],
) -> CreatedScimTokenOut:
    """Mint a SCIM credential for this tenant."""
    expires_at = None
    if body.expires_in_days is not None:
        expires_at = datetime.now(UTC) + timedelta(days=body.expires_in_days)

    token, raw = await scim_tokens.mint_token(
        db,
        tenant_id=current_user.tenant_id,
        org_id=await _owning_org(db, current_user.tenant_id),
        name=body.name,
        created_by=current_user.user_id,
        expires_at=expires_at,
    )
    await emit_audit(
        db=db,
        tenant_id=current_user.tenant_id,
        actor_id=current_user.user_id,
        actor_email=current_user.email,
        action="scim:token:create",
        resource="scim_token",
        resource_id=str(token.id),
        changes={"name": body.name, "prefix": token.token_prefix, "expires_at": expires_at.isoformat() if expires_at else None},
        request=request,
    )
    await db.commit()
    await db.refresh(token)
    return CreatedScimTokenOut(**_to_out(token).model_dump(), token=raw)


@router.post("/{token_id}/rotate", response_model=CreatedScimTokenOut, status_code=status.HTTP_201_CREATED)
async def rotate_scim_token(
    token_id: uuid.UUID,
    body: RotateScimTokenRequest,
    db: DBSession,
    request: Request,
    current_user: Annotated[AuthUser, Depends(require_permission("settings:write"))],
) -> CreatedScimTokenOut:
    """Replace a credential, leaving the old one working for a grace window."""
    result = await db.execute(select(ScimToken).where(ScimToken.id == token_id, ScimToken.tenant_id == current_user.tenant_id))
    token = result.scalar_one_or_none()
    if token is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="SCIM token not found")
    if token.revoked_at is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="This token is revoked; create a new one instead")

    replacement, raw = await scim_tokens.rotate_token(
        db, token=token, created_by=current_user.user_id, grace=timedelta(hours=body.grace_hours)
    )
    await emit_audit(
        db=db,
        tenant_id=current_user.tenant_id,
        actor_id=current_user.user_id,
        actor_email=current_user.email,
        action="scim:token:rotate",
        resource="scim_token",
        resource_id=str(replacement.id),
        changes={
            "superseded": str(token.id),
            "grace_hours": body.grace_hours,
            "superseded_expires_at": token.expires_at.isoformat() if token.expires_at else None,
        },
        request=request,
    )
    await db.commit()
    await db.refresh(replacement)
    return CreatedScimTokenOut(**_to_out(replacement).model_dump(), token=raw)


@router.delete("/{token_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def revoke_scim_token(
    token_id: uuid.UUID,
    db: DBSession,
    request: Request,
    current_user: Annotated[AuthUser, Depends(require_permission("settings:write"))],
) -> None:
    """Revoke a credential immediately.

    The row stays, because ``aisoc_scim_users.token_id`` references it and
    the audit trail answers "which integration provisioned this principal"
    through it.
    """
    result = await db.execute(select(ScimToken).where(ScimToken.id == token_id, ScimToken.tenant_id == current_user.tenant_id))
    token = result.scalar_one_or_none()
    if token is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="SCIM token not found")

    if token.revoked_at is None:
        token.revoked_at = datetime.now(UTC)

    await emit_audit(
        db=db,
        tenant_id=current_user.tenant_id,
        actor_id=current_user.user_id,
        actor_email=current_user.email,
        action="scim:token:revoke",
        resource="scim_token",
        resource_id=str(token.id),
        changes={"prefix": token.token_prefix},
        request=request,
    )
    await db.commit()
