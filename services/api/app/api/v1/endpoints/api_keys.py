"""
Scoped API key management endpoints.

POST   /api-keys          – create a new API key (returns raw key ONCE)
GET    /api-keys          – list API keys for the current tenant (no raw keys)
GET    /api-keys/{key_id} – get a single key's metadata
DELETE /api-keys/{key_id} – revoke (deactivate) a key
PATCH  /api-keys/{key_id} – update name / scopes / expiry

VALID SCOPES
  alerts:read  alerts:write  alerts:delete
  cases:read   cases:write   cases:delete
  playbooks:read playbooks:write playbooks:execute
  connectors:read connectors:write connectors:delete
  plugins:read plugins:execute plugins:admin
  rules:read   rules:write
  users:read
  threat_intel:read threat_intel:write
  reports:read reports:write
  *            (all permissions — admin only)

MIT License — AiSOC (open-source AI Security Operations Center)
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.api.v1.deps import AuthUser, DBSession, require_permission
from app.core.security import generate_api_key
from app.models.tenant import ApiKey

router = APIRouter(prefix="/api-keys", tags=["api-keys"])

# ── Valid scopes ──────────────────────────────────────────────────────────────

VALID_SCOPES: frozenset[str] = frozenset(
    [
        "alerts:read",
        "alerts:write",
        "alerts:delete",
        "cases:read",
        "cases:write",
        "cases:delete",
        "playbooks:read",
        "playbooks:write",
        "playbooks:execute",
        "connectors:read",
        "connectors:write",
        "connectors:delete",
        "plugins:read",
        "plugins:execute",
        "plugins:admin",
        "rules:read",
        "rules:write",
        "users:read",
        "threat_intel:read",
        "threat_intel:write",
        "reports:read",
        "reports:write",
        "*",
    ]
)


def _validate_scopes(scopes: list[str]) -> None:
    invalid = [s for s in scopes if s not in VALID_SCOPES]
    if invalid:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid scope(s): {', '.join(invalid)}. Valid scopes: {sorted(VALID_SCOPES)}",
        )


# ── Request / response schemas ────────────────────────────────────────────────


class CreateApiKeyRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=255, description="Human-readable name")
    scopes: list[str] = Field(default_factory=list, description="Permission scopes granted to this key")
    expires_in_days: int | None = Field(None, ge=1, le=3650, description="TTL in days; None = never expires")


class CreateApiKeyResponse(BaseModel):
    id: uuid.UUID
    name: str
    key: str = Field(..., description="Raw API key — shown ONCE, store securely")
    prefix: str
    scopes: list[str]
    expires_at: datetime | None
    created_at: datetime


class ApiKeyOut(BaseModel):
    id: uuid.UUID
    name: str
    prefix: str
    scopes: list[str]
    is_active: bool
    expires_at: datetime | None
    last_used_at: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}


class UpdateApiKeyRequest(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=255)
    scopes: list[str] | None = None
    expires_in_days: int | None = Field(None, ge=1, le=3650, description="Reset TTL from now; 0 = never")


# ── Helper ────────────────────────────────────────────────────────────────────


def _api_key_to_out(ak: ApiKey) -> ApiKeyOut:
    return ApiKeyOut(
        id=ak.id,
        name=ak.name,
        prefix=ak.key_prefix,
        scopes=ak.scopes or [],
        is_active=ak.is_active,
        expires_at=ak.expires_at,
        last_used_at=ak.last_used_at,
        created_at=ak.created_at,
    )


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.post("", response_model=CreateApiKeyResponse, status_code=status.HTTP_201_CREATED)
async def create_api_key(
    body: CreateApiKeyRequest,
    db: DBSession,
    current_user: Annotated[Any, require_permission("users:write")],
) -> CreateApiKeyResponse:
    """
    Create a new scoped API key for the current tenant.

    The raw key value is returned **only once** in this response.
    """
    _validate_scopes(body.scopes)

    # Only admins can issue wildcard keys
    if "*" in body.scopes and current_user.role not in ("platform_admin", "tenant_admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can create wildcard (*) API keys",
        )

    raw_key, prefix, hashed_key = generate_api_key()

    expires_at = None
    if body.expires_in_days is not None:
        from datetime import timedelta

        expires_at = datetime.now(UTC) + timedelta(days=body.expires_in_days)

    api_key = ApiKey(
        tenant_id=current_user.tenant_id,
        user_id=current_user.user_id,
        name=body.name,
        key_prefix=prefix,
        hashed_key=hashed_key,
        scopes=body.scopes,
        is_active=True,
        expires_at=expires_at,
    )
    db.add(api_key)
    await db.commit()
    await db.refresh(api_key)

    return CreateApiKeyResponse(
        id=api_key.id,
        name=api_key.name,
        key=raw_key,
        prefix=prefix,
        scopes=api_key.scopes,
        expires_at=api_key.expires_at,
        created_at=api_key.created_at,
    )


@router.get("", response_model=list[ApiKeyOut])
async def list_api_keys(
    db: DBSession,
    current_user: AuthUser,
) -> list[ApiKeyOut]:
    """List all API keys for the current tenant (raw keys are never returned)."""
    result = await db.execute(select(ApiKey).where(ApiKey.tenant_id == current_user.tenant_id).order_by(ApiKey.created_at.desc()))
    return [_api_key_to_out(ak) for ak in result.scalars().all()]


@router.get("/{key_id}", response_model=ApiKeyOut)
async def get_api_key(
    key_id: uuid.UUID,
    db: DBSession,
    current_user: AuthUser,
) -> ApiKeyOut:
    """Get metadata for a specific API key."""
    result = await db.execute(select(ApiKey).where(ApiKey.id == key_id, ApiKey.tenant_id == current_user.tenant_id))
    ak = result.scalar_one_or_none()
    if ak is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API key not found")
    return _api_key_to_out(ak)


@router.patch("/{key_id}", response_model=ApiKeyOut)
async def update_api_key(
    key_id: uuid.UUID,
    body: UpdateApiKeyRequest,
    db: DBSession,
    current_user: Annotated[Any, require_permission("users:write")],
) -> ApiKeyOut:
    """Update an API key's name, scopes, or expiry."""
    result = await db.execute(select(ApiKey).where(ApiKey.id == key_id, ApiKey.tenant_id == current_user.tenant_id))
    ak = result.scalar_one_or_none()
    if ak is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API key not found")

    if body.name is not None:
        ak.name = body.name

    if body.scopes is not None:
        _validate_scopes(body.scopes)
        if "*" in body.scopes and current_user.role not in ("platform_admin", "tenant_admin"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only admins can grant wildcard (*) scope",
            )
        ak.scopes = body.scopes

    if body.expires_in_days is not None:
        from datetime import timedelta

        ak.expires_at = datetime.now(UTC) + timedelta(days=body.expires_in_days)

    await db.commit()
    await db.refresh(ak)
    return _api_key_to_out(ak)


@router.delete("/{key_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def revoke_api_key(
    key_id: uuid.UUID,
    db: DBSession,
    current_user: Annotated[Any, require_permission("users:write")],
) -> None:
    """Revoke (deactivate) an API key. The key can no longer be used for authentication."""
    result = await db.execute(select(ApiKey).where(ApiKey.id == key_id, ApiKey.tenant_id == current_user.tenant_id))
    ak = result.scalar_one_or_none()
    if ak is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API key not found")

    ak.is_active = False
    await db.commit()
