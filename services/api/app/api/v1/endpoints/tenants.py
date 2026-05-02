"""Tenant and user management endpoints."""
import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import AuthUser, DBSession, require_permission
from app.core.security import get_password_hash
from app.models.tenant import Tenant, User

router = APIRouter(prefix="/tenants", tags=["tenants"])


class TenantResponse(BaseModel):
    id: uuid.UUID
    name: str
    slug: str
    plan: str
    is_active: bool
    settings: dict
    limits: dict
    created_at: datetime

    model_config = {"from_attributes": True}


class UserResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    email: str
    username: str
    role: str
    is_active: bool
    last_login: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}


class CreateUserRequest(BaseModel):
    email: EmailStr
    username: str
    password: str
    role: str = "soc_analyst"


class UpdateUserRequest(BaseModel):
    username: str | None = None
    role: str | None = None
    is_active: bool | None = None


class UpdateTenantSettingsRequest(BaseModel):
    settings: dict = {}


@router.get("/me", response_model=TenantResponse)
async def get_my_tenant(
    current_user: Annotated[AuthUser, Depends(require_permission("settings:read"))],
    db: DBSession,
) -> TenantResponse:
    """Get the current user's tenant details."""
    result = await db.execute(select(Tenant).where(Tenant.id == current_user.tenant_id))
    tenant = result.scalar_one_or_none()
    if tenant is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found")
    return TenantResponse.model_validate(tenant)


@router.patch("/me/settings", response_model=TenantResponse)
async def update_tenant_settings(
    request: UpdateTenantSettingsRequest,
    current_user: Annotated[AuthUser, Depends(require_permission("settings:write"))],
    db: DBSession,
) -> TenantResponse:
    """Update tenant settings."""
    await db.execute(
        update(Tenant).where(Tenant.id == current_user.tenant_id).values(
            settings=request.settings,
            updated_at=datetime.now(UTC),
        )
    )
    await db.commit()

    result = await db.execute(select(Tenant).where(Tenant.id == current_user.tenant_id))
    return TenantResponse.model_validate(result.scalar_one())


@router.get("/me/users", response_model=list[UserResponse])
async def list_users(
    current_user: Annotated[AuthUser, Depends(require_permission("users:read"))],
    db: DBSession,
) -> list[UserResponse]:
    """List all users in the current tenant."""
    result = await db.execute(
        select(User).where(User.tenant_id == current_user.tenant_id).order_by(User.created_at)
    )
    users = result.scalars().all()
    return [UserResponse.model_validate(u) for u in users]


@router.post("/me/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    request: CreateUserRequest,
    current_user: Annotated[AuthUser, Depends(require_permission("users:write"))],
    db: DBSession,
) -> UserResponse:
    """Create a new user in the current tenant."""
    # Check email uniqueness
    existing = await db.execute(select(User).where(User.email == request.email))
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User with this email already exists",
        )

    user = User(
        tenant_id=current_user.tenant_id,
        email=request.email,
        username=request.username,
        hashed_password=get_password_hash(request.password),
        role=request.role,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return UserResponse.model_validate(user)


@router.patch("/me/users/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: uuid.UUID,
    request: UpdateUserRequest,
    current_user: Annotated[AuthUser, Depends(require_permission("users:write"))],
    db: DBSession,
) -> UserResponse:
    """Update a user."""
    result = await db.execute(
        select(User).where(User.id == user_id, User.tenant_id == current_user.tenant_id)
    )
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    updates: dict = {}
    for field in ["username", "role", "is_active"]:
        val = getattr(request, field, None)
        if val is not None:
            updates[field] = val

    if updates:
        updates["updated_at"] = datetime.now(UTC)
        await db.execute(update(User).where(User.id == user_id).values(**updates))
        await db.commit()
        await db.refresh(user)

    return UserResponse.model_validate(user)
