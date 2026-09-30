"""Authentication endpoints: login, refresh, logout, user preferences."""

import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, EmailStr
from sqlalchemy import select, update

from app.api.v1.deps import AuthUser, DBSession, get_current_user

__all__ = ["router", "get_current_user"]
from app.core.config import settings
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    token_is_revoked,
    verify_password,
)
from app.models.tenant import User
from app.services.login_throttle import client_ip, get_login_throttle

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60


class RefreshRequest(BaseModel):
    refresh_token: str


class UserMeResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    email: str
    username: str
    role: str
    is_active: bool
    preferences: dict[str, Any] = {}

    model_config = {"from_attributes": True}


class PreferencesPatch(BaseModel):
    """Partial update payload for user preferences (merged server-side)."""

    preferences: dict[str, Any]


@router.post("/login", response_model=TokenResponse)
async def login(request: LoginRequest, http_request: Request, db: DBSession) -> TokenResponse:
    """Authenticate with email/password, return JWT tokens.

    Fifty wrong passwords for one account inside a minute used to return
    fifty 401s with no delay and no lockout. The throttle runs *before* the
    password is verified, and its reply is the same whether the account
    exists or not: a throttle that only engages for real accounts is a
    user-enumeration oracle.
    """
    throttle = get_login_throttle()
    source = client_ip(http_request)
    decision = await throttle.check(email=request.email, source_ip=source)
    if not decision.allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=decision.detail,
            headers={"Retry-After": str(decision.retry_after_seconds)},
        )

    result = await db.execute(select(User).where(User.email == request.email, User.is_active.is_(True)))
    user = result.scalar_one_or_none()

    if user is None or not verify_password(request.password, user.hashed_password):
        locked = await throttle.record_failure(email=request.email, source_ip=source)
        if locked.locked_out:
            logger.warning(
                "login lockout: %s principal locked after %d failures (ip=%s)",
                locked.scope,
                locked.failures,
                str(source).replace("\r", "").replace("\n", " ")[:64],
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    await throttle.record_success(email=request.email, source_ip=source)

    # Update last login
    await db.execute(update(User).where(User.id == user.id).values(last_login=datetime.now(UTC)))

    token_data = {
        "sub": str(user.id),
        "tenant_id": str(user.tenant_id),
        "role": user.role,
        "email": user.email,
    }
    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(request: RefreshRequest, db: DBSession) -> TokenResponse:
    """Refresh access token using a valid refresh token."""
    try:
        payload = decode_token(request.refresh_token)
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")
        user_id = payload.get("sub")
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token") from e

    result = await db.execute(select(User).where(User.id == uuid.UUID(user_id), User.is_active.is_(True)))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    # A refresh token outlives an access token by days, so without this a
    # deprovisioned principal who is later re-activated could mint a fresh
    # session from a token issued before the revocation.
    if token_is_revoked(payload.get("iat"), user.sessions_revoked_at):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session revoked")

    token_data = {
        "sub": str(user.id),
        "tenant_id": str(user.tenant_id),
        "role": user.role,
        "email": user.email,
    }
    return TokenResponse(
        access_token=create_access_token(token_data),
        refresh_token=create_refresh_token(token_data),
    )


@router.get("/me", response_model=UserMeResponse)
async def get_me(current_user: AuthUser, db: DBSession) -> UserMeResponse:
    """Get current authenticated user info."""
    result = await db.execute(select(User).where(User.id == current_user.user_id))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return UserMeResponse.model_validate(user)


@router.patch("/me/preferences", response_model=UserMeResponse)
async def patch_me_preferences(
    body: PreferencesPatch,
    current_user: AuthUser,
    db: DBSession,
) -> UserMeResponse:
    """Merge user preferences (e.g. theme) into the stored JSONB column.

    Only the keys supplied in the request body are updated; all other
    existing keys are preserved.  This lets the frontend evolve independent
    preference namespaces without overwriting each other.
    """
    result = await db.execute(select(User).where(User.id == current_user.user_id))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    merged = {**(user.preferences or {}), **body.preferences}
    await db.execute(update(User).where(User.id == current_user.user_id).values(preferences=merged))
    await db.commit()

    # Re-fetch to return fresh state
    result = await db.execute(select(User).where(User.id == current_user.user_id))
    user = result.scalar_one_or_none()
    return UserMeResponse.model_validate(user)
