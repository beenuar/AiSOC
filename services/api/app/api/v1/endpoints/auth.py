"""Authentication endpoints: login, refresh, logout, user preferences."""

import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr
from sqlalchemy import select, update

from app.api.v1.deps import AuthUser, DBSession, get_current_user

__all__ = ["router", "get_current_user"]
from app.core.config import settings
from app.core.role_grants import wildcard_roles as WILDCARD_ROLES
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


# The throttle runs *before* the password is verified, and answers the same
# whether the account exists or not. A throttle that engaged only for real
# accounts would reply 429 for those and 401 for the rest, and that difference
# is a user list.
#
# The explanation lives here rather than in the docstring because the
# docstring is published as the operation's `description` in
# `docs/openapi.yaml`, and an API description should say what the endpoint
# does, not what it used to do wrong.
@router.post(
    "/login",
    response_model=TokenResponse,
    responses={
        202: {
            "description": (
                "The password was accepted and a second factor is outstanding. The body carries "
                "`mfa_token` plus either `mfa_required` (complete it at `POST /auth/mfa/verify`) or "
                "`mfa_enrollment_required` (the tenant requires a factor this account has not enrolled; "
                "enrol at `POST /auth/mfa/enroll/begin`). No session is issued."
            ),
            "content": {"application/json": {"example": {"mfa_required": True, "mfa_token": "eyJ…", "methods": ["totp", "recovery_code"]}}},
        }
    },
)
async def login(request: LoginRequest, http_request: Request, db: DBSession) -> TokenResponse | JSONResponse:
    """Authenticate with email/password, return JWT tokens."""
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

    # Break-glass policy: once SSO is enabled, an operator may close the
    # password door for everyone except the wildcard roles, so local
    # accounts survive as the path that works when the IdP is down -- and
    # only as that path. Answered after password verification so it leaks
    # nothing about which addresses exist, and throttled above like every
    # other attempt here.
    sso_enabled = (settings_dict().get("SSO_ENABLED") or "false").strip().lower() in {"1", "true", "yes", "on"}
    local_admin_only = (settings_dict().get("SSO_LOCAL_ADMIN_ONLY") or "false").strip().lower() in {"1", "true", "yes", "on"}
    if sso_enabled and local_admin_only and user.role not in WILDCARD_ROLES():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Password sign-in is disabled for this account. Use single sign-on.",
        )

    await throttle.record_success(email=request.email, source_ip=source)

    # Fix pass 4.2. The password is one factor, and for an enrolled user or
    # an enforcing tenant it is no longer the whole answer. Answered as 202
    # rather than by widening the 200 body: `access_token` and
    # `refresh_token` are required fields of `TokenResponse`, and making
    # either optional is a break for every generated client.
    challenge = await mfa_challenge_for(db, user_id=user.id, tenant_id=user.tenant_id)
    if challenge is not None:
        return JSONResponse(status_code=status.HTTP_202_ACCEPTED, content=challenge)

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


async def mfa_challenge_for(db: Any, *, user_id: uuid.UUID, tenant_id: uuid.UUID) -> dict[str, Any] | None:
    """What this account still owes before a session is issued, or `None`.

    Two cases and they are not the same thing. An enrolled user owes a
    code. A user in an enforcing tenant who has never enrolled owes an
    enrolment — refusing them instead would lock out every unenrolled user
    the moment an administrator turns the policy on, which is the whole
    tenant at once.

    A failure to read either table is **not** treated as "no MFA". That
    would fail open at the one place in the product where open is worst.
    """
    from app.api.v1.endpoints.mfa import has_confirmed_factor, mint_challenge, tenant_requires_totp

    if await has_confirmed_factor(db, user_id):
        return {
            "mfa_required": True,
            "mfa_token": mint_challenge(user_id=user_id, tenant_id=tenant_id, purpose="verify"),
            "methods": ["totp", "recovery_code"],
        }
    if await tenant_requires_totp(db, tenant_id):
        return {
            "mfa_enrollment_required": True,
            "mfa_token": mint_challenge(user_id=user_id, tenant_id=tenant_id, purpose="enroll"),
        }
    return None


def settings_dict() -> dict[str, str]:
    """The SSO-related environment, read live so an operator can flip the
    flag without a redeploy. Anything unset reads as its safe default."""
    import os

    return {k: (os.getenv(k) or "") for k in ("SSO_ENABLED", "SSO_LOCAL_ADMIN_ONLY", "SSO_LOGIN_LABEL", "SSO_PROVIDER")}


@router.get("/sso/status")
async def sso_status() -> dict[str, Any]:
    """What the login screen asks before it offers SSO. Public: it reveals
    only that SSO is offered, under what label, and whether password sign-in
    remains open -- never issuers, client ids, endpoints or secrets."""
    d = settings_dict()
    enabled = d["SSO_ENABLED"].strip().lower() in {"1", "true", "yes", "on"}
    local_admin_only = d["SSO_LOCAL_ADMIN_ONLY"].strip().lower() in {"1", "true", "yes", "on"}
    return {
        "sso_enabled": enabled,
        "provider": (d["SSO_PROVIDER"] or "oidc").strip().lower(),
        "login_label": (d["SSO_LOGIN_LABEL"] or "Continue with SSO").strip()[:80],
        "local_login_enabled": (not enabled) or (not local_admin_only),
    }


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
