"""FastAPI dependency injection."""
import uuid
from collections.abc import AsyncGenerator
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dev_auth import (
    DEMO_TENANT_ID,
    DEMO_USER_EMAIL,
    DEMO_USER_ID,
    DEMO_USER_ROLE,
    is_dev_mode,
)
from app.core.security import decode_token, has_permission
from app.db.database import get_db
from app.models.tenant import ApiKey, Tenant, User

bearer_scheme = HTTPBearer(auto_error=False)


class CurrentUser:
    """Resolved authenticated user context."""

    def __init__(
        self,
        user_id: uuid.UUID,
        tenant_id: uuid.UUID,
        role: str,
        email: str,
    ) -> None:
        self.user_id = user_id
        self.tenant_id = tenant_id
        self.role = role
        self.email = email

    def require_permission(self, permission: str) -> None:
        if not has_permission(self.role, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: {permission}",
            )


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Security(bearer_scheme)],
    db: AsyncSession = Depends(get_db),
) -> CurrentUser:
    """Resolve JWT bearer token to CurrentUser.

    In development mode an unauthenticated request resolves to a deterministic
    demo user (see ``app.api.v1.dev_auth``). Production requires a bearer token.
    """
    if credentials is None:
        if is_dev_mode():
            return CurrentUser(
                user_id=DEMO_USER_ID,
                tenant_id=DEMO_TENANT_ID,
                role=DEMO_USER_ROLE,
                email=DEMO_USER_EMAIL,
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = decode_token(credentials.credentials)
        user_id: str = payload.get("sub")
        token_type: str = payload.get("type", "access")
        if user_id is None or token_type != "access":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
        ) from e

    result = await db.execute(select(User).where(User.id == uuid.UUID(user_id), User.is_active == True))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    return CurrentUser(
        user_id=user.id,
        tenant_id=user.tenant_id,
        role=user.role,
        email=user.email,
    )


async def get_current_active_user(
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
) -> CurrentUser:
    return current_user


def require_permission(permission: str):
    """Factory for permission-checking dependencies."""

    async def _check(current_user: Annotated[CurrentUser, Depends(get_current_user)]) -> CurrentUser:
        current_user.require_permission(permission)
        return current_user

    return _check


# Type aliases
DBSession = Annotated[AsyncSession, Depends(get_db)]
AuthUser = Annotated[CurrentUser, Depends(get_current_user)]
