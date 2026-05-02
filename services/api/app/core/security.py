"""
Security utilities: JWT tokens, password hashing, RBAC
"""
from datetime import UTC, datetime, timedelta
from typing import Any

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

ROLE_PERMISSIONS: dict[str, list[str]] = {
    "platform_admin": ["*"],
    "tenant_admin": [
        "alerts:read", "alerts:write", "alerts:delete",
        "cases:read", "cases:write", "cases:delete",
        "playbooks:read", "playbooks:write", "playbooks:execute",
        "connectors:read", "connectors:write", "connectors:delete",
        "users:read", "users:write",
        "rules:read", "rules:write",
        "reports:read", "reports:write",
        "threat_intel:read",
        "settings:read", "settings:write",
    ],
    "soc_lead": [
        "alerts:read", "alerts:write",
        "cases:read", "cases:write",
        "playbooks:read", "playbooks:execute",
        "connectors:read",
        "users:read",
        "rules:read", "rules:write",
        "reports:read", "reports:write",
        "threat_intel:read",
    ],
    "soc_analyst": [
        "alerts:read", "alerts:write",
        "cases:read", "cases:write",
        "playbooks:read", "playbooks:execute",
        "connectors:read",
        "threat_intel:read",
        "reports:read",
    ],
    "threat_hunter": [
        "alerts:read",
        "cases:read", "cases:write",
        "threat_intel:read", "threat_intel:write",
        "rules:read", "rules:write",
        "reports:read",
    ],
    "viewer": [
        "alerts:read",
        "cases:read",
        "reports:read",
        "threat_intel:read",
    ],
    "api_service": [
        "alerts:read", "alerts:write",
        "cases:read", "cases:write",
        "threat_intel:read",
    ],
}


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(data: dict[str, Any], expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(UTC) + expires_delta
    else:
        expire = datetime.now(UTC) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "type": "access"})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def create_refresh_token(data: dict[str, Any]) -> str:
    to_encode = data.copy()
    expire = datetime.now(UTC) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "type": "refresh"})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def decode_token(token: str) -> dict[str, Any]:
    return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])


def has_permission(role: str, permission: str) -> bool:
    """Check if a role has a specific permission."""
    perms = ROLE_PERMISSIONS.get(role, [])
    if "*" in perms:
        return True
    if permission in perms:
        return True
    # Check wildcard resource (e.g., "alerts:*" covers "alerts:read")
    resource = permission.split(":")[0]
    return f"{resource}:*" in perms
