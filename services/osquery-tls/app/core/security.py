"""Security helpers for the AiSOC osquery TLS service.

Handles two authentication concerns:

1. **Enroll secret** — the shared secret an osqueryd agent must supply when
   first enrolling.  Validated in ``verify_enroll_secret()``.
2. **Node key** — a server-issued opaque token (UUID) returned after enroll.
   Every subsequent request validates ``node_key`` against ``node_registry``.
3. **mTLS** (optional, controlled by ``AISOC_OSQUERY_TLS_REQUIRE_CLIENT_CERT``)
   — after enroll, the TLS client certificate CN must match
   ``node.host_identifier``.

The FastAPI dependency ``require_valid_node_key`` is used by all post-enroll
endpoints.  It returns the resolved ``OsqueryNode`` so handlers don't need
a separate DB lookup.
"""

from __future__ import annotations

import secrets
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.crypto import generate_node_key
from app.db.session import get_db

__all__ = ["generate_node_key", "verify_enroll_secret", "require_valid_node_key"]


def _tenant_from_header(x_aisoc_tenant: str | None) -> str:
    """Return tenant identifier from request header, defaulting to 'default'."""
    return x_aisoc_tenant or "default"


def verify_enroll_secret(submitted_secret: str, tenant_id: str = "default") -> bool:
    """Constant-time comparison of the submitted enroll secret.

    In a multi-tenant deployment the enroll secret would be looked up per
    tenant.  For now we use the single-tenant secret from settings.
    """
    return secrets.compare_digest(submitted_secret, settings.enroll_secret)


async def require_valid_node_key(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    x_aisoc_tenant: Annotated[str | None, Header()] = None,
) -> app.models.node.OsqueryNode:  # type: ignore[name-defined]  # noqa: F821
    """FastAPI dependency: parse node_key from JSON body and resolve the node.

    Raises ``HTTP 401`` if the key is missing or unknown.

    Returns the resolved ``OsqueryNode`` ORM instance.
    """
    from app.services.node_registry import get_node_by_key  # noqa: PLC0415

    body = await request.json()
    node_key: str | None = body.get("node_key")
    if not node_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="node_key is required",
        )

    node = await get_node_by_key(db, node_key)
    if node is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="node_invalid",
        )

    if settings.require_client_cert:
        # Validate that the TLS client certificate CN matches host_identifier.
        # Nginx / Caddy should forward the verified CN in X-SSL-Client-CN.
        client_cn = request.headers.get("X-SSL-Client-CN", "")
        if client_cn != node.host_identifier:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="client certificate CN does not match host_identifier",
            )

    return node
