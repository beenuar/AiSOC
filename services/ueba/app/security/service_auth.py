"""Service-to-service bearer auth for mutating routes.

Vendored byte-identical into each Python service that needs it, following the
same convention as ``app/core/cors.py``. Keep the copies in sync.

Why this exists
---------------
Several backend services shipped with every route reachable without any
credential at all. The worst case was ``purple-team``'s ``POST /caldera/run``,
which starts a real adversary-emulation operation against live hosts and read
the caller's ``tenant_id`` and ``executed_by`` straight out of the request body
— so the caller declared their own identity and their own tenant.

These services are not reachable from the browser (the web app only proxies to
api, agents, enrichment, fusion, osquery-tls and realtime), so they are
service-to-service surfaces and a shared bearer token is the right shape. They
fail closed: without a configured token a production deployment answers 503
rather than serving the route openly.

Deliberately NOT applied to ``services/mesh``, which is a federated community
hub that is public by design and protected instead by Ed25519 signature
verification and k-anonymity.

Configuration
-------------
``AISOC_SERVICE_TOKEN``
    Shared secret presented as ``Authorization: Bearer <token>`` by callers.
``AISOC_<SERVICE>_SERVICE_TOKEN``
    Optional per-service override, e.g. ``AISOC_PURPLE_TEAM_SERVICE_TOKEN``.
``AISOC_DEV_MODE``
    When set and no token is configured, requests are allowed through so a
    local ``docker compose up`` still works. This mirrors the single canonical
    dev-mode flag used across the platform; it is asserted off in production by
    ``services/api/tests/test_security_defaults.py``.
"""

from __future__ import annotations

import hmac
import os

from fastapi import Header, HTTPException, status

#: Set by each vendored copy so the per-service override resolves.
SERVICE_NAME = "UEBA"

_TRUTHY = {"1", "true", "yes", "on"}


def _dev_mode() -> bool:
    return os.getenv("AISOC_DEV_MODE", "").strip().lower() in _TRUTHY


def resolve_token() -> str:
    """Per-service override wins, then the shared platform token."""
    specific = os.getenv(f"AISOC_{SERVICE_NAME}_SERVICE_TOKEN", "").strip()
    if specific:
        return specific
    return os.getenv("AISOC_SERVICE_TOKEN", "").strip()


async def require_service_auth(authorization: str | None = Header(default=None)) -> None:
    """FastAPI dependency. Fails closed unless explicitly in dev mode."""
    token = resolve_token()
    if not token:
        if _dev_mode():
            return
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "service auth is not configured; set AISOC_SERVICE_TOKEN "
                f"(or AISOC_{SERVICE_NAME}_SERVICE_TOKEN) before exposing this service"
            ),
        )

    expected = f"Bearer {token}"
    # compare_digest rather than == so the comparison is not timing-variable.
    if not authorization or not hmac.compare_digest(authorization, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid or missing service token",
            headers={"WWW-Authenticate": "Bearer"},
        )
