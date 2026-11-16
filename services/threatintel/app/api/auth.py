"""Optional shared-secret auth for the threat-actor attribution HTTP surface.

The ``threatintel`` service runs inside the cluster's private network, so by
default the ``/api/v1/actors/*`` endpoints accept internal calls without
authentication (their historical behaviour). When an operator exposes the
service beyond that perimeter — or runs it in an MSSP / multi-tenant
deployment — they set ``AISOC_THREATINTEL_SERVICE_TOKEN``; the endpoints then
require ``Authorization: Bearer <token>``, compared in constant time.

This mirrors two existing conventions in the codebase:

* the ingest ``k8s-audit`` shared-secret gate — a header token compared with
  ``subtle.ConstantTimeCompare`` (here: :func:`hmac.compare_digest`), and
* the actions->api ``AISOC_API_SERVICE_TOKEN`` inter-service token.

Resolves the ``[#TODO-attribution-rbac]`` caveat in
``docs/threat-actor-attribution.md``.
"""

from __future__ import annotations

import hmac

import structlog
from fastapi import Header, HTTPException, status

from app.config import settings

logger = structlog.get_logger(__name__)

_BEARER_PREFIX = "bearer "

# Warn at most once per process so an exposed-but-unauthenticated deployment
# is visible in logs without flooding them on every request.
_warned_unconfigured = False


def _expected_token() -> str:
    return (getattr(settings, "AISOC_THREATINTEL_SERVICE_TOKEN", "") or "").strip()


async def require_actor_auth(authorization: str | None = Header(default=None)) -> None:
    """FastAPI dependency gating the ``/api/v1/actors/*`` endpoints.

    * Token unset → allow (internal-only default), warning once so operators
      who have exposed the service notice it is unauthenticated.
    * Token set → require a matching ``Authorization: Bearer <token>``,
      constant-time compared; missing or wrong → ``401``.
    """
    expected = _expected_token()
    if not expected:
        global _warned_unconfigured
        if not _warned_unconfigured:
            logger.warning(
                "actor_auth.unconfigured",
                detail=(
                    "AISOC_THREATINTEL_SERVICE_TOKEN is unset; /api/v1/actors/* "
                    "is unauthenticated. Set it (and configure the investigation "
                    "agent with the same value) before exposing the service "
                    "beyond the private network."
                ),
            )
            _warned_unconfigured = True
        return

    presented = ""
    if authorization and authorization.lower().startswith(_BEARER_PREFIX):
        presented = authorization[len(_BEARER_PREFIX) :].strip()

    if not presented or not hmac.compare_digest(presented, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid or missing bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
