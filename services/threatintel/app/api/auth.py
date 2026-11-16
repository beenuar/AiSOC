"""Shared-secret auth for the threat-actor attribution HTTP surface.

The ``/api/v1/actors/*`` endpoints require ``AISOC_THREATINTEL_SERVICE_TOKEN``
(``Authorization: Bearer <token>``, compared in constant time). An unset
token refuses every caller with 503 rather than failing open — the service
historically allowed unauthenticated internal calls, which left actor
profiles readable by anyone who could reach the port the moment a deployment
exposed it (SEC-15). ``ensure_env`` generates the token and compose forwards
it to this service and to the calling agents, so the default stack is closed
with no operator step; the pre-token open behaviour survives only behind an
explicit ``AISOC_THREATINTEL_ALLOW_UNAUTHENTICATED=1``.

This mirrors two existing conventions in the codebase:

* the ingest ``k8s-audit`` shared-secret gate — a header token compared with
  ``subtle.ConstantTimeCompare`` (here: :func:`hmac.compare_digest`), and
* the actions->api ``AISOC_API_SERVICE_TOKEN`` inter-service token.

Resolves the ``[#TODO-attribution-rbac]`` caveat in
``docs/threat-actor-attribution.md``.
"""

from __future__ import annotations

import functools
import hmac
import os

import structlog
from fastapi import Header, HTTPException, status

from app.config import settings

logger = structlog.get_logger(__name__)

_BEARER_PREFIX = "bearer "


@functools.lru_cache(maxsize=1)
def _warn_unconfigured_once() -> None:
    """Warn once per process that the gate is refusing for want of a token.

    ``lru_cache`` is the once-mechanism rather than a module flag: CodeQL
    reads a ``global`` rebind as an unused write, and the route-state gate
    (rightly) refuses route modules that keep mutable module-level
    containers — a cached no-arg call keeps the once-only behaviour with
    neither.
    """
    logger.warning(
        "actor_auth.unconfigured",
        detail=(
            "AISOC_THREATINTEL_SERVICE_TOKEN is unset; /api/v1/actors/* "
            "refuses callers (503). Set it — ensure_env generates one — "
            "or opt into the open mode with "
            "AISOC_THREATINTEL_ALLOW_UNAUTHENTICATED=1."
        ),
    )


def _expected_token() -> str:
    return (getattr(settings, "AISOC_THREATINTEL_SERVICE_TOKEN", "") or "").strip()


async def require_actor_auth(authorization: str | None = Header(default=None)) -> None:
    """FastAPI dependency gating the ``/api/v1/actors/*`` endpoints.

    * Token unset → **503** (SEC-15: fail closed; the pre-token open
      behaviour survives only behind an explicit
      ``AISOC_THREATINTEL_ALLOW_UNAUTHENTICATED=1``), warning once so an
      operator sees why every caller is refused.
    * Token set → require a matching ``Authorization: Bearer <token>``,
      constant-time compared; missing or wrong → ``401``.
    """
    expected = _expected_token()
    if not expected:
        _warn_unconfigured_once()
        # [SEC-15] Fail closed. An unset token used to warn and allow every
        # caller, leaving the actor-attribution profiles exposed to anyone
        # who could reach the port, with a log line as the only trace.
        # The open pre-token behaviour survives only behind an explicit opt-in.
        if os.getenv("AISOC_THREATINTEL_ALLOW_UNAUTHENTICATED", "").strip().lower() in {"1", "true", "yes"}:
            return
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "actor attribution requires AISOC_THREATINTEL_SERVICE_TOKEN; "
                "set it, or opt into the open mode with "
                "AISOC_THREATINTEL_ALLOW_UNAUTHENTICATED=1"
            ),
        )

    presented = ""
    if authorization and authorization.lower().startswith(_BEARER_PREFIX):
        presented = authorization[len(_BEARER_PREFIX) :].strip()

    if not presented or not hmac.compare_digest(presented, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid or missing bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
