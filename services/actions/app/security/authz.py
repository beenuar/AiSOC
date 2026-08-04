"""Invoking-identity authorization for the actions service (Wave 4).

Three guarantees layered on top of the blast-radius gate:

* **W4.2 least-privilege** — an action only runs if its invoking principal
  holds the permission its blast radius demands (``actions:execute:{low,medium,
  high}``, with higher tiers granting lower and ``actions:*`` granting all).
* **W4.3 authenticated routes** — the mutating routes require a service bearer
  token; a missing token fails closed in production.
* **W4.4 bound approval** — an approver must hold the action's permission AND
  must not be the requester (separation of duties).
"""

from __future__ import annotations

import hmac
from typing import Any

from fastapi import Header, HTTPException, status

from app.core.config import get_settings
from app.models.action import (
    ACTION_REQUIRED_PERMISSION,
    ActionPrincipal,
    ActionRequest,
    ActionType,
)

# Ordered execution tiers — a higher tier grants every lower one.
_TIER_RANK: dict[str, int] = {
    "actions:execute:low": 1,
    "actions:execute:medium": 2,
    "actions:execute:high": 3,
}


class ActionAuthzError(Exception):
    """Raised when a principal is not authorized for an action / approval."""


def has_action_permission(permissions: list[str], required: str) -> bool:
    """True if ``permissions`` satisfies ``required`` (exact, wildcard, or a
    higher execution tier)."""
    if not permissions:
        return False
    perms = set(permissions)
    if "*" in perms or "actions:*" in perms or "actions:execute:*" in perms:
        return True
    if required in perms:
        return True
    req_rank = _TIER_RANK.get(required, 0)
    if req_rank:
        return any(_TIER_RANK.get(p, 0) >= req_rank for p in perms)
    return False


def _required_permission(action_type: ActionType) -> str:
    # Unknown/newly-added action types default to the strictest tier.
    return ACTION_REQUIRED_PERMISSION.get(action_type, "actions:execute:high")


def authorize_action(request: ActionRequest, *, require_principal: bool | None = None) -> None:
    """Enforce least-privilege for an action's invoking principal (W4.2).

    Raises :class:`ActionAuthzError` on denial. A principal-less request is
    allowed only when principals aren't required (legacy / system path)."""
    if require_principal is None:
        require_principal = get_settings().AISOC_ACTIONS_REQUIRE_PRINCIPAL

    principal = request.principal
    if principal is None:
        if require_principal:
            raise ActionAuthzError("no authenticated principal on action request")
        return

    if principal.tenant_id is not None and principal.tenant_id != request.tenant_id:
        raise ActionAuthzError("principal tenant does not match the action's tenant")

    required = _required_permission(request.action_type)
    if not has_action_permission(principal.permissions, required):
        raise ActionAuthzError(f"principal {principal.user_id} lacks '{required}' required for {request.action_type.value}")


def authorize_approver(
    record: dict[str, Any],
    approver: ActionPrincipal,
    *,
    separation_of_duties: bool = True,
) -> None:
    """Enforce that an approver may approve this action (W4.4).

    The approver must hold the action's required permission and — under
    separation of duties — must not be the principal who requested it."""
    action_type = ActionType(record["action_type"])
    required = _required_permission(action_type)
    if not has_action_permission(approver.permissions, required):
        raise ActionAuthzError(f"approver {approver.user_id} lacks '{required}' to approve {action_type.value}")

    requester = record.get("requested_by_user_id")
    if separation_of_duties and requester and str(requester) == str(approver.user_id):
        raise ActionAuthzError("approver cannot be the requester (separation of duties)")


async def require_service_auth(authorization: str | None = Header(default=None)) -> None:
    """FastAPI dependency: verify the service bearer token on mutating routes
    (W4.3). Fails closed in production when no token is configured."""
    settings = get_settings()
    token = settings.AISOC_ACTIONS_SERVICE_TOKEN.strip()
    if not token:
        if settings.AISOC_DEV_MODE:
            return
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="actions service auth is not configured",
        )
    expected = f"Bearer {token}"
    if not authorization or not hmac.compare_digest(authorization, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid or missing service token",
            headers={"WWW-Authenticate": "Bearer"},
        )
