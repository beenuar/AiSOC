"""Resolve a verified ChatOps identity into an authorization principal (T3.6).

The Slack and Teams bots verify who clicked — Slack signs every interaction
payload, Teams payloads carry an HMAC — and then recorded that identity in an
audit event and *nothing else*. ``approve_action(action_id)`` sent no approver,
so the actions service ran :func:`authorize_approver` on nobody: the
permission-tier check and separation of duties were both skipped, and the only
trace of the human was a log line. An approval path that does not authorize is
worse than no approval path, because it reads as a control.

The bot cannot supply permissions itself. It knows a Slack user id; it has no
idea what that person may do in AiSOC, and a bot that asserted its own
permissions would be a bot that could grant itself anything. So the bot asserts
only *identity* and this module maps that identity onto a principal using
configuration the operator controls.

Mapping is deliberately operator-configured rather than read from a user
directory. The actions service owns no user table — the API does — and a
network lookup on the approval path would mean an approval whose authorization
depends on another service being reachable. A missing mapping therefore
resolves to ``None``, and the caller refuses the approval.

Configuration
=============

``AISOC_CHATOPS_APPROVERS`` holds JSON, either inline or as a ``file:`` path::

    {
      "slack": {
        "U123ABC": {
          "user_id": "dana@example.com",
          "permissions": ["actions:execute:high"],
          "tenant_id": "0b4e...",
          "roles": ["soc-lead"]
        }
      },
      "teams": {"29:1xyz": {"user_id": "sam@example.com",
                            "permissions": ["actions:execute:low"]}}
    }

Platform keys are lower-cased. Platform user ids are matched exactly, because
Slack ids are case-sensitive opaque handles. Unset config means nobody can
approve over ChatOps — which is the correct default for a control that was
previously absent.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

import structlog

from app.core.config import get_settings
from app.models.action import ActionPrincipal

logger = structlog.get_logger()

#: Platforms a bot may assert. An unknown platform is refused rather than
#: trusted, so a new integration cannot quietly inherit approval rights.
SUPPORTED_PLATFORMS = frozenset({"slack", "teams", "email"})


class ChatOpsIdentityError(ValueError):
    """Raised when the approver map is present but unusable.

    Distinguished from "no mapping for this user" on purpose: a malformed map
    is an operator error that should be loud, while an unmapped user is a
    routine denial.
    """


def _coerce_principal(platform: str, platform_user_id: str, raw: Any) -> ActionPrincipal:
    if not isinstance(raw, dict):
        raise ChatOpsIdentityError(f"approver entry for {platform}/{platform_user_id} is not an object")
    user_id = raw.get("user_id") or raw.get("email")
    if not user_id:
        raise ChatOpsIdentityError(f"approver entry for {platform}/{platform_user_id} has no user_id")
    return ActionPrincipal(
        user_id=str(user_id),
        tenant_id=raw.get("tenant_id"),
        email=raw.get("email") or (str(user_id) if "@" in str(user_id) else None),
        roles=[str(r) for r in (raw.get("roles") or [])],
        permissions=[str(p) for p in (raw.get("permissions") or [])],
    )


def _load_raw_map(spec: str) -> dict[str, Any]:
    spec = spec.strip()
    if not spec:
        return {}
    if spec.startswith("file:"):
        path = Path(spec[len("file:") :]).expanduser()
        try:
            spec = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ChatOpsIdentityError(f"cannot read approver map at {path}: {exc}") from exc
    try:
        parsed = json.loads(spec)
    except ValueError as exc:
        raise ChatOpsIdentityError(f"approver map is not valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ChatOpsIdentityError("approver map must be a JSON object keyed by platform")
    return parsed


@lru_cache(maxsize=1)
def _approver_map() -> dict[str, dict[str, Any]]:
    raw = _load_raw_map(get_settings().AISOC_CHATOPS_APPROVERS)
    normalised: dict[str, dict[str, Any]] = {}
    for platform, entries in raw.items():
        key = str(platform).strip().lower()
        if key not in SUPPORTED_PLATFORMS:
            raise ChatOpsIdentityError(f"unsupported approver platform '{platform}' (expected one of {sorted(SUPPORTED_PLATFORMS)})")
        if not isinstance(entries, dict):
            raise ChatOpsIdentityError(f"approver entries for '{platform}' must be an object")
        normalised[key] = entries
    return normalised


def reset_cache() -> None:
    """Drop the memoised map. Tests and config reloads use this."""
    _approver_map.cache_clear()


def resolve_approver(platform: str, platform_user_id: str) -> ActionPrincipal | None:
    """Map a verified ChatOps identity to a principal, or ``None``.

    ``None`` means "this identity is not authorised to approve", not "allow by
    default" — the caller must refuse. Returning a permission-less principal
    instead would be worse than returning nothing, because it would pass an
    identity check and then silently fail an authorization check for a reason
    the operator cannot distinguish from a misconfigured tier.
    """
    key = (platform or "").strip().lower()
    if key not in SUPPORTED_PLATFORMS:
        logger.warning("chatops_approver_unsupported_platform", platform=platform)
        return None
    if not platform_user_id:
        return None

    entry = _approver_map().get(key, {}).get(platform_user_id)
    if entry is None:
        logger.warning(
            "chatops_approver_not_mapped",
            platform=key,
            platform_user_id=platform_user_id[:64],
        )
        return None
    return _coerce_principal(key, platform_user_id, entry)
