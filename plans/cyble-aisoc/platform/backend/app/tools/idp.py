"""Identity provider tools (Okta / Entra ID): user lookup, session revoke, MFA reset.

Thin wrappers over the connector SDK. Each tool resolves the per-tenant
IdP connector (Okta / Microsoft Entra ID / mock fallback) via
:func:`app.connectors.get_connector` and delegates to the matching
protocol method on :class:`app.connectors.sdk.protocols.BaseIdpConnector`.

Tenancy
-------
Every handler is tagged with ``needs:tenant``. The agent base injects
``params["tenant_id"]`` from its own bound tenant before dispatch — the
LLM never sees ``tenant_id`` in the JSON schema and cannot spoof it.
"""
from __future__ import annotations

from typing import Any

from app.connectors import ConnectorKind, get_connector
from app.tools.registry import RiskClass, tool


_NEEDS_TENANT = "needs:tenant"


# ── Reverse-params builders (t1-reverse-actions) ───────────────────────────
# Pure: derive reverse-tool params from forward-call (params, result).
def _reverse_disable_user(
    params: dict[str, Any], _result: dict[str, Any]
) -> dict[str, Any]:
    return {"user": params["user"]}


# NOTE: `idp.revoke_sessions` has no clean inverse — you cannot un-revoke
# a session, only re-issue one. We deliberately do NOT pair it; HITL must
# treat it as a forward-only action. Same for `idp.reset_password` (the
# password is already changed by the time we'd "undo" it).


@tool(
    name="idp.get_user",
    integration="okta",
    risk=RiskClass.READ,
    description="Lookup user details, group memberships, recent sign-ins.",
    params={"type": "object", "properties": {"user": {"type": "string"}}, "required": ["user"]},
    result={
        "type": "object",
        "properties": {
            "user": {"type": "string"},
            "email": {"type": "string"},
            "department": {"type": "string"},
            "manager": {"type": "string"},
            "groups": {
                "type": "array",
                "items": {"type": "string"},
            },
            "last_signin": {
                "type": "object",
                "properties": {
                    "ts": {"type": "string"},
                    "src_ip": {"type": "string"},
                    "country": {"type": "string"},
                    "asn": {"type": "string"},
                    "anomaly_score": {"type": "number"},
                },
                "additionalProperties": True,
            },
            "mfa_factors": {
                "type": "array",
                "items": {"type": "string"},
            },
        },
        "required": ["user"],
        "additionalProperties": False,
    },
    tags=[_NEEDS_TENANT, "idp"],
)
async def idp_get_user(*, tenant_id: str, user: str) -> dict[str, Any]:
    idp = await get_connector(tenant_id, ConnectorKind.IDP)
    return await idp.get_user(user=user)


@tool(
    name="idp.revoke_sessions",
    integration="okta",
    # WRITE_SIGNIFICANT, not WRITE_REVERSIBLE: a revoked session token
    # cannot be un-revoked — the best we can do is let the user sign in
    # again, which is a *new* session, not the old one. See module-level
    # NOTE above. The rollback service refuses to reverse this.
    risk=RiskClass.WRITE_SIGNIFICANT,
    forward_only_reason=(
        "revoked OAuth/SSO session tokens cannot be un-revoked; a "
        "subsequent sign-in produces a fresh session, not the old one, so "
        "there is no semantic inverse to apply"
    ),
    description="Revoke all active OAuth and SSO sessions for a user. Forces re-auth.",
    params={"type": "object", "properties": {"user": {"type": "string"}}, "required": ["user"]},
    result={
        "type": "object",
        "properties": {
            "user": {"type": "string"},
            "sessions_revoked": {"type": "integer"},
            "ticket": {"type": "string"},
        },
        "required": ["user", "sessions_revoked"],
        "additionalProperties": False,
    },
    tags=[_NEEDS_TENANT, "containment"],
)
async def idp_revoke_sessions(*, tenant_id: str, user: str) -> dict[str, Any]:
    idp = await get_connector(tenant_id, ConnectorKind.IDP)
    return await idp.revoke_sessions(user=user)


@tool(
    name="idp.disable_user",
    integration="okta",
    risk=RiskClass.WRITE_SIGNIFICANT,
    description="Suspend a user account. Reversible by admin re-activation.",
    params={"type": "object", "properties": {"user": {"type": "string"}, "reason": {"type": "string"}}, "required": ["user", "reason"]},
    result={
        "type": "object",
        "properties": {
            "user": {"type": "string"},
            "disabled": {"type": "boolean"},
            "reason": {"type": "string"},
        },
        "required": ["user", "disabled"],
        "additionalProperties": False,
    },
    tags=[_NEEDS_TENANT, "containment"],
    reverse_tool="idp.enable_user",
    reverse_params_builder=_reverse_disable_user,
)
async def idp_disable_user(
    *, tenant_id: str, user: str, reason: str
) -> dict[str, Any]:
    idp = await get_connector(tenant_id, ConnectorKind.IDP)
    return await idp.disable_user(user=user, reason=reason)


@tool(
    name="idp.enable_user",
    integration="okta",
    risk=RiskClass.WRITE_SIGNIFICANT,
    forward_only_reason=(
        "this IS the reverse of idp.disable_user; re-disabling via rollback "
        "would re-trigger containment and loop. Re-disable must be a fresh "
        "HITL decision through idp.disable_user"
    ),
    description=(
        "Re-enable a previously disabled user account. "
        "Reverse pair of idp.disable_user."
    ),
    params={
        "type": "object",
        "properties": {"user": {"type": "string"}},
        "required": ["user"],
    },
    result={
        "type": "object",
        "properties": {
            "user": {"type": "string"},
            "disabled": {"type": "boolean"},
            "ticket": {"type": "string"},
        },
        "required": ["user", "disabled"],
        "additionalProperties": False,
    },
    tags=[_NEEDS_TENANT, "rollback"],
)
async def idp_enable_user(*, tenant_id: str, user: str) -> dict[str, Any]:
    idp = await get_connector(tenant_id, ConnectorKind.IDP)
    return await idp.enable_user(user=user)


@tool(
    name="idp.reset_password",
    integration="okta",
    # WRITE_SIGNIFICANT, not WRITE_REVERSIBLE: once the reset email is sent
    # (and especially once the user clicks the link and picks a new
    # password) we cannot restore the previous credential. The rollback
    # service refuses to reverse this; HITL must own the forward decision.
    risk=RiskClass.WRITE_SIGNIFICANT,
    forward_only_reason=(
        "the previous password hash is gone the moment the user completes "
        "the reset flow; there is no credential to restore, and silently "
        "restoring a stale credential would be a security regression"
    ),
    description="Force password reset for user. User receives email link to set new password.",
    params={"type": "object", "properties": {"user": {"type": "string"}}, "required": ["user"]},
    result={
        "type": "object",
        "properties": {
            "user": {"type": "string"},
            "reset_email_sent": {"type": "boolean"},
        },
        "required": ["user", "reset_email_sent"],
        "additionalProperties": False,
    },
    tags=[_NEEDS_TENANT, "idp"],
)
async def idp_reset_password(*, tenant_id: str, user: str) -> dict[str, Any]:
    idp = await get_connector(tenant_id, ConnectorKind.IDP)
    return await idp.reset_password(user=user)


# ─── ITDR tools (Theme 2c) ────────────────────────────────────────────────
# Session-graph read + targeted-revoke + OAuth grant discovery. The session
# revoke is `WRITE_SIGNIFICANT` (no inverse: you can't un-revoke a token,
# you can only let the user sign back in). The grant revoke is
# `WRITE_SIGNIFICANT` for the same reason — re-granting consent is a *new*
# decision, not an undo.


@tool(
    name="idp.list_user_sessions",
    integration="okta",
    risk=RiskClass.READ,
    description=(
        "List active SSO/OAuth sessions for a user with device, IP, geo, "
        "MFA method, and AitM-suspicion signals. Used by the ITDR agent to "
        "build a session graph and spot adversary-in-the-middle takeovers."
    ),
    params={
        "type": "object",
        "properties": {"user": {"type": "string"}},
        "required": ["user"],
    },
    result={
        "type": "object",
        "properties": {
            "user": {"type": "string"},
            "sessions": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "string"},
                        "created_at": {"type": "string"},
                        "last_active": {"type": "string"},
                        "src_ip": {"type": "string"},
                        "country": {"type": "string"},
                        "asn": {"type": "string"},
                        "user_agent": {"type": "string"},
                        "device_id": {"type": "string"},
                        "device_trusted": {"type": "boolean"},
                        "mfa_method": {"type": "string"},
                        "aitm_suspected": {"type": "boolean"},
                        "anomaly_score": {"type": "number"},
                    },
                    "additionalProperties": True,
                },
            },
        },
        "required": ["user", "sessions"],
        "additionalProperties": False,
    },
    tags=[_NEEDS_TENANT, "idp", "itdr"],
)
async def idp_list_user_sessions(*, tenant_id: str, user: str) -> dict[str, Any]:
    idp = await get_connector(tenant_id, ConnectorKind.IDP)
    return await idp.list_user_sessions(user=user)


@tool(
    name="idp.revoke_session",
    integration="okta",
    # WRITE_SIGNIFICANT, not WRITE_REVERSIBLE: see module-level NOTE.
    # Targeted revoke is the *whole point* of ITDR — kill the AitM session
    # without taking the legit user offline. There is no inverse.
    risk=RiskClass.WRITE_SIGNIFICANT,
    forward_only_reason=(
        "the whole point of targeted session revoke is to kill an AitM / "
        "hijacked session; restoring that session token would re-grant the "
        "attacker access. There is no safe inverse"
    ),
    description=(
        "Revoke a single session by id. Used to surgically kill an "
        "AitM/hijacked session while leaving the user's other devices "
        "signed in. Pair with idp.list_user_sessions to find the target."
    ),
    params={
        "type": "object",
        "properties": {
            "user": {"type": "string"},
            "session_id": {"type": "string"},
            "reason": {"type": "string"},
        },
        "required": ["user", "session_id"],
    },
    result={
        "type": "object",
        "properties": {
            "user": {"type": "string"},
            "session_id": {"type": "string"},
            "revoked": {"type": "boolean"},
            "ticket": {"type": "string"},
        },
        "required": ["user", "session_id", "revoked"],
        "additionalProperties": False,
    },
    tags=[_NEEDS_TENANT, "containment", "itdr"],
)
async def idp_revoke_session(
    *,
    tenant_id: str,
    user: str,
    session_id: str,
    reason: str | None = None,
) -> dict[str, Any]:
    idp = await get_connector(tenant_id, ConnectorKind.IDP)
    return await idp.revoke_session(
        user=user, session_id=session_id, reason=reason
    )


@tool(
    name="idp.list_oauth_grants",
    integration="okta",
    risk=RiskClass.READ,
    description=(
        "List OAuth consent grants attached to a user (illicit-consent / "
        "third-party app abuse). Each grant carries scopes, publisher trust, "
        "last-used time, and a 0–1 heuristic risk score."
    ),
    params={
        "type": "object",
        "properties": {"user": {"type": "string"}},
        "required": ["user"],
    },
    result={
        "type": "object",
        "properties": {
            "user": {"type": "string"},
            "grants": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "grant_id": {"type": "string"},
                        "client_id": {"type": "string"},
                        "app_name": {"type": "string"},
                        "publisher": {"type": "string"},
                        "publisher_verified": {"type": "boolean"},
                        "scopes": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                        "granted_at": {"type": "string"},
                        "last_used": {"type": "string"},
                        "risk_score": {"type": "number"},
                    },
                    "additionalProperties": True,
                },
            },
        },
        "required": ["user", "grants"],
        "additionalProperties": False,
    },
    tags=[_NEEDS_TENANT, "idp", "itdr"],
)
async def idp_list_oauth_grants(*, tenant_id: str, user: str) -> dict[str, Any]:
    idp = await get_connector(tenant_id, ConnectorKind.IDP)
    return await idp.list_oauth_grants(user=user)


@tool(
    name="idp.revoke_oauth_grant",
    integration="okta",
    # WRITE_SIGNIFICANT, not WRITE_REVERSIBLE: once revoked, the consent
    # decision is gone. Re-granting requires the user (or admin) to walk
    # through the consent prompt again, which is a fresh approval, not an
    # undo. Rollback service refuses to reverse.
    risk=RiskClass.WRITE_SIGNIFICANT,
    forward_only_reason=(
        "re-granting an OAuth consent must come from the user (or admin) "
        "walking through the consent prompt again — a fresh approval with "
        "audit trail, not an automated undo of a security action"
    ),
    description=(
        "Revoke an OAuth consent grant. Kills the third-party app's "
        "long-lived access token chain. Used to evict illicit-consent apps "
        "from a compromised user account."
    ),
    params={
        "type": "object",
        "properties": {
            "user": {"type": "string"},
            "grant_id": {"type": "string"},
            "reason": {"type": "string"},
        },
        "required": ["user", "grant_id"],
    },
    result={
        "type": "object",
        "properties": {
            "user": {"type": "string"},
            "grant_id": {"type": "string"},
            "revoked": {"type": "boolean"},
            "ticket": {"type": "string"},
        },
        "required": ["user", "grant_id", "revoked"],
        "additionalProperties": False,
    },
    tags=[_NEEDS_TENANT, "containment", "itdr"],
)
async def idp_revoke_oauth_grant(
    *,
    tenant_id: str,
    user: str,
    grant_id: str,
    reason: str | None = None,
) -> dict[str, Any]:
    idp = await get_connector(tenant_id, ConnectorKind.IDP)
    return await idp.revoke_oauth_grant(
        user=user, grant_id=grant_id, reason=reason
    )


@tool(
    name="idp.list_oauth_apps",
    integration="okta",
    risk=RiskClass.READ,
    description=(
        "List third-party OAuth applications registered in the tenant with "
        "publisher info, scopes, install counts, and verification status. "
        "Used by ITDR to surface tenant-wide illicit-consent app exposure."
    ),
    params={
        "type": "object",
        "properties": {
            "limit": {"type": "integer", "minimum": 1, "maximum": 200}
        },
    },
    result={
        "type": "object",
        "properties": {
            "apps": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "client_id": {"type": "string"},
                        "name": {"type": "string"},
                        "publisher": {"type": "string"},
                        "publisher_verified": {"type": "boolean"},
                        "scopes": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                        "install_count": {"type": "integer"},
                    },
                    "additionalProperties": True,
                },
            },
        },
        "required": ["apps"],
        "additionalProperties": False,
    },
    tags=[_NEEDS_TENANT, "idp", "itdr"],
)
async def idp_list_oauth_apps(
    *, tenant_id: str, limit: int = 50
) -> dict[str, Any]:
    idp = await get_connector(tenant_id, ConnectorKind.IDP)
    return await idp.list_oauth_apps(limit=limit)
