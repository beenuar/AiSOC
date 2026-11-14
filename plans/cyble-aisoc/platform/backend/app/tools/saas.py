"""SaaS Security Posture (SSPM) tools: app inventory, public shares, third-party grants, targeted revoke.

Thin wrappers over the connector SDK. Each tool resolves the per-tenant
SaaS connector via :func:`app.connectors.get_connector` and delegates to
the matching protocol method on
:class:`app.connectors.sdk.protocols.BaseSaaSConnector`.

Powers the SaaS Posture sub-agent (Theme 2e). One ``ConnectorKind.SAAS``
connector multiplexes across all five v1 providers — M365, Google
Workspace, Salesforce, GitHub, Slack — by passing a ``provider`` arg on
each call. The single-kind model keeps tool count flat as we add
providers; the connector implementation owns the per-vendor SDKs.

Tenancy
-------
Every handler is tagged with ``needs:tenant``. The agent base injects
``params["tenant_id"]`` from its own bound tenant before dispatch — the
LLM never sees ``tenant_id`` in the JSON schema and cannot spoof it.

Why no reverse pairs
--------------------
All three writes here are ``WRITE_SIGNIFICANT``:

  * ``saas.revoke_third_party_integration`` — re-granting an OAuth app
    requires the original user to consent again. A "re-grant" tool would
    be a phishing primitive. Forward-only.
  * ``saas.restrict_external_share`` — the link-share scope can be
    widened again, but that's a fresh sharing decision; auto-rollback
    would re-expose data we just hid. Forward-only.
  * ``saas.remove_external_collaborator`` — re-inviting is a fresh
    decision and requires the external party to re-accept. Forward-only.
"""
from __future__ import annotations

from typing import Any

from app.connectors import ConnectorKind, get_connector
from app.tools.registry import RiskClass, tool


_NEEDS_TENANT = "needs:tenant"

# Providers the v1 SSPM connector knows how to talk to. Surfaced on the
# JSON schema as an enum so the LLM can't invent a provider name and
# crash the connector with a 404.
_SAAS_PROVIDERS = ["m365", "workspace", "salesforce", "github", "slack"]


# ─── Application & integration inventory (read) ──────────────────────────


@tool(
    name="saas.list_applications",
    integration="saas",
    risk=RiskClass.READ,
    description=(
        "Enumerate installed SaaS applications across one or all v1 SSPM "
        "providers (M365, Workspace, Salesforce, GitHub, Slack). Each row "
        "carries publisher-verified status, granted scopes, install user "
        "count, and a heuristic risk score. Used by the SaaS Posture "
        "agent to seed the third-party-app graph."
    ),
    params={
        "type": "object",
        "properties": {
            "provider": {"type": "string", "enum": _SAAS_PROVIDERS},
        },
    },
    result={
        "type": "object",
        "properties": {
            "applications": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "app_id": {"type": "string"},
                        "provider": {"type": "string"},
                        "name": {"type": "string"},
                        "vendor": {"type": "string"},
                        "installed_at": {"type": "string"},
                        "scopes": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                        "install_user_count": {"type": "integer"},
                        "publisher_verified": {"type": "boolean"},
                        "risk_score": {"type": "number"},
                        "reasons": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                    },
                    "additionalProperties": True,
                },
            },
            "count": {"type": "integer"},
        },
        "required": ["applications"],
        "additionalProperties": False,
    },
    tags=[_NEEDS_TENANT, "saas", "sspm"],
)
async def saas_list_applications(
    *, tenant_id: str, provider: str | None = None
) -> dict[str, Any]:
    saas = await get_connector(tenant_id, ConnectorKind.SAAS)
    return await saas.list_applications(provider=provider)


@tool(
    name="saas.list_misconfigurations",
    integration="saas",
    risk=RiskClass.READ,
    description=(
        "List CIS-style posture findings (auth policies, sharing defaults, "
        "admin MFA, branch protection, etc.) across the configured SaaS "
        "providers. Each finding includes current vs recommended value, "
        "severity, and a remediation hint. Used by the agent to prioritise "
        "what to flag in the case file vs what to action immediately."
    ),
    params={
        "type": "object",
        "properties": {
            "provider": {"type": "string", "enum": _SAAS_PROVIDERS},
        },
    },
    result={
        "type": "object",
        "properties": {
            "findings": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "provider": {"type": "string"},
                        "control_id": {"type": "string"},
                        "control_name": {"type": "string"},
                        "severity": {"type": "string"},
                        "current_value": {"type": "string"},
                        "recommended_value": {"type": "string"},
                        "evidence_url": {"type": "string"},
                        "last_checked": {"type": "string"},
                        "remediation_hint": {"type": "string"},
                    },
                    "additionalProperties": True,
                },
            },
            "count": {"type": "integer"},
        },
        "required": ["findings"],
        "additionalProperties": False,
    },
    tags=[_NEEDS_TENANT, "saas", "sspm"],
)
async def saas_list_misconfigurations(
    *, tenant_id: str, provider: str | None = None
) -> dict[str, Any]:
    saas = await get_connector(tenant_id, ConnectorKind.SAAS)
    return await saas.list_misconfigurations(provider=provider)


@tool(
    name="saas.list_external_shares",
    integration="saas",
    risk=RiskClass.READ,
    description=(
        "Enumerate resources shared publicly or with external principals "
        "(OneDrive/SharePoint files, Drive folders, Salesforce reports, "
        "public GitHub repos, Slack channels with external guests). Each "
        "row carries the share scope, sensitivity heuristics, and a risk "
        "score. The agent uses this to find data-exposure incidents that "
        "no detection rule fires on."
    ),
    params={
        "type": "object",
        "properties": {
            "provider": {"type": "string", "enum": _SAAS_PROVIDERS},
            "limit": {"type": "integer", "minimum": 1, "maximum": 1000},
        },
    },
    result={
        "type": "object",
        "properties": {
            "shares": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "share_id": {"type": "string"},
                        "provider": {"type": "string"},
                        "resource_type": {"type": "string"},
                        "resource_name": {"type": "string"},
                        "resource_url": {"type": "string"},
                        "shared_with": {"type": "string"},
                        "external_principals": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                        "created_at": {"type": "string"},
                        "last_accessed": {"type": "string"},
                        "contains_sensitive": {"type": "boolean"},
                        "risk_score": {"type": "number"},
                        "reasons": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                    },
                    "additionalProperties": True,
                },
            },
            "count": {"type": "integer"},
        },
        "required": ["shares"],
        "additionalProperties": False,
    },
    tags=[_NEEDS_TENANT, "saas", "sspm"],
)
async def saas_list_external_shares(
    *, tenant_id: str, provider: str | None = None, limit: int = 200
) -> dict[str, Any]:
    saas = await get_connector(tenant_id, ConnectorKind.SAAS)
    return await saas.list_external_shares(provider=provider, limit=limit)


@tool(
    name="saas.list_third_party_integrations",
    integration="saas",
    risk=RiskClass.READ,
    description=(
        "Enumerate active OAuth grants and third-party integrations across "
        "providers. Each grant includes scopes, granting user, last-used "
        "time, publisher-verified state, and a risk score. This is the "
        "illicit-consent / OAuth-abuse signal — the read counterpart of "
        "saas.revoke_third_party_integration."
    ),
    params={
        "type": "object",
        "properties": {
            "provider": {"type": "string", "enum": _SAAS_PROVIDERS},
        },
    },
    result={
        "type": "object",
        "properties": {
            "integrations": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "grant_id": {"type": "string"},
                        "provider": {"type": "string"},
                        "app_id": {"type": "string"},
                        "app_name": {"type": "string"},
                        "publisher": {"type": "string"},
                        "publisher_verified": {"type": "boolean"},
                        "scopes": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                        "granted_by_user": {"type": "string"},
                        "granted_at": {"type": "string"},
                        "last_used": {"type": "string"},
                        "total_users_granted": {"type": "integer"},
                        "risk_score": {"type": "number"},
                        "reasons": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                    },
                    "additionalProperties": True,
                },
            },
            "count": {"type": "integer"},
        },
        "required": ["integrations"],
        "additionalProperties": False,
    },
    tags=[_NEEDS_TENANT, "saas", "sspm"],
)
async def saas_list_third_party_integrations(
    *, tenant_id: str, provider: str | None = None
) -> dict[str, Any]:
    saas = await get_connector(tenant_id, ConnectorKind.SAAS)
    return await saas.list_third_party_integrations(provider=provider)


# ─── Containment (write, significant) ────────────────────────────────────


@tool(
    name="saas.revoke_third_party_integration",
    integration="saas",
    risk=RiskClass.WRITE_SIGNIFICANT,
    forward_only_reason=(
        "re-granting an OAuth integration requires fresh user consent; "
        "auto-reactivating a revoked third-party app would bypass that "
        "consent boundary"
    ),
    description=(
        "Revoke a single third-party OAuth grant / installed SaaS app. "
        "Surgical: kills only the named grant, leaves the user's account "
        "and other apps untouched. Forward-only — re-granting requires "
        "fresh user consent."
    ),
    params={
        "type": "object",
        "properties": {
            "provider": {"type": "string", "enum": _SAAS_PROVIDERS},
            "grant_id": {"type": "string"},
            "reason": {"type": "string"},
        },
        "required": ["provider", "grant_id"],
    },
    result={
        "type": "object",
        "properties": {
            "provider": {"type": "string"},
            "grant_id": {"type": "string"},
            "revoked": {"type": "boolean"},
            "reason": {"type": "string"},
            "ticket": {"type": "string"},
        },
        "required": ["provider", "grant_id", "revoked"],
        "additionalProperties": False,
    },
    tags=[_NEEDS_TENANT, "containment", "saas", "sspm"],
)
async def saas_revoke_third_party_integration(
    *,
    tenant_id: str,
    provider: str,
    grant_id: str,
    reason: str | None = None,
) -> dict[str, Any]:
    saas = await get_connector(tenant_id, ConnectorKind.SAAS)
    return await saas.revoke_third_party_integration(
        provider=provider, grant_id=grant_id, reason=reason
    )


@tool(
    name="saas.restrict_external_share",
    integration="saas",
    risk=RiskClass.WRITE_SIGNIFICANT,
    forward_only_reason=(
        "re-widening a share scope is a fresh sharing decision the data "
        "owner must make explicitly; auto-reverting would silently re-expose "
        "data the responder just decided was over-shared"
    ),
    description=(
        "Restrict the sharing scope on a single resource (file, folder, "
        "report, repo, channel) to internal-only. Surgical: touches only "
        "the named share_id; doesn't change tenant-wide sharing defaults. "
        "Forward-only — re-widening is a fresh sharing decision."
    ),
    params={
        "type": "object",
        "properties": {
            "provider": {"type": "string", "enum": _SAAS_PROVIDERS},
            "share_id": {"type": "string"},
            "reason": {"type": "string"},
        },
        "required": ["provider", "share_id"],
    },
    result={
        "type": "object",
        "properties": {
            "provider": {"type": "string"},
            "share_id": {"type": "string"},
            "restricted": {"type": "boolean"},
            "new_scope": {"type": "string"},
            "reason": {"type": "string"},
            "ticket": {"type": "string"},
        },
        "required": ["provider", "share_id", "restricted"],
        "additionalProperties": False,
    },
    tags=[_NEEDS_TENANT, "containment", "saas", "sspm"],
)
async def saas_restrict_external_share(
    *,
    tenant_id: str,
    provider: str,
    share_id: str,
    reason: str | None = None,
) -> dict[str, Any]:
    saas = await get_connector(tenant_id, ConnectorKind.SAAS)
    return await saas.restrict_external_share(
        provider=provider, share_id=share_id, reason=reason
    )


@tool(
    name="saas.remove_external_collaborator",
    integration="saas",
    risk=RiskClass.WRITE_SIGNIFICANT,
    forward_only_reason=(
        "re-inviting an external collaborator requires them to re-accept; "
        "we cannot synthesize their acceptance, so rollback is not "
        "technically possible — re-grant must be a fresh decision"
    ),
    description=(
        "Remove one external principal from a single SaaS resource "
        "(channel guest, repo outside collaborator, Salesforce community "
        "user, shared file recipient). Surgical: only the named principal "
        "on the named resource. Forward-only — re-inviting requires the "
        "external party to re-accept."
    ),
    params={
        "type": "object",
        "properties": {
            "provider": {"type": "string", "enum": _SAAS_PROVIDERS},
            "resource_id": {"type": "string"},
            "external_principal": {"type": "string"},
            "reason": {"type": "string"},
        },
        "required": ["provider", "resource_id", "external_principal"],
    },
    result={
        "type": "object",
        "properties": {
            "provider": {"type": "string"},
            "resource_id": {"type": "string"},
            "external_principal": {"type": "string"},
            "removed": {"type": "boolean"},
            "reason": {"type": "string"},
            "ticket": {"type": "string"},
        },
        "required": [
            "provider",
            "resource_id",
            "external_principal",
            "removed",
        ],
        "additionalProperties": False,
    },
    tags=[_NEEDS_TENANT, "containment", "saas", "sspm"],
)
async def saas_remove_external_collaborator(
    *,
    tenant_id: str,
    provider: str,
    resource_id: str,
    external_principal: str,
    reason: str | None = None,
) -> dict[str, Any]:
    saas = await get_connector(tenant_id, ConnectorKind.SAAS)
    return await saas.remove_external_collaborator(
        provider=provider,
        resource_id=resource_id,
        external_principal=external_principal,
        reason=reason,
    )


__all__ = [
    "saas_list_applications",
    "saas_list_external_shares",
    "saas_list_misconfigurations",
    "saas_list_third_party_integrations",
    "saas_remove_external_collaborator",
    "saas_restrict_external_share",
    "saas_revoke_third_party_integration",
]
