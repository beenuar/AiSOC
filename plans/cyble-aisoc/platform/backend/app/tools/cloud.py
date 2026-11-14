"""Cloud control-plane tools (AWS today): IAM graph, STS chain, K8s RBAC, targeted revoke.

Thin wrappers over the connector SDK. Each tool resolves the per-tenant
cloud connector (AWS today; GCP/Azure on roadmap) via
:func:`app.connectors.get_connector` and delegates to the matching
protocol method on :class:`app.connectors.sdk.protocols.BaseCloudConnector`.

Powers the Cloud Detection & Response sub-agent (Theme 2d). The design
mirrors the ITDR tools (``app/tools/idp.py``) on purpose: read tools
enumerate the principal/session/RBAC graph, write tools are *surgical*
forward-only containment — deactivate one access key, attach an
explicit-deny policy to one principal, delete one suspicious RoleBinding.
We never expose "delete role" / "delete user" to the LLM — those have a
blast radius too large for an agent, even with HITL.

Tenancy
-------
Every handler is tagged with ``needs:tenant``. The agent base injects
``params["tenant_id"]`` from its own bound tenant before dispatch — the
LLM never sees ``tenant_id`` in the JSON schema and cannot spoof it.

Why no reverse pairs
--------------------
All three writes here are ``WRITE_SIGNIFICANT``, not ``WRITE_REVERSIBLE``:

  * ``cloud.deactivate_access_key`` — *technically* invertible (you can
    re-Activate) but in a real compromise the analyst must rotate, not
    reactivate. Forward-only at the tool layer; re-activation is a fresh
    HITL decision.
  * ``cloud.attach_deny_policy`` — the deny policy itself can be detached,
    but that's a forward un-quarantine decision, not an "undo". We avoid
    auto-rollback because forgetting to detach the deny would be safer
    than auto-detaching and letting the attacker back in.
  * ``cloud.delete_k8s_rolebinding`` — RoleBindings are GitOps-owned in
    every shop that takes K8s seriously; recreating from an in-memory
    snapshot would fight the GitOps reconciliation loop. Forward-only.
"""
from __future__ import annotations

from typing import Any

from app.connectors import ConnectorKind, get_connector
from app.tools.registry import RiskClass, tool


_NEEDS_TENANT = "needs:tenant"


# ─── IAM principal graph (read) ────────────────────────────────────────────


@tool(
    name="cloud.list_iam_principals",
    integration="aws",
    risk=RiskClass.READ,
    description=(
        "Enumerate IAM users and roles in the AWS account with attached "
        "policies, last-used timestamps, MFA state, and a heuristic risk "
        "score per principal. Used by the CDR agent to seed the cloud "
        "principal graph and spot abandoned credentials."
    ),
    params={
        "type": "object",
        "properties": {
            "limit": {"type": "integer", "minimum": 1, "maximum": 1000}
        },
    },
    result={
        "type": "object",
        "properties": {
            "principals": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "principal_id": {"type": "string"},
                        "principal_type": {"type": "string"},
                        "name": {"type": "string"},
                        "arn": {"type": "string"},
                        "created_at": {"type": "string"},
                        "last_used": {"type": "string"},
                        "mfa_enabled": {"type": "boolean"},
                        "attached_policies": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                        "risk_score": {"type": "number"},
                    },
                    "additionalProperties": True,
                },
            },
            "count": {"type": "integer"},
        },
        "required": ["principals"],
        "additionalProperties": False,
    },
    tags=[_NEEDS_TENANT, "cloud", "cdr"],
)
async def cloud_list_iam_principals(
    *, tenant_id: str, limit: int = 200
) -> dict[str, Any]:
    cloud = await get_connector(tenant_id, ConnectorKind.CLOUD)
    return await cloud.list_iam_principals(limit=limit)


@tool(
    name="cloud.get_iam_principal",
    integration="aws",
    risk=RiskClass.READ,
    description=(
        "Detailed view of one IAM principal: attached/inline policies, "
        "access keys, assume-role trust relationships (assumed_by / "
        "can_assume). The CDR agent uses can_assume to expand pivot paths."
    ),
    params={
        "type": "object",
        "properties": {"principal": {"type": "string"}},
        "required": ["principal"],
    },
    result={
        "type": "object",
        "properties": {
            "principal_id": {"type": "string"},
            "principal_type": {"type": "string"},
            "name": {"type": "string"},
            "arn": {"type": "string"},
            "attached_policies": {
                "type": "array",
                "items": {"type": "string"},
            },
            "inline_policies": {
                "type": "array",
                "items": {"type": "string"},
            },
            "access_keys": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "key_id": {"type": "string"},
                        "status": {"type": "string"},
                        "created_at": {"type": "string"},
                        "last_used": {"type": "string"},
                    },
                    "additionalProperties": True,
                },
            },
            "assumed_by": {"type": "array", "items": {"type": "string"}},
            "can_assume": {"type": "array", "items": {"type": "string"}},
        },
        "required": ["arn"],
        "additionalProperties": True,
    },
    tags=[_NEEDS_TENANT, "cloud", "cdr"],
)
async def cloud_get_iam_principal(
    *, tenant_id: str, principal: str
) -> dict[str, Any]:
    cloud = await get_connector(tenant_id, ConnectorKind.CLOUD)
    return await cloud.get_iam_principal(principal=principal)


@tool(
    name="cloud.list_access_keys",
    integration="aws",
    risk=RiskClass.READ,
    description=(
        "List IAM access keys for one user with status, last-used "
        "service/region, and a per-key anomaly score. Used to identify "
        "abandoned credentials and target the deactivation surgery."
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
            "keys": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "key_id": {"type": "string"},
                        "status": {"type": "string"},
                        "created_at": {"type": "string"},
                        "last_used": {"type": "string"},
                        "last_used_service": {"type": "string"},
                        "last_used_region": {"type": "string"},
                        "anomaly_score": {"type": "number"},
                    },
                    "additionalProperties": True,
                },
            },
        },
        "required": ["user", "keys"],
        "additionalProperties": False,
    },
    tags=[_NEEDS_TENANT, "cloud", "cdr"],
)
async def cloud_list_access_keys(
    *, tenant_id: str, user: str
) -> dict[str, Any]:
    cloud = await get_connector(tenant_id, ConnectorKind.CLOUD)
    return await cloud.list_access_keys(user=user)


# ─── STS / session graph (read) ────────────────────────────────────────────


@tool(
    name="cloud.list_sts_sessions",
    integration="aws",
    risk=RiskClass.READ,
    description=(
        "List recent STS AssumeRole sessions across the account (or "
        "filtered to one principal). Each row carries chain depth, source "
        "IP/ASN/country, MFA-used flag, and an anomaly score — the inputs "
        "the CDR agent fuses to detect assume-role-chain abuse."
    ),
    params={
        "type": "object",
        "properties": {
            "principal": {"type": "string"},
            "hours": {"type": "integer", "minimum": 1, "maximum": 168},
        },
    },
    result={
        "type": "object",
        "properties": {
            "sessions": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "string"},
                        "started_at": {"type": "string"},
                        "source_principal": {"type": "string"},
                        "assumed_role": {"type": "string"},
                        "source_ip": {"type": "string"},
                        "country": {"type": "string"},
                        "asn": {"type": "string"},
                        "user_agent": {"type": "string"},
                        "mfa_used": {"type": "boolean"},
                        "chain_depth": {"type": "integer"},
                        "anomaly_score": {"type": "number"},
                    },
                    "additionalProperties": True,
                },
            },
            "count": {"type": "integer"},
        },
        "required": ["sessions"],
        "additionalProperties": False,
    },
    tags=[_NEEDS_TENANT, "cloud", "cdr"],
)
async def cloud_list_sts_sessions(
    *,
    tenant_id: str,
    principal: str | None = None,
    hours: int = 24,
) -> dict[str, Any]:
    cloud = await get_connector(tenant_id, ConnectorKind.CLOUD)
    return await cloud.list_sts_sessions(principal=principal, hours=hours)


@tool(
    name="cloud.trace_assume_role_chain",
    integration="aws",
    risk=RiskClass.READ,
    description=(
        "Walk an STS AssumeRole chain back to its origin principal and "
        "surface why each hop is (or isn't) suspicious. Use on the "
        "highest-anomaly session from cloud.list_sts_sessions."
    ),
    params={
        "type": "object",
        "properties": {"session_id": {"type": "string"}},
        "required": ["session_id"],
    },
    result={
        "type": "object",
        "properties": {
            "session_id": {"type": "string"},
            "chain": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "principal_arn": {"type": "string"},
                        "action": {"type": "string"},
                        "ts": {"type": "string"},
                    },
                    "additionalProperties": True,
                },
            },
            "origin_principal": {"type": ["string", "null"]},
            "depth": {"type": "integer"},
            "suspicious": {"type": "boolean"},
            "reasons": {"type": "array", "items": {"type": "string"}},
        },
        "required": ["session_id", "chain", "depth", "suspicious"],
        "additionalProperties": False,
    },
    tags=[_NEEDS_TENANT, "cloud", "cdr"],
)
async def cloud_trace_assume_role_chain(
    *, tenant_id: str, session_id: str
) -> dict[str, Any]:
    cloud = await get_connector(tenant_id, ConnectorKind.CLOUD)
    return await cloud.trace_assume_role_chain(session_id=session_id)


# ─── Kubernetes RBAC (read) ────────────────────────────────────────────────


@tool(
    name="cloud.list_k8s_rolebindings",
    integration="aws",
    risk=RiskClass.READ,
    description=(
        "List Kubernetes RoleBindings and ClusterRoleBindings, optionally "
        "filtered to one namespace. Each row carries a risk score and "
        "reason strings (e.g. 'default ServiceAccount bound to "
        "cluster-admin', 'created <5min ago, outside change window')."
    ),
    params={
        "type": "object",
        "properties": {"namespace": {"type": "string"}},
    },
    result={
        "type": "object",
        "properties": {
            "bindings": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "namespace": {"type": ["string", "null"]},
                        "kind": {"type": "string"},
                        "role_ref": {"type": "string"},
                        "subjects": {
                            "type": "array",
                            "items": {"type": "object"},
                        },
                        "created_at": {"type": "string"},
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
        "required": ["bindings"],
        "additionalProperties": False,
    },
    tags=[_NEEDS_TENANT, "cloud", "cdr"],
)
async def cloud_list_k8s_rolebindings(
    *, tenant_id: str, namespace: str | None = None
) -> dict[str, Any]:
    cloud = await get_connector(tenant_id, ConnectorKind.CLOUD)
    return await cloud.list_k8s_rolebindings(namespace=namespace)


# ─── Targeted containment (write, no inverse) ─────────────────────────────


@tool(
    name="cloud.deactivate_access_key",
    integration="aws",
    # WRITE_SIGNIFICANT, not WRITE_REVERSIBLE: technically you can flip
    # status back to Active, but in a compromise the right move is to
    # rotate the key, not reactivate it. We leave reactivation as a fresh
    # HITL decision (a new approved forward action) — the rollback
    # service deliberately won't auto-reactivate.
    risk=RiskClass.WRITE_SIGNIFICANT,
    forward_only_reason=(
        "auto-reactivating a deactivated access key after a suspected "
        "compromise would silently restore attacker access; the correct "
        "recovery is rotation via a fresh HITL-approved decision, not undo"
    ),
    description=(
        "Set a single IAM access key to Inactive. Surgical containment — "
        "kills the leaked key without touching the user's console "
        "password, other keys, or attached roles. Forward-only."
    ),
    params={
        "type": "object",
        "properties": {
            "user": {"type": "string"},
            "key_id": {"type": "string"},
            "reason": {"type": "string"},
        },
        "required": ["user", "key_id"],
    },
    result={
        "type": "object",
        "properties": {
            "user": {"type": "string"},
            "key_id": {"type": "string"},
            "deactivated": {"type": "boolean"},
            "ticket": {"type": "string"},
        },
        "required": ["user", "key_id", "deactivated"],
        "additionalProperties": False,
    },
    tags=[_NEEDS_TENANT, "containment", "cdr"],
)
async def cloud_deactivate_access_key(
    *,
    tenant_id: str,
    user: str,
    key_id: str,
    reason: str | None = None,
) -> dict[str, Any]:
    cloud = await get_connector(tenant_id, ConnectorKind.CLOUD)
    return await cloud.deactivate_access_key(
        user=user, key_id=key_id, reason=reason
    )


@tool(
    name="cloud.attach_deny_policy",
    integration="aws",
    # WRITE_SIGNIFICANT: detachable in principle, but auto-detaching the
    # quarantine policy would silently let the attacker back in. Treat
    # un-quarantine as a fresh forward decision, not an undo.
    risk=RiskClass.WRITE_SIGNIFICANT,
    forward_only_reason=(
        "auto-detaching the quarantine Deny policy would silently restore "
        "the attacker's effective permissions; un-quarantine must be a "
        "fresh HITL-approved decision, not an automatic rollback"
    ),
    description=(
        "Attach an explicit-Deny-* policy to a single IAM principal. "
        "Canonical 'freeze this identity' containment — explicit deny "
        "beats every other allow, halting the principal without deleting "
        "it (preserves forensic state). Use when we can't identify which "
        "specific credential is in the attacker's hand."
    ),
    params={
        "type": "object",
        "properties": {
            "principal": {"type": "string"},
            "reason": {"type": "string"},
        },
        "required": ["principal"],
    },
    result={
        "type": "object",
        "properties": {
            "principal": {"type": "string"},
            "policy_arn": {"type": "string"},
            "attached": {"type": "boolean"},
            "ticket": {"type": "string"},
        },
        "required": ["principal", "attached"],
        "additionalProperties": False,
    },
    tags=[_NEEDS_TENANT, "containment", "cdr"],
)
async def cloud_attach_deny_policy(
    *,
    tenant_id: str,
    principal: str,
    reason: str | None = None,
) -> dict[str, Any]:
    cloud = await get_connector(tenant_id, ConnectorKind.CLOUD)
    return await cloud.attach_deny_policy(principal=principal, reason=reason)


@tool(
    name="cloud.delete_k8s_rolebinding",
    integration="aws",
    # WRITE_SIGNIFICANT: in real shops bindings are GitOps-owned and
    # recreating from an in-memory snapshot would fight reconciliation.
    # Forward-only — operators must re-apply from source if needed.
    risk=RiskClass.WRITE_SIGNIFICANT,
    forward_only_reason=(
        "RoleBindings are GitOps-owned in well-run shops; auto-recreating "
        "from an in-memory snapshot would fight reconciliation and re-grant "
        "permissions outside the source-of-truth. Recreation must come from "
        "the GitOps source, not from a rollback handler"
    ),
    description=(
        "Delete a single suspicious RoleBinding or ClusterRoleBinding. "
        "Forward-only — operators must re-create from GitOps if the "
        "decision is reversed."
    ),
    params={
        "type": "object",
        "properties": {
            "name": {"type": "string"},
            "namespace": {"type": "string"},
            "reason": {"type": "string"},
        },
        "required": ["name"],
    },
    result={
        "type": "object",
        "properties": {
            "name": {"type": "string"},
            "namespace": {"type": ["string", "null"]},
            "kind": {"type": "string"},
            "deleted": {"type": "boolean"},
            "ticket": {"type": "string"},
        },
        "required": ["name", "deleted"],
        "additionalProperties": False,
    },
    tags=[_NEEDS_TENANT, "containment", "cdr"],
)
async def cloud_delete_k8s_rolebinding(
    *,
    tenant_id: str,
    name: str,
    namespace: str | None = None,
    reason: str | None = None,
) -> dict[str, Any]:
    cloud = await get_connector(tenant_id, ConnectorKind.CLOUD)
    return await cloud.delete_k8s_rolebinding(
        name=name, namespace=namespace, reason=reason
    )
