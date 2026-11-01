"""Privilege tier and the four computed tags, derived from effective permissions.

Depth plan wave 2, Phase 1.1 (carrying the first depth plan's 2.6).

The gap this closes
-------------------
Six resolvers answer "what can this principal do" and nothing asked them.
A tier is a resolver answer compressed to the one thing a queue, a scorer and
a prompt can all use, and the four tags are the questions an analyst actually
asks of an identity during an incident:

``can_escalate``
    Can it grant itself or anyone else more access — directly, or by editing
    a role or trust policy it can reach? This is the tag that turns a
    middling alert into an incident, because an identity that can escalate
    makes every other permission a lower bound.
``data_access``
    Can it read a resource the tenant tagged sensitive?
``third_party``
    Is it external or vendor-owned — a guest, an outside collaborator, an
    OAuth app, a cross-tenant service principal?
``cross_account``
    Does it reach another account, project, subscription or organisation?

Three rules the rest of the module exists to keep
-------------------------------------------------
1. **Unknown is a value.** No snapshot covering the time means ``tier =
   "unknown"`` and all four tags ``None``. Not ``standard``, not ``False``.
   A default tier makes a measured standard account and an unmeasured one
   identical, and the unmeasured one is the one worth looking at.
2. **Every tag carries its evidence.** A tag with no matching action is a
   label; a tag with the actions that produced it is a finding.
3. **The derivation is pure.** It takes a :class:`ResolverResult` and
   returns facts. The store, the lake and the API are elsewhere, so this can
   be tested against a fixture snapshot with no database.
"""

from __future__ import annotations

import fnmatch
from dataclasses import asdict, dataclass, field
from typing import Any, Literal

from app.services.effective_permissions.base import ResolverResult

__all__ = [
    "ESCALATION_ACTIONS",
    "TIER_ORDER",
    "UNKNOWN_PRIVILEGE",
    "IdentityPrivilege",
    "PrivilegeTags",
    "Tier",
    "derive_privilege",
    "tier_at_least",
]

Tier = Literal["unknown", "standard", "elevated", "admin", "domain_admin"]

#: Ordered weakest to strongest. ``unknown`` sorts below ``standard`` so a
#: naive comparison cannot accidentally treat it as privileged, while every
#: surface still has to render it as its own state.
TIER_ORDER: tuple[Tier, ...] = ("unknown", "standard", "elevated", "admin", "domain_admin")


def tier_at_least(tier: str, floor: Tier) -> bool:
    """``True`` when ``tier`` is at or above ``floor`` on :data:`TIER_ORDER`.

    ``unknown`` is never "at least" anything above itself, so a caller
    gating on ``admin`` does not silently include identities nobody measured.
    """
    try:
        return TIER_ORDER.index(tier) >= TIER_ORDER.index(floor)  # type: ignore[arg-type]
    except ValueError:
        return False


#: Action patterns that let a principal grant access. Provider-namespaced and
#: matched with shell globbing against the resolver's own action strings, so
#: the same table serves all six providers.
#:
#: Every entry is an action that writes an *authorization* object. Actions
#: that merely read one are deliberately absent: `iam:GetRole` tells an
#: attacker where to go and grants nothing, and tagging it `can_escalate`
#: would put the tag on most of the estate, at which point nobody reads it.
ESCALATION_ACTIONS: tuple[str, ...] = (
    # AWS
    "iam:Attach*Policy",
    "iam:Put*Policy",
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "iam:UpdateAssumeRolePolicy",
    "iam:CreateAccessKey",
    "iam:CreateLoginProfile",
    "iam:UpdateLoginProfile",
    "iam:AddUserToGroup",
    "iam:CreateRole",
    "iam:CreateUser",
    "iam:PassRole",
    "sts:AssumeRole",
    "organizations:*Policy",
    # Azure / Entra
    "Microsoft.Authorization/roleAssignments/write",
    "Microsoft.Authorization/roleDefinitions/write",
    "microsoft.directory/roleAssignments/*",
    "microsoft.directory/users/password/update",
    "microsoft.directory/servicePrincipals/credentials/update",
    "microsoft.directory/applications/credentials/update",
    # GCP
    "resourcemanager.projects.setIamPolicy",
    "resourcemanager.organizations.setIamPolicy",
    "resourcemanager.folders.setIamPolicy",
    "iam.roles.create",
    "iam.roles.update",
    "iam.serviceAccounts.actAs",
    "iam.serviceAccounts.getAccessToken",
    "iam.serviceAccountKeys.create",
    # Okta
    "okta.roles.manage",
    "okta.users.manage",
    "okta.groups.manage",
    "okta.apps.manage",
    # Google Workspace
    "admin.roles.manage",
    "admin.users.update",
    "admin.users.create",
    # GitHub
    "admin:org",
    "write:org",
    "repo:admin",
    "admin:repo_hook",
    "manage_runners:org",
)

#: Action patterns that read data. Tagged ``data_access`` only when the
#: resource they land on is marked sensitive, because "can read an object" on
#: its own describes most identities in a cloud estate.
_DATA_READ_ACTIONS: tuple[str, ...] = (
    "s3:Get*",
    "s3:List*",
    "dynamodb:GetItem",
    "dynamodb:Scan",
    "dynamodb:Query",
    "secretsmanager:GetSecretValue",
    "ssm:GetParameter*",
    "kms:Decrypt",
    "rds:DownloadDBLogFilePortion",
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
    "Microsoft.KeyVault/vaults/secrets/read",
    "storage.objects.get",
    "storage.objects.list",
    "bigquery.tables.getData",
    "secretmanager.versions.access",
    "drive.files.read",
    "gmail.messages.read",
    "repo",
    "read:packages",
)

#: Resource kinds and tag values that mean "the tenant called this sensitive".
_SENSITIVE_MARKERS: frozenset[str] = frozenset(
    {"sensitive", "restricted", "confidential", "pii", "phi", "pci", "regulated", "crown-jewel"}
)

#: Tier floors by how much of the estate's authorization surface a principal
#: can write. Derived from what the identity can *do*, never from the name of
#: the role it holds -- a role called "ReadOnly" that can call
#: `iam:PutUserPolicy` is an admin, and the name is the part an attacker
#: controls when they create it.
_ADMIN_WILDCARDS: tuple[str, ...] = ("*", "*:*", "iam:*", "Microsoft.Authorization/*", "resourcemanager.*")


@dataclass(frozen=True)
class PrivilegeTags:
    """The four computed tags. ``None`` is "no snapshot could answer"."""

    can_escalate: bool | None = None
    data_access: bool | None = None
    third_party: bool | None = None
    cross_account: bool | None = None

    def as_dict(self) -> dict[str, bool | None]:
        return asdict(self)

    def set_tags(self) -> list[str]:
        """The tag names that are ``True``, for a prompt or a chip row."""
        return [name for name, value in asdict(self).items() if value is True]


@dataclass(frozen=True)
class IdentityPrivilege:
    """One identity's tier, tags and the evidence for each."""

    tier: Tier = "unknown"
    tags: PrivilegeTags = field(default_factory=PrivilegeTags)
    provider: str = ""
    principal_id: str = ""
    #: ``{tag_name: [action, ...]}`` plus ``"tier"`` -> the actions that set it.
    evidence: dict[str, list[str]] = field(default_factory=dict)
    action_count: int = 0
    resource_count: int = 0
    #: Set when the snapshot the facts came from was itself incomplete.
    partial_source: bool = False
    #: Carried from the resolver so a surface can say what was not modelled.
    notes: list[str] = field(default_factory=list)

    @property
    def measured(self) -> bool:
        """``False`` when no snapshot covered the question."""
        return self.tier != "unknown" or self.action_count > 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "tier": self.tier,
            "tags": self.tags.as_dict(),
            "provider": self.provider,
            "principal_id": self.principal_id,
            "evidence": {k: list(v) for k, v in self.evidence.items()},
            "action_count": self.action_count,
            "resource_count": self.resource_count,
            "partial_source": self.partial_source,
            "measured": self.measured,
            "notes": list(self.notes),
        }


#: The singleton every caller returns when no snapshot covers the time. A
#: module-level constant rather than a fresh `IdentityPrivilege()` per call
#: site, so "is this unknown" is one identity comparison and a reviewer can
#: grep for every place that gives up.
UNKNOWN_PRIVILEGE = IdentityPrivilege()


def _matches_any(action: str, patterns: tuple[str, ...]) -> bool:
    return any(fnmatch.fnmatchcase(action, pattern) for pattern in patterns)


def _is_sensitive(decision: Any) -> bool:
    """Does this decision land on something the tenant marked sensitive?"""
    kind = str(getattr(decision, "resource_kind", "") or "").lower()
    arn = str(getattr(decision, "resource_arn", "") or "").lower()
    rid = str(getattr(decision, "resource_id", "") or "").lower()
    haystack = f"{kind} {arn} {rid}"
    return any(marker in haystack for marker in _SENSITIVE_MARKERS)


def _account_of(arn_or_id: str) -> str:
    """The account / project / subscription an identifier belongs to.

    Six providers spell this six ways, so the parse is deliberately shallow:
    an AWS ARN's fifth colon-separated field, and otherwise the first path
    segment of a GCP-style ``projects/x/...`` or Azure-style
    ``/subscriptions/x/...`` identifier. Anything else returns ``""``, which
    reads as "cannot tell" and never as "same account".
    """
    value = (arn_or_id or "").strip()
    if value.startswith("arn:"):
        parts = value.split(":")
        return parts[4] if len(parts) > 4 else ""
    lowered = value.lower().lstrip("/")
    for prefix in ("subscriptions/", "projects/", "organizations/", "folders/"):
        if lowered.startswith(prefix):
            rest = lowered[len(prefix) :]
            return rest.split("/", 1)[0]
    return ""


def derive_privilege(
    result: ResolverResult,
    *,
    principal_account: str | None = None,
    external_domains: frozenset[str] | None = None,
    principal_kind: str | None = None,
    partial_source: bool = False,
) -> IdentityPrivilege:
    """Compress a resolver answer into a tier, four tags and their evidence.

    Pure. ``result`` is whatever :func:`resolve_effective_permissions`
    returned; everything else is optional context the caller already has.

    A resolver result with no decisions returns :data:`UNKNOWN_PRIVILEGE`
    rather than ``standard`` with four ``False`` tags, because "the resolver
    found nothing" and "this identity can do nothing" are different claims
    and only one of them is safe to act on.
    """
    decisions = list(result.decisions or ())
    if not decisions:
        return IdentityPrivilege(
            provider=result.provider,
            principal_id=result.principal_id,
            partial_source=partial_source,
            notes=list(result.notes or ()),
        )

    all_actions: set[str] = set()
    escalation_evidence: set[str] = set()
    data_evidence: set[str] = set()
    cross_account_evidence: set[str] = set()
    admin_evidence: set[str] = set()

    home_account = (principal_account or _account_of(result.principal_id) or "").lower()

    for decision in decisions:
        actions = tuple(decision.actions)
        all_actions.update(actions)

        for action in actions:
            if _matches_any(action, ESCALATION_ACTIONS):
                escalation_evidence.add(action)
            if _matches_any(action, _ADMIN_WILDCARDS):
                admin_evidence.add(action)

        if _is_sensitive(decision):
            data_evidence.update(a for a in actions if _matches_any(a, _DATA_READ_ACTIONS))

        resource_account = _account_of(str(decision.resource_arn or decision.resource_id or "")).lower()
        if home_account and resource_account and resource_account != home_account:
            cross_account_evidence.add(str(decision.resource_arn or decision.resource_id))

    # `sts:AssumeRole` onto a role in another account is the canonical
    # cross-account reach and does not show up as a differing resource
    # account unless the role itself is in the snapshot's resource list.
    for action in all_actions:
        if action.startswith("sts:AssumeRole") and home_account:
            cross_account_evidence.add(action)

    tier = _derive_tier(
        admin_evidence=admin_evidence,
        escalation_evidence=escalation_evidence,
        action_count=len(all_actions),
    )

    external = _is_third_party(
        principal_id=result.principal_id,
        principal_kind=principal_kind,
        external_domains=external_domains or frozenset(),
    )

    evidence: dict[str, list[str]] = {}
    if escalation_evidence:
        evidence["can_escalate"] = sorted(escalation_evidence)
    if data_evidence:
        evidence["data_access"] = sorted(data_evidence)
    if cross_account_evidence:
        evidence["cross_account"] = sorted(cross_account_evidence)
    if admin_evidence:
        evidence["tier"] = sorted(admin_evidence)
    elif escalation_evidence:
        evidence["tier"] = sorted(escalation_evidence)

    return IdentityPrivilege(
        tier=tier,
        tags=PrivilegeTags(
            can_escalate=bool(escalation_evidence),
            data_access=bool(data_evidence),
            # `third_party` is the one tag that is not derivable from the
            # permission set at all -- it is a property of the principal. It
            # stays None when the caller supplied nothing to decide it with,
            # rather than defaulting to "internal", because "we assume
            # everyone is staff" is the wrong default in a product whose job
            # is noticing when they are not.
            third_party=external,
            cross_account=bool(cross_account_evidence),
        ),
        provider=result.provider,
        principal_id=result.principal_id,
        evidence=evidence,
        action_count=len(all_actions),
        resource_count=len(decisions),
        partial_source=partial_source,
        notes=list(result.notes or ()),
    )


def _derive_tier(*, admin_evidence: set[str], escalation_evidence: set[str], action_count: int) -> Tier:
    """Tier from what the identity can write, never from what it is called.

    ``domain_admin`` is reserved for a wildcard over the whole provider --
    the thing that makes every other permission moot. ``admin`` is
    authorization-write without that wildcard. ``elevated`` is a principal
    with a wide action surface and no authorization write, which is the
    "powerful but cannot grant" shape (a data engineer with full BigQuery)
    that a tiering scheme collapsing to admin/standard cannot express.
    """
    if any(pattern in admin_evidence for pattern in ("*", "*:*")):
        return "domain_admin"
    if admin_evidence:
        return "admin"
    if escalation_evidence:
        return "admin"
    if action_count >= _ELEVATED_ACTION_FLOOR:
        return "elevated"
    return "standard"


#: Where "a wide action surface" starts. Not a free parameter: it is the
#: point above which an identity's reach stops being summarisable by a human
#: reading the list, which is the thing the tier exists to flag. Pinned by a
#: test so moving it is a decision rather than a tweak.
_ELEVATED_ACTION_FLOOR = 25


def _is_third_party(
    *,
    principal_id: str,
    principal_kind: str | None,
    external_domains: frozenset[str],
) -> bool | None:
    """External or vendor-owned, or ``None`` when nothing says either way."""
    kind = (principal_kind or "").strip().lower()
    if kind:
        if kind in {"guest", "external", "outside_collaborator", "oauth_app", "vendor", "service_principal_external"}:
            return True
        if kind in {"member", "employee", "user", "service_account", "workload"}:
            return False

    if "#ext#" in principal_id.lower():
        # Entra's own spelling for a guest account.
        return True

    if external_domains and "@" in principal_id:
        domain = principal_id.rsplit("@", 1)[-1].strip().lower()
        if domain:
            return domain in external_domains

    return None
