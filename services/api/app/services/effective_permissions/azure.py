"""Azure RBAC effective-permissions resolver (T3.2 — Phase 4.1 full impl).

Resolution model
----------------

Azure RBAC is a *scope-inheriting* model. A role assignment made at a
parent scope (management group, subscription, resource group) applies
to every resource inside that scope. The resolver walks the scope
chain top-down so the higher-scope assignments are folded in first
and lower-scope deny assignments correctly override them.

Snapshot shape::

    {
      "tenant_id": "...",
      "principals": [
        {"id": "alice", "object_id": "...", "type": "user|servicePrincipal|group",
         "groups": ["g1", "g2"]},
      ],
      "groups": [
        {"id": "g1", "name": "Reader-Engineering"},
      ],
      "role_definitions": [
        {"id": "reader", "name": "Reader",
         "permissions": [
           {"actions": ["Microsoft.Storage/*/read"],
            "notActions": [],
            "dataActions": [],
            "notDataActions": []}
         ]},
      ],
      "role_assignments": [
        {"id": "a1", "principal_id": "alice",
         "role_definition_id": "reader",
         "scope": "/subscriptions/<sub>/resourceGroups/<rg>"},
      ],
      "deny_assignments": [
        {"id": "d1", "principal_id": "alice",
         "permissions": [{"actions": ["Microsoft.Storage/*/delete"], "notActions": []}],
         "scope": "/subscriptions/<sub>"},
      ],
      "resources": [
        {"id": "blob1",
         "azure_id": "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Storage/storageAccounts/acct/blob1",
         "kind": "Microsoft.Storage/storageAccounts/blobs",
         "service_actions": ["Microsoft.Storage/storageAccounts/blobs/read", ...]},
      ],
      "action_catalogue": {"Microsoft.Storage": ["Microsoft.Storage/.../read", ...]}
    }

For each ``(principal, resource)`` pair the algorithm is:

1. Collect every role assignment that:
   * targets the principal *or* one of the principal's groups, **and**
   * has a scope that is a prefix of the resource's ``azure_id``.
2. For each assignment, intersect the role-definition's ``actions`` /
   ``dataActions`` patterns with the resource's service action
   catalogue, then subtract ``notActions`` / ``notDataActions``.
3. Apply deny assignments the same way (allow + ``notActions`` subtract).
4. Final = ``allow ∪ data_allow − deny − data_deny``.

Notable simplifications:

* ABAC condition expressions on role assignments are not modelled.
* Built-in roles are not pre-loaded — their permission patterns must
  be present in the snapshot. The connector tier writes them in.
"""

from __future__ import annotations

import fnmatch
from datetime import UTC, datetime
from typing import Any

from app.services.effective_permissions.base import (
    PolicyChainStep,
    ResolvedPermission,
    Resolver,
    ResolverError,
    ResolverResult,
)


def _scope_covers(scope: str, resource_azure_id: str) -> bool:
    """Return True if ``scope`` is an ancestor (or equal) of the resource path.

    Azure scopes use ``/subscriptions/{}/resourceGroups/{}/...`` form;
    a parent scope is always a prefix of its children. Comparison is
    case-insensitive because Azure resource IDs are case-insensitive
    on the wire even though the portal occasionally normalises them.
    """
    if not scope or not resource_azure_id:
        return False
    s = scope.rstrip("/").lower()
    r = resource_azure_id.lower()
    if s == "/":
        return True
    return r == s or r.startswith(s + "/")


def _expand_patterns(patterns: list[str], catalogue: list[str]) -> set[str]:
    """Expand Azure action wildcard patterns against a service action catalogue.

    Azure uses ``Microsoft.Storage/*/read`` style wildcards, where
    ``*`` matches any segment(s). fnmatch handles this correctly
    because we're folding multi-segment matches into the catalogue
    (which is already expanded into concrete actions).
    """
    out: set[str] = set()
    for pattern in patterns:
        if "*" not in pattern:
            out.add(pattern)
            continue
        for known in catalogue:
            if fnmatch.fnmatchcase(known, pattern):
                out.add(known)
    return out


class AzureRbacResolver(Resolver):
    """Production Azure RBAC resolver — scope-inheriting walker."""

    provider = "azure"
    coverage = "full"

    def __init__(self, snapshot: dict[str, Any] | None = None) -> None:
        self._snapshot = snapshot

    def resolve(
        self,
        principal_id: str,
        *,
        snapshot: dict[str, Any] | None = None,
    ) -> ResolverResult:
        snap = snapshot if snapshot is not None else self._snapshot
        if snap is None:
            raise ResolverError("AzureRbacResolver.resolve called without a snapshot")

        principals_by_id = {p["id"]: p for p in snap.get("principals", [])}
        principal = principals_by_id.get(principal_id)
        if principal is None:
            # Fall back to object_id lookup — Azure assignments often
            # reference principals by their tenant-scoped object_id.
            for p in snap.get("principals", []):
                if p.get("object_id") == principal_id:
                    principal = p
                    break
        if principal is None:
            raise ResolverError(f"principal {principal_id!r} not present in snapshot")

        role_defs_by_id = {r["id"]: r for r in snap.get("role_definitions", [])}
        action_catalogue: dict[str, list[str]] = snap.get("action_catalogue", {})

        principal_keys = {principal["id"]}
        if "object_id" in principal:
            principal_keys.add(principal["object_id"])
        principal_keys.update(principal.get("groups", []))

        relevant_allow_assignments = [a for a in snap.get("role_assignments", []) if a.get("principal_id") in principal_keys]
        relevant_deny_assignments = [d for d in snap.get("deny_assignments", []) if d.get("principal_id") in principal_keys]

        decisions: list[ResolvedPermission] = []
        notes: list[str] = []
        for resource in snap.get("resources", []):
            decision = self._resolve_resource(
                principal=principal,
                resource=resource,
                allow_assignments=relevant_allow_assignments,
                deny_assignments=relevant_deny_assignments,
                role_defs_by_id=role_defs_by_id,
                action_catalogue=action_catalogue,
            )
            if decision is not None:
                decisions.append(decision)

        if any(a.get("condition") for a in relevant_allow_assignments):
            notes.append(
                "ABAC conditions present on one or more role assignments — "
                "conditions are not evaluated by this resolver; the allow "
                "set may over-permit."
            )

        return ResolverResult(
            provider=self.provider,
            principal_id=principal_id,
            coverage=self.coverage,
            last_resolved=datetime.now(tz=UTC),
            decisions=decisions,
            notes=notes,
        )

    def _resolve_resource(
        self,
        *,
        principal: dict[str, Any],
        resource: dict[str, Any],
        allow_assignments: list[dict[str, Any]],
        deny_assignments: list[dict[str, Any]],
        role_defs_by_id: dict[str, dict[str, Any]],
        action_catalogue: dict[str, list[str]],
    ) -> ResolvedPermission | None:
        resource_azure_id: str = resource.get("azure_id") or resource.get("arn") or ""
        if not resource_azure_id:
            return None
        # Default the resource's service catalogue to either an
        # inline list or the action_catalogue keyed by the resource's
        # provider namespace (the first two segments of the kind:
        # "Microsoft.Storage/...").
        kind = resource.get("kind", "")
        namespace = kind.split("/", 1)[0] if "/" in kind else kind
        catalogue: list[str] = resource.get("service_actions") or action_catalogue.get(namespace, [])

        allow_actions: set[str] = set()
        deny_actions: set[str] = set()
        chain: list[PolicyChainStep] = []

        # Allow assignments — scope-inherited
        for assignment in allow_assignments:
            scope = assignment.get("scope", "")
            if not _scope_covers(scope, resource_azure_id):
                continue
            role_def_id = assignment.get("role_definition_id", "")
            role_def = role_defs_by_id.get(role_def_id)
            if role_def is None:
                continue
            granted = self._evaluate_role_permissions(role_def, catalogue)
            if not granted:
                continue
            allow_actions |= granted
            chain.append(
                PolicyChainStep(
                    kind="role",
                    id=assignment.get("id", role_def_id),
                    name=role_def.get("name", role_def_id),
                    effect="allow",
                    via=role_def_id,
                )
            )

        # Deny assignments — also scope-inherited
        for d in deny_assignments:
            scope = d.get("scope", "")
            if not _scope_covers(scope, resource_azure_id):
                continue
            denied = self._evaluate_permission_blocks(d.get("permissions", []), catalogue)
            if not denied:
                continue
            deny_actions |= denied
            chain.append(
                PolicyChainStep(
                    kind="deny-assignment",
                    id=d.get("id", "deny"),
                    name=d.get("name", "deny-assignment"),
                    effect="deny",
                )
            )

        pre_deny_allow = set(allow_actions)
        final = allow_actions - deny_actions
        shadowed = pre_deny_allow & deny_actions

        if not final and not shadowed:
            return None

        return ResolvedPermission(
            principal_id=principal["id"],
            resource_id=resource["id"],
            resource_kind=resource.get("kind"),
            resource_arn=resource_azure_id,
            actions=tuple(sorted(final)),
            deny_actions=tuple(sorted(shadowed)),
            policy_chain=tuple(chain),
        )

    def _evaluate_role_permissions(
        self,
        role_def: dict[str, Any],
        catalogue: list[str],
    ) -> set[str]:
        return self._evaluate_permission_blocks(role_def.get("permissions", []), catalogue)

    @staticmethod
    def _evaluate_permission_blocks(
        blocks: list[dict[str, Any]],
        catalogue: list[str],
    ) -> set[str]:
        allowed: set[str] = set()
        for block in blocks:
            actions = _expand_patterns(list(block.get("actions") or []), catalogue)
            data_actions = _expand_patterns(list(block.get("dataActions") or []), catalogue)
            not_actions = _expand_patterns(list(block.get("notActions") or []), catalogue)
            not_data_actions = _expand_patterns(list(block.get("notDataActions") or []), catalogue)
            block_allow = (actions | data_actions) - (not_actions | not_data_actions)
            allowed |= block_allow
        return allowed
