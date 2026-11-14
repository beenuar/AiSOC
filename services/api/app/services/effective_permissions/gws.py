"""Google Workspace effective-permissions resolver (T3.2 — Phase 4.1 full impl).

Resolution model
----------------

Google Workspace has a small, well-bounded admin model:

* A user holds zero or more admin role assignments. Each assignment
  is scoped to either the whole org or a specific org-unit (OU)
  path; if scoped to an OU, the role only applies to resources
  inside that OU.
* Each role is a bag of *privilege* strings
  (``USER_MANAGEMENT``, ``GROUPS_RETRIEVE``, ``MANAGE_USER_SECURITY``…).
  We use the Google Admin SDK privilege string directly as the
  action so the UI matches the docs.

Snapshot shape::

    {
      "principals": [
        {"id": "alice@corp.com", "ou_path": "/Eng"},
      ],
      "admin_roles": [
        {"id": "USER_MANAGEMENT_ADMIN",
         "name": "User Management Admin",
         "privileges": ["USERS_CREATE", "USERS_UPDATE", "USERS_RETRIEVE"]},
      ],
      "role_assignments": [
        {"id": "ra1", "principal_id": "alice@corp.com",
         "role_id": "USER_MANAGEMENT_ADMIN",
         "scope_type": "ORG_UNIT", "ou_path": "/Eng"},
      ],
      "resources": [
        {"id": "user-bob", "kind": "gws-user", "ou_path": "/Eng/Bob"},
      ],
    }

The resolver matches a role assignment to a resource when:

* ``scope_type=="CUSTOMER"`` (org-wide), **or**
* ``scope_type=="ORG_UNIT"`` and the assignment's ``ou_path`` is a
  prefix of the resource's ``ou_path``.

Effective actions = union of privileges from every matching role.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.services.effective_permissions.base import (
    PolicyChainStep,
    ResolvedPermission,
    Resolver,
    ResolverError,
    ResolverResult,
)


def _ou_covers(role_ou: str, resource_ou: str) -> bool:
    """Return True if ``role_ou`` is an ancestor of ``resource_ou``.

    Workspace OU paths look like ``/`` (root), ``/Eng``,
    ``/Eng/Backend``. The match is case-sensitive (Workspace
    preserves casing) and exact-prefix; ``/Eng`` covers ``/Eng/X``
    but not ``/Engineering``.
    """
    if role_ou == "/":
        return True
    if not role_ou or not resource_ou:
        return False
    if role_ou == resource_ou:
        return True
    return resource_ou.startswith(role_ou + "/")


class GoogleWorkspaceResolver(Resolver):
    """Production Google Workspace resolver — OU-scoped role expander."""

    provider = "gws"
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
            raise ResolverError("GoogleWorkspaceResolver.resolve called without a snapshot")

        principals_by_id = {p["id"]: p for p in snap.get("principals", [])}
        principal = principals_by_id.get(principal_id)
        if principal is None:
            raise ResolverError(f"principal {principal_id!r} not present in snapshot")

        roles_by_id = {r["id"]: r for r in snap.get("admin_roles", [])}

        relevant_assignments = [a for a in snap.get("role_assignments", []) if a.get("principal_id") == principal["id"]]

        decisions: list[ResolvedPermission] = []
        for resource in snap.get("resources", []):
            decision = self._resolve_resource(
                principal=principal,
                resource=resource,
                assignments=relevant_assignments,
                roles_by_id=roles_by_id,
            )
            if decision is not None:
                decisions.append(decision)

        return ResolverResult(
            provider=self.provider,
            principal_id=principal_id,
            coverage=self.coverage,
            last_resolved=datetime.now(tz=UTC),
            decisions=decisions,
        )

    def _resolve_resource(
        self,
        *,
        principal: dict[str, Any],
        resource: dict[str, Any],
        assignments: list[dict[str, Any]],
        roles_by_id: dict[str, dict[str, Any]],
    ) -> ResolvedPermission | None:
        resource_ou: str = resource.get("ou_path") or "/"

        allow: set[str] = set()
        chain: list[PolicyChainStep] = []

        for assignment in assignments:
            scope_type = assignment.get("scope_type") or "CUSTOMER"
            if scope_type == "CUSTOMER":
                covers = True
            elif scope_type == "ORG_UNIT":
                covers = _ou_covers(assignment.get("ou_path") or "/", resource_ou)
            else:
                covers = False
            if not covers:
                continue
            role = roles_by_id.get(assignment.get("role_id", ""))
            if role is None:
                continue
            privs = set(role.get("privileges") or [])
            if not privs:
                continue
            allow |= privs
            chain.append(
                PolicyChainStep(
                    kind="role",
                    id=assignment.get("id", role.get("id", "role")),
                    name=role.get("name", role.get("id", "role")),
                    effect="allow",
                    via=role.get("id"),
                )
            )

        if not allow:
            return None

        return ResolvedPermission(
            principal_id=principal["id"],
            resource_id=resource["id"],
            resource_kind=resource.get("kind"),
            resource_arn=resource.get("id"),
            actions=tuple(sorted(allow)),
            deny_actions=(),
            policy_chain=tuple(chain),
        )
