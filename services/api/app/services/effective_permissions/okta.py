"""Okta effective-permissions resolver (T3.2 — Phase 4.1 full impl).

Resolution model
----------------

Okta has two distinct privilege surfaces:

1. **App access**   — group memberships drive which apps a user can
                      reach. Each app assignment is modelled as a
                      single ``okta.app.{app_id}.read`` action.
2. **Admin roles**  — Super Admin, Org Admin, App Admin, Help Desk,
                      Mobile Admin, Read-only, Group Admin, etc.
                      Each role declares a set of privilege strings
                      (``okta.users.read``, ``okta.users.manage``…).

Snapshot shape::

    {
      "principals": [
        {"id": "alice", "email": "alice@corp.com",
         "groups": ["g-admins"]},
      ],
      "groups": [
        {"id": "g-admins", "name": "Admins",
         "assigned_apps": ["app-okta-admin"],
         "admin_roles": ["SUPER_ADMIN"]},
      ],
      "apps": [
        {"id": "app-salesforce", "name": "Salesforce"},
      ],
      "admin_roles": [
        {"id": "SUPER_ADMIN",
         "name": "Super Administrator",
         "privileges": ["okta.users.manage", "okta.groups.manage", ...]},
      ],
      "resources": [
        {"id": "res-okta", "kind": "okta-org"},
      ],
    }

We model the org itself as a single resource (``res-okta``). Each
app surface ``apps[]`` entry also becomes a resource so the UI can
render per-app access.

The principal's effective permissions for the org resource are:

* Union of ``admin_role.privileges`` over every admin role the user
  is granted (directly or via a group).
* Plus ``okta.app.{app_id}.read`` for every app the user is
  assigned (directly or via a group).
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


class OktaResolver(Resolver):
    """Production Okta resolver — group + admin-role expander."""

    provider = "okta"
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
            raise ResolverError("OktaResolver.resolve called without a snapshot")

        principals_by_id = {p["id"]: p for p in snap.get("principals", [])}
        principal = principals_by_id.get(principal_id)
        if principal is None:
            raise ResolverError(f"principal {principal_id!r} not present in snapshot")

        groups_by_id = {g["id"]: g for g in snap.get("groups", [])}
        admin_roles_by_id = {r["id"]: r for r in snap.get("admin_roles", [])}
        apps_by_id = {a["id"]: a for a in snap.get("apps", [])}

        granted_role_ids: set[str] = set(principal.get("admin_roles", []))
        assigned_app_ids: set[str] = set(principal.get("assigned_apps", []))
        # Group inheritance
        group_role_via: dict[str, str] = {}
        group_app_via: dict[str, str] = {}
        for group_id in principal.get("groups", []):
            group = groups_by_id.get(group_id)
            if group is None:
                continue
            for role_id in group.get("admin_roles", []):
                granted_role_ids.add(role_id)
                group_role_via.setdefault(role_id, group_id)
            for app_id in group.get("assigned_apps", []):
                assigned_app_ids.add(app_id)
                group_app_via.setdefault(app_id, group_id)

        # The org itself is a resource. We surface app reads + admin
        # privileges as a single decision per resource record in the
        # snapshot.
        resources = list(snap.get("resources", []))
        if not resources:
            # If the snapshot didn't enumerate the org explicitly,
            # synthesise one so callers always get a decision.
            resources = [{"id": "okta-org", "kind": "okta-org"}]

        decisions: list[ResolvedPermission] = []
        for resource in resources:
            decision = self._build_decision(
                principal=principal,
                resource=resource,
                granted_role_ids=granted_role_ids,
                assigned_app_ids=assigned_app_ids,
                group_role_via=group_role_via,
                group_app_via=group_app_via,
                admin_roles_by_id=admin_roles_by_id,
                apps_by_id=apps_by_id,
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

    def _build_decision(
        self,
        *,
        principal: dict[str, Any],
        resource: dict[str, Any],
        granted_role_ids: set[str],
        assigned_app_ids: set[str],
        group_role_via: dict[str, str],
        group_app_via: dict[str, str],
        admin_roles_by_id: dict[str, dict[str, Any]],
        apps_by_id: dict[str, dict[str, Any]],
    ) -> ResolvedPermission | None:
        # The resolver supports either:
        #   * a single ``okta-org`` resource that aggregates every
        #     privilege (the default path);
        #   * a per-app resource (``kind=okta-app``, id matches
        #     ``apps[].id``) — in which case we surface only that
        #     app's read action.
        actions: set[str] = set()
        chain: list[PolicyChainStep] = []

        if resource.get("kind") == "okta-app":
            app_id = resource.get("id")
            if app_id in assigned_app_ids:
                actions.add(f"okta.app.{app_id}.read")
                via = group_app_via.get(app_id)
                chain.append(
                    PolicyChainStep(
                        kind="binding",
                        id=app_id,
                        name=apps_by_id.get(app_id, {}).get("name", app_id),
                        effect="allow",
                        via=via,
                    )
                )
            if not actions:
                return None
        else:
            # Aggregate org-level surface.
            for role_id in granted_role_ids:
                role = admin_roles_by_id.get(role_id)
                if role is None:
                    continue
                actions.update(role.get("privileges") or [])
                chain.append(
                    PolicyChainStep(
                        kind="role",
                        id=role_id,
                        name=role.get("name", role_id),
                        effect="allow",
                        via=group_role_via.get(role_id),
                    )
                )
            for app_id in assigned_app_ids:
                actions.add(f"okta.app.{app_id}.read")
                chain.append(
                    PolicyChainStep(
                        kind="binding",
                        id=app_id,
                        name=apps_by_id.get(app_id, {}).get("name", app_id),
                        effect="allow",
                        via=group_app_via.get(app_id),
                    )
                )
            if not actions:
                return None

        return ResolvedPermission(
            principal_id=principal["id"],
            resource_id=resource["id"],
            resource_kind=resource.get("kind"),
            resource_arn=resource.get("id"),
            actions=tuple(sorted(actions)),
            deny_actions=(),
            policy_chain=tuple(chain),
        )
