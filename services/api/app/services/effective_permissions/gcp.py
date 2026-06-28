"""GCP IAM effective-permissions resolver (T3.2 — Phase 4.1 full impl).

Resolution model
----------------

GCP IAM is an *allow-only*, hierarchy-inheriting model. Bindings at
the organization apply to every folder, project, and resource
inside. Org policies (constraints) can deny services or restrict
location, and are evaluated as a separate, non-overridable deny
layer.

Snapshot shape::

    {
      "principals": [
        {"id": "alice@corp.com", "type": "user",
         "groups": ["group:eng@corp.com"]}
      ],
      "groups": [
        {"id": "group:eng@corp.com", "name": "engineering"},
      ],
      "roles": [
        {"id": "roles/storage.objectViewer",
         "name": "Storage Object Viewer",
         "permissions": ["storage.objects.get", "storage.objects.list"]},
      ],
      "bindings": [
        {"id": "b1",
         "resource_id": "//cloudresourcemanager.googleapis.com/projects/proj",
         "role": "roles/storage.objectViewer",
         "members": ["user:alice@corp.com", "group:eng@corp.com"]},
      ],
      "org_policies": [
        {"id": "op1",
         "resource_id": "organizations/123",
         "constraint": "constraints/iam.disableServiceAccountKeyCreation",
         "denied_permissions": ["iam.serviceAccountKeys.create"]},
      ],
      "resources": [
        {"id": "bucket1",
         "gcp_id": "//storage.googleapis.com/buckets/bucket1",
         "ancestors": [
           "//storage.googleapis.com/buckets/bucket1",
           "//cloudresourcemanager.googleapis.com/projects/proj",
           "//cloudresourcemanager.googleapis.com/folders/fld",
           "//cloudresourcemanager.googleapis.com/organizations/123"
         ],
         "kind": "storage.googleapis.com/Bucket"},
      ],
    }

Resolution proceeds as follows:

1. For each resource, expand the principal's identifiers into the
   set of GCP member strings that match: ``user:<email>``,
   ``serviceAccount:<email>``, ``group:<g>``, ``allAuthenticatedUsers``,
   ``allUsers``.
2. Find every binding whose ``resource_id`` is one of the resource's
   ancestors (this is how hierarchy inheritance works), and whose
   ``members`` overlaps the principal's member set.
3. Union the role permissions across matched bindings.
4. For each org policy that applies (constraint on an ancestor),
   subtract its ``denied_permissions``.

Notable simplifications:

* IAM conditions (CEL expressions) are not modelled.
* Domain restricted sharing is not modelled — connector tier already
  flags it as a separate signal.
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


def _principal_members(principal: dict[str, Any]) -> set[str]:
    """Expand a principal into the GCP member strings that may match a binding.

    Bindings list members like ``user:alice@corp.com`` /
    ``group:eng@corp.com`` / ``serviceAccount:sa@x.iam...`` /
    ``allUsers`` / ``allAuthenticatedUsers``. We yield every form
    the principal could legitimately match.
    """
    members: set[str] = set()
    ptype = principal.get("type") or "user"
    pid = principal.get("id", "")
    if pid:
        # If the snapshot already stored it as ``user:...`` keep it.
        if ":" in pid:
            members.add(pid)
        else:
            members.add(f"{ptype}:{pid}")
    members.update(principal.get("groups", []))
    # All-principals tokens always match if a binding targets them.
    members.add("allAuthenticatedUsers")
    members.add("allUsers")
    return members


class GcpIamResolver(Resolver):
    """Production GCP IAM resolver — hierarchy-inheriting walker."""

    provider = "gcp"
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
            raise ResolverError("GcpIamResolver.resolve called without a snapshot")

        principals_by_id = {p["id"]: p for p in snap.get("principals", [])}
        principal = principals_by_id.get(principal_id)
        if principal is None:
            raise ResolverError(f"principal {principal_id!r} not present in snapshot")

        members = _principal_members(principal)
        roles_by_id = {r["id"]: r for r in snap.get("roles", [])}

        decisions: list[ResolvedPermission] = []
        notes: list[str] = []
        for resource in snap.get("resources", []):
            decision = self._resolve_resource(
                principal=principal,
                resource=resource,
                principal_members=members,
                bindings=snap.get("bindings", []),
                roles_by_id=roles_by_id,
                org_policies=snap.get("org_policies", []),
            )
            if decision is not None:
                decisions.append(decision)

        if any(b.get("condition") for b in snap.get("bindings", [])):
            notes.append(
                "IAM conditions (CEL) present on one or more bindings — "
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
        principal_members: set[str],
        bindings: list[dict[str, Any]],
        roles_by_id: dict[str, dict[str, Any]],
        org_policies: list[dict[str, Any]],
    ) -> ResolvedPermission | None:
        ancestors: set[str] = set(resource.get("ancestors") or [])
        gcp_id = resource.get("gcp_id") or resource.get("arn") or resource["id"]
        ancestors.add(gcp_id)

        allow: set[str] = set()
        chain: list[PolicyChainStep] = []

        # Matched bindings -> role permissions
        for binding in bindings:
            scope = binding.get("resource_id", "")
            if scope not in ancestors:
                continue
            members = set(binding.get("members") or [])
            if members.isdisjoint(principal_members):
                continue
            role = roles_by_id.get(binding.get("role", ""))
            if role is None:
                continue
            perms = set(role.get("permissions") or [])
            if not perms:
                continue
            allow |= perms
            chain.append(
                PolicyChainStep(
                    kind="binding",
                    id=binding.get("id", binding.get("role", "binding")),
                    name=role.get("name", binding.get("role", "")),
                    effect="allow",
                    via=binding.get("role"),
                )
            )

        # Org policies (constraints) -> subtractive deny
        deny: set[str] = set()
        for op in org_policies:
            if op.get("resource_id") not in ancestors:
                continue
            denied = set(op.get("denied_permissions") or [])
            if not denied:
                continue
            deny |= denied
            chain.append(
                PolicyChainStep(
                    kind="org-policy",
                    id=op.get("id", op.get("constraint", "org-policy")),
                    name=op.get("constraint", "constraint"),
                    effect="deny",
                )
            )

        pre_deny_allow = set(allow)
        final = allow - deny
        shadowed = pre_deny_allow & deny

        if not final and not shadowed:
            return None

        return ResolvedPermission(
            principal_id=principal["id"],
            resource_id=resource["id"],
            resource_kind=resource.get("kind"),
            resource_arn=gcp_id,
            actions=tuple(sorted(final)),
            deny_actions=tuple(sorted(shadowed)),
            policy_chain=tuple(chain),
        )
