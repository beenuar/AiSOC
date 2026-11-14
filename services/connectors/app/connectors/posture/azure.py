"""Collect an Entra ID directory-RBAC posture snapshot.

Returns the shape documented in
``services/api/app/services/effective_permissions/azure.py``.

Scope, stated plainly
---------------------
This reads **Entra ID directory roles** -- the control plane over identities
themselves (Global Administrator, User Administrator, Privileged Role
Administrator). It does *not* read Azure resource RBAC, which lives behind a
different API (``management.azure.com``), a different credential and a
different consent, and which governs subscriptions and resource groups.

The distinction matters to a reader of the resolver's answer: an identity
with no directory role may still own a subscription. The collection says so
in a note rather than leaving a reader to infer that "no permissions found"
means "harmless", which is the misreading that costs an incident.

Every assignment is emitted at scope ``/`` because a directory role applies
tenant-wide unless it carries an administrative-unit scope, which is read
from ``directoryScopeId`` when present.
"""

from __future__ import annotations

from typing import Any

import structlog

from app.connectors.posture import Collected

logger = structlog.get_logger()

_GRAPH = "https://graph.microsoft.com/v1.0"
_MAX_PAGES = 50


async def _paged(client: Any, url: str, headers: dict[str, str], out: Collected, what: str) -> list[dict[str, Any]]:
    """Follow Graph's ``@odata.nextLink`` and return every item.

    A truncated read is recorded rather than returned as if complete: a
    missing page of role assignments is a privileged identity the resolver
    will report as unprivileged.
    """
    items: list[dict[str, Any]] = []
    next_url: str | None = url
    pages = 0
    while next_url and pages < _MAX_PAGES:
        pages += 1
        try:
            resp = await client.get(next_url, headers=headers)
        except Exception as exc:  # noqa: BLE001
            out.note(f"{what}: request failed after {pages - 1} page(s): {exc}")
            return items
        if resp.status_code != 200:
            out.note(f"{what}: HTTP {resp.status_code} after {pages - 1} page(s)")
            return items
        body = resp.json()
        items.extend(body.get("value") or [])
        next_url = body.get("@odata.nextLink")
    if next_url:
        out.note(f"{what}: stopped after {_MAX_PAGES} pages; the directory is larger than one pass")
    return items


async def collect(client: Any, headers: dict[str, str], *, tenant_id: str = "") -> Collected:
    out = Collected(snapshot={})

    role_defs = await _paged(client, f"{_GRAPH}/roleManagement/directory/roleDefinitions", headers, out, "role definitions")
    assignments = await _paged(client, f"{_GRAPH}/roleManagement/directory/roleAssignments", headers, out, "role assignments")

    definitions: list[dict[str, Any]] = []
    for definition in role_defs:
        rid = definition.get("id")
        if not rid:
            continue
        actions: list[str] = []
        not_actions: list[str] = []
        for permission in definition.get("rolePermissions") or []:
            actions.extend(permission.get("allowedResourceActions") or [])
            not_actions.extend(permission.get("excludedResourceActions") or [])
        definitions.append(
            {
                "id": rid,
                "name": definition.get("displayName") or rid,
                "permissions": [
                    {
                        "actions": actions,
                        "notActions": not_actions,
                        "dataActions": [],
                        "notDataActions": [],
                    }
                ],
            }
        )

    role_assignments: list[dict[str, Any]] = []
    principal_ids: set[str] = set()
    for assignment in assignments:
        principal_id = assignment.get("principalId")
        role_definition_id = assignment.get("roleDefinitionId")
        if not principal_id or not role_definition_id:
            continue
        principal_ids.add(principal_id)
        role_assignments.append(
            {
                "id": assignment.get("id") or f"{principal_id}:{role_definition_id}",
                "principal_id": principal_id,
                "role_definition_id": role_definition_id,
                # "/" is tenant-wide. An administrative unit narrows it, and
                # the resolver's prefix match handles both without a special
                # case.
                "scope": assignment.get("directoryScopeId") or "/",
            }
        )

    # Only the principals that actually hold a role are resolved. Reading
    # every user in a directory to answer "what can this one do" is a far
    # larger and slower collection, and a principal absent from the snapshot
    # is correctly reported by the resolver as unknown rather than as
    # unprivileged.
    principals: list[dict[str, Any]] = []
    for principal_id in sorted(principal_ids):
        kind = "user"
        name = principal_id
        try:
            resp = await client.get(f"{_GRAPH}/directoryObjects/{principal_id}", headers=headers)
            if resp.status_code == 200:
                obj = resp.json()
                odata = str(obj.get("@odata.type") or "")
                if "servicePrincipal" in odata:
                    kind = "servicePrincipal"
                elif "group" in odata:
                    kind = "group"
                name = obj.get("displayName") or obj.get("userPrincipalName") or principal_id
        except Exception as exc:  # noqa: BLE001
            out.note(f"could not type principal {principal_id}: {exc}")
        principals.append(
            {
                "id": principal_id,
                "object_id": principal_id,
                "name": name,
                "type": kind,
                "groups": [],
            }
        )

    if not principals:
        out.note(
            "no directory role assignments were returned. On a live tenant this is far more often a "
            "missing RoleManagement.Read.Directory permission than a tenant with no administrators"
        )

    out.snapshot = {
        "tenant_id": tenant_id,
        "principals": principals,
        "groups": [],
        "role_definitions": definitions,
        "role_assignments": role_assignments,
        "deny_assignments": [],
        "resources": [],
        "action_catalogue": {},
    }
    out.note(
        "Entra directory roles only: Azure resource RBAC (subscriptions, resource groups) is a "
        "separate API and is not collected, so an identity with no directory role here may still "
        "own a subscription"
    )
    return out
