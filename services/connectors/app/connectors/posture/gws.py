"""Collect a Google Workspace admin posture snapshot.

Returns the shape documented in
``services/api/app/services/effective_permissions/gws.py``.

Workspace has the smallest admin model of the five providers: a user holds
role assignments, each role is a bag of privilege strings, and an assignment
is scoped either customer-wide or to an org unit. All three come from the
Admin SDK Directory API.

The one trap worth naming: the API identifies an org-unit-scoped assignment
by ``orgUnitId``, not by path, while the resolver matches on an OU *path*
prefix (an assignment on ``/Eng`` covering a user in ``/Eng/Platform``). The
ids are therefore resolved to paths here, once, rather than leaving the
resolver to compare an id against a path -- a comparison that never matches
and would silently report every OU-scoped administrator as having no reach.
"""

from __future__ import annotations

from typing import Any

import structlog

from app.connectors.posture import Collected

logger = structlog.get_logger()

_DIRECTORY = "https://admin.googleapis.com/admin/directory/v1"
_MAX_PAGES = 50


async def _paged(
    client: Any,
    url: str,
    headers: dict[str, str],
    key: str,
    out: Collected,
    what: str,
    params: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    token: str | None = None
    pages = 0
    while pages < _MAX_PAGES:
        pages += 1
        query = dict(params or {})
        if token:
            query["pageToken"] = token
        try:
            resp = await client.get(url, headers=headers, params=query)
        except Exception as exc:  # noqa: BLE001
            out.note(f"{what}: request failed after {pages - 1} page(s): {exc}")
            return items
        if resp.status_code != 200:
            out.note(f"{what}: HTTP {resp.status_code} after {pages - 1} page(s)")
            return items
        body = resp.json()
        items.extend(body.get(key) or [])
        token = body.get("nextPageToken")
        if not token:
            return items
    out.note(f"{what}: stopped after {_MAX_PAGES} pages; the directory is larger than one pass")
    return items


async def collect(client: Any, headers: dict[str, str], *, customer: str = "my_customer") -> Collected:
    out = Collected(snapshot={})

    roles = await _paged(client, f"{_DIRECTORY}/customer/{customer}/roles", headers, "items", out, "admin roles")
    assignments = await _paged(
        client,
        f"{_DIRECTORY}/customer/{customer}/roleassignments",
        headers,
        "items",
        out,
        "role assignments",
    )
    org_units = await _paged(
        client,
        f"{_DIRECTORY}/customer/{customer}/orgunits",
        headers,
        "organizationUnits",
        out,
        "org units",
        params={"type": "all"},
    )

    # orgUnitId arrives with an "id:" prefix in assignments and without it in
    # the org-unit listing. Both spellings are indexed so a prefix mismatch
    # cannot silently drop an assignment's scope.
    path_by_ou_id: dict[str, str] = {}
    for unit in org_units:
        ou_id = unit.get("orgUnitId")
        path = unit.get("orgUnitPath")
        if not ou_id or not path:
            continue
        path_by_ou_id[ou_id] = path
        if ou_id.startswith("id:"):
            path_by_ou_id[ou_id[3:]] = path
        else:
            path_by_ou_id[f"id:{ou_id}"] = path

    admin_roles: list[dict[str, Any]] = []
    for role in roles:
        rid = role.get("roleId")
        if not rid:
            continue
        admin_roles.append(
            {
                "id": str(rid),
                "name": role.get("roleName") or str(rid),
                "privileges": [p.get("privilegeName") for p in role.get("rolePrivileges") or [] if p.get("privilegeName")],
            }
        )

    role_assignments: list[dict[str, Any]] = []
    principal_ids: set[str] = set()
    for assignment in assignments:
        assigned_to = assignment.get("assignedTo")
        role_id = assignment.get("roleId")
        if not assigned_to or not role_id:
            continue
        principal_ids.add(str(assigned_to))
        scope_type = assignment.get("scopeType") or "CUSTOMER"
        ou_id = assignment.get("orgUnitId")
        ou_path = path_by_ou_id.get(str(ou_id)) if ou_id else None
        if scope_type == "ORG_UNIT" and ou_id and ou_path is None:
            out.note(
                f"assignment {assignment.get('roleAssignmentId')} is scoped to org unit {ou_id}, "
                f"whose path could not be read; its reach is reported as org-wide, which "
                f"over-states it rather than silently dropping the assignment"
            )
        role_assignments.append(
            {
                "id": str(assignment.get("roleAssignmentId") or f"{assigned_to}:{role_id}"),
                "principal_id": str(assigned_to),
                "role_id": str(role_id),
                "scope_type": "CUSTOMER" if ou_path is None else scope_type,
                "ou_path": ou_path or "/",
            }
        )

    principals: list[dict[str, Any]] = []
    for principal_id in sorted(principal_ids):
        ou_path = "/"
        name = principal_id
        try:
            resp = await client.get(f"{_DIRECTORY}/users/{principal_id}", headers=headers)
            if resp.status_code == 200:
                user = resp.json()
                ou_path = user.get("orgUnitPath") or "/"
                name = user.get("primaryEmail") or principal_id
        except Exception as exc:  # noqa: BLE001
            out.note(f"could not read org unit for principal {principal_id}: {exc}")
        principals.append({"id": principal_id, "name": name, "ou_path": ou_path})

    if not principals:
        out.note(
            "no admin role assignments were returned. On a live tenant this is far more often a "
            "missing admin.directory.rolemanagement.readonly scope, or a service account without "
            "domain-wide delegation, than a tenant with no administrators"
        )

    out.snapshot = {
        "principals": principals,
        "admin_roles": admin_roles,
        "role_assignments": role_assignments,
        "resources": [],
    }
    return out
