"""Collect a GCP IAM posture snapshot for one or more projects.

Returns the shape documented in
``services/api/app/services/effective_permissions/gcp.py``.

Two things worth knowing before reading the answer
--------------------------------------------------
**A project's IAM policy is not the whole story.** GCP inherits bindings
downward from the organisation and folders, so a principal with no binding
on a project can still hold ``roles/owner`` on its parent folder. This
collector reads the ancestry via ``projects.getAncestry`` and fetches each
ancestor's policy when the credential is allowed to, and records a note when
it is not -- because "no bindings" read off a project alone is exactly the
answer that makes an owner look like a stranger.

**Role permissions have to be fetched per role.** A binding names
``roles/storage.admin``; what that expands to lives behind
``iam.roles.get``. Predefined roles are fetched once and shared across
projects. A role whose permissions could not be read is emitted with an
empty permission list *and* a note, never silently dropped -- dropping it
would remove a grant from the answer entirely, while an empty role at least
shows up in the provenance chain as something the resolver could not expand.
"""

from __future__ import annotations

from typing import Any

import structlog

from app.connectors.posture import Collected

logger = structlog.get_logger()

_CRM_V1 = "https://cloudresourcemanager.googleapis.com/v1"
_CRM_V3 = "https://cloudresourcemanager.googleapis.com/v3"
_IAM = "https://iam.googleapis.com/v1"

#: Ancestry is org -> folder... -> project and is never deep in practice.
_MAX_ANCESTORS = 20

#: 500 projects per page, so this covers 5,000 before the note fires.
_MAX_PROJECT_PAGES = 10


def _resource_name(ancestor: dict[str, Any]) -> str | None:
    rid = ancestor.get("resourceId") or {}
    kind, value = rid.get("type"), rid.get("id")
    if not kind or not value:
        return None
    return f"//cloudresourcemanager.googleapis.com/{kind}s/{value}"


async def _discover_projects(client: Any, headers: dict[str, str], organization_id: str, out: Collected) -> list[str]:
    """List the active projects under an organisation.

    The SCC connector is configured with an organisation rather than a list
    of projects, so the set has to be discovered. A failure here is recorded
    rather than raised: a snapshot of the projects we *could* enumerate is
    worth more than no snapshot, as long as it says so.
    """
    found: list[str] = []
    page_token: str | None = None
    for _ in range(_MAX_PROJECT_PAGES):
        params: dict[str, Any] = {"filter": f"parent.type:organization parent.id:{organization_id}", "pageSize": 500}
        if page_token:
            params["pageToken"] = page_token
        try:
            resp = await client.get(f"{_CRM_V1}/projects", headers=headers, params=params)
        except Exception as exc:  # noqa: BLE001
            out.note(f"project discovery under organisation {organization_id} failed: {exc}")
            return found
        if resp.status_code != 200:
            out.note(
                f"project discovery under organisation {organization_id} returned HTTP {resp.status_code}; "
                f"this usually means the service account lacks resourcemanager.projects.list"
            )
            return found
        body = resp.json()
        for project in body.get("projects") or []:
            pid = project.get("projectId")
            if pid and project.get("lifecycleState", "ACTIVE") == "ACTIVE":
                found.append(pid)
        page_token = body.get("nextPageToken")
        if not page_token:
            return found
    out.note(f"project discovery stopped after {_MAX_PROJECT_PAGES} pages; the organisation has more projects than one pass")
    return found


async def collect(
    client: Any,
    headers: dict[str, str],
    project_ids: list[str] | None = None,
    *,
    organization_id: str = "",
) -> Collected:
    out = Collected(snapshot={})

    members: dict[str, dict[str, Any]] = {}
    bindings: list[dict[str, Any]] = []
    roles: dict[str, dict[str, Any]] = {}
    resources: list[dict[str, Any]] = []

    project_ids = list(project_ids or [])
    if not project_ids and organization_id:
        project_ids = await _discover_projects(client, headers, organization_id, out)

    if not project_ids:
        out.note("no projects were configured or discovered, so nothing could be collected")

    async def _read_policy(resource_name: str, api_url: str, label: str) -> list[dict[str, Any]]:
        try:
            resp = await client.post(api_url, headers=headers, json={})
        except Exception as exc:  # noqa: BLE001
            out.note(f"{label}: getIamPolicy request failed: {exc}")
            return []
        if resp.status_code != 200:
            out.note(f"{label}: getIamPolicy returned HTTP {resp.status_code}; its bindings are not in this snapshot")
            return []
        return resp.json().get("bindings") or []

    for project_id in project_ids:
        project_resource = f"//cloudresourcemanager.googleapis.com/projects/{project_id}"
        ancestry: list[str] = [project_resource]

        try:
            resp = await client.post(f"{_CRM_V1}/projects/{project_id}:getAncestry", headers=headers, json={})
            if resp.status_code == 200:
                for ancestor in (resp.json().get("ancestor") or [])[:_MAX_ANCESTORS]:
                    name = _resource_name(ancestor)
                    if name and name not in ancestry:
                        ancestry.append(name)
            else:
                out.note(
                    f"project {project_id}: getAncestry returned HTTP {resp.status_code}; inherited "
                    f"organisation and folder bindings are not in this snapshot, so a principal that "
                    f"holds a role on a parent will read as having none here"
                )
        except Exception as exc:  # noqa: BLE001
            out.note(f"project {project_id}: getAncestry failed ({exc}); inherited bindings are not reflected")

        resources.append(
            {
                "id": project_id,
                "gcp_id": project_resource,
                "ancestors": ancestry,
                "kind": "cloudresourcemanager.googleapis.com/Project",
            }
        )

        for resource_name in ancestry:
            short = resource_name.rsplit("/", 2)
            if len(short) < 2:
                continue
            kind, value = short[-2], short[-1]
            if kind == "projects":
                url = f"{_CRM_V1}/projects/{value}:getIamPolicy"
            else:
                url = f"{_CRM_V3}/{kind}/{value}:getIamPolicy"
            for binding in await _read_policy(resource_name, url, f"{kind[:-1]} {value}"):
                role = binding.get("role")
                if not role:
                    continue
                roles.setdefault(role, {"id": role, "name": role, "permissions": []})
                bindings.append(
                    {
                        "id": f"{resource_name}:{role}",
                        "resource_id": resource_name,
                        "role": role,
                        "members": list(binding.get("members") or []),
                    }
                )
                for member in binding.get("members") or []:
                    if ":" not in member:
                        continue
                    member_type, _, identifier = member.partition(":")
                    members.setdefault(
                        identifier,
                        {
                            "id": identifier,
                            "type": member_type,
                            "groups": [],
                        },
                    )

    for role_id, role in roles.items():
        # A predefined role is `roles/<name>` and a custom one is
        # `projects/<p>/roles/<name>`; both are full resource names and both
        # answer the same GET, so there is no branch here on purpose.
        url = f"{_IAM}/{role_id}"
        try:
            resp = await client.get(url, headers=headers)
        except Exception as exc:  # noqa: BLE001
            out.note(f"role {role_id}: could not be expanded ({exc}); it resolves to no permissions here")
            continue
        if resp.status_code != 200:
            out.note(
                f"role {role_id}: expansion returned HTTP {resp.status_code}; it appears in the chain "
                f"with no permissions rather than being dropped from it"
            )
            continue
        role["permissions"] = list(resp.json().get("includedPermissions") or [])

    if not members:
        out.note(
            "no IAM members were returned. On a live project this is far more often a missing "
            "resourcemanager.projects.getIamPolicy permission than a project nobody can access"
        )

    out.snapshot = {
        "principals": list(members.values()),
        "groups": [],
        "roles": list(roles.values()),
        "bindings": bindings,
        "org_policies": [],
        "resources": resources,
    }
    out.note(
        "organisation policy constraints are not collected, so a constraint that blocks an action "
        "granted by a binding will not appear as a denial"
    )
    return out
