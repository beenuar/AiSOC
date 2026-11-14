"""Collect an AWS IAM posture snapshot for the effective-permissions resolver.

Reads the account's identity plane through ``iam:Get*`` / ``iam:List*`` and
returns the snapshot shape documented in
``services/api/app/services/effective_permissions/aws.py``.

Why ``GetAccountAuthorizationDetails`` and not twenty List calls
---------------------------------------------------------------
One paginated call returns every user, group, role, their inline policies,
their attached managed policy ARNs, and the managed policy documents
themselves. The obvious alternative -- list users, then for each user list
its policies, then fetch each policy -- is O(principals x policies) requests
against an API with a low request rate, and on an estate of any size it gets
throttled into a partial snapshot that looks complete.

It also carries ``PermissionsBoundary`` per principal, which is the field
2.5 exists to model and which several of the per-entity List calls omit.

What this deliberately does not collect
---------------------------------------
Resource-based policies and the resource inventory. Enumerating every bucket,
key and queue in an account is a different and much larger job than reading
the identity plane, and a snapshot that half-enumerated resources would make
the resolver's answer *look* resource-aware while silently omitting whatever
it missed. ``resources`` is therefore empty and the collection says so, so a
reader sees "identity plane only" rather than a thin answer presented as a
complete one.

SCPs are read when the caller is in an organisation and has
``organizations:List*``; a member account without that permission is the
normal case, not a failure, and is noted rather than retried.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any
from urllib.parse import unquote

import structlog

from app.connectors.posture import Collected

logger = structlog.get_logger()

#: AWS caps a single page at 1000 and most accounts need one or two. The
#: ceiling exists so a pagination bug cannot spin forever against a provider
#: that is handing back a cursor it never retires.
_MAX_PAGES = 50


def _policy_document(version: Any) -> dict[str, Any]:
    """An IAM policy document, which the API returns URL-encoded JSON.

    ``GetAccountAuthorizationDetails`` returns the document as a
    percent-encoded JSON string, not as a dict. Handing that string to the
    resolver would make every statement unreadable and every principal look
    as though it had no permissions at all -- a snapshot that collects
    cleanly and resolves to nothing.
    """
    if isinstance(version, dict):
        return version
    if not isinstance(version, str):
        return {}
    try:
        return json.loads(unquote(version))
    except (ValueError, TypeError):
        return {}


def collect_sync(session: Any, *, account_id: str | None = None) -> Collected:
    """Collect the snapshot with a synchronous boto3 session.

    Separated from the async wrapper so tests can drive it with a stub
    client and no event loop.
    """
    out = Collected(snapshot={})
    iam = session.client("iam")

    principals: list[dict[str, Any]] = []
    groups: list[dict[str, Any]] = []
    policies: list[dict[str, Any]] = []
    seen_policies: set[str] = set()

    marker: str | None = None
    pages = 0
    try:
        while pages < _MAX_PAGES:
            pages += 1
            kwargs: dict[str, Any] = {"Filter": ["User", "Role", "Group", "LocalManagedPolicy", "AWSManagedPolicy"]}
            if marker:
                kwargs["Marker"] = marker
            page = iam.get_account_authorization_details(**kwargs)

            for policy in page.get("Policies", []):
                arn = policy.get("Arn")
                if not arn or arn in seen_policies:
                    continue
                default_id = policy.get("DefaultVersionId")
                document: dict[str, Any] = {}
                for version in policy.get("PolicyVersionList", []):
                    if version.get("VersionId") == default_id or version.get("IsDefaultVersion"):
                        document = _policy_document(version.get("Document"))
                        break
                seen_policies.add(arn)
                policies.append(
                    {
                        "id": arn,
                        "name": policy.get("PolicyName") or arn,
                        "kind": "identity",
                        "document": document,
                    }
                )

            for group in page.get("GroupDetailList", []):
                gid = group.get("Arn") or group.get("GroupId")
                if not gid:
                    continue
                inline = []
                for entry in group.get("GroupPolicyList", []) or []:
                    name = entry.get("PolicyName")
                    if not name:
                        continue
                    pid = f"inline:group:{group.get('GroupName')}:{name}"
                    if pid not in seen_policies:
                        seen_policies.add(pid)
                        policies.append(
                            {
                                "id": pid,
                                "name": name,
                                "kind": "identity",
                                "document": _policy_document(entry.get("PolicyDocument")),
                            }
                        )
                    inline.append(pid)
                groups.append(
                    {
                        "id": gid,
                        "name": group.get("GroupName") or gid,
                        "attached_policies": [p["PolicyArn"] for p in group.get("AttachedManagedPolicies", []) if p.get("PolicyArn")],
                        "inline_policies": inline,
                    }
                )

            group_arn_by_name = {g.get("GroupName"): g.get("Arn") for g in page.get("GroupDetailList", [])}

            for kind, key in (("user", "UserDetailList"), ("role", "RoleDetailList")):
                for entity in page.get(key, []):
                    arn = entity.get("Arn")
                    if not arn:
                        continue
                    name = entity.get("UserName") or entity.get("RoleName") or arn
                    inline_key = "UserPolicyList" if kind == "user" else "RolePolicyList"
                    inline: list[str] = []
                    for entry in entity.get(inline_key, []) or []:
                        pname = entry.get("PolicyName")
                        if not pname:
                            continue
                        pid = f"inline:{kind}:{name}:{pname}"
                        if pid not in seen_policies:
                            seen_policies.add(pid)
                            policies.append(
                                {
                                    "id": pid,
                                    "name": pname,
                                    "kind": "identity",
                                    "document": _policy_document(entry.get("PolicyDocument")),
                                }
                            )
                        inline.append(pid)

                    boundary = entity.get("PermissionsBoundary") or {}
                    principals.append(
                        {
                            "id": arn,
                            "arn": arn,
                            "name": name,
                            "type": kind,
                            # Group membership only exists for users. A role
                            # belongs to no group in IAM, and emitting an
                            # empty list for both keeps the resolver's walk
                            # uniform.
                            "groups": [group_arn_by_name.get(g) for g in entity.get("GroupList", []) or [] if group_arn_by_name.get(g)],
                            "attached_policies": [
                                p["PolicyArn"] for p in entity.get("AttachedManagedPolicies", []) or [] if p.get("PolicyArn")
                            ],
                            "inline_policies": inline,
                            # The field 2.5 exists to model. Absent for most
                            # principals, and absent is not the same as
                            # "boundary that allows everything".
                            "permissions_boundary": boundary.get("PermissionsBoundaryArn"),
                        }
                    )

            marker = page.get("Marker") if page.get("IsTruncated") else None
            if not marker:
                break
        else:
            out.note(
                f"stopped after {_MAX_PAGES} pages of GetAccountAuthorizationDetails; "
                f"the identity plane is larger than this collector will read in one pass"
            )
    except Exception as exc:  # noqa: BLE001 — a partial estate is still useful
        out.note(f"GetAccountAuthorizationDetails failed after {pages} page(s): {exc}")

    scps: list[str] = []
    try:
        org = session.client("organizations")
        for policy in org.list_policies(Filter="SERVICE_CONTROL_POLICY").get("Policies", []):
            pid = policy.get("Id")
            if not pid:
                continue
            content = org.describe_policy(PolicyId=pid).get("Policy", {}).get("Content")
            policies.append(
                {
                    "id": pid,
                    "name": policy.get("Name") or pid,
                    "kind": "scp",
                    "document": _policy_document(content),
                }
            )
            scps.append(pid)
    except Exception as exc:  # noqa: BLE001
        # A member account without organizations:List* is the normal case,
        # not a failure -- but it does change the answer, because without
        # SCPs the resolver cannot show an action the org blocks. Said out
        # loud rather than left as a silent absence.
        out.note(f"service control policies not read ({exc}); org-level denials are not reflected")

    if not principals:
        out.note(
            "no IAM principals were returned. On a live account this is far more often a missing "
            "iam:GetAccountAuthorizationDetails permission than an empty estate"
        )

    out.snapshot = {
        "account_id": account_id or "",
        "principals": principals,
        "groups": groups,
        "policies": policies,
        # Deliberately empty -- see the module docstring. Enumerating every
        # resource in an account is a different job, and a half-enumerated
        # list would read as a complete one.
        "resources": [],
        "scps": scps,
        "action_catalogue": {},
    }
    out.note(
        "identity plane only: resource-based policies and the resource inventory are not collected, "
        "so a grant made by a bucket or key policy will not appear"
    )
    return out


async def collect(session: Any, *, account_id: str | None = None) -> Collected:
    """Async wrapper. boto3 is synchronous and this runs on an async path."""
    return await asyncio.to_thread(collect_sync, session, account_id=account_id)
