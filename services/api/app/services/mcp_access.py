"""Decide whether one MCP tool call may run, for one tenant, right now.

Depth plan 9.1 (parity 6.6). ``services/mcp`` used to be a stdio child
process holding one operator's API key. Over HTTP it is a shared process that
several tenants reach with credentials of their own, so three questions have
to be answered before a tool runs, and this module is the only place that
answers them:

1. **Does the credential carry the scope the tool needs?** The MCP process is
   not the authority on that. It asks here, and here asks the same
   ``require_permission`` path every console route uses.
2. **Has the tenant turned this tool on?** A separate decision from (1),
   owned by a different person: a key's scopes are what a credential may do,
   a grant is what the estate has agreed an assistant reaches at all.
3. **Is this a read?** Anything that is not gets a human in front of it.

The tenant is never a parameter here. It is taken from the authenticated
principal by the route and passed in as a resolved ``uuid.UUID``, which is
the lesson from the outbound MCP surface: a tool that *declares* a
``tenant_id`` and forwards it is a cross-tenant read waiting for a schema to
stop being strict by accident.

Catalogue, not a hand-written table
-----------------------------------
What a tool is called and whether it writes come from
``app/data/mcp_tool_catalog.json``, generated from the TypeScript registry
and held in parity with it by ``scripts/check_mcp_over_http.py``. Hand-keying
that list here would let the authority and the thing it authorises drift, and
the quiet direction of that drift -- this file not knowing a tool writes --
is the one that costs something.
"""

from __future__ import annotations

import functools
import hashlib
import json
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.mcp_access import McpToolApproval, McpToolGrant

CATALOGUE_PATH = Path(__file__).resolve().parent.parent / "data" / "mcp_tool_catalog.json"

#: How long an approval stays usable once granted. Short on purpose: an
#: approval is a decision about a call somebody is making now, not a standing
#: permission, and an unbounded one would quietly become the latter.
APPROVAL_TTL = timedelta(minutes=30)

#: Which permission each tool needs. Keyed by tool, because the scope a tool
#: needs is a property of what it reaches rather than of its name -- and a
#: default of "any authenticated caller" would make the whole surface
#: reachable with a key minted for one narrow job.
TOOL_PERMISSIONS: dict[str, str] = {
    "aisoc_list_alerts": "alerts:read",
    "aisoc_get_alert": "alerts:read",
    "aisoc_get_triage_verdict": "alerts:read",
    "aisoc_list_cases": "cases:read",
    "aisoc_get_case": "cases:read",
    "aisoc_run_investigation": "cases:write",
    "aisoc_query_detections": "rules:read",
    "aisoc_get_detection_rule": "rules:read",
    "aisoc_list_investigations": "cases:read",
    "aisoc_get_investigation": "cases:read",
    "aisoc_replay_decision": "cases:read",
    "aisoc_explain_step": "cases:read",
    "aisoc_list_replay_reports": "reports:read",
    "aisoc_get_replay_report": "reports:read",
    "aisoc_list_actions": "actions:read",
    "aisoc_preview_action": "actions:execute",
    "aisoc_lake_schema": "lake:read_schema",
    "aisoc_lake_query": "lake:query",
    "aisoc_run_hunt": "hunts:read",
}


@dataclass(frozen=True)
class ToolSpec:
    """One row of the generated catalogue."""

    name: str
    read_only: bool
    default_enabled: bool

    @property
    def required_permission(self) -> str:
        # A tool with no entry above is refused rather than defaulted: an
        # unmapped tool is one nobody decided the authority for, and
        # inventing one here is how a narrow key reaches a wide surface.
        return TOOL_PERMISSIONS.get(self.name, "")


@functools.lru_cache(maxsize=1)
def tool_catalogue() -> dict[str, ToolSpec]:
    """The generated catalogue, parsed once.

    Cached because it is a committed file that cannot change inside a
    process. Tests that need a different catalogue call ``.cache_clear()``.
    """
    raw = json.loads(CATALOGUE_PATH.read_text(encoding="utf-8"))
    return {
        entry["name"]: ToolSpec(
            name=entry["name"],
            read_only=bool(entry.get("read_only")),
            default_enabled=bool(entry.get("default_enabled")),
        )
        for entry in raw.get("tools", [])
    }


def argument_fingerprint(arguments: Mapping[str, Any] | None) -> str:
    """A stable digest of the arguments a call was made with.

    An approval has to be for a call, not for a verb: approving "investigate
    case A" must not authorise "investigate case B". Canonical JSON with
    sorted keys so two clients that serialise in different orders produce the
    same fingerprint for the same call.
    """
    payload = json.dumps(arguments or {}, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Decision:
    """What the authorize route answers with."""

    #: ``allow`` | ``deny`` | ``approval_required``
    outcome: str
    reason: str
    #: Set when ``outcome`` is ``approval_required`` -- the row a human decides.
    approval_id: uuid.UUID | None = None
    required_permission: str = ""

    @property
    def allowed(self) -> bool:
        return self.outcome == "allow"


async def effective_tools(db: AsyncSession, tenant_id: uuid.UUID) -> list[dict[str, Any]]:
    """Every catalogued tool with this tenant's effective enablement.

    ``source`` says which decision produced the answer, because "on because
    nobody has thought about it" and "on because somebody turned it on" are
    different states and a console that renders them identically invites the
    operator to assume the second.
    """
    rows = (await db.execute(select(McpToolGrant).where(McpToolGrant.tenant_id == tenant_id))).scalars().all()
    grants = {row.tool_name: row for row in rows}
    out: list[dict[str, Any]] = []
    for spec in sorted(tool_catalogue().values(), key=lambda s: s.name):
        grant = grants.get(spec.name)
        out.append(
            {
                "name": spec.name,
                "read_only": spec.read_only,
                "enabled": grant.enabled if grant is not None else spec.default_enabled,
                "source": "tenant" if grant is not None else "default",
                "required_permission": spec.required_permission,
                "requires_approval": not spec.read_only,
                "decided_by": grant.decided_by if grant is not None else "",
            }
        )
    return out


async def _claim_approval(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    tool_name: str,
    fingerprint: str,
    *,
    requester_id: uuid.UUID | None,
    requested_by: str,
) -> tuple[uuid.UUID, str | None] | None:
    """Spend one approved, unexpired approval for exactly this call, or None.

    Spent rather than left standing: an approver is deciding about a call, and
    a grant that outlives the call it was given for is a permission nobody
    agreed to.

    **The lock is the fix** (GHSA-xhmc-69rh-h3rr, F12). This was the same
    select-then-write with no ``with_for_update``: two calls racing resolved
    the *same* row and both were told ``allow``, so one approval authorised
    more than one tool call. ``skip_locked`` rather than a plain row lock
    because the loser should be refused, not queued -- waiting for the winner
    to commit and then spending the row as well is the identical defect with a
    delay in front of it, and that is what the live race asserts.

    ``skip_locked`` is a no-op on SQLite, which the offline suite runs on and
    where there is no concurrency to lose. The property is proved against real
    Postgres in ``tests/isolation/test_mcp_approval_governance_live.py``.

    The requester predicate is the second half. The old one was tenant + tool
    + fingerprint, with no requester at all, so an approval granted for one
    principal's call was spendable by *any* principal in the tenant holding
    the permission. An approval is for a call, by a caller, once. Rows
    predating migration 158 carry no requester id and fall back to the label,
    which is what ``authorize`` has always written -- matching on the id alone
    would have made every one of them unspendable.
    """
    owned = McpToolApproval.requested_by == requested_by
    if requester_id is not None:
        owned = or_(
            McpToolApproval.requested_by_user_id == requester_id,
            and_(McpToolApproval.requested_by_user_id.is_(None), McpToolApproval.requested_by == requested_by),
        )

    approval = (
        await db.execute(
            select(McpToolApproval)
            .where(
                McpToolApproval.tenant_id == tenant_id,
                McpToolApproval.tool_name == tool_name,
                McpToolApproval.argument_fingerprint == fingerprint,
                McpToolApproval.state == "approved",
                McpToolApproval.expires_at > datetime.now(UTC),
                owned,
            )
            .order_by(McpToolApproval.created_at.desc())
            .limit(1)
            .with_for_update(skip_locked=True)
        )
    ).scalar_one_or_none()
    if approval is None:
        return None

    approval.state = "consumed"
    await db.flush()
    return (approval.id, approval.decided_by)


async def authorize(
    *,
    db: AsyncSession,
    tenant_id: uuid.UUID,
    tool_name: str,
    arguments: Mapping[str, Any] | None,
    has_permission: Any,
    requested_by: str,
    requested_by_user_id: uuid.UUID | None = None,
) -> Decision:
    """Answer the three questions in the module docstring, in that order.

    ``has_permission`` is a callable taking a permission string -- the
    principal's own check, passed in rather than reached for, so this module
    stays testable without a request and cannot accidentally consult a
    different authorization path than the routes do.

    ``requested_by`` is the credential label, for display. ``requested_by_user_id``
    is the *person*, and is what separation of duties later compares -- an API
    key resolves to its owning user, so one human is one id across both
    credentials (GHSA-xhmc-69rh-h3rr, F10).
    """
    spec = tool_catalogue().get(tool_name)
    if spec is None:
        # Not a refusal to be fixed by granting something. The catalogue is
        # generated from the registry, so an unknown name means the caller is
        # asking for a tool this deployment does not serve.
        return Decision(outcome="deny", reason=f"Unknown tool: {tool_name}")

    permission = spec.required_permission
    if not permission:
        return Decision(
            outcome="deny",
            reason=(
                f"{tool_name} has no permission mapped in TOOL_PERMISSIONS, so nothing "
                "decides what a key must hold to call it. Refusing rather than defaulting."
            ),
        )
    if not has_permission(permission):
        return Decision(
            outcome="deny",
            reason=f"The presented credential does not carry {permission}.",
            required_permission=permission,
        )

    grant = (
        await db.execute(
            select(McpToolGrant).where(
                McpToolGrant.tenant_id == tenant_id,
                McpToolGrant.tool_name == tool_name,
            )
        )
    ).scalar_one_or_none()
    enabled = grant.enabled if grant is not None else spec.default_enabled
    if not enabled:
        where = "disabled for this tenant" if grant is not None else "off by default because it is not read-only"
        return Decision(
            outcome="deny",
            reason=f"{tool_name} is {where}. A tenant administrator enables it at /api/v1/mcp/tools.",
            required_permission=permission,
        )

    if spec.read_only:
        return Decision(outcome="allow", reason="read-only tool", required_permission=permission)

    fingerprint = argument_fingerprint(arguments)
    claimed = await _claim_approval(
        db,
        tenant_id,
        tool_name,
        fingerprint,
        requester_id=requested_by_user_id,
        requested_by=requested_by,
    )
    if claimed is not None:
        approval_id, decided_by = claimed
        return Decision(
            outcome="allow",
            reason=f"approved by {decided_by or 'an approver'}",
            approval_id=approval_id,
            required_permission=permission,
        )

    pending = (
        await db.execute(
            select(McpToolApproval)
            .where(
                McpToolApproval.tenant_id == tenant_id,
                McpToolApproval.tool_name == tool_name,
                McpToolApproval.argument_fingerprint == fingerprint,
                McpToolApproval.state == "pending",
                McpToolApproval.expires_at > datetime.now(UTC),
            )
            .order_by(McpToolApproval.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    if pending is None:
        pending = McpToolApproval(
            tenant_id=tenant_id,
            tool_name=tool_name,
            argument_fingerprint=fingerprint,
            requested_by=requested_by,
            requested_by_user_id=requested_by_user_id,
            state="pending",
            expires_at=datetime.now(UTC) + APPROVAL_TTL,
        )
        db.add(pending)
        await db.flush()

    return Decision(
        outcome="approval_required",
        reason=(
            f"{tool_name} is not read-only, so a bearer credential is not enough. "
            f"Approval {pending.id} is waiting at /api/v1/mcp/approvals."
        ),
        approval_id=pending.id,
        required_permission=permission,
    )
