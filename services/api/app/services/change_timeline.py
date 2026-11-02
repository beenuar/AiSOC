"""What changed before this alert (depth plan wave 2, Phase 1.5).

The first question an analyst asks about an identity alert is what changed
in the days before it: a role granted, a policy edited, an OAuth app
consented to, an MFA factor replaced, a share opened, a key created. Both
halves of the answer already exist in the platform and nothing joined them:

* **versioned posture** (`posture_snapshots`, migration 103, and the derived
  `identity_privilege_facts`, migration 124) — a diff between consecutive
  versions is a record of grants and policy edits with the exact interval
  each was true over;
* **audit events** in the lake — the vendor's own record of the change
  event, with the actor who made it.

They answer differently and are both kept. Posture says *what the estate
looked like* and is complete for the providers collected; audit says *who
did it and when*, and is complete only for the sources ingested. A timeline
built from one alone is missing either the attribution or the coverage.

Two honesty properties the result shape enforces
------------------------------------------------
**"Nothing changed" and "we could not read it" are different answers.**
:class:`ChangeTimeline` carries ``sources_read``, and ``measured`` is false
when it is empty. An empty list with no such field would turn a lake outage
into evidence of a quiet week, and an investigation closes on that.

**Every change names its source.** A citation whose target nobody can find
is not a citation, so each row carries the store it came from and a
reference into it. This is what makes the ledger entry checkable rather
than a sentence the model was handed.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.clickhouse import execute_lake_query
from app.services.posture_store import PROVIDERS, snapshot_history

logger = structlog.get_logger(__name__)

__all__ = [
    "CHANGE_KINDS",
    "DEFAULT_WINDOW_DAYS",
    "ChangeTimeline",
    "IdentityChange",
    "changes_before",
]

#: Lake table, spelled exactly as `investigation_tools` spells it. The
#: raw-SQL gate declares `aisoc.raw_events` as ClickHouse-owned in its
#: `UNMIGRATED_TABLES` list, which is what lets a statement against it be
#: compared against no migration without the gate silently excusing the
#: whole class of unknown tables.
LAKE_TABLE = "aisoc.raw_events"

#: How far back to look. Seven days by default: long enough to cover a
#: grant made the previous working week, short enough that the answer is a
#: list a person reads rather than a change log they scroll.
DEFAULT_WINDOW_DAYS = 7
MAX_WINDOW_DAYS = 90
MAX_CHANGES = 200

#: The six kinds the plan names, each with the vendor actions that produce
#: it. Matched case-insensitively against the lake's normalised `action`.
#:
#: Deliberately a closed vocabulary rather than a "contains the word
#: policy" heuristic: a timeline that silently reclassifies an unfamiliar
#: action is worse than one that reports it as `other`, because a reader
#: cannot tell which rows were understood.
CHANGE_KINDS: dict[str, tuple[str, ...]] = {
    "role_or_group_grant": (
        "AddUserToGroup",
        "AttachUserPolicy",
        "AttachRolePolicy",
        "AttachGroupPolicy",
        "CreateRole",
        "AddRoleToInstanceProfile",
        "roleAssignments/write",
        "Add member to role",
        "SetIamPolicy",
        "setIamPolicy",
        "group.user_membership.add",
        "user.account.privilege.grant",
        "ASSIGN_ROLE",
        "GRANT_ADMIN_PRIVILEGE",
        "team.add_member",
        "org.add_member",
        "org.update_member",
    ),
    "policy_edit": (
        "PutUserPolicy",
        "PutRolePolicy",
        "PutGroupPolicy",
        "CreatePolicyVersion",
        "SetDefaultPolicyVersion",
        "UpdateAssumeRolePolicy",
        "PutBucketPolicy",
        "policyAssignments/write",
        "roleDefinitions/write",
        "iam.roles.update",
        "policy.lifecycle.update",
        "protected_branch.policy_override",
    ),
    "oauth_consent": (
        "Consent to application",
        "Add app role assignment grant to user",
        "authorize",
        "oauth2.grant",
        "app.oauth2.client.create",
        "AUTHORIZE_API_CLIENT_ACCESS",
        "oauth_application.create",
        "integration_installation.create",
    ),
    "mfa_factor_change": (
        "User registered security info",
        "Update user",
        "user.mfa.factor.activate",
        "user.mfa.factor.reset_all",
        "user.mfa.factor.deactivate",
        "UNENROLL_2SV",
        "ENROLL_2SV",
        "two_factor_authentication.disabled",
        "two_factor_authentication.enabled",
    ),
    "sharing_change": (
        "PutBucketAcl",
        "PutObjectAcl",
        "storage.setIamPermissions",
        "CHANGE_DOCUMENT_VISIBILITY",
        "CHANGE_DOCUMENT_ACCESS_SCOPE",
        "CREATE_DATA_TRANSFER_REQUEST",
        "repo.access",
        "repo.change_merge_setting",
    ),
    "key_creation": (
        "CreateAccessKey",
        "CreateLoginProfile",
        "UpdateLoginProfile",
        "iam.serviceAccountKeys.create",
        "Add service principal credentials",
        "user.api_token.create",
        "personal_access_token.create",
        "public_key.create",
        "deploy_key.create",
    ),
}

#: Flattened once at import rather than per call. The lookup is per lake row.
_ACTION_TO_KIND: dict[str, str] = {action.lower(): kind for kind, actions in CHANGE_KINDS.items() for action in actions}


@dataclass(frozen=True)
class IdentityChange:
    """One recorded change, with where it was read from."""

    kind: str
    at: str
    subject: str
    summary: str
    #: Which store this came from: ``posture_snapshot`` or ``audit_event``.
    source: str
    #: A reference into that store a reviewer can follow.
    source_ref: str
    actor: str = ""
    detail: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "at": self.at,
            "subject": self.subject,
            "summary": self.summary,
            "actor": self.actor,
            "source": self.source,
            "source_ref": self.source_ref,
            "detail": dict(self.detail),
        }


@dataclass(frozen=True)
class ChangeTimeline:
    """The window's changes, and which stores could actually be read.

    ``measured`` is the field that stops an outage reading as a quiet week.
    """

    changes: list[IdentityChange] = field(default_factory=list)
    #: Which sources answered. Empty means nothing could be read, which is
    #: not the same as nothing having happened.
    sources_read: tuple[str, ...] = ()
    #: Which sources were asked and could not answer, with why.
    sources_failed: tuple[str, ...] = ()
    window_start: str | None = None
    window_end: str | None = None

    @property
    def measured(self) -> bool:
        return bool(self.sources_read)

    def as_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "measured": self.measured,
            "changes": [c.as_dict() for c in self.changes],
            "change_count": len(self.changes),
            "sources_read": list(self.sources_read),
            "sources_failed": list(self.sources_failed),
            "window_start": self.window_start,
            "window_end": self.window_end,
        }
        if not self.measured:
            payload["reason"] = (
                "No source could be read for this window, so whether anything changed is UNKNOWN. "
                "This is a gap in visibility, not evidence that nothing changed."
            )
        elif not self.changes:
            payload["reason"] = (
                f"Read {', '.join(self.sources_read)} over this window and found no recorded change. This is a measured result."
            )
        return payload


def _clamp_days(days: int | None) -> int:
    if not days or days < 1:
        return DEFAULT_WINDOW_DAYS
    return min(int(days), MAX_WINDOW_DAYS)


async def changes_before(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    subjects: list[str],
    at: datetime,
    days: int = DEFAULT_WINDOW_DAYS,
    providers: list[str] | None = None,
) -> ChangeTimeline:
    """Every recorded change touching ``subjects`` in the ``days`` before ``at``.

    Reads both stores and reports which answered. Never raises: a store that
    cannot be read lands in ``sources_failed`` and the caller can say so.
    """
    days = _clamp_days(days)
    window_start = at - timedelta(days=days)
    wanted = {s.strip().lower() for s in subjects if s and s.strip()}

    changes: list[IdentityChange] = []
    read: list[str] = []
    failed: list[str] = []

    posture = await _posture_changes(
        db,
        tenant_id=tenant_id,
        window_start=window_start,
        at=at,
        providers=providers or sorted(PROVIDERS),
    )
    if posture is None:
        failed.append("posture snapshots could not be read")
    else:
        read.append("posture snapshots")
        changes.extend(posture)

    audit = await _audit_changes(tenant_id=tenant_id, wanted=wanted, window_start=window_start, at=at)
    if audit is None:
        failed.append("the event lake could not be queried (it is a `full`-profile component)")
    else:
        read.append("audit events")
        changes.extend(audit)

    changes.sort(key=lambda c: c.at, reverse=True)
    return ChangeTimeline(
        changes=changes[:MAX_CHANGES],
        sources_read=tuple(read),
        sources_failed=tuple(failed),
        window_start=window_start.isoformat(),
        window_end=at.isoformat(),
    )


async def _posture_changes(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    window_start: datetime,
    at: datetime,
    providers: list[str],
) -> list[IdentityChange] | None:
    """Posture versions that opened inside the window.

    A new version exists only when the content hash moved, so every row here
    is a real posture change — which is the property migration 103 was
    designed for and the reason this is cheap.

    ``None`` means the store could not be read at all, which the caller
    reports rather than folding into "no changes".
    """
    out: list[IdentityChange] = []
    try:
        for provider in providers:
            for snapshot in await snapshot_history(db, tenant_id=tenant_id, provider=provider, limit=50):
                started = snapshot.valid_from
                if started.tzinfo is None:
                    started = started.replace(tzinfo=UTC)
                if not (window_start <= started <= at):
                    continue
                out.append(
                    IdentityChange(
                        kind="policy_edit",
                        at=started.isoformat(),
                        subject=f"{provider} estate",
                        summary=(f"{provider} posture changed: {snapshot.principal_count} principals, {snapshot.policy_count} policies"),
                        source="posture_snapshot",
                        source_ref=f"snapshot:{snapshot.content_hash[:16]}",
                        detail={
                            "provider": provider,
                            "principal_count": snapshot.principal_count,
                            "policy_count": snapshot.policy_count,
                            "partial": snapshot.partial,
                        },
                    )
                )
    except Exception as exc:  # noqa: BLE001 — an unreadable store is not an empty one
        logger.warning("change_timeline.posture_failed", error=type(exc).__name__)
        return None
    return out


async def _audit_changes(
    *,
    tenant_id: uuid.UUID,
    wanted: set[str],
    window_start: datetime,
    at: datetime,
) -> list[IdentityChange] | None:
    """Change-shaped audit events naming one of ``subjects``.

    The action vocabulary is closed (:data:`CHANGE_KINDS`). An unfamiliar
    action is simply not returned rather than guessed into a kind, because
    a reader cannot tell a guessed classification from a known one.
    """
    if not wanted:
        return []

    sql = f"""
        SELECT event_time, action, user_name, resource, event_id, connector_type
        FROM {LAKE_TABLE}
        WHERE tenant_id = %(tenant_id)s
          AND event_time >= %(window_start)s
          AND event_time <= %(window_end)s
          AND lower(action) IN %(actions)s
          AND (lower(user_name) IN %(subjects)s OR lower(resource) IN %(subjects)s)
        ORDER BY event_time DESC
        LIMIT %(limit)s
    """
    params = {
        "tenant_id": str(tenant_id),
        "window_start": window_start,
        "window_end": at,
        "actions": tuple(_ACTION_TO_KIND),
        "subjects": tuple(wanted),
        "limit": MAX_CHANGES,
    }

    try:
        result = await execute_lake_query(sql, params=params)
    except Exception as exc:  # noqa: BLE001
        logger.warning("change_timeline.lake_failed", error=type(exc).__name__)
        return None

    columns = list(result.columns or [])
    out: list[IdentityChange] = []
    for row in result.rows or ():
        record = dict(zip(columns, row, strict=False))
        action = str(record.get("action") or "")
        kind = _ACTION_TO_KIND.get(action.lower())
        if kind is None:
            continue
        when = record.get("event_time")
        out.append(
            IdentityChange(
                kind=kind,
                at=when.isoformat() if isinstance(when, datetime) else str(when),
                subject=str(record.get("resource") or record.get("user_name") or ""),
                summary=f"{action} by {record.get('user_name') or 'an unnamed actor'}",
                actor=str(record.get("user_name") or ""),
                source="audit_event",
                source_ref=f"event:{record.get('event_id') or ''}",
                detail={"connector_type": record.get("connector_type"), "action": action},
            )
        )
    return out
