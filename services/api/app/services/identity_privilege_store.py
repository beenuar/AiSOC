"""Read and write derived privilege facts and the runtime-usage overlay.

Backs migration 124. The pure derivation lives in
:mod:`app.services.identity_privilege`; this module is the only thing that
writes the two tables, and it exists to keep the same two invariants the
posture store keeps one file over:

* at most one row per ``(tenant, provider, principal)`` has
  ``valid_until IS NULL``;
* the point-in-time read is the easy call to reach for, so a caller asking
  "what could this identity do when it acted" does not quietly get "what can
  it do now" because that query was shorter to write.

Every statement filters on ``tenant_id`` in the ``WHERE`` clause. RLS is on
the tables too, but the query-layer filter is the control relied on here: a
path that forgets the session GUC would read across tenants with the policy
still in force.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.identity_privilege import UNKNOWN_PRIVILEGE, IdentityPrivilege, PrivilegeTags

logger = structlog.get_logger(__name__)

__all__ = [
    "PrivilegeFact",
    "UsageOverlay",
    "live_facts_for_provider",
    "privilege_at",
    "record_usage",
    "save_privilege",
    "usage_for_principal",
]

_FACT_COLUMNS = """
    id, tenant_id, provider, principal_id, principal_label, principal_kind,
    tier, can_escalate, data_access, third_party, cross_account,
    evidence, action_count, resource_count, snapshot_id, resolver_version,
    partial_source, valid_from, valid_until
"""


@dataclass(frozen=True)
class PrivilegeFact:
    """A stored fact plus the interval over which it was true."""

    privilege: IdentityPrivilege
    principal_label: str | None
    valid_from: datetime
    valid_until: datetime | None
    snapshot_id: uuid.UUID | None

    @property
    def is_live(self) -> bool:
        return self.valid_until is None


@dataclass(frozen=True)
class UsageOverlay:
    """Which granted actions were exercised, and over what window.

    ``measured`` is the field that stops this from becoming a right-sizing
    disaster. An install with no lake returns ``measured=False`` and an empty
    ``used`` set, and a caller that treats the two the same recommends
    revoking every permission in the estate.
    """

    measured: bool
    used: dict[str, datetime | None]
    window_start: datetime | None = None
    window_end: datetime | None = None
    source: str = "lake"

    def unused(self, granted: set[str]) -> set[str] | None:
        """Granted-but-unexercised, or ``None`` when usage was not measured."""
        if not self.measured:
            return None
        return granted - set(self.used)


def _bool_or_none(value: Any) -> bool | None:
    return None if value is None else bool(value)


def _row_to_fact(row: Any) -> PrivilegeFact:
    evidence = row.evidence if isinstance(row.evidence, dict) else json.loads(row.evidence or "{}")
    return PrivilegeFact(
        privilege=IdentityPrivilege(
            tier=row.tier,
            tags=PrivilegeTags(
                can_escalate=_bool_or_none(row.can_escalate),
                data_access=_bool_or_none(row.data_access),
                third_party=_bool_or_none(row.third_party),
                cross_account=_bool_or_none(row.cross_account),
            ),
            provider=row.provider,
            principal_id=row.principal_id,
            evidence={k: list(v) for k, v in evidence.items() if isinstance(v, list)},
            action_count=int(row.action_count or 0),
            resource_count=int(row.resource_count or 0),
            partial_source=bool(row.partial_source),
        ),
        principal_label=row.principal_label,
        valid_from=row.valid_from,
        valid_until=row.valid_until,
        snapshot_id=row.snapshot_id,
    )


async def save_privilege(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    privilege: IdentityPrivilege,
    principal_label: str | None = None,
    principal_kind: str | None = None,
    snapshot_id: uuid.UUID | None = None,
    resolver_version: str = "",
) -> PrivilegeFact:
    """Record a derivation, opening a new version only when something changed.

    Same reasoning as ``posture_store.save_snapshot``: a collector running
    hourly against an estate nobody changed must not write a version an hour,
    or "when did this identity's privilege last change" -- the question every
    one of these rows exists to answer -- becomes unanswerable.

    Equality is on the facts, not on the snapshot hash: two different posture
    documents can derive the same tier and tags, and that is not a privilege
    change.
    """
    live = await _live_fact(db, tenant_id=tenant_id, provider=privilege.provider, principal_id=privilege.principal_id)

    if live is not None and _same_facts(live.privilege, privilege) and live.principal_label == principal_label:
        return live

    if live is not None:
        await db.execute(
            text(
                """
                UPDATE identity_privilege_facts
                   SET valid_until = NOW()
                 WHERE tenant_id = :tenant_id
                   AND provider = :provider
                   AND principal_id = :principal_id
                   AND valid_until IS NULL
                """
            ),
            {
                "tenant_id": str(tenant_id),
                "provider": privilege.provider,
                "principal_id": privilege.principal_id,
            },
        )

    result = await db.execute(
        text(
            f"""
            INSERT INTO identity_privilege_facts (
                tenant_id, provider, principal_id, principal_label, principal_kind,
                tier, can_escalate, data_access, third_party, cross_account,
                evidence, action_count, resource_count, snapshot_id, resolver_version,
                partial_source
            ) VALUES (
                :tenant_id, :provider, :principal_id, :principal_label, :principal_kind,
                :tier, :can_escalate, :data_access, :third_party, :cross_account,
                CAST(:evidence AS jsonb), :action_count, :resource_count, :snapshot_id,
                :resolver_version, :partial_source
            )
            RETURNING {_FACT_COLUMNS}
            """
        ),
        {
            "tenant_id": str(tenant_id),
            "provider": privilege.provider,
            "principal_id": privilege.principal_id,
            "principal_label": principal_label,
            "principal_kind": principal_kind,
            "tier": privilege.tier,
            "can_escalate": privilege.tags.can_escalate,
            "data_access": privilege.tags.data_access,
            "third_party": privilege.tags.third_party,
            "cross_account": privilege.tags.cross_account,
            "evidence": json.dumps(privilege.evidence, default=str),
            "action_count": privilege.action_count,
            "resource_count": privilege.resource_count,
            "snapshot_id": str(snapshot_id) if snapshot_id else None,
            "resolver_version": resolver_version,
            "partial_source": privilege.partial_source,
        },
    )
    return _row_to_fact(result.fetchone())


def _same_facts(left: IdentityPrivilege, right: IdentityPrivilege) -> bool:
    return (
        left.tier == right.tier
        and left.tags == right.tags
        and left.evidence == right.evidence
        and left.action_count == right.action_count
        and left.partial_source == right.partial_source
    )


async def _live_fact(db: AsyncSession, *, tenant_id: uuid.UUID, provider: str, principal_id: str) -> PrivilegeFact | None:
    result = await db.execute(
        text(
            f"""
            SELECT {_FACT_COLUMNS}
              FROM identity_privilege_facts
             WHERE tenant_id = :tenant_id
               AND provider = :provider
               AND principal_id = :principal_id
               AND valid_until IS NULL
             LIMIT 1
            """
        ),
        {"tenant_id": str(tenant_id), "provider": provider, "principal_id": principal_id},
    )
    row = result.fetchone()
    return _row_to_fact(row) if row else None


async def privilege_at(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    principal_id: str,
    at: datetime,
    provider: str | None = None,
) -> PrivilegeFact | None:
    """The fact that was in force at ``at``, by id or by label.

    ``provider`` is optional because an alert rarely names one: it carries a
    username and the platform has to find whichever provider knows it. When
    several do, the strongest tier wins -- a person who is a standard Okta
    user and an AWS administrator is an administrator for the purposes of
    deciding what an alert about them means.

    Returns ``None`` when nothing covers ``at``. Falling back to the live row
    would answer a question nobody asked in a way no reader could detect,
    which is the exact failure migration 103 is versioned to prevent.
    """
    clauses = [
        "tenant_id = :tenant_id",
        "valid_from <= :at",
        "(valid_until IS NULL OR valid_until > :at)",
        "(principal_id = :principal_id OR lower(principal_label) = lower(:principal_id))",
    ]
    params: dict[str, Any] = {
        "tenant_id": str(tenant_id),
        "principal_id": principal_id,
        "at": at,
    }
    if provider:
        clauses.append("provider = :provider")
        params["provider"] = provider

    result = await db.execute(
        text(
            f"""
            SELECT {_FACT_COLUMNS}
              FROM identity_privilege_facts
             WHERE {" AND ".join(clauses)}
             ORDER BY array_position(
                        ARRAY['unknown','standard','elevated','admin','domain_admin']::text[], tier
                      ) DESC,
                      valid_from DESC
             LIMIT 1
            """
        ),
        params,
    )
    row = result.fetchone()
    return _row_to_fact(row) if row else None


async def live_facts_for_provider(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    provider: str,
    limit: int = 2000,
) -> list[PrivilegeFact]:
    """Every live fact for one provider — the access review's scan."""
    result = await db.execute(
        text(
            f"""
            SELECT {_FACT_COLUMNS}
              FROM identity_privilege_facts
             WHERE tenant_id = :tenant_id
               AND provider = :provider
               AND valid_until IS NULL
             ORDER BY principal_id
             LIMIT :limit
            """
        ),
        {"tenant_id": str(tenant_id), "provider": provider, "limit": max(1, min(limit, 10000))},
    )
    return [_row_to_fact(row) for row in result.fetchall()]


async def record_usage(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    provider: str,
    principal_id: str,
    observations: dict[str, tuple[int, datetime | None, datetime | None]],
    window_start: datetime,
    window_end: datetime,
    source: str = "lake",
) -> int:
    """Upsert one principal's observed actions for a window.

    ``observations`` maps action to ``(count, first_used, last_used)``.
    Returns the number of rows written. An empty mapping writes nothing and
    returns 0 -- which is correct, and is also why the *caller* has to record
    whether it measured at all: this function cannot tell "the principal used
    nothing" from "the lake was unreachable", and neither can its rows.
    """
    if not observations:
        return 0

    written = 0
    for action, (count, first_used, last_used) in observations.items():
        await db.execute(
            text(
                """
                INSERT INTO identity_permission_usage (
                    tenant_id, provider, principal_id, action,
                    use_count, first_used_at, last_used_at,
                    window_start, window_end, source
                ) VALUES (
                    :tenant_id, :provider, :principal_id, :action,
                    :use_count, :first_used_at, :last_used_at,
                    :window_start, :window_end, :source
                )
                ON CONFLICT (tenant_id, provider, principal_id, action) DO UPDATE
                   SET use_count     = EXCLUDED.use_count,
                       first_used_at = LEAST(
                           identity_permission_usage.first_used_at, EXCLUDED.first_used_at
                       ),
                       last_used_at  = GREATEST(
                           identity_permission_usage.last_used_at, EXCLUDED.last_used_at
                       ),
                       window_start  = EXCLUDED.window_start,
                       window_end    = EXCLUDED.window_end,
                       source        = EXCLUDED.source,
                       computed_at   = NOW()
                """
            ),
            {
                "tenant_id": str(tenant_id),
                "provider": provider,
                "principal_id": principal_id,
                "action": action,
                "use_count": int(count),
                "first_used_at": first_used,
                "last_used_at": last_used,
                "window_start": window_start,
                "window_end": window_end,
                "source": source,
            },
        )
        written += 1
    return written


async def usage_for_principal(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    provider: str,
    principal_id: str,
) -> UsageOverlay:
    """What this principal exercised, or an honest "not measured".

    No rows means no observation was ever recorded for this principal, and
    this function says so with ``measured=False`` rather than returning an
    empty used-set that a caller would read as "used nothing".
    """
    result = await db.execute(
        text(
            """
            SELECT action, last_used_at, window_start, window_end, source
              FROM identity_permission_usage
             WHERE tenant_id = :tenant_id
               AND provider = :provider
               AND principal_id = :principal_id
            """
        ),
        {"tenant_id": str(tenant_id), "provider": provider, "principal_id": principal_id},
    )
    rows = result.fetchall()
    if not rows:
        return UsageOverlay(measured=False, used={})
    return UsageOverlay(
        measured=True,
        used={row.action: row.last_used_at for row in rows},
        window_start=rows[0].window_start,
        window_end=rows[0].window_end,
        source=rows[0].source,
    )


def privilege_or_unknown(fact: PrivilegeFact | None) -> IdentityPrivilege:
    """``fact.privilege`` or the unknown singleton — never a default tier."""
    return fact.privilege if fact is not None else UNKNOWN_PRIVILEGE
