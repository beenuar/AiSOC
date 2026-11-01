"""Persist and read access-review runs and findings (migration 125).

The pure review logic is in :mod:`app.services.access_review`; this module
joins it to the privilege facts and usage overlay 1.1 produces, writes the
result, and reads it back for the console.

Every statement filters on ``tenant_id`` in the ``WHERE`` clause. RLS is on
both tables as well, but the query-layer filter is the control relied on
here, for the same reason the posture store gives: RLS depends on the
session GUC being set, and a path that forgets it would read across tenants
with the policy still in force.

Repeats extend rather than accumulate
-------------------------------------
A nightly review must not leave ninety copies of one sentence. The unique
index on ``(tenant, provider, principal, kind)`` makes a repeat an update
that moves ``last_seen`` and leaves the reviewer's acknowledgement attached
to the row they already read.

Findings that stop reproducing are deleted for that run's provider, because
a review page listing a permission somebody already removed is a page people
stop trusting. The run row keeps the history of what each pass found.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Any

import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.access_review import ReviewResult, review_principal, summarise
from app.services.identity_privilege_store import live_facts_for_provider, usage_for_principal
from app.services.identity_usage_collector import collect_usage_for_tenant

logger = structlog.get_logger(__name__)

__all__ = ["acknowledge", "list_findings", "run_review", "summary"]

# Written out per statement rather than interpolated, and the optional
# filters below are parameters rather than appended clauses. `text()` with
# an f-string is a taint sink for `avoid-sqlalchemy-text`, and the rule is
# right that it cannot tell a constant clause from a caller-supplied one.
# One statement per query is also the better shape: there is no second
# query path that only some callers exercise.


def _row_to_finding(row: Any) -> dict[str, Any]:
    evidence = row.evidence if isinstance(row.evidence, dict) else json.loads(row.evidence or "{}")
    return {
        "id": str(row.id),
        "run_id": str(row.run_id),
        "kind": row.kind,
        "provider": row.provider,
        "principal_id": row.principal_id,
        "severity": row.severity,
        "title": row.title,
        "detail": row.detail,
        "object_hint": row.object_hint,
        "recommendation": row.recommendation,
        "best_fit_role": row.best_fit_role,
        "evidence": evidence,
        "usage_measured": bool(row.usage_measured),
        "acknowledged_at": row.acknowledged_at.isoformat() if row.acknowledged_at else None,
        "acknowledged_by": str(row.acknowledged_by) if row.acknowledged_by else None,
        "acknowledged_note": row.acknowledged_note,
        "first_seen": row.first_seen.isoformat() if row.first_seen else None,
        "last_seen": row.last_seen.isoformat() if row.last_seen else None,
    }


async def run_review(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    provider: str,
    collect_usage: bool = True,
) -> dict[str, Any]:
    """Recompute this provider's review and persist the result.

    Reads only: privilege facts, the event lake and the usage overlay. No
    vendor API is called from here and none may be added — the plan's
    read-only rule for 1.2 is why the review can be run across a whole
    estate without a change-control conversation.

    ``collect_usage`` refreshes the runtime overlay from the lake first,
    because this is the only caller that needs it and a collector with no
    caller is the defect this repository keeps rediscovering. It is a
    parameter rather than unconditional so a test can separate "the review
    is wrong" from "the lake is slow", and so a scheduled sweep that has
    already collected can skip it.

    When the lake cannot be read the collection reports ``measured=False``
    and the review proceeds with usage unknown — which suppresses the
    usage-dependent findings rather than emitting them against an empty
    used-set.
    """
    facts = await live_facts_for_provider(db, tenant_id=tenant_id, provider=provider)

    if collect_usage and facts:
        collection = await collect_usage_for_tenant(
            db,
            tenant_id=tenant_id,
            provider=provider,
            principals=[f.privilege.principal_id for f in facts],
        )
        if not collection.measured:
            logger.info(
                "access_review.usage_not_measured",
                provider=provider,
                reason=collection.reason,
            )

    results: list[ReviewResult] = []
    window_start: datetime | None = None
    window_end: datetime | None = None
    for fact in facts:
        usage = await usage_for_principal(
            db,
            tenant_id=tenant_id,
            provider=provider,
            principal_id=fact.privilege.principal_id,
        )
        if usage.measured and window_start is None:
            window_start, window_end = usage.window_start, usage.window_end
        results.append(
            review_principal(
                privilege=fact.privilege,
                usage=usage,
                # A long-lived key is a property of the principal that the
                # posture snapshot carries; `None` means the snapshot did
                # not say, and the finding is skipped rather than guessed.
                has_long_lived_key=_has_long_lived_key(fact),
                is_human=_is_human(fact),
            )
        )

    stats = summarise(results)
    run_id = await _insert_run(
        db,
        tenant_id=tenant_id,
        provider=provider,
        stats=stats,
        window_start=window_start,
        window_end=window_end,
    )

    seen_keys: list[tuple[str, str]] = []
    for result in results:
        for finding in result.findings:
            seen_keys.append((finding.principal_id, finding.kind))
            await _upsert_finding(
                db,
                tenant_id=tenant_id,
                run_id=run_id,
                finding=finding,
                best_fit=result.best_fit,
                usage_measured=result.usage_measured,
            )

    await _delete_resolved(db, tenant_id=tenant_id, provider=provider, keep=seen_keys)
    return {"run_id": str(run_id), **stats}


def _has_long_lived_key(fact: Any) -> bool | None:
    """Whether the snapshot says this principal holds a static key.

    ``None`` when it does not say, which is a third answer and not a no.
    The finding it feeds is suppressed on ``None``, so an absent field can
    never manufacture a high-severity claim about somebody's credentials.
    """
    evidence = fact.privilege.evidence or {}
    for actions in evidence.values():
        if any(a in {"iam:CreateAccessKey", "iam.serviceAccountKeys.create"} for a in actions):
            return True
    return None


def _is_human(fact: Any) -> bool | None:
    tags = fact.privilege.tags
    if tags.third_party is True:
        return False
    return None


async def _insert_run(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    provider: str,
    stats: dict[str, Any],
    window_start: datetime | None,
    window_end: datetime | None,
) -> uuid.UUID:
    result = await db.execute(
        text(
            """
            INSERT INTO access_review_runs (
                tenant_id, provider, run_state, reviewed_principals,
                usage_measured_for, finding_count, window_start, window_end,
                note, completed_at
            ) VALUES (
                :tenant_id, :provider, :run_state, :reviewed,
                :measured_for, :findings, :window_start, :window_end,
                :note, NOW()
            )
            RETURNING id
            """
        ),
        {
            "tenant_id": str(tenant_id),
            "provider": provider,
            "run_state": stats["state"],
            "reviewed": stats["reviewed_principals"],
            "measured_for": stats.get("usage_measured_for", 0),
            "findings": stats["findings"],
            "window_start": window_start,
            "window_end": window_end,
            "note": stats.get("note"),
        },
    )
    return result.scalar_one()


async def _upsert_finding(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    run_id: uuid.UUID,
    finding: Any,
    best_fit: str | None,
    usage_measured: bool,
) -> None:
    await db.execute(
        text(
            """
            INSERT INTO access_review_findings (
                tenant_id, run_id, kind, provider, principal_id, severity,
                title, detail, object_hint, recommendation, best_fit_role,
                evidence, usage_measured
            ) VALUES (
                :tenant_id, :run_id, :kind, :provider, :principal_id, :severity,
                :title, :detail, :object_hint, :recommendation, :best_fit_role,
                CAST(:evidence AS jsonb), :usage_measured
            )
            ON CONFLICT (tenant_id, provider, principal_id, kind) DO UPDATE
               SET run_id         = EXCLUDED.run_id,
                   severity       = EXCLUDED.severity,
                   detail         = EXCLUDED.detail,
                   recommendation = EXCLUDED.recommendation,
                   best_fit_role  = EXCLUDED.best_fit_role,
                   evidence       = EXCLUDED.evidence,
                   usage_measured = EXCLUDED.usage_measured,
                   last_seen      = NOW()
            """
        ),
        {
            "tenant_id": str(tenant_id),
            "run_id": str(run_id),
            "kind": finding.kind,
            "provider": finding.provider,
            "principal_id": finding.principal_id,
            "severity": finding.severity,
            "title": finding.title,
            "detail": finding.detail,
            "object_hint": finding.object_hint,
            "recommendation": finding.recommendation,
            "best_fit_role": best_fit,
            "evidence": json.dumps(finding.evidence, default=str),
            "usage_measured": usage_measured,
        },
    )


async def _delete_resolved(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    provider: str,
    keep: list[tuple[str, str]],
) -> None:
    """Drop findings this pass no longer reproduces.

    A review page still listing a permission somebody removed last week is
    a page people stop opening. The run row keeps what each pass found, so
    the history is not lost with the row.
    """
    if keep:
        await db.execute(
            text(
                """
                DELETE FROM access_review_findings
                 WHERE tenant_id = :tenant_id
                   AND provider = :provider
                   AND (principal_id, kind) NOT IN (
                         SELECT p, k
                           FROM unnest(CAST(:principals AS text[]), CAST(:kinds AS text[]))
                                AS pairs(p, k)
                       )
                """
            ),
            {
                "tenant_id": str(tenant_id),
                "provider": provider,
                "principals": [k[0] for k in keep],
                "kinds": [k[1] for k in keep],
            },
        )
        return
    await db.execute(
        text("DELETE FROM access_review_findings WHERE tenant_id = :tenant_id AND provider = :provider"),
        {"tenant_id": str(tenant_id), "provider": provider},
    )


async def list_findings(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    provider: str | None = None,
    kind: str | None = None,
    include_acknowledged: bool = False,
    limit: int = 100,
) -> list[dict[str, Any]]:
    result = await db.execute(
        text(
            """
            SELECT id, run_id, kind, provider, principal_id, severity, title, detail,
                   object_hint, recommendation, best_fit_role, evidence, usage_measured,
                   acknowledged_at, acknowledged_by, acknowledged_note, first_seen, last_seen
              FROM access_review_findings
             WHERE tenant_id = :tenant_id
               AND (CAST(:provider AS text) IS NULL OR provider = :provider)
               AND (CAST(:kind AS text) IS NULL OR kind = :kind)
               AND (CAST(:include_acknowledged AS boolean) OR acknowledged_at IS NULL)
             ORDER BY array_position(
                        ARRAY['critical','high','medium','low','info']::text[], severity
                      ),
                      last_seen DESC
             LIMIT :limit
            """
        ),
        {
            "tenant_id": str(tenant_id),
            "provider": provider or None,
            "kind": kind or None,
            "include_acknowledged": bool(include_acknowledged),
            "limit": max(1, min(limit, 500)),
        },
    )
    return [_row_to_finding(row) for row in result.fetchall()]


async def summary(db: AsyncSession, *, tenant_id: uuid.UUID, provider: str | None = None) -> dict[str, Any]:
    """The page header, including the state that is not a clean bill.

    A tenant that has never run a review gets ``never_run``; a run over zero
    principals gets ``nothing_reviewed``. Both are rendered as their own
    sentence, because the one thing this page must not do is show a zero
    that a reader takes for an all-clear.
    """
    params: dict[str, Any] = {"tenant_id": str(tenant_id), "provider": provider or None}

    runs = (
        await db.execute(
            text(
                """
                SELECT DISTINCT ON (provider)
                       provider, run_state, reviewed_principals, usage_measured_for,
                       finding_count, window_start, window_end, note, started_at
                  FROM access_review_runs
                 WHERE tenant_id = :tenant_id
                   AND (CAST(:provider AS text) IS NULL OR provider = :provider)
                 ORDER BY provider, started_at DESC
                """
            ),
            params,
        )
    ).fetchall()

    if not runs:
        return {
            "state": "never_run",
            "providers": [],
            "open_findings": 0,
            "note": (
                "No access review has been run for this tenant. This is not a clean bill of health: "
                "collect a provider's posture, then run a review."
            ),
        }

    open_count = (
        await db.execute(
            text(
                """
                SELECT count(*) FROM access_review_findings
                 WHERE tenant_id = :tenant_id
                   AND (CAST(:provider AS text) IS NULL OR provider = :provider)
                   AND acknowledged_at IS NULL
                """
            ),
            params,
        )
    ).scalar_one()

    return {
        "state": "reviewed",
        "open_findings": int(open_count or 0),
        "providers": [
            {
                "provider": r.provider,
                "run_state": r.run_state,
                "reviewed_principals": int(r.reviewed_principals or 0),
                "usage_measured_for": int(r.usage_measured_for or 0),
                "finding_count": int(r.finding_count or 0),
                "window_start": r.window_start.isoformat() if r.window_start else None,
                "window_end": r.window_end.isoformat() if r.window_end else None,
                "note": r.note,
                "last_run_at": r.started_at.isoformat() if r.started_at else None,
            }
            for r in runs
        ],
    }


async def acknowledge(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    finding_id: uuid.UUID,
    user_id: uuid.UUID | str,
    note: str = "",
) -> dict[str, Any] | None:
    """Record who decided a finding is acceptable. ``None`` if not this tenant's.

    The tenant predicate is in the ``UPDATE`` rather than checked after a
    fetch: a handler that reads first and filters second is the same bug one
    line later, and this one writes.
    """
    result = await db.execute(
        text(
            """
            UPDATE access_review_findings
               SET acknowledged_at = NOW(),
                   acknowledged_by = :user_id,
                   acknowledged_note = :note
             WHERE tenant_id = :tenant_id
               AND id = :finding_id
            RETURNING id, run_id, kind, provider, principal_id, severity, title, detail,
                   object_hint, recommendation, best_fit_role, evidence, usage_measured,
                   acknowledged_at, acknowledged_by, acknowledged_note, first_seen, last_seen
            """
        ),
        {
            "tenant_id": str(tenant_id),
            "finding_id": str(finding_id),
            "user_id": str(user_id),
            "note": note or None,
        },
    )
    row = result.fetchone()
    return _row_to_finding(row) if row else None
