"""Rolling agreement between the agent and the analysts who closed the same alerts.

Gap-closure Phase 2.2.

``services/agents`` writes a row to ``aisoc_shadow_decisions`` every time it
triages an alert for a tenant that is measuring rather than acting. That row
holds half a comparison. This module supplies the other half and then does the
arithmetic:

* :func:`reconcile_local_closures` copies an analyst's own closure off the
  ``alerts`` row onto the decision it should be graded against.
* :func:`agreement_for` runs the two aggregates from the shared rules module
  and returns the window plus the trailing drift slice.
* :func:`breakdown_for` runs the same aggregate grouped by class, rule, source
  and model, which is what the scorecard and the operations dashboard render.

Why the arithmetic is not here
==============================

Every rate on :class:`AgreementWindow` and both SQL statements live in
``app/_vendor/autonomy_evidence_rules.py``, a byte-identical copy of the
module ``services/actions`` enforces from. Recomputing an agreement rate here
would give the console one definition and the dispatch gate another, and the
two would only be discovered to differ when a tenant asked why the scorecard
said they qualified and the gate said they did not.

Why reconciliation is a sweep and not a hook
============================================

The obvious design puts a call on the disposition endpoint: analyst closes an
alert, the decision row updates. It would miss most closures. An alert can be
closed by the feedback endpoint, by a case being resolved, by a bulk action,
by a playbook, or in the source SIEM entirely, and a hook on one of those
paths silently grades a biased subset: the alerts closed the way the hook was
written for. A sweep over ``alerts`` asks the question the evidence actually
needs, which is "has anybody closed this yet, by any route".

A closure the platform cannot name
==================================

``alerts.disposition`` is free-ish text and only four values are gradeable.
Anything else becomes ``unlabeled``: recorded as resolved, excluded from every
rate. The alternative is to guess, and a guess here manufactures agreement out
of an analyst's shrug. A closure with no disposition at all is treated the
same way, because "closed, reason not recorded" is exactly that shrug.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from sqlalchemy import bindparam, text
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.types import Text

from app._vendor.autonomy_evidence_rules import (
    ABSTENTION_VERDICTS,
    AGREEMENT_COUNTS_SQL,
    GRADED_DISPOSITIONS,
    MALICIOUS,
    RECENT_COUNTS_SQL,
    UNLABELED,
    AgreementWindow,
    PromotionThresholds,
    scoped_sql,
    to_named_params,
    window_from_counts,
)

logger = structlog.get_logger(__name__)

__all__ = [
    "AgreementEvidence",
    "ScopeBreakdown",
    "WindowProvenance",
    "agreement_for",
    "breakdown_for",
    "reconcile_local_closures",
]


#: Parameters that carry a list and therefore need a declared type. Without it
#: SQLAlchemy binds a Python list as a scalar of unknown type and Postgres
#: refuses the comparison. Declaring it here rather than casting inside the
#: shared SQL keeps that statement identical for the asyncpg caller, which
#: infers the type from the column and needs no help.
_ARRAY_PARAMS = ("graded", "abstentions")


def _statement(sql: str):
    """``text()`` with whichever array parameters this statement actually binds.

    Only the ones present, because ``bindparams`` raises on a name the
    statement does not contain: the reconcile sweep binds ``graded`` and not
    ``abstentions``, and declaring both unconditionally took it down.
    """
    declared = [bindparam(name, type_=ARRAY(Text)) for name in _ARRAY_PARAMS if f":{name}" in sql]
    statement = text(sql)
    return statement.bindparams(*declared) if declared else statement


#: The placeholder names the two aggregates bind, in ``$1 … $7`` order.
_PARAM_NAMES = [
    "tenant_id",
    "graded",
    "abstentions",
    "malicious",
    "window_start",
    "window_end",
    "recent_limit",
]

#: Which shadow-decision column each scope dimension reads. Fixed vocabulary:
#: a caller names a dimension, never a column, so nothing from a request
#: reaches the statement.
SCOPE_COLUMNS: dict[str, str] = {
    "alert_class": "alert_class",
    "rule": "rule_id",
    "source": "source",
    "model": "model",
}


@dataclass(frozen=True)
class WindowProvenance:
    """Where the window's rows came from, for the audit snapshot.

    Counts summarise; these let somebody find the rows again. A promotion
    disputed six months later resolves into a list of alerts an operator can
    open, and without the decision ids at both ends of the window there is no
    way back to them once the window has moved on.
    """

    first_decision_id: str | None = None
    last_decision_id: str | None = None
    models: tuple[str, ...] = ()
    resolution_sources: tuple[str, ...] = ()


@dataclass(frozen=True)
class AgreementEvidence:
    """One scope's track record: the window, and the trailing slice of it."""

    scope_kind: str
    scope_key: str
    window: AgreementWindow
    recent: AgreementWindow
    window_start: datetime
    window_end: datetime
    provenance: WindowProvenance = field(default_factory=WindowProvenance)

    def as_dict(self) -> dict[str, Any]:
        return {
            "scope_kind": self.scope_kind,
            "scope_key": self.scope_key,
            "window": self.window.as_dict(),
            "recent": self.recent.as_dict(),
            "window_start": self.window_start.isoformat(),
            "window_end": self.window_end.isoformat(),
        }


@dataclass(frozen=True)
class ScopeBreakdown:
    """One row of a per-class, per-rule, per-source or per-model table."""

    key: str
    window: AgreementWindow

    def as_dict(self) -> dict[str, Any]:
        return {"key": self.key, **self.window.as_dict()}


def _bind(
    tenant_id: uuid.UUID | str,
    window_start: datetime,
    window_end: datetime,
    recent_limit: int,
) -> dict[str, Any]:
    return {
        "tenant_id": str(tenant_id),
        "graded": list(GRADED_DISPOSITIONS),
        "abstentions": sorted(ABSTENTION_VERDICTS),
        "malicious": MALICIOUS,
        "window_start": window_start,
        "window_end": window_end,
        "recent_limit": recent_limit,
    }


async def reconcile_local_closures(
    db: AsyncSession,
    tenant_id: uuid.UUID | str,
    *,
    limit: int = 5000,
) -> int:
    """Grade every shadow decision whose alert an analyst has since closed here.

    Returns how many decisions gained an analyst label on this pass. Idempotent:
    a decision that already carries ``resolved_at`` is never revisited, so an
    analyst who later changes their mind does not silently rewrite evidence a
    promotion was already granted on. That is deliberate. The record of what
    was known at the time is the thing an audit needs; a later correction is a
    new fact, and it arrives as new decisions rather than by editing old ones.
    """
    statement = _statement(
        """
        UPDATE aisoc_shadow_decisions d
           SET analyst_disposition = CASE
                   WHEN a.disposition = ANY(:graded) THEN a.disposition
                   ELSE :unlabeled
               END,
               resolution_source = 'aisoc',
               resolved_at = COALESCE(a.resolved_at, a.updated_at, now()),
               vendor_disposition = a.disposition
          FROM alerts a
         WHERE d.alert_id = a.id
           AND d.tenant_id = :tenant_id
           AND a.tenant_id = :tenant_id
           AND d.resolved_at IS NULL
           AND a.status IN ('resolved', 'closed')
           AND d.id IN (
               SELECT id FROM aisoc_shadow_decisions
                WHERE tenant_id = :tenant_id AND resolved_at IS NULL
                ORDER BY decided_at
                LIMIT :limit
           )
        """
    )
    result = await db.execute(
        statement,
        {
            "tenant_id": str(tenant_id),
            "graded": list(GRADED_DISPOSITIONS),
            "unlabeled": UNLABELED,
            "limit": int(limit),
        },
    )
    reconciled = int(result.rowcount or 0)
    if reconciled:
        logger.info("shadow_agreement.reconciled", tenant_id=str(tenant_id), decisions=reconciled)
    return reconciled


def _scope_predicate(scope_kind: str, scope_key: str) -> tuple[str, dict[str, Any]]:
    """The extra ``WHERE`` clause for one scope, plus what it binds.

    The column comes from :data:`SCOPE_COLUMNS`, never from the caller's
    string, so a scope name that is not in the vocabulary raises rather than
    reaching the statement.
    """
    if scope_kind == "tenant":
        return "", {}
    column = SCOPE_COLUMNS.get(scope_kind)
    if column is None:
        raise ValueError(f"unknown scope kind {scope_kind!r}; expected one of {sorted(SCOPE_COLUMNS) + ['tenant']}")
    return f"AND d.{column} = :scope_key", {"scope_key": scope_key}


async def _provenance(
    db: AsyncSession,
    predicate: str,
    params: dict[str, Any],
) -> WindowProvenance:
    """The ends of the window, and what produced the verdicts inside it."""
    row = (
        await db.execute(
            text(
                f"""
                SELECT
                    (ARRAY_AGG(d.id ORDER BY d.resolved_at ASC))[1]::text  AS first_decision_id,
                    (ARRAY_AGG(d.id ORDER BY d.resolved_at DESC))[1]::text AS last_decision_id,
                    ARRAY_REMOVE(ARRAY_AGG(DISTINCT d.model), NULL)             AS models,
                    ARRAY_REMOVE(ARRAY_AGG(DISTINCT d.resolution_source), NULL) AS resolution_sources
                FROM aisoc_shadow_decisions d
                WHERE d.tenant_id = :tenant_id
                  AND d.resolved_at IS NOT NULL
                  AND d.resolved_at >= :window_start
                  AND d.resolved_at <= :window_end
                  {predicate}
                """
            ),
            params,
        )
    ).mappings().first() or {}
    return WindowProvenance(
        first_decision_id=row.get("first_decision_id"),
        last_decision_id=row.get("last_decision_id"),
        models=tuple(sorted(row.get("models") or ())),
        resolution_sources=tuple(sorted(row.get("resolution_sources") or ())),
    )


async def agreement_for(
    db: AsyncSession,
    tenant_id: uuid.UUID | str,
    *,
    scope_kind: str = "tenant",
    scope_key: str = "*",
    thresholds: PromotionThresholds | None = None,
    now: datetime | None = None,
    with_provenance: bool = False,
) -> AgreementEvidence:
    """The tenant's rolling agreement for one scope, plus its trailing slice.

    ``now`` is injectable so a test can pin the window; production passes
    nothing and gets the wall clock. The window bounds are returned as
    absolute timestamps rather than as "the last 30 days", because the second
    form stops meaning anything the moment somebody reads it on a later day.

    ``with_provenance`` adds the decision ids at each end of the window, the
    models that produced the verdicts and where the closures came from. It is
    off by default because only the audit snapshot needs them.
    """
    limits = thresholds or PromotionThresholds()
    window_end = now or datetime.now(UTC)
    window_start = window_end - timedelta(days=limits.window_days)

    predicate, extra = _scope_predicate(scope_kind, scope_key)
    params = {**_bind(tenant_id, window_start, window_end, limits.drift_sample), **extra}

    window_row = (
        (await db.execute(_statement(to_named_params(scoped_sql(AGREEMENT_COUNTS_SQL, predicate), _PARAM_NAMES)), params))
        .mappings()
        .first()
    )
    recent_row = (
        (await db.execute(_statement(to_named_params(scoped_sql(RECENT_COUNTS_SQL, predicate), _PARAM_NAMES)), params)).mappings().first()
    )

    return AgreementEvidence(
        scope_kind=scope_kind,
        scope_key=scope_key,
        window=window_from_counts(dict(window_row or {})),
        recent=window_from_counts(dict(recent_row or {})),
        window_start=window_start,
        window_end=window_end,
        # Only fetched when a snapshot is about to be written. The console
        # reads this endpoint on every visit and does not need the decision
        # ids, and an extra aggregate on a hot read for a field nobody renders
        # is the kind of cost that never gets attributed back to its cause.
        provenance=(await _provenance(db, predicate, params) if with_provenance else WindowProvenance()),
    )


async def breakdown_for(
    db: AsyncSession,
    tenant_id: uuid.UUID | str,
    *,
    scope_kind: str,
    thresholds: PromotionThresholds | None = None,
    now: datetime | None = None,
    limit: int = 50,
) -> list[ScopeBreakdown]:
    """Agreement grouped by one dimension: class, rule, source or model.

    Ordered by sample size rather than by rate, so the table leads with the
    scopes there is most evidence about. A 100% agreement over three decisions
    sorted to the top would be the most prominent number on the page and the
    least informative one.
    """
    limits = thresholds or PromotionThresholds()
    window_end = now or datetime.now(UTC)
    window_start = window_end - timedelta(days=limits.window_days)

    column = SCOPE_COLUMNS.get(scope_kind)
    if column is None:
        raise ValueError(f"unknown scope kind {scope_kind!r}; expected one of {sorted(SCOPE_COLUMNS)}")

    # The same FILTER expressions as the shared aggregate, grouped rather than
    # scoped. Kept beside the caller instead of in the rules module because
    # only the console needs it: the dispatch gate asks about one scope at a
    # time and must never pull a whole table across to answer that.
    statement = _statement(
        f"""
        SELECT
            COALESCE(NULLIF(d.{column}, ''), 'unattributed') AS key,
            COUNT(*)::int AS resolved,
            COUNT(*) FILTER (WHERE d.analyst_disposition = ANY(:graded))::int AS labelled,
            COUNT(*) FILTER (
                WHERE d.analyst_disposition = ANY(:graded)
                  AND COALESCE(d.verdict, '') = ANY(:abstentions)
            )::int AS abstained,
            COUNT(*) FILTER (
                WHERE d.analyst_disposition = ANY(:graded)
                  AND NOT (COALESCE(d.verdict, '') = ANY(:abstentions))
            )::int AS answered,
            COUNT(*) FILTER (
                WHERE d.analyst_disposition = ANY(:graded)
                  AND NOT (COALESCE(d.verdict, '') = ANY(:abstentions))
                  AND d.verdict = d.analyst_disposition
            )::int AS agreed,
            COUNT(*) FILTER (WHERE d.analyst_disposition = :malicious)::int AS malicious_support,
            COUNT(*) FILTER (WHERE d.analyst_disposition = :malicious AND d.verdict = :malicious)::int AS malicious_caught
        FROM aisoc_shadow_decisions d
        WHERE d.tenant_id = :tenant_id
          AND d.resolved_at IS NOT NULL
          AND d.resolved_at >= :window_start
          AND d.resolved_at <= :window_end
        GROUP BY 1
        ORDER BY labelled DESC, key ASC
        LIMIT :row_limit
        """
    )
    rows = (
        (
            await db.execute(
                statement,
                {
                    **_bind(tenant_id, window_start, window_end, limits.drift_sample),
                    "row_limit": int(limit),
                },
            )
        )
        .mappings()
        .all()
    )
    return [ScopeBreakdown(key=str(row["key"]), window=window_from_counts(dict(row))) for row in rows]
