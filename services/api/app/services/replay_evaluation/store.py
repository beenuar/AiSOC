"""Reading and writing replay evaluations, always bound to one tenant.

Gap-closure Phase 1.4.

Every statement here binds ``tenant_id`` as a query parameter, and every
caller receives that tenant from the authenticated principal. The row-level
security policies in migration 065 are defence in depth behind this, not
instead of it: this repository enforces tenant isolation at the query layer
and keeps RLS as the second layer, because the services connect as a role the
policies apply to only after 061 and a query-layer predicate holds on any
connection.

Raw SQL rather than an ORM model, following ``app.services.sandbox.store``.
The rows are written once by a background job and read back whole; mapping
them would add a model to keep in parity with a migration for no reader that
needs one.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

__all__ = [
    "TERMINAL_STATUSES",
    "EvaluationRow",
    "create_evaluation",
    "fail_evaluation",
    "get_evaluation",
    "list_decisions",
    "list_evaluations",
    "mark_running",
    "store_result",
]

#: A run in one of these will never change again, so a poller can stop.
TERMINAL_STATUSES = frozenset({"completed", "failed"})

#: Columns the list view needs. The score and the report are deliberately
#: absent: a list query should not drag a few megabytes of JSONB and prose per
#: row across the wire to render a table of sample sizes.
_SUMMARY_COLUMNS = """
    id, tenant_id, status, error, connector_id, vendor,
    window_start, window_end, train_fraction, bootstrap_seed, bootstrap_resamples,
    findings_read, findings_labelled, decisions_recorded, graded, malicious_support,
    headline_accuracy, headline_withheld_reason, malicious_recall,
    requested_by, created_at, started_at, completed_at
"""


@dataclass(frozen=True)
class EvaluationRow:
    """One evaluation as the API returns it.

    ``score``, ``method`` and ``report_markdown`` are ``None`` on a summary
    read rather than empty, so a caller can tell "not loaded" from "the run
    produced none", which are different states with different causes.
    """

    id: uuid.UUID
    tenant_id: uuid.UUID
    status: str
    error: str | None
    connector_id: str
    vendor: str
    window_start: datetime
    window_end: datetime
    train_fraction: float
    bootstrap_seed: int
    bootstrap_resamples: int
    findings_read: int
    findings_labelled: int
    decisions_recorded: int
    graded: int
    malicious_support: int
    headline_accuracy: float | None
    headline_withheld_reason: str | None
    malicious_recall: float | None
    requested_by: uuid.UUID | None
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    score: dict[str, Any] | None = None
    method: dict[str, Any] | None = None
    report_markdown: str | None = None

    @property
    def is_terminal(self) -> bool:
        return self.status in TERMINAL_STATUSES


def _row_to_evaluation(row: Any, *, detailed: bool = False) -> EvaluationRow:
    return EvaluationRow(
        id=row.id,
        tenant_id=row.tenant_id,
        status=row.status,
        error=row.error,
        connector_id=row.connector_id,
        vendor=row.vendor,
        window_start=row.window_start,
        window_end=row.window_end,
        train_fraction=float(row.train_fraction),
        bootstrap_seed=int(row.bootstrap_seed),
        bootstrap_resamples=int(row.bootstrap_resamples),
        findings_read=int(row.findings_read),
        findings_labelled=int(row.findings_labelled),
        decisions_recorded=int(row.decisions_recorded),
        graded=int(row.graded),
        malicious_support=int(row.malicious_support),
        headline_accuracy=row.headline_accuracy,
        headline_withheld_reason=row.headline_withheld_reason,
        malicious_recall=row.malicious_recall,
        requested_by=row.requested_by,
        created_at=row.created_at,
        started_at=row.started_at,
        completed_at=row.completed_at,
        score=_as_json(row.score) if detailed else None,
        method=_as_json(row.method) if detailed else None,
        report_markdown=row.report_markdown if detailed else None,
    )


def _as_json(value: Any) -> dict[str, Any] | None:
    """Read a JSONB column back as a dict.

    asyncpg returns JSONB as a parsed object through SQLAlchemy's JSONB type,
    but this module binds through ``text()`` and gets whatever the driver
    hands back. A string is parsed; anything else is returned as-is.
    """
    if value is None:
        return None
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except ValueError:
            return None
        return parsed if isinstance(parsed, dict) else None
    return value if isinstance(value, dict) else None


async def create_evaluation(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    connector_id: str,
    vendor: str,
    window_start: datetime,
    window_end: datetime,
    train_fraction: float,
    bootstrap_seed: int,
    bootstrap_resamples: int,
    requested_by: uuid.UUID | None,
) -> uuid.UUID:
    """Insert a queued run and return its id.

    The row exists before any work starts, so a caller that polls immediately
    gets ``queued`` rather than a 404 that looks like a lost request.
    """
    evaluation_id = uuid.uuid4()
    await db.execute(
        # `requested_by` is resolved through a subselect rather than bound
        # straight into the column. The authenticated principal is not always
        # a row in `users`: the dev-mode demo user has a fixed id that no
        # migration seeds, and an API key is a row in `api_keys`. Binding the
        # id directly turns either of those into a foreign-key violation, so
        # starting an evaluation would 500 on a deployment where every other
        # route works. An id with no user resolves to NULL, which is what the
        # column's `ON DELETE SET NULL` already means: attribution is unknown,
        # and the evaluation is still the tenant's.
        text("""
            INSERT INTO aisoc_replay_evaluations
                (id, tenant_id, status, connector_id, vendor, window_start, window_end,
                 train_fraction, bootstrap_seed, bootstrap_resamples, requested_by)
            VALUES
                (:id, :tenant_id, 'queued', :connector_id, :vendor, :window_start, :window_end,
                 :train_fraction, :bootstrap_seed, :bootstrap_resamples,
                 (SELECT id FROM users WHERE id = :requested_by))
        """).bindparams(
            id=evaluation_id,
            tenant_id=tenant_id,
            connector_id=connector_id,
            vendor=vendor,
            window_start=window_start,
            window_end=window_end,
            train_fraction=train_fraction,
            bootstrap_seed=bootstrap_seed,
            bootstrap_resamples=bootstrap_resamples,
            requested_by=requested_by,
        )
    )
    await db.commit()
    return evaluation_id


async def mark_running(db: AsyncSession, *, tenant_id: uuid.UUID, evaluation_id: uuid.UUID) -> None:
    await db.execute(
        text("""
            UPDATE aisoc_replay_evaluations
               SET status = 'running', started_at = NOW()
             WHERE id = :id AND tenant_id = :tenant_id
        """).bindparams(id=evaluation_id, tenant_id=tenant_id)
    )
    await db.commit()


async def fail_evaluation(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    evaluation_id: uuid.UUID,
    error: str,
) -> None:
    """Record a terminal failure with the reason.

    A run that crashed must not be left ``running``: a job that never
    terminates is indistinguishable from a slow one, and a poller would wait
    on it forever.
    """
    await db.execute(
        text("""
            UPDATE aisoc_replay_evaluations
               SET status = 'failed', error = :error, completed_at = NOW()
             WHERE id = :id AND tenant_id = :tenant_id
        """).bindparams(id=evaluation_id, tenant_id=tenant_id, error=error[:4000])
    )
    await db.commit()


async def store_result(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    evaluation_id: uuid.UUID,
    score: dict[str, Any],
    method: dict[str, Any],
    report_markdown: str,
    decisions: list[dict[str, Any]],
    findings_read: int,
    findings_labelled: int,
) -> None:
    """Write the report and the decisions behind it, in one transaction.

    The report is stored as the renderer produced it. The phase's acceptance
    bar is that a report reproduces byte for byte, and a report re-rendered
    later by a newer renderer is a different artefact from the one the
    operator read.
    """
    await db.execute(
        text("""
            UPDATE aisoc_replay_evaluations
               SET status = 'completed',
                   completed_at = NOW(),
                   score = CAST(:score AS JSONB),
                   method = CAST(:method AS JSONB),
                   report_markdown = :report,
                   findings_read = :findings_read,
                   findings_labelled = :findings_labelled,
                   decisions_recorded = :decisions_recorded,
                   graded = :graded,
                   malicious_support = :malicious_support,
                   headline_accuracy = :headline_accuracy,
                   headline_withheld_reason = :withheld,
                   malicious_recall = :malicious_recall
             WHERE id = :id AND tenant_id = :tenant_id
        """).bindparams(
            id=evaluation_id,
            tenant_id=tenant_id,
            score=json.dumps(score, sort_keys=True, default=str),
            method=json.dumps(method, sort_keys=True, default=str),
            report=report_markdown,
            findings_read=findings_read,
            findings_labelled=findings_labelled,
            decisions_recorded=len(decisions),
            graded=int(score.get("graded") or 0),
            malicious_support=int(score.get("malicious_support") or 0),
            # Left NULL when withheld. Never 0, which would read as "the agent
            # got every answer wrong".
            headline_accuracy=score.get("headline_accuracy"),
            withheld=score.get("headline_withheld_reason"),
            malicious_recall=score.get("malicious_recall"),
        )
    )

    for decision in decisions:
        await db.execute(
            text("""
                INSERT INTO aisoc_replay_decisions
                    (evaluation_id, tenant_id, finding_id, vendor, rule_id, closed_at,
                     expected_disposition, vendor_disposition, labelled,
                     verdict, verdict_raw, confidence, tier, decision, error)
                VALUES
                    (:evaluation_id, :tenant_id, :finding_id, :vendor, :rule_id,
                     CAST(NULLIF(:closed_at, '') AS TIMESTAMPTZ),
                     :expected, :vendor_disposition, :labelled,
                     :verdict, :verdict_raw, :confidence, :tier, CAST(:decision AS JSONB), :error)
            """).bindparams(
                evaluation_id=evaluation_id,
                tenant_id=tenant_id,
                finding_id=str(decision.get("finding_id") or ""),
                vendor=str(decision.get("vendor") or ""),
                rule_id=decision.get("rule_id"),
                closed_at=str(decision.get("closed_at") or ""),
                expected=str(decision.get("expected_disposition") or ""),
                vendor_disposition=str(decision.get("vendor_disposition") or ""),
                labelled=bool(decision.get("labelled")),
                verdict=decision.get("verdict"),
                verdict_raw=decision.get("verdict_raw"),
                confidence=float(decision.get("confidence") or 0.0),
                tier=str(decision.get("tier") or ""),
                decision=json.dumps(decision, sort_keys=True, default=str),
                error=decision.get("error"),
            )
        )
    await db.commit()


async def get_evaluation(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    evaluation_id: uuid.UUID,
    detailed: bool = True,
) -> EvaluationRow | None:
    columns = f"{_SUMMARY_COLUMNS}, score, method, report_markdown" if detailed else _SUMMARY_COLUMNS
    row = (
        await db.execute(
            text(
                f"SELECT {columns} FROM aisoc_replay_evaluations "  # noqa: S608 - column list is a module constant
                "WHERE id = :id AND tenant_id = :tenant_id"
            ).bindparams(id=evaluation_id, tenant_id=tenant_id)
        )
    ).fetchone()
    return _row_to_evaluation(row, detailed=detailed) if row else None


async def list_evaluations(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    limit: int = 50,
) -> list[EvaluationRow]:
    rows = (
        await db.execute(
            text(
                f"SELECT {_SUMMARY_COLUMNS} FROM aisoc_replay_evaluations "  # noqa: S608 - column list is a module constant
                "WHERE tenant_id = :tenant_id ORDER BY created_at DESC LIMIT :limit"
            ).bindparams(tenant_id=tenant_id, limit=limit)
        )
    ).fetchall()
    return [_row_to_evaluation(row) for row in rows]


async def list_decisions(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    evaluation_id: uuid.UUID,
    limit: int = 2000,
) -> list[dict[str, Any]]:
    """The decisions behind a report, oldest close time first.

    Ordered by ``(closed_at, finding_id)`` rather than by insertion, because
    close times collide when an analyst bulk-closes a queue and a sort that is
    not total makes the page order depend on the database's row layout.
    """
    rows = (
        await db.execute(
            text("""
                SELECT decision FROM aisoc_replay_decisions
                 WHERE evaluation_id = :evaluation_id AND tenant_id = :tenant_id
                 ORDER BY closed_at NULLS LAST, finding_id
                 LIMIT :limit
            """).bindparams(evaluation_id=evaluation_id, tenant_id=tenant_id, limit=limit)
        )
    ).fetchall()
    return [parsed for row in rows if (parsed := _as_json(row.decision)) is not None]
