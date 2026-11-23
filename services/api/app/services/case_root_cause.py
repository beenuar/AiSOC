"""The evidence-backed root-cause record.

One record per case, with a status that separates what an investigation
*established* from what a model *suggested*:

* ``determined`` — the walk-back reached the earliest related event(s), and
  **every determined record carries at least one citation**. A citation names
  an Investigation Ledger entry by ``(run_id, seq)`` — the ledger's stable
  address (``investigation_events`` is ``UNIQUE (run_id, seq)``; the row UUID
  is minted fresh at write time and is nobody's reference). The write path
  verifies each cited entry exists: a citation that resolves to nothing is
  decoration, not evidence.
* ``hypothesis`` — a plausible cause nothing has verified. Reports and the
  post-mortem must label it as such; this module is where the distinction is
  stored so the renderers cannot blur it.
* ``undetermined`` — honest ignorance, which must name the telemetry that was
  missing, because "we could not know" has to say what would have made it
  knowable.

The free-prose ``root_cause_hypothesis`` on the forensic agent's run state
stays what it always was — a model's sentence. When an analyst or an agent
promotes it into a record, it enters as ``hypothesis`` until citations make
it ``determined``.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

RootCauseStatus = Literal["determined", "hypothesis", "undetermined"]

#: Where the walk-back found a cited event.
CitationSource = Literal["story_link", "graph", "lake", "ledger"]


class RootCauseValidationError(ValueError):
    """A record that violates the contract, with the rule named."""


class RootCauseCitationIn(BaseModel):
    run_id: uuid.UUID
    seq: int = Field(ge=0)
    source: CitationSource = "ledger"
    event_time: datetime | None = None
    description: str = Field(min_length=1, max_length=2000)


class RootCauseRecordIn(BaseModel):
    status: RootCauseStatus
    summary: str = Field(min_length=1, max_length=8000)
    missing_telemetry: str | None = Field(default=None, max_length=4000)
    citations: list[RootCauseCitationIn] = Field(default_factory=list, max_length=50)


def validate_record(record: RootCauseRecordIn) -> None:
    """The contract: raise :class:`RootCauseValidationError` naming the rule.

    * ``determined`` requires at least one cited event.
    * ``undetermined`` requires the missing telemetry to be named.

    A ``hypothesis`` may carry citations (supporting-but-not-conclusive
    evidence) or none; it is the status that says "nothing verified this",
    not the citation count.
    """
    if record.status == "determined" and not record.citations:
        raise RootCauseValidationError(
            "a 'determined' root cause requires at least one cited event; without a citation it is a hypothesis and must say so"
        )
    if record.status == "undetermined" and not (record.missing_telemetry or "").strip():
        raise RootCauseValidationError(
            "an 'undetermined' root cause must name the missing telemetry — what was not collected that would have made the cause knowable"
        )


async def count_resolving_ledger_entries(db: AsyncSession, tenant_id: uuid.UUID, citations: list[RootCauseCitationIn]) -> int:
    """How many of the cited ``(run_id, seq)`` pairs exist in the ledger.

    One query over ``investigation_events``, **bound to the caller's
    tenant**: without the predicate a record could "verify" by citing
    another tenant's ledger entries — and the check itself would be an
    existence oracle over foreign run ids. The caller compares against
    ``len(citations)`` and refuses on any shortfall, naming the gap.
    """
    if not citations:
        return 0
    pairs = sorted({(str(c.run_id), int(c.seq)) for c in citations})
    # One static statement, the cited pairs as parallel array binds — never a
    # string-built WHERE (the Semgrep sqlalchemy-text rule exists for exactly
    # that shape, and dynamic SQL earns its flag even with bound values).
    row = (
        await db.execute(
            text(
                """
                SELECT COUNT(*) AS n
                FROM investigation_events e
                JOIN unnest(CAST(:run_ids AS uuid[]), CAST(:seqs AS int[]))
                    AS cited(run_id, seq)
                  ON e.run_id = cited.run_id AND e.seq = cited.seq
                WHERE e.tenant_id = :tenant_id
                """
            ),
            {
                "tenant_id": str(tenant_id),
                "run_ids": [p[0] for p in pairs],
                "seqs": [p[1] for p in pairs],
            },
        )
    ).fetchone()
    return int(row.n if row is not None else 0)


async def upsert_record(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    case_id: uuid.UUID,
    record: RootCauseRecordIn,
    created_by: str | None,
) -> uuid.UUID:
    """Write the record and replace its citations, one per case.

    The caller has already run :func:`validate_record` and the ledger
    existence check; this is the persistence half. Explicit tenant predicates
    on every statement — the cases-family convention — on top of the RLS the
    tables also carry.
    """
    row = (
        await db.execute(
            text(
                """
                INSERT INTO case_root_cause_records
                    (tenant_id, case_id, status, summary, missing_telemetry, created_by)
                VALUES
                    (:tenant_id, :case_id, :status, :summary, :missing_telemetry, :created_by)
                ON CONFLICT (tenant_id, case_id) DO UPDATE SET
                    status = EXCLUDED.status,
                    summary = EXCLUDED.summary,
                    missing_telemetry = EXCLUDED.missing_telemetry,
                    created_by = EXCLUDED.created_by,
                    updated_at = now()
                RETURNING id
                """
            ),
            {
                "tenant_id": str(tenant_id),
                "case_id": str(case_id),
                "status": record.status,
                "summary": record.summary,
                "missing_telemetry": record.missing_telemetry,
                "created_by": created_by,
            },
        )
    ).fetchone()
    record_id: uuid.UUID = row.id if isinstance(row.id, uuid.UUID) else uuid.UUID(str(row.id))

    await db.execute(
        text("DELETE FROM case_root_cause_citations WHERE tenant_id = :tenant_id AND record_id = :record_id"),
        {"tenant_id": str(tenant_id), "record_id": str(record_id)},
    )
    for citation in record.citations:
        await db.execute(
            text(
                """
                INSERT INTO case_root_cause_citations
                    (tenant_id, record_id, run_id, seq, source, event_time, description)
                VALUES
                    (:tenant_id, :record_id, :run_id, :seq, :source, :event_time, :description)
                """
            ),
            {
                "tenant_id": str(tenant_id),
                "record_id": str(record_id),
                "run_id": str(citation.run_id),
                "seq": citation.seq,
                "source": citation.source,
                "event_time": citation.event_time,
                "description": citation.description,
            },
        )
    return record_id


async def fetch_record(db: AsyncSession, *, tenant_id: uuid.UUID, case_id: uuid.UUID) -> dict[str, Any] | None:
    """The case's record with its citations, or ``None`` — never invented."""
    row = (
        await db.execute(
            text(
                """
                SELECT id, status, summary, missing_telemetry, created_by,
                       created_at, updated_at
                FROM case_root_cause_records
                WHERE tenant_id = :tenant_id AND case_id = :case_id
                """
            ),
            {"tenant_id": str(tenant_id), "case_id": str(case_id)},
        )
    ).fetchone()
    if row is None:
        return None
    citations = (
        await db.execute(
            text(
                """
                SELECT run_id, seq, source, event_time, description
                FROM case_root_cause_citations
                WHERE tenant_id = :tenant_id AND record_id = :record_id
                ORDER BY event_time NULLS LAST, seq
                """
            ),
            {"tenant_id": str(tenant_id), "record_id": str(row.id)},
        )
    ).fetchall()
    return {
        "status": row.status,
        "summary": row.summary,
        "missing_telemetry": row.missing_telemetry,
        "created_by": row.created_by,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
        "citations": [
            {
                "run_id": str(c.run_id),
                "seq": int(c.seq),
                "source": c.source,
                "event_time": c.event_time.isoformat() if c.event_time else None,
                "description": c.description,
            }
            for c in citations
        ],
    }
