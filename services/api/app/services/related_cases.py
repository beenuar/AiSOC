"""Read-only case relationships backed by shared, typed evidence.

An overlap is a reason to inspect another case, not a finding that the two
incidents should be merged. Matching is exact; neither titles nor model
judgements participate. PostgreSQL filters and ranks the tenant's candidates
before limiting results, so an older match is not lost behind recent cases.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Any, Literal, get_args

from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

ObservableKind = Literal["ip", "user", "host", "domain", "hash", "file", "process", "alert"]
_OBSERVABLE_KINDS = frozenset(get_args(ObservableKind))
_RESULT_LIMIT = 20
_EVIDENCE_LIMIT = 10


class RelatedCaseObservable(BaseModel):
    kind: ObservableKind
    value: str


class RelatedCase(BaseModel):
    id: uuid.UUID
    case_number: str | None
    title: str
    severity: str
    status: str
    created_at: datetime | None
    # Preserve the original field for integrations that already read it.
    reason: Literal["shared_alerts", "shared_observables"]
    shared_alert_ids: list[uuid.UUID] = Field(max_length=_EVIDENCE_LIMIT)
    shared_alert_count: int = Field(ge=0)
    shared_observables: list[RelatedCaseObservable] = Field(max_length=_EVIDENCE_LIMIT)
    shared_observable_count: int = Field(ge=0)


class RelatedCasesResponse(BaseModel):
    related: list[RelatedCase] = Field(default_factory=list, max_length=_RESULT_LIMIT)
    limit: int = _RESULT_LIMIT
    has_more: bool = False


def _observables(graph: Any) -> list[dict[str, str]]:
    """Validate legacy graph JSON without treating malformed data as evidence."""
    nodes = graph.get("nodes") if isinstance(graph, dict) else None
    if not isinstance(nodes, list):
        return []
    distinct: set[tuple[str, str]] = set()
    for node in nodes:
        if not isinstance(node, dict):
            continue
        kind, value = node.get("kind"), node.get("value")
        if isinstance(kind, str) and kind in _OBSERVABLE_KINDS and isinstance(value, str) and value.strip():
            # Retain the original value. Normalising a username or file path
            # here could equate distinct observables; this is exact matching.
            distinct.add((kind, value))
    return [{"kind": kind, "value": value} for kind, value in sorted(distinct)]


_RELATED_CASES_SQL = text("""
    WITH source_observables AS MATERIALIZED (
        SELECT kind, value
        FROM jsonb_to_recordset(CAST(:observables AS JSONB)) AS source(kind TEXT, value TEXT)
    )
    SELECT candidate.id, candidate.case_number, candidate.title,
           candidate.severity, candidate.status, candidate.created_at,
           alert_overlap.shared_alert_ids, alert_overlap.shared_alert_count,
           observable_overlap.shared_observables, observable_overlap.shared_observable_count
    FROM aisoc_cases AS candidate
    CROSS JOIN LATERAL (
        SELECT count(*) AS shared_alert_count,
               COALESCE(
                   array_agg(alert_id ORDER BY alert_id) FILTER (WHERE ordinal <= :evidence_limit),
                   ARRAY[]::UUID[]
               ) AS shared_alert_ids
        FROM (
            SELECT alert_id, row_number() OVER (ORDER BY alert_id) AS ordinal
            FROM (
                SELECT DISTINCT alert_id
                FROM unnest(candidate.alert_ids) AS ids(alert_id)
                WHERE alert_id = ANY(CAST(:alerts AS UUID[]))
            ) AS distinct_alerts
        ) AS ranked_alerts
    ) AS alert_overlap
    CROSS JOIN LATERAL (
        SELECT count(*) AS shared_observable_count,
               COALESCE(
                   jsonb_agg(jsonb_build_object('kind', kind, 'value', value) ORDER BY kind, value)
                       FILTER (WHERE ordinal <= :evidence_limit),
                   '[]'::JSONB
               ) AS shared_observables
        FROM (
            SELECT kind, value, row_number() OVER (ORDER BY kind, value) AS ordinal
            FROM (
                SELECT DISTINCT source.kind, source.value
                FROM jsonb_array_elements(
                    CASE WHEN jsonb_typeof(candidate.observable_graph -> 'nodes') = 'array'
                         THEN candidate.observable_graph -> 'nodes'
                         ELSE '[]'::JSONB END
                ) AS node(value)
                JOIN source_observables AS source
                  ON node.value ->> 'kind' = source.kind
                 AND node.value ->> 'value' = source.value
                WHERE jsonb_typeof(node.value -> 'kind') = 'string'
                  AND jsonb_typeof(node.value -> 'value') = 'string'
            ) AS distinct_observables
        ) AS ranked_observables
    ) AS observable_overlap
    WHERE candidate.tenant_id = :tenant_id
      AND candidate.id <> :case_id
      AND (alert_overlap.shared_alert_count > 0 OR observable_overlap.shared_observable_count > 0)
    ORDER BY alert_overlap.shared_alert_count DESC,
             observable_overlap.shared_observable_count DESC,
             candidate.created_at DESC, candidate.id ASC
    LIMIT :candidate_limit
""")


async def find_related_cases(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    case_id: uuid.UUID,
) -> RelatedCasesResponse | None:
    """Return bounded evidence, or ``None`` when this tenant has no such case."""
    source = (
        await db.execute(
            text("SELECT alert_ids, observable_graph FROM aisoc_cases WHERE id = :case_id AND tenant_id = :tenant_id"),
            {"case_id": case_id, "tenant_id": tenant_id},
        )
    ).fetchone()
    if source is None:
        return None
    alerts = list(source.alert_ids or [])
    observables = _observables(source.observable_graph)
    if not alerts and not observables:
        return RelatedCasesResponse()

    rows = (
        await db.execute(
            _RELATED_CASES_SQL,
            {
                "case_id": case_id,
                "tenant_id": tenant_id,
                "alerts": alerts,
                "observables": json.dumps(observables),
                "evidence_limit": _EVIDENCE_LIMIT,
                "candidate_limit": _RESULT_LIMIT + 1,
            },
        )
    ).fetchall()
    return RelatedCasesResponse(
        related=[
            RelatedCase(
                id=row.id,
                case_number=row.case_number,
                title=row.title,
                severity=row.severity or "medium",
                status=row.status or "new",
                created_at=row.created_at,
                reason="shared_alerts" if row.shared_alert_count else "shared_observables",
                shared_alert_ids=list(row.shared_alert_ids),
                shared_alert_count=row.shared_alert_count,
                shared_observables=[RelatedCaseObservable.model_validate(value) for value in row.shared_observables],
                shared_observable_count=row.shared_observable_count,
            )
            for row in rows[:_RESULT_LIMIT]
        ],
        has_more=len(rows) > _RESULT_LIMIT,
    )
