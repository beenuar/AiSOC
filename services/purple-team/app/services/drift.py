"""Detection drift snapshotting + delta computation.

Wave 1 of the AiSOC v6 capability roadmap (`w1-drift`) — turns the existing
ATT&CK coverage heatmap from a point-in-time view into a tracked time series
so the console can surface "delta vs. last week" on the MITRE heatmap.

Design notes
------------
The roadmap calls this "scheduled Atomic Red Team + Caldera runs". In
practice we do *not* execute attacks on a schedule — actual atomic
execution is gated behind an explicit human/operator action because it
mutates production endpoints. Instead, the scheduler periodically
*recomputes coverage from the existing execution history* and writes a
snapshot row, plus exposes an on-demand snapshot endpoint so operators
can capture coverage immediately after an exercise.

This still meets the "automated, not point-in-time" mandate from the
2026 buyer-side rubric: drift is detected by diffing the JSONB coverage
matrices of consecutive snapshots, regardless of *when* the underlying
runs happened.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.purple_team import AtomicTest, DetectionDriftSnapshot, TestExecution
from app.services.coverage import build_coverage_matrix

LOG = logging.getLogger(__name__)


async def compute_coverage_for_tenant(
    session: AsyncSession,
    tenant_id: uuid.UUID,
) -> dict[str, Any]:
    """Build the ATT&CK coverage matrix for a tenant from current executions.

    Resolves the ``tactic`` field by joining executions to the tenant's
    Atomic Red Team catalog so the coverage matrix is grouped under real
    tactics rather than the placeholder "unknown" the legacy endpoint
    used.
    """

    exec_result = await session.execute(select(TestExecution).where(TestExecution.tenant_id == tenant_id))
    executions = exec_result.scalars().all()

    atomic_result = await session.execute(select(AtomicTest.technique_id, AtomicTest.tactic).where(AtomicTest.tenant_id == tenant_id))
    tactic_by_technique: dict[str, str] = {}
    for technique_id, tactic in atomic_result.all():
        # Atomic Red Team can list the same technique under multiple
        # tactics; first writer wins, which keeps the heatmap stable
        # across snapshots.
        tactic_by_technique.setdefault(technique_id, tactic)

    rows = [
        {
            "technique_id": ex.technique_id,
            "test_name": ex.test_name,
            "tactic": tactic_by_technique.get(ex.technique_id, "unknown"),
            "status": ex.status,
            "detected": ex.detected,
        }
        for ex in executions
    ]
    return build_coverage_matrix(rows)


async def capture_snapshot(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    *,
    trigger: str = "scheduled",
    coverage: dict[str, Any] | None = None,
) -> DetectionDriftSnapshot:
    """Persist a `DetectionDriftSnapshot` for a tenant and return it.

    If ``coverage`` is not supplied it is computed from the tenant's
    current execution history. Caller is responsible for committing the
    surrounding transaction.
    """

    if coverage is None:
        coverage = await compute_coverage_for_tenant(session, tenant_id)

    summary = coverage.get("summary", {})
    snapshot = DetectionDriftSnapshot(
        tenant_id=tenant_id,
        captured_at=datetime.now(UTC),
        trigger=trigger,
        total_techniques=int(summary.get("total_techniques", 0)),
        tested_techniques=int(summary.get("tested_techniques", 0)),
        detected_techniques=int(summary.get("detected_techniques", 0)),
        overall_coverage=float(summary.get("overall_coverage", 0.0)),
        coverage=coverage,
    )
    session.add(snapshot)
    await session.flush()
    return snapshot


async def list_snapshots(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    *,
    limit: int = 50,
) -> list[DetectionDriftSnapshot]:
    """Return the most recent snapshots for a tenant, newest first."""

    result = await session.execute(
        select(DetectionDriftSnapshot)
        .where(DetectionDriftSnapshot.tenant_id == tenant_id)
        .order_by(DetectionDriftSnapshot.captured_at.desc())
        .limit(limit)
    )
    return list(result.scalars().all())


async def latest_two_snapshots(
    session: AsyncSession,
    tenant_id: uuid.UUID,
) -> tuple[DetectionDriftSnapshot | None, DetectionDriftSnapshot | None]:
    """Return ``(current, previous)`` snapshots for delta computation."""

    snaps = await list_snapshots(session, tenant_id, limit=2)
    current = snaps[0] if snaps else None
    previous = snaps[1] if len(snaps) > 1 else None
    return current, previous


# NOTE: ``compute_drift`` (and its helper ``_index_techniques``) are
# imported from ``app.services.drift_diff`` so the pure-Python delta
# logic stays unit-testable without SQLAlchemy installed.
from app.services.drift_diff import compute_drift  # noqa: E402

__all__ = [
    "compute_drift",
    "get_latest_snapshots",
    "list_snapshots",
    "take_snapshot",
]
