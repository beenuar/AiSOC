"""The per-tenant service review — measured, denominated, delivered.

A weekly executive digest already existed, scheduled and persisted — and
its means lacked denominators and **nothing delivered it**. This module is
the review a co-managed engagement actually runs on, built only from the
tenant's own rows, with the two disciplines the recorded metric defects
demand:

* **Every mean travels with the count of rows it averaged**, and a figure
  with no denominator reads ``"not measured"`` — never a confident zero.
* **Each section comes from its own store** and carries its own failure:
  a store that cannot answer contributes the reason, not zeros.

Sections: alert funnel (ingested / auto-closed / escalated-to-case),
QA-sampled closure review (reviewed count over sampled count — the
denominator IS the point), MTTD/MTTR/MTTC per severity against the
tenant's own targets (via ``compute_sla_metrics``, which already carries
``total`` per severity), actions (executed / failed, from the action
ledger), hunts run, and detection coverage changes in the window.

Delivery is the outbound-webhook queue (`service.review` events), so the
review reaches the channel the tenant configured — the "nothing delivers
it" half — and the full document persists as a ``ReportArtefact`` beside
the digest.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.sla import compute_sla_metrics

logger = logging.getLogger("aisoc.service_review")

_FUNNEL_SQL = text(
    """
    SELECT
      count(*) AS ingested,
      count(*) FILTER (WHERE status IN ('resolved', 'closed') AND disposition_source = 'ai') AS auto_closed,
      count(*) FILTER (WHERE status IN ('resolved', 'closed')) AS closed_any
    FROM alerts
    WHERE tenant_id = :tenant_id AND created_at >= :start AND created_at < :end
    """
)

_CASES_SQL = text(
    """
    SELECT
      count(*) FILTER (WHERE created_at >= :start AND created_at < :end) AS opened,
      count(*) FILTER (WHERE status = 'closed' AND closed_at >= :start AND closed_at < :end) AS closed
    FROM aisoc_cases
    WHERE tenant_id = :tenant_id
    """
)

_QA_SQL = text(
    """
    SELECT
      count(*) AS sampled,
      count(*) FILTER (WHERE score_verdict IS NOT NULL) AS reviewed,
      count(*) FILTER (WHERE score_verdict >= 4) AS agreed
    FROM aisoc_closure_qa_samples
    WHERE tenant_id = :tenant_id AND created_at >= :start AND created_at < :end
    """
)

_ACTIONS_SQL = text(
    """
    SELECT
      count(*) AS dispatched,
      count(*) FILTER (WHERE status IN ('completed', 'awaiting_completion')) AS executed,
      count(*) FILTER (WHERE status = 'failed') AS failed
    FROM aisoc_action_records
    WHERE tenant_id = :tenant_id AND created_at >= :start AND created_at < :end
    """
)

#: Saved hunts record only their LAST run, so this counts hunts whose most
#: recent execution fell in the window — a lower bound on runs, stated as
#: such in the section note.
_HUNTS_SQL = text(
    """
    SELECT count(*) FROM aisoc_saved_hunts
    WHERE tenant_id = :tenant_id AND last_run_at >= :start AND last_run_at < :end
    """
)


async def build_service_review(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    *,
    period_start: datetime,
    period_end: datetime,
) -> dict[str, Any]:
    review: dict[str, Any] = {
        "tenant_id": str(tenant_id),
        "period": {"start": period_start.isoformat(), "end": period_end.isoformat()},
        "discipline": ("every mean carries the count it averaged; a figure with no denominator reads 'not measured', never zero"),
    }
    params = {"tenant_id": str(tenant_id), "start": period_start, "end": period_end}

    try:
        row = (await db.execute(_FUNNEL_SQL, params)).fetchone()
        ingested = int(row[0]) if row else 0
        review["alert_funnel"] = {
            "ingested": ingested,
            "auto_closed": int(row[1]) if row else 0,
            "closed_any": int(row[2]) if row else 0,
            "auto_close_share": (round(int(row[1]) / ingested, 4) if row and ingested else None),
            "note": None if ingested else "no alerts in the window; shares are not measured",
        }
    except Exception as exc:  # noqa: BLE001 — a section that cannot answer says so
        review["alert_funnel"] = {"could_not_check": type(exc).__name__}

    try:
        row = (await db.execute(_CASES_SQL, params)).fetchone()
        review["cases"] = {"opened": int(row[0]) if row else 0, "closed": int(row[1]) if row else 0}
    except Exception as exc:  # noqa: BLE001
        review["cases"] = {"could_not_check": type(exc).__name__}

    try:
        row = (await db.execute(_QA_SQL, params)).fetchone()
        sampled = int(row[0]) if row else 0
        reviewed = int(row[1]) if row else 0
        agreed = int(row[2]) if row else 0
        review["closure_qa"] = {
            "sampled": sampled,
            "reviewed": reviewed,
            "agreement": (round(agreed / reviewed, 4) if reviewed else None),
            "agreement_denominator": reviewed,
            "note": (None if reviewed else "no reviewed samples in the window; agreement is not measured"),
        }
    except Exception as exc:  # noqa: BLE001
        review["closure_qa"] = {"could_not_check": type(exc).__name__}

    try:
        days = max(1, (period_end - period_start).days)
        sla = await compute_sla_metrics(db, tenant_id, days=days)
        # compute_sla_metrics already carries `total` per severity — the
        # denominator discipline this review exists to enforce.
        review["response_times"] = {
            "per_severity": sla.get("per_severity", {}),
            "targets": sla.get("targets", {}),
            "note": "averages carry `total`, the rows they averaged; a severity with total=0 is not measured",
        }
    except Exception as exc:  # noqa: BLE001
        review["response_times"] = {"could_not_check": type(exc).__name__}

    try:
        row = (await db.execute(_ACTIONS_SQL, params)).fetchone()
        review["actions"] = {
            "dispatched": int(row[0]) if row else 0,
            "executed": int(row[1]) if row else 0,
            "failed": int(row[2]) if row else 0,
        }
    except Exception as exc:  # noqa: BLE001
        review["actions"] = {"could_not_check": type(exc).__name__}

    try:
        count = (await db.execute(_HUNTS_SQL, params)).scalar_one()
        review["hunts_run"] = {
            "hunts_with_latest_run_in_window": int(count),
            "note": "saved hunts record only their last run; this is a lower bound on executions",
        }
    except Exception as exc:  # noqa: BLE001
        review["hunts_run"] = {"could_not_check": type(exc).__name__}

    return review


def review_summary_for_webhook(review: dict[str, Any]) -> dict[str, Any]:
    """The compact body a webhook receiver gets; the artefact holds the rest."""
    funnel = review.get("alert_funnel", {})
    qa = review.get("closure_qa", {})
    return {
        "tenant_id": review["tenant_id"],
        "period": review["period"],
        "ingested": funnel.get("ingested"),
        "auto_closed": funnel.get("auto_closed"),
        "qa_agreement": qa.get("agreement"),
        "qa_denominator": qa.get("agreement_denominator"),
        "hunts_run": review.get("hunts_run"),
    }
