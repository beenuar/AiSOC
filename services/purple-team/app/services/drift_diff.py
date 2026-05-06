"""Pure-Python delta computation between two ATT&CK coverage matrices.

Split out from `app.services.drift` so the heatmap-friendly delta logic
stays importable without SQLAlchemy — the storage/scheduler concerns
live in `drift.py`, the math lives here so unit tests can run with only
the standard library.
"""

from __future__ import annotations

from typing import Any


def _index_techniques(coverage: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Flatten a coverage matrix into ``{technique_id: technique_row}``."""

    out: dict[str, dict[str, Any]] = {}
    for techniques in (coverage.get("techniques") or {}).values():
        for tech in techniques:
            tid = tech.get("technique_id")
            if tid:
                out[tid] = tech
    return out


def compute_drift(
    current: dict[str, Any] | None,
    previous: dict[str, Any] | None,
) -> dict[str, Any]:
    """Compute a per-technique delta between two coverage matrices.

    Output schema is intentionally heatmap-friendly: a flat list of
    technique rows annotated with ``delta_*`` and a ``status`` enum that
    the frontend overlays directly on the existing MITRE grid.
    """

    current = current or {"techniques": {}, "summary": {}}
    previous = previous or {"techniques": {}, "summary": {}}

    cur_idx = _index_techniques(current)
    prev_idx = _index_techniques(previous)

    techniques: list[dict[str, Any]] = []
    for tid in sorted(set(cur_idx) | set(prev_idx)):
        cur = cur_idx.get(tid)
        prev = prev_idx.get(tid)

        if cur and not prev:
            status = "new"
        elif prev and not cur:
            status = "removed"
        else:
            cur_cov = float(cur.get("coverage", 0.0)) if cur else 0.0
            prev_cov = float(prev.get("coverage", 0.0)) if prev else 0.0
            cur_det = int(cur.get("detected", 0)) if cur else 0
            prev_det = int(prev.get("detected", 0)) if prev else 0

            if cur_cov > prev_cov or cur_det > prev_det:
                status = "improved"
            elif cur_cov < prev_cov or cur_det < prev_det:
                status = "regressed"
            else:
                status = "unchanged"

        techniques.append(
            {
                "technique_id": tid,
                "current": cur,
                "previous": prev,
                "delta_coverage": round(
                    float((cur or {}).get("coverage", 0.0))
                    - float((prev or {}).get("coverage", 0.0)),
                    3,
                ),
                "delta_detected": int((cur or {}).get("detected", 0))
                - int((prev or {}).get("detected", 0)),
                "status": status,
            }
        )

    cur_sum = current.get("summary") or {}
    prev_sum = previous.get("summary") or {}
    summary_delta = {
        "delta_total": int(cur_sum.get("total_techniques", 0))
        - int(prev_sum.get("total_techniques", 0)),
        "delta_tested": int(cur_sum.get("tested_techniques", 0))
        - int(prev_sum.get("tested_techniques", 0)),
        "delta_detected": int(cur_sum.get("detected_techniques", 0))
        - int(prev_sum.get("detected_techniques", 0)),
        "delta_coverage": round(
            float(cur_sum.get("overall_coverage", 0.0))
            - float(prev_sum.get("overall_coverage", 0.0)),
            3,
        ),
    }

    return {
        "techniques": techniques,
        "summary": {
            "current": cur_sum,
            "previous": prev_sum,
            "delta": summary_delta,
            "regressed": sum(1 for t in techniques if t["status"] == "regressed"),
            "improved": sum(1 for t in techniques if t["status"] == "improved"),
            "new": sum(1 for t in techniques if t["status"] == "new"),
            "removed": sum(1 for t in techniques if t["status"] == "removed"),
        },
    }
