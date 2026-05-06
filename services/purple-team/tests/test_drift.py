"""Unit tests for compute_drift — pure stdlib, no DB required."""

from __future__ import annotations

from app.services.coverage import build_coverage_matrix
from app.services.drift_diff import compute_drift


def _exec(
    technique_id: str,
    tactic: str,
    *,
    status: str = "success",
    detected: bool = False,
) -> dict:
    return {
        "technique_id": technique_id,
        "tactic": tactic,
        "status": status,
        "detected": detected,
        "test_name": f"test for {technique_id}",
    }


class TestComputeDrift:
    def test_no_change_marks_all_unchanged(self) -> None:
        cov = build_coverage_matrix(
            [
                _exec("T1078", "initial-access", status="success", detected=True),
                _exec("T1059", "execution", status="success", detected=True),
            ]
        )
        drift = compute_drift(cov, cov)
        statuses = {t["status"] for t in drift["techniques"]}
        assert statuses == {"unchanged"}
        assert drift["summary"]["regressed"] == 0
        assert drift["summary"]["improved"] == 0

    def test_new_technique_marked_new(self) -> None:
        prev = build_coverage_matrix([_exec("T1078", "initial-access")])
        curr = build_coverage_matrix(
            [
                _exec("T1078", "initial-access"),
                _exec("T1059", "execution"),
            ]
        )
        drift = compute_drift(curr, prev)
        new_techs = [t for t in drift["techniques"] if t["status"] == "new"]
        assert len(new_techs) == 1
        assert new_techs[0]["technique_id"] == "T1059"
        assert drift["summary"]["new"] == 1

    def test_removed_technique_marked_removed(self) -> None:
        prev = build_coverage_matrix(
            [
                _exec("T1078", "initial-access"),
                _exec("T1059", "execution"),
            ]
        )
        curr = build_coverage_matrix([_exec("T1078", "initial-access")])
        drift = compute_drift(curr, prev)
        removed = [t for t in drift["techniques"] if t["status"] == "removed"]
        assert len(removed) == 1
        assert removed[0]["technique_id"] == "T1059"
        assert drift["summary"]["removed"] == 1

    def test_regression_lowers_detection_count(self) -> None:
        prev = build_coverage_matrix([_exec("T1078", "initial-access", status="success", detected=True)])
        curr = build_coverage_matrix([_exec("T1078", "initial-access", status="success", detected=False)])
        drift = compute_drift(curr, prev)
        regressed = [t for t in drift["techniques"] if t["status"] == "regressed"]
        assert len(regressed) == 1
        assert regressed[0]["delta_detected"] == -1
        assert drift["summary"]["regressed"] == 1

    def test_improvement_raises_detection_count(self) -> None:
        prev = build_coverage_matrix([_exec("T1078", "initial-access", status="success", detected=False)])
        curr = build_coverage_matrix([_exec("T1078", "initial-access", status="success", detected=True)])
        drift = compute_drift(curr, prev)
        improved = [t for t in drift["techniques"] if t["status"] == "improved"]
        assert len(improved) == 1
        assert improved[0]["delta_detected"] == 1
        assert drift["summary"]["improved"] == 1

    def test_summary_delta_reflects_aggregate_change(self) -> None:
        prev = build_coverage_matrix([_exec("T1078", "initial-access", status="success", detected=False)])
        curr = build_coverage_matrix(
            [
                _exec("T1078", "initial-access", status="success", detected=True),
                _exec("T1059", "execution", status="success", detected=True),
            ]
        )
        drift = compute_drift(curr, prev)
        delta = drift["summary"]["delta"]
        assert delta["delta_total"] == 1
        assert delta["delta_tested"] == 1
        assert delta["delta_detected"] == 2

    def test_none_inputs_produce_empty_drift(self) -> None:
        drift = compute_drift(None, None)
        assert drift["techniques"] == []
        assert drift["summary"]["new"] == 0
        assert drift["summary"]["removed"] == 0

    def test_first_snapshot_against_none_marks_all_new(self) -> None:
        curr = build_coverage_matrix(
            [
                _exec("T1078", "initial-access"),
                _exec("T1059", "execution"),
            ]
        )
        drift = compute_drift(curr, None)
        statuses = {t["status"] for t in drift["techniques"]}
        assert statuses == {"new"}
        assert drift["summary"]["new"] == 2
