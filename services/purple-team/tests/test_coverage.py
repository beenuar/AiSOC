"""Unit tests for build_coverage_matrix — pure stdlib, no infra."""

from __future__ import annotations

import pytest
from app.services.coverage import TACTIC_ORDER, build_coverage_matrix


def _exec(
    technique_id: str,
    tactic: str,
    *,
    status: str = "success",
    detected: bool = False,
    test_name: str = "",
) -> dict:
    return {
        "technique_id": technique_id,
        "tactic": tactic,
        "status": status,
        "detected": detected,
        "test_name": test_name or f"test for {technique_id}",
    }


class TestBuildCoverageMatrix:
    def test_empty_input_returns_zero_coverage(self) -> None:
        result = build_coverage_matrix([])
        assert result["tactics"] == []
        assert result["techniques"] == {}
        assert result["summary"] == {
            "total_techniques": 0,
            "tested_techniques": 0,
            "detected_techniques": 0,
            "overall_coverage": 0.0,
        }

    def test_executions_without_technique_id_are_skipped(self) -> None:
        result = build_coverage_matrix([{"tactic": "execution"}])
        assert result["summary"]["total_techniques"] == 0

    def test_single_passing_execution_with_detection(self) -> None:
        result = build_coverage_matrix([_exec("T1078", "initial-access", status="success", detected=True)])
        techs = result["techniques"]["initial-access"]
        assert len(techs) == 1
        t = techs[0]
        assert t["technique_id"] == "T1078"
        assert t["test_count"] == 1
        assert t["pass_count"] == 1
        assert t["detected"] == 1
        assert t["coverage"] == 1.0

        s = result["summary"]
        assert s["total_techniques"] == 1
        assert s["tested_techniques"] == 1
        assert s["detected_techniques"] == 1
        assert s["overall_coverage"] == 1.0

    def test_partial_pass_partial_detect(self) -> None:
        result = build_coverage_matrix(
            [
                _exec("T1059", "execution", status="success", detected=True),
                _exec("T1059", "execution", status="failure", detected=False),
                _exec("T1059", "execution", status="success", detected=False),
            ]
        )
        t = result["techniques"]["execution"][0]
        assert t["test_count"] == 3
        assert t["pass_count"] == 2
        assert t["detected"] == 1
        assert t["coverage"] == round(2 / 3, 3)

    def test_tactic_ordering_follows_attack_order(self) -> None:
        # Provide tactics out of canonical order
        result = build_coverage_matrix(
            [
                _exec("T1486", "impact"),
                _exec("T1059", "execution"),
                _exec("T1078", "initial-access"),
            ]
        )
        # Expect canonical ATT&CK order: initial-access, execution, impact
        idx = {tactic: i for i, tactic in enumerate(TACTIC_ORDER)}
        ordered = result["tactics"]
        assert ordered == sorted(ordered, key=lambda t: idx.get(t, 999))
        assert ordered[0] == "initial-access"
        assert ordered[-1] == "impact"

    def test_unknown_tactics_appended_at_end_alphabetically(self) -> None:
        result = build_coverage_matrix(
            [
                _exec("T1234", "made-up-tactic"),
                _exec("T5678", "another-fake"),
                _exec("T1078", "initial-access"),
            ]
        )
        # Known tactic comes first, unknowns appended (sorted)
        assert result["tactics"][0] == "initial-access"
        assert "made-up-tactic" in result["tactics"][1:]
        assert "another-fake" in result["tactics"][1:]

    def test_techniques_within_tactic_are_sorted(self) -> None:
        result = build_coverage_matrix(
            [
                _exec("T1110", "credential-access"),
                _exec("T1078", "credential-access"),
                _exec("T1003", "credential-access"),
            ]
        )
        ids = [t["technique_id"] for t in result["techniques"]["credential-access"]]
        assert ids == sorted(ids)

    def test_summary_detected_count_uses_any_detection(self) -> None:
        result = build_coverage_matrix(
            [
                _exec("T1078", "initial-access", detected=False),
                _exec("T1078", "initial-access", detected=True),
                _exec("T1059", "execution", detected=False),
            ]
        )
        # T1078 had at least one detection -> counted; T1059 had none.
        assert result["summary"]["detected_techniques"] == 1
        assert result["summary"]["total_techniques"] == 2

    @pytest.mark.parametrize(
        "tactic",
        [
            "initial-access",
            "execution",
            "persistence",
            "privilege-escalation",
            "defense-evasion",
            "credential-access",
            "discovery",
            "lateral-movement",
            "collection",
            "command-and-control",
            "exfiltration",
            "impact",
        ],
    )
    def test_all_canonical_tactics_supported(self, tactic: str) -> None:
        result = build_coverage_matrix([_exec(f"T-{tactic}", tactic)])
        assert tactic in result["tactics"]
