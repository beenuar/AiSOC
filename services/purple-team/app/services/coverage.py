"""ATT&CK coverage computation from execution history."""
from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any

LOG = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Tactic display ordering (ATT&CK Enterprise)
# ---------------------------------------------------------------------------
TACTIC_ORDER = [
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
]


def build_coverage_matrix(
    executions: list[dict[str, Any]],
) -> dict[str, Any]:
    """Given a flat list of execution records, build an ATT&CK coverage heatmap.

    Returns:
        {
            "tactics": [...],              # ordered tactic names
            "techniques": {
                "<tactic>": [             # techniques per tactic
                    {
                        "technique_id": str,
                        "test_count":   int,
                        "pass_count":   int,
                        "detected":     int,    # detections fired
                        "coverage":     float,  # 0.0 – 1.0
                    },
                    ...
                ]
            },
            "summary": {
                "total_techniques": int,
                "tested_techniques": int,
                "detected_techniques": int,
                "overall_coverage": float,
            }
        }
    """
    # Group executions by technique
    by_technique: dict[str, list[dict]] = defaultdict(list)
    tactic_for_technique: dict[str, str] = {}

    for ex in executions:
        tid = ex.get("technique_id", "")
        if not tid:
            continue
        by_technique[tid].append(ex)
        tactic_for_technique[tid] = ex.get("tactic", "unknown")

    # Build per-tactic lists
    tactic_techniques: dict[str, list[dict]] = defaultdict(list)

    for tid, tests in by_technique.items():
        tactic = tactic_for_technique[tid]
        total = len(tests)
        passed = sum(1 for t in tests if t.get("status") == "success")
        detected = sum(1 for t in tests if t.get("detected") is True)
        coverage = (passed / total) if total else 0.0

        tactic_techniques[tactic].append(
            {
                "technique_id": tid,
                "technique_name": tests[0].get("test_name", ""),
                "test_count": total,
                "pass_count": passed,
                "detected": detected,
                "coverage": round(coverage, 3),
            }
        )

    # Sort techniques within each tactic
    for tactic in tactic_techniques:
        tactic_techniques[tactic].sort(key=lambda x: x["technique_id"])

    total_techniques = len(by_technique)
    tested = sum(1 for ts in by_technique.values() if ts)
    detected_techniques = sum(
        1
        for tid, ts in by_technique.items()
        if any(t.get("detected") for t in ts)
    )
    overall = (tested / total_techniques) if total_techniques else 0.0

    tactics = [t for t in TACTIC_ORDER if t in tactic_techniques]
    for t in sorted(tactic_techniques):
        if t not in tactics:
            tactics.append(t)

    return {
        "tactics": tactics,
        "techniques": {k: v for k, v in tactic_techniques.items()},
        "summary": {
            "total_techniques": total_techniques,
            "tested_techniques": tested,
            "detected_techniques": detected_techniques,
            "overall_coverage": round(overall, 3),
        },
    }
