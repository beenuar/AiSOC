"""Drift-sentinel v2 regression tests.

Pins the behavior that ended the m365_audit drift-noise storm:

1. Batches of *different event kinds* from the same connector produce the
   same dynamic fingerprint (param_* lifts + conditional optionals excluded).
2. A baseline with NO core fields removed => no drift, even when the
   fingerprint differs (pure additions grow the baseline silently).
3. A baseline core field DISAPPEARING => drift with that field in `removed`.
4. No persisted baseline => cannot drift; first batch seeds it.
5. Optional fields disappearing never drift.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.pipeline.fingerprint import (  # noqa: E402
    compute_dynamic_fingerprint,
    compute_fingerprint,
    evaluate_drift,
    stable_keys,
)


def _m365_event(kind: str, **extra) -> dict:
    """A normalize()-shaped m365 event of a given workload kind."""
    ev = {
        "source": "c1",
        "external_id": f"id-{kind}",
        "title": f"op {kind}",
        "description": "d",
        "severity": "info",
        "actor": "u@example.com",
        "workload": kind,
        "operation": f"Op {kind}",
        "event_type": f"m365.{kind.lower()}.op{kind}",
        "raw_event": {},
        "created_at": "2026-11-19T00:00:00Z",
    }
    ev.update(extra)
    return ev


def test_dynamic_fingerprint_stable_across_event_kinds() -> None:
    exchange = [_m365_event("Exchange", src_ip="1.2.3.4", param_url="http://x")]
    sharepoint = [_m365_event("SharePoint", object_id="/sites/y", param_folder="docs")]
    ad = [_m365_event("AzureActiveDirectory", record_type=8, param_roleinfo="admin")]
    assert compute_dynamic_fingerprint(exchange) == compute_dynamic_fingerprint(sharepoint)
    assert compute_dynamic_fingerprint(sharepoint) == compute_dynamic_fingerprint(ad)
    # legacy flavour WOULD differ — that's the noise we eliminated
    assert compute_fingerprint(exchange) != compute_fingerprint(sharepoint)


def test_optional_and_dynamic_never_in_fingerprint() -> None:
    keys = stable_keys([_m365_event("Exchange", src_ip="1.2.3.4", param_anything=1)])
    assert "src_ip" not in keys
    assert "param_anything" not in keys
    assert "workload" in keys  # core stays


def test_pure_addition_is_not_drift() -> None:
    baseline = ["actor", "event_type", "severity", "workload"]
    current = baseline + ["new_core_field"]
    res = evaluate_drift(baseline, current)
    assert res["drift_detected"] is False
    assert res["added"] == ["new_core_field"]
    assert res["removed"] == []


def test_core_field_removal_is_drift() -> None:
    baseline = ["actor", "event_type", "severity", "workload"]
    current = ["actor", "severity"]  # workload renamed/removed upstream
    res = evaluate_drift(baseline, current)
    assert res["drift_detected"] is True
    assert res["removed"] == ["event_type", "workload"]


def test_no_baseline_cannot_drift() -> None:
    res = evaluate_drift([], ["actor", "severity"])
    assert res["drift_detected"] is False


def test_optional_field_disappearance_is_not_drift() -> None:
    # baseline seeded without optionals (they never enter stable_keys),
    # current batch missing src_ip — must not flip.
    baseline = sorted(stable_keys([_m365_event("Exchange", src_ip="1.1.1.1")]))
    current = sorted(stable_keys([_m365_event("Exchange")]))
    res = evaluate_drift(baseline, current)
    assert res["drift_detected"] is False
