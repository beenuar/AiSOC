"""The fusion gateway's console-shape adapters (#1931).

Fusion's entity-risk wire shapes and the console's ``EntityRiskRecord`` /
``EntityRiskStats`` types had never met. On a stock Compose install the
gateway wasn't even wired (no ``FUSION_SERVICE_URL``), and the first
deployment that wired it crashed the Alerts route on
``severity_histogram.critical`` of ``undefined``. These tests feed the
adapters fusion's *actual* wire shapes — including the historical
``…+00:00Z`` timestamps — and assert the console contract comes out.
"""

from __future__ import annotations

from datetime import datetime

from app.api.v1.endpoints.fusion import (
    _adapt_queue,
    _adapt_record,
    _adapt_stats,
    _clean_iso,
)

#: Exactly what fusion's EntityRiskRecord.to_dict() returned before (and
#: after, modulo the timestamp repair) — see services/fusion entity_risk.py.
FUSION_RECORD = {
    "tenant_id": "00000000-0000-0000-0000-000000000001",
    "entity_type": "src_ip",
    "entity_value": "198.51.100.42",
    "score": 92.41,
    "alert_count": 3,
    "last_seen": "2026-11-15T13:30:00Z",
    "contributing_alerts": ["a1", "a2", "a3"],
    "severities": {"critical": 1, "high": 2},
    "promoted_at": None,
    "contributors": [
        {
            "alert_id": "a1",
            "severity": "high",
            "detection": "Impossible travel",
            "points": 12.0,
            # The historical malformed stamp: offset AND Z (#1931).
            "at": "2026-11-15T13:22:10+00:00Z",
        },
        {
            "alert_id": "a2",
            "severity": "critical",
            "detection": "C2 beacon",
            "points": 20.0,
            "at": "2026-11-15T13:25:00Z",
        },
    ],
}

FUSION_QUEUE = {
    "tenant_id": "00000000-0000-0000-0000-000000000001",
    "threshold": 80.0,
    "entities": [FUSION_RECORD],
}

FUSION_STATS = {
    "tenant_id": "00000000-0000-0000-0000-000000000001",
    "tracked_entities": 41,
    "promoted_entities": 2,
    "score_bands": {"critical": 2, "high": 5, "medium": 9, "low": 25},
    "threshold": 80.0,
}


def _parseable(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


# ────────────────────────────────────────────────────────────────────────────
# Timestamp repair
# ────────────────────────────────────────────────────────────────────────────


def test_clean_iso_repairs_offset_plus_z() -> None:
    repaired = _clean_iso("2026-11-15T13:22:10+00:00Z")
    assert repaired is not None
    assert repaired == "2026-11-15T13:22:10Z"
    _parseable(repaired)


def test_clean_iso_passes_well_formed_through() -> None:
    assert _clean_iso("2026-11-15T13:22:10Z") == "2026-11-15T13:22:10Z"
    assert _clean_iso("2026-11-15T13:22:10+02:00") == "2026-11-15T13:22:10+02:00"


def test_clean_iso_refuses_non_strings() -> None:
    assert _clean_iso(None) is None
    assert _clean_iso(12345) is None
    assert _clean_iso("") is None


# ────────────────────────────────────────────────────────────────────────────
# Record adaptation — the SeverityHistogram crash and friends
# ────────────────────────────────────────────────────────────────────────────


def test_adapted_record_matches_console_contract() -> None:
    out = _adapt_record(dict(FUSION_RECORD), threshold=80.0)

    # The crash in #1931: ["critical","high",...].map(s => e[s]) with the
    # histogram undefined. All five tiers must exist, zero-filled.
    assert out["severity_histogram"] == {"critical": 1, "high": 2, "medium": 0, "low": 0, "info": 0}

    assert out["entity_type"] == "ip"  # src_ip is fusion's internal name
    assert out["score"] == 92.41
    assert out["display_score"] == 92
    assert out["threshold"] == 80.0
    assert out["promoted"] is True  # score >= threshold, promoted_at unset
    assert out["promoted_incident_id"] is None
    assert out["alert_count"] == 3

    assert len(out["contributions"]) == 2
    first = out["contributions"][0]
    assert first["title"] == "Impossible travel"  # detection → title
    assert first["raw_points"] == 12.0  # points → raw_points
    assert first["observed_at"] == "2026-11-15T13:22:10Z"  # at → observed_at, repaired
    assert first["source"] is None

    # first_seen = oldest surviving contribution; last_seen passthrough.
    assert out["first_seen"] == "2026-11-15T13:22:10Z"
    assert out["last_seen"] == "2026-11-15T13:30:00Z"
    for key in ("first_seen", "last_seen"):
        _parseable(out[key])


def test_promoted_at_alone_marks_promoted() -> None:
    record = dict(FUSION_RECORD, score=10.0, promoted_at="2026-11-15T13:00:00Z")
    out = _adapt_record(record, threshold=80.0)
    assert out["promoted"] is True


def test_below_threshold_unpromoted() -> None:
    record = dict(FUSION_RECORD, score=10.0, promoted_at=None)
    out = _adapt_record(record, threshold=80.0)
    assert out["promoted"] is False


def test_record_without_contributors_falls_back_to_last_seen() -> None:
    record = dict(FUSION_RECORD, contributors=[])
    out = _adapt_record(record, threshold=80.0)
    assert out["first_seen"] == out["last_seen"]
    assert out["contributions"] == []


def test_detail_route_threshold_rides_the_record() -> None:
    """A current fusion sends threshold on the detail record; the adapter
    must prefer it over the engine-default fallback."""
    record = dict(FUSION_RECORD, threshold=65.0)
    out = _adapt_record(record, threshold=None)
    assert out["threshold"] == 65.0
    assert out["promoted"] is True  # 92.41 >= 65


# ────────────────────────────────────────────────────────────────────────────
# Queue + stats envelopes
# ────────────────────────────────────────────────────────────────────────────


def test_adapted_queue_inherits_envelope_threshold() -> None:
    out = _adapt_queue(dict(FUSION_QUEUE))
    assert out["threshold"] == 80.0
    assert len(out["entities"]) == 1
    assert out["entities"][0]["threshold"] == 80.0
    assert out["entities"][0]["entity_type"] == "ip"


def test_adapted_stats_match_console_contract() -> None:
    out = _adapt_stats(dict(FUSION_STATS))
    assert out["total"] == 41  # tracked_entities
    assert out["promoted"] == 2  # promoted_entities
    assert out["bands"] == {"critical": 2, "high": 5, "medium": 9, "low": 25}  # score_bands
    assert out["threshold"] == 80.0
    # Fusion publishes no total alert count; the console computes it from the
    # queue rows when the key is absent. A confident 0 here would be a wrong
    # number on every dashboard.
    assert "alert_count" not in out


def test_sparse_stats_zero_fill_bands() -> None:
    out = _adapt_stats({"tracked_entities": 1, "promoted_entities": 0, "score_bands": {"high": 1}})
    assert out["bands"] == {"critical": 0, "high": 1, "medium": 0, "low": 0}
