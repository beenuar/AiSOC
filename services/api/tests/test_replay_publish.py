"""Tests for the v8 W3 public-replay publish flow.

Focus on the two things that carry the correctness + safety contract without a
live DB: the redaction snapshot builder (no raw customer PII may survive) and
the route registration (public + authed surfaces are wired).
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

import pytest
from app.services.replay_redaction import build_redacted_snapshot


def _sample_run_events() -> tuple[dict, list[dict]]:
    started = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
    run = {
        "case_id": "INC-RT-001",
        "alert_summary": "Ransomware on WIN-FIN-DB01.corp for user j.doe (j.doe@acme.local)",
        "raw_alert": {"mitre_techniques": ["T1486", "T1490"], "src_ip": "10.0.0.5"},
        "model_used": "gpt-4o-mini",
        "status": "completed",
        "started_at": started,
        "completed_at": started + timedelta(seconds=94),
    }
    events = [
        {
            "seq": 0,
            "kind": "recon",
            "agent": "TriageAgent",
            "summary": "Investigating host WIN-FIN-DB01.corp, internal IP 10.0.0.5",
            "payload": {"reason": "host WIN-FIN-DB01.corp shows mass encryption", "confidence": 0.9},
            "ts": started,
            "duration_ms": 1200,
        },
        {
            "seq": 1,
            "kind": "tool_call",
            "agent": "HuntAgent",
            "summary": "Queried EDR for user j.doe@acme.local from C:\\Users\\jdoe\\ransom.exe",
            "payload": {"tool": "edr_search", "techniques": ["T1021.002"]},
            "ts": started + timedelta(seconds=10),
            "duration_ms": 800,
        },
        {
            "seq": 2,
            "kind": "evidence_cited",
            "agent": "HuntAgent",
            "summary": "Beacon to malware-c2.example.com confirmed",
            "payload": {"source": "threat-intel", "verdict": "true_positive"},
            "ts": started + timedelta(seconds=40),
            "duration_ms": 100,
        },
    ]
    return run, events


def test_redaction_hides_customer_pii_but_keeps_public_iocs() -> None:
    run, events = _sample_run_events()
    result = build_redacted_snapshot(run=run, events=events)
    serialized = str(result.snapshot)

    # Customer PII must be gone from the stored snapshot.
    assert "j.doe@acme.local" not in serialized
    assert "WIN-FIN-DB01.corp" not in serialized
    assert "10.0.0.5" not in serialized
    assert "C:\\Users\\jdoe" not in serialized

    # Aliases must appear instead, and the alias map (preview-only) must carry
    # the originals so the publisher can review the diff.
    assert any(tok.startswith(("HOST_", "USER_", "IP_", "EMAIL_", "PATH_")) for tok in result.alias_map)
    assert "WIN-FIN-DB01.corp" in result.alias_map.values()

    # Public IOCs (external domain) are intentionally preserved — they are the
    # shareable threat-intel value, not customer PII. (Regex match, not a URL
    # substring check — this is a presence assertion, not sanitization.)
    assert re.search(r"malware-c2\.example\.com", serialized) is not None


def test_snapshot_shape_and_counts() -> None:
    run, events = _sample_run_events()
    result = build_redacted_snapshot(run=run, events=events)
    snap = result.snapshot

    assert snap["schemaVersion"] == 1
    assert snap["stepCount"] == 3
    assert snap["toolCallCount"] == 1
    assert snap["evidenceSourceCount"] == 1
    assert snap["elapsedMs"] == 94_000
    assert snap["verdict"] == "true_positive"
    # Techniques collected from raw_alert + event payloads, de-duplicated.
    assert "T1486" in snap["techniques"]
    assert "T1021.002" in snap["techniques"]
    # Attack graph seeds an alert node feeding a technique chain.
    assert snap["attackGraph"]["nodes"][0]["id"] == "alert"
    assert len(snap["attackGraph"]["edges"]) >= 1


def test_routes_registered() -> None:
    # Assert directly on the replay router objects' path contract. This is
    # deterministic and independent of the global app singleton (which other
    # tests in the full suite mutate) and of include-order/prefix resolution.
    try:
        from app.api.v1.endpoints import replay
    except ModuleNotFoundError as exc:  # pragma: no cover - local envs missing runtime deps
        pytest.skip(f"API runtime dependency unavailable in this environment: {exc.name}")

    ledger_paths = {getattr(r, "path", "") for r in replay.router.routes}
    public_paths = {getattr(r, "path", "") for r in replay.public_router.routes}
    assert "/ledger/{run_id}/publish" in ledger_paths
    assert "/ledger/{run_id}/publish/preview" in ledger_paths
    assert "/r/{slug}" in public_paths
