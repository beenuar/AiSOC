"""Schema contract tests for alert.confidence + critical severity.

These tests lock in the AlertResponse Pydantic contract introduced by the
v1.5 SOC Console Parity plan (W2 critical-severity tier + W3 alert-level
confidence). They are intentionally pure — no DB, no FastAPI app — so they
run in milliseconds and stay readable.

The contract we're guarding:

1. The five-tier severity ladder (`info | low | medium | high | critical`)
   round-trips through ``AlertResponse``.
2. ``confidence`` (int 0-100), ``confidence_label`` (high|medium|low|None),
   and ``confidence_rationale`` (list|None) are part of the response model
   and accept the values the fusion service emits.
3. Legacy alerts that pre-date fusion-emitted confidence serialise cleanly
   with ``None`` on all three fields.
4. ``confidence_label`` mirrors the band enum exposed by
   ``services/fusion``'s ``ConfidenceLabel`` so the UI doesn't have to
   translate between services.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from app.api.v1.endpoints.alerts import AlertResponse


def _make_alert_payload(**overrides) -> dict:
    """Build a minimum-viable AlertResponse-shaped dict.

    Mirrors the columns ``AlertResponse`` exposes today. Tests override
    just the fields they care about so each assertion stays focused.
    """
    now = datetime.now(UTC)
    base = {
        "id": uuid.uuid4(),
        "tenant_id": uuid.uuid4(),
        "title": "Suspicious Login",
        "description": None,
        "severity": "medium",
        "status": "new",
        "priority": 50,
        "category": None,
        "mitre_tactics": [],
        "mitre_techniques": [],
        "connector_type": None,
        "ai_score": None,
        "ai_summary": None,
        "ai_recommendations": [],
        "confidence": None,
        "confidence_label": None,
        "confidence_rationale": None,
        "disposition": None,
        "affected_ips": [],
        "affected_hosts": [],
        "affected_users": [],
        "case_id": None,
        "tags": [],
        "event_time": now,
        "first_seen": now,
        "last_seen": now,
        "created_at": now,
        "updated_at": now,
    }
    base.update(overrides)
    return base


# ─── Severity ladder ──────────────────────────────────────────────────────────


@pytest.mark.parametrize("severity", ["info", "low", "medium", "high", "critical"])
def test_alert_response_accepts_all_five_severity_tiers(severity: str) -> None:
    """v1.5+ ladder: every tier must round-trip through ``AlertResponse``.

    Vendor-native ``critical`` (Azure 5-tier, GCP SCC 5-tier, GitHub critical,
    AWS GuardDuty ≥8.0, AuditD identity-destruction, K8s cluster-admin
    bindings, ServiceNow P1, Tailscale tailnet lockdown) must NOT collapse
    into ``high`` at the connector boundary, so we explicitly verify it
    flows through the API contract.
    """
    payload = _make_alert_payload(severity=severity)
    resp = AlertResponse.model_validate(payload)
    assert resp.severity == severity


# ─── Confidence (W3) ──────────────────────────────────────────────────────────


def test_alert_response_accepts_full_confidence_payload() -> None:
    """A fusion-emitted alert carries score + label + rationale."""
    rationale = [
        {
            "factor": "asset_criticality",
            "weight": 0.30,
            "contribution": 25,
            "description": "Asset prod-db-01 is tier-1 critical",
        },
        {
            "factor": "threat_intel_match",
            "weight": 0.25,
            "contribution": 20,
            "description": "Source IP matched 2 IOCs",
        },
    ]
    resp = AlertResponse.model_validate(
        _make_alert_payload(
            severity="critical",
            confidence=82,
            confidence_label="high",
            confidence_rationale=rationale,
        )
    )

    assert resp.confidence == 82
    assert resp.confidence_label == "high"
    assert resp.confidence_rationale is not None
    assert len(resp.confidence_rationale) == 2
    assert resp.confidence_rationale[0]["factor"] == "asset_criticality"


def test_alert_response_accepts_null_confidence_for_legacy_alerts() -> None:
    """Pre-W3 alerts have NULL confidence and must still serialise.

    The fusion service started emitting ``confidence`` in v1.5; alerts
    created before that boundary have NULL on all three columns. The API
    contract must keep returning ``None`` rather than coerce to 0 — UIs
    interpret 0 as "actively low-confidence", which would mis-rank legacy
    alerts in the queue workbench.
    """
    resp = AlertResponse.model_validate(_make_alert_payload(severity="info"))
    assert resp.confidence is None
    assert resp.confidence_label is None
    assert resp.confidence_rationale is None


@pytest.mark.parametrize("label", ["high", "medium", "low"])
def test_alert_response_accepts_all_confidence_label_bands(label: str) -> None:
    """Bands mirror services/fusion ConfidenceLabel.{HIGH,MEDIUM,LOW}.

    Keeping the strings identical means the frontend's confidence pill
    can use the same colour-coding the fusion service intends — no
    translation layer between services.
    """
    resp = AlertResponse.model_validate(
        _make_alert_payload(confidence=60, confidence_label=label),
    )
    assert resp.confidence_label == label


def test_alert_response_accepts_empty_rationale_list() -> None:
    """An empty rationale array is valid (some scorers emit no factors)."""
    resp = AlertResponse.model_validate(
        _make_alert_payload(
            confidence=50,
            confidence_label="medium",
            confidence_rationale=[],
        ),
    )
    assert resp.confidence_rationale == []


def test_alert_response_serialises_confidence_fields_in_snake_case() -> None:
    """API uses snake_case on the wire; UI normaliser converts to camelCase.

    This pins the wire format so we don't accidentally swap to ``alias``-
    based camelCase here without also updating ``apps/web/src/lib/api.ts``.
    The frontend ``Alert`` interface uses ``confidenceLabel`` /
    ``confidenceScore``, but the conversion happens in the React layer
    (or via ``alias`` in a future cleanup), not in this endpoint.
    """
    resp = AlertResponse.model_validate(
        _make_alert_payload(
            confidence=75,
            confidence_label="high",
            confidence_rationale=[{"factor": "x", "contribution": 10}],
        ),
    )
    dumped = resp.model_dump()
    assert "confidence" in dumped
    assert "confidence_label" in dumped
    assert "confidence_rationale" in dumped
    # We have NOT (yet) introduced camelCase aliases at the API layer; if
    # someone does, they should also update the frontend normaliser in
    # ``apps/web/src/lib/api.ts``. This guard makes the migration explicit.
    assert "confidenceLabel" not in dumped
    assert "confidenceRationale" not in dumped


# ─── SLA contract: critical = P1 ──────────────────────────────────────────────


def test_sla_default_targets_treat_critical_as_p1() -> None:
    """``critical`` must have a 15-minute MTTD target (P1 / Sev1 contract).

    The five-tier ladder split out ``critical`` from ``high`` precisely so
    that real P1 incidents get a 15-minute detect / 60-minute respond
    target. If a refactor accidentally drops these back to the ``high``
    defaults (30 / 120), this test will catch it.
    """
    from app.services.sla import DEFAULT_SLA_TARGETS

    assert "critical" in DEFAULT_SLA_TARGETS
    assert DEFAULT_SLA_TARGETS["critical"]["mttd_target"] == 15
    assert DEFAULT_SLA_TARGETS["critical"]["mttr_target"] == 60
    assert DEFAULT_SLA_TARGETS["critical"]["mttc_target"] == 120


def test_sla_default_targets_treat_info_as_lowest_priority() -> None:
    """``info`` exists for awareness only — it must have the loosest SLA."""
    from app.services.sla import DEFAULT_SLA_TARGETS

    assert "info" in DEFAULT_SLA_TARGETS
    # Info should never be tighter than ``low`` on any of the three timers.
    for key in ("mttd_target", "mttr_target", "mttc_target"):
        assert DEFAULT_SLA_TARGETS["info"][key] >= DEFAULT_SLA_TARGETS["low"][key]


def test_sla_default_targets_strict_severity_ordering() -> None:
    """SLA targets must monotonically widen across the five-tier ladder.

    Each tier should have targets ≥ the next-stricter tier. This prevents a
    config refactor from accidentally making ``medium`` stricter than
    ``high``, which would confuse downstream breach reporting.
    """
    from app.services.sla import DEFAULT_SLA_TARGETS

    order = ["critical", "high", "medium", "low", "info"]
    for key in ("mttd_target", "mttr_target", "mttc_target"):
        values = [DEFAULT_SLA_TARGETS[sev][key] for sev in order]
        assert values == sorted(values), f"SLA {key} must widen across {order}: got {values}"
