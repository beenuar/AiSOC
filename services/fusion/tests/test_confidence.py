"""
Tests for the detection-confidence + explainability scorer.

Wave 1 contract:

* every fused alert leaves the engine with a ``confidence_label`` of
  high / medium / low **and** a non-empty ``confidence_rationale``
  containing the factors that produced the score;
* the rationale is reproducible — the same input always produces the same
  score and the same ordering of factors;
* "high confidence" requires multiple positive signals (severity alone is
  not enough to clear the bar) so the analyst can trust the label;
* "low confidence" reliably surfaces the weak / suspicious / informational
  alerts so the queue stays clean.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from app.models.alert import (
    AlertSeverity,
    ConfidenceLabel,
    FusedAlert,
    FusionDecision,
    RawAlert,
)
from app.services.confidence import (
    HIGH_THRESHOLD,
    LOW_THRESHOLD,
    ConfidenceScorer,
)

# ─── Helpers ─────────────────────────────────────────────────────────────────


def _alert(
    *,
    severity: AlertSeverity = AlertSeverity.MEDIUM,
    techniques: list[str] | None = None,
    risk_score: float = 0.0,
    src_ip: str | None = None,
    dst_ip: str | None = None,
    hostname: str | None = None,
    username: str | None = None,
    file_hash: str | None = None,
    domain: str | None = None,
    url: str | None = None,
) -> RawAlert:
    return RawAlert(
        tenant_id=uuid4(),
        source="unit-test",
        title="Test alert",
        severity=severity,
        mitre_techniques=techniques or [],
        risk_score=risk_score,
        src_ip=src_ip,
        dst_ip=dst_ip,
        hostname=hostname,
        username=username,
        file_hash=file_hash,
        domain=domain,
        url=url,
    )


def _fused(
    alert: RawAlert,
    *,
    anomaly_score: float = 0.0,
    priority_score: float = 0.0,
    enrichments: dict | None = None,
) -> FusedAlert:
    return FusedAlert(
        id=alert.id,
        tenant_id=alert.tenant_id,
        incident_id=uuid4(),
        fusion_decision=FusionDecision.NEW_INCIDENT,
        alert=alert,
        anomaly_score=anomaly_score,
        priority_score=priority_score,
        enrichments=enrichments or {},
    )


@pytest.fixture
def scorer() -> ConfidenceScorer:
    return ConfidenceScorer()


# ─── Rationale shape ─────────────────────────────────────────────────────────


def test_score_attaches_complete_rationale(scorer: ConfidenceScorer) -> None:
    """Every alert leaves the scorer with a non-empty rationale chain
    that names every weighted factor — no silent drops."""
    fused = _fused(_alert())
    scored = scorer.score(fused)
    factors = {f.factor for f in scored.confidence_rationale}
    assert factors == {
        "severity",
        "ml_anomaly",
        "ml_priority",
        "mitre_coverage",
        "threat_intel",
        "upstream_risk",
        "ioc_density",
    }


def test_rationale_is_sorted_by_impact(scorer: ConfidenceScorer) -> None:
    """The UI renders the rationale top-down, so the most impactful
    factor must come first."""
    fused = _fused(
        _alert(
            severity=AlertSeverity.CRITICAL,
            techniques=["T1078", "T1098", "T1556"],
            src_ip="10.0.0.1",
            hostname="prod-1",
            username="alice",
        ),
        anomaly_score=0.95,
        priority_score=0.95,
        enrichments={"misp": {"hit": True}, "kev": {"matches": ["CVE-2024-1234"]}},
    )
    scored = scorer.score(fused)
    impacts = [abs(f.contribution * f.weight) for f in scored.confidence_rationale]
    assert impacts == sorted(impacts, reverse=True)


def test_rationale_weights_sum_to_one(scorer: ConfidenceScorer) -> None:
    """Weights are the model's *relative importance*; they must sum to 1.0
    so that a 100%-positive contribution maps to a full +0.5 delta."""
    scored = scorer.score(_fused(_alert()))
    total = sum(f.weight for f in scored.confidence_rationale)
    assert total == pytest.approx(1.0, abs=1e-6)


def test_score_is_deterministic(scorer: ConfidenceScorer) -> None:
    """Same input → identical score and rationale ordering. The rationale
    is reproducible audit evidence."""
    alert = _alert(severity=AlertSeverity.HIGH, techniques=["T1078"])
    a = scorer.score(_fused(alert, anomaly_score=0.7, priority_score=0.6))
    b = scorer.score(_fused(alert, anomaly_score=0.7, priority_score=0.6))
    assert a.confidence_score == b.confidence_score
    assert a.confidence_label == b.confidence_label
    assert [f.factor for f in a.confidence_rationale] == [f.factor for f in b.confidence_rationale]


# ─── Banding ─────────────────────────────────────────────────────────────────


def test_high_confidence_requires_multiple_positive_signals(scorer: ConfidenceScorer) -> None:
    """Severity alone must NOT clear the HIGH threshold — the whole point
    of the explainability surface is that "critical" without supporting
    evidence is a noisy detection, not a confident one."""
    bare = _fused(_alert(severity=AlertSeverity.CRITICAL))
    scored = scorer.score(bare)
    assert scored.confidence_label != ConfidenceLabel.HIGH


def test_high_confidence_with_strong_corroborating_signals(scorer: ConfidenceScorer) -> None:
    """Critical severity + strong ML scores + MITRE coverage + TI hit + IOCs
    must produce HIGH confidence. This is the "ship it" path."""
    fused = _fused(
        _alert(
            severity=AlertSeverity.CRITICAL,
            techniques=["T1078", "T1098", "T1556"],
            risk_score=0.9,
            src_ip="10.0.0.1",
            dst_ip="8.8.8.8",
            hostname="prod-1",
            username="alice",
            file_hash="abc123",
        ),
        anomaly_score=0.92,
        priority_score=0.95,
        enrichments={
            "misp": {"hit": True},
            "otx": {"hit": True},
            "kev": {"matches": ["CVE-2024-1234"]},
        },
    )
    scored = scorer.score(fused)
    assert scored.confidence_label == ConfidenceLabel.HIGH
    assert scored.confidence_score >= HIGH_THRESHOLD


def test_low_confidence_for_info_severity_with_no_signals(scorer: ConfidenceScorer) -> None:
    """An info-severity alert with no MITRE coverage, no TI hit, no IOCs,
    and zero ML scores belongs in the low-confidence band — that's the
    "suppress or downgrade" lane."""
    fused = _fused(_alert(severity=AlertSeverity.INFO))
    scored = scorer.score(fused)
    assert scored.confidence_label == ConfidenceLabel.LOW
    assert scored.confidence_score < LOW_THRESHOLD


def test_medium_confidence_for_balanced_signal(scorer: ConfidenceScorer) -> None:
    """High severity + two techniques + a couple IOCs + reasonable ML
    scores but **no TI hit** must land in MEDIUM. This is the most
    realistic real-world detection — looks suspicious but missing the
    last bit of corroborating evidence to auto-action."""
    fused = _fused(
        _alert(
            severity=AlertSeverity.HIGH,
            techniques=["T1078", "T1098"],
            src_ip="10.0.0.1",
            hostname="prod-1",
        ),
        anomaly_score=0.6,
        priority_score=0.55,
    )
    scored = scorer.score(fused)
    assert scored.confidence_label == ConfidenceLabel.MEDIUM
    assert LOW_THRESHOLD <= scored.confidence_score < HIGH_THRESHOLD


# ─── Individual factors ──────────────────────────────────────────────────────


def test_threat_intel_hit_increases_score(scorer: ConfidenceScorer) -> None:
    """A TI hit must monotonically increase confidence relative to the
    same alert without one — that's the whole point of enrichment."""
    base = _alert(severity=AlertSeverity.HIGH, techniques=["T1078"], src_ip="10.0.0.1")

    no_ti = scorer.score(_fused(base, anomaly_score=0.6, priority_score=0.6))
    with_ti = scorer.score(
        _fused(
            base,
            anomaly_score=0.6,
            priority_score=0.6,
            enrichments={"misp": {"hit": True}},
        )
    )
    assert with_ti.confidence_score > no_ti.confidence_score


def test_mitre_coverage_increases_score(scorer: ConfidenceScorer) -> None:
    """More MITRE techniques → more confident detection. Three techniques
    must beat zero, all else equal."""
    sparse = _fused(
        _alert(severity=AlertSeverity.HIGH, src_ip="10.0.0.1"),
        anomaly_score=0.5,
        priority_score=0.5,
    )
    rich = _fused(
        _alert(
            severity=AlertSeverity.HIGH,
            techniques=["T1078", "T1098", "T1556"],
            src_ip="10.0.0.1",
        ),
        anomaly_score=0.5,
        priority_score=0.5,
    )
    assert scorer.score(rich).confidence_score > scorer.score(sparse).confidence_score


def test_ioc_density_increases_score(scorer: ConfidenceScorer) -> None:
    """More populated IOC fields → more concrete signal → higher score.
    Five IOC fields must beat zero, all else equal."""
    sparse = _fused(_alert(severity=AlertSeverity.MEDIUM, techniques=["T1078"]))
    rich = _fused(
        _alert(
            severity=AlertSeverity.MEDIUM,
            techniques=["T1078"],
            src_ip="10.0.0.1",
            dst_ip="8.8.8.8",
            hostname="prod-1",
            username="alice",
            file_hash="abc123",
        )
    )
    assert scorer.score(rich).confidence_score > scorer.score(sparse).confidence_score


# ─── Feature flag (break-glass) ──────────────────────────────────────────────


def test_disabled_scorer_passes_alert_through_unchanged() -> None:
    """When ``AISOC_FEATURE_CONFIDENCE`` is off the scorer must be a no-op:
    the alert keeps the FusedAlert defaults (MEDIUM / 0.5 / []) so the
    frontend degrades gracefully and downstream consumers never see a
    half-populated rationale."""
    disabled = ConfidenceScorer(enabled=False)
    assert disabled.enabled is False

    fused = _fused(
        _alert(severity=AlertSeverity.CRITICAL, techniques=["T1078"]),
        anomaly_score=0.95,
        priority_score=0.95,
        enrichments={"misp": {"hit": True}},
    )
    scored = disabled.score(fused)

    # Same instance back; we explicitly do NOT compute a rationale when off.
    assert scored is fused
    assert scored.confidence_label == ConfidenceLabel.MEDIUM
    assert scored.confidence_score == 0.5
    assert scored.confidence_rationale == []


def test_score_clamped_to_unit_interval(scorer: ConfidenceScorer) -> None:
    """Score must always live in [0, 1] no matter how many signals fire."""
    extreme = _fused(
        _alert(
            severity=AlertSeverity.CRITICAL,
            techniques=["T1078", "T1098", "T1556", "T1110", "T1003"],
            risk_score=1.0,
            src_ip="10.0.0.1",
            dst_ip="8.8.8.8",
            hostname="prod-1",
            username="alice",
            file_hash="abc123",
            domain="evil.example",
            url="https://evil.example/payload",
        ),
        anomaly_score=1.0,
        priority_score=1.0,
        enrichments={
            "misp": {"hit": True},
            "otx": {"hit": True},
            "kev": {"matches": ["CVE-2024-1234"]},
            "virustotal": {"hit": True},
        },
    )
    scored = scorer.score(extreme)
    assert 0.0 <= scored.confidence_score <= 1.0
