"""The NetAPI feed has to reach a verdict, not just the store.

A polled feed that ingests indicators and never moves a score is the
"exists but unwired" defect, and it is invisible: the feed logs healthy
counts, the indicator list fills up, and every alert still scores
"no TI match".

Three links have to hold for a NetAPI hit to change a confidence score, and
each is pinned below:

1. the enrichment service surfaces a feed hit under the IOC's own ``source``
   name (``services/enrichment/internal/enricher/threatintel.go`` lower-cases
   ``ioc.Source`` into ``EnrichmentSource.Name``, and scores a single-feed
   match at 70.0, above this service's 50.0 malicious floor);
2. ``AlertEnricher`` maps that provider name onto a threat-intel key; and
3. ``ConfidenceScorer`` recognises that key as a positive signal.

Link 1 is Go and is covered by that service's own tests. Links 2 and 3 are
here, plus the end-to-end composition of the two.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from app.models.alert import AlertSeverity, FusedAlert, FusionDecision, RawAlert
from app.services.alert_enricher import AlertEnricher
from app.services.confidence import ConfidenceScorer, _ti_contribution


def _alert(**kwargs) -> RawAlert:
    return RawAlert(
        tenant_id=uuid4(),
        source="unit-test",
        title="Test alert",
        severity=AlertSeverity.MEDIUM,
        **kwargs,
    )


def _fused(alert: RawAlert, enrichments: dict) -> FusedAlert:
    return FusedAlert(
        id=alert.id,
        tenant_id=alert.tenant_id,
        incident_id=uuid4(),
        fusion_decision=FusionDecision.NEW_INCIDENT,
        alert=alert,
        anomaly_score=0.0,
        priority_score=0.0,
        enrichments=enrichments,
    )


# ─── Link 3: the scorer recognises the key ───────────────────────────────────


def test_netapi_hit_is_a_positive_threat_intel_signal() -> None:
    contribution, value = _ti_contribution({"netapi": {"hit": True, "matches": ["1.2.3.4"]}})

    assert contribution > 0.0
    assert "NETAPI" in value


def test_netapi_hit_is_worth_the_same_as_any_other_single_feed() -> None:
    # Not special-cased in either direction: one keyless feed matching is the
    # same evidence as one keyed feed matching.
    netapi, _ = _ti_contribution({"netapi": {"hit": True, "matches": ["1.2.3.4"]}})
    otx, _ = _ti_contribution({"otx": {"hit": True, "matches": ["1.2.3.4"]}})

    assert netapi == otx


def test_netapi_corroborated_by_another_feed_scores_higher() -> None:
    single, _ = _ti_contribution({"netapi": {"hit": True, "matches": ["1.2.3.4"]}})
    both, sources = _ti_contribution(
        {
            "netapi": {"hit": True, "matches": ["1.2.3.4"]},
            "misp": {"hit": True, "matches": ["1.2.3.4"]},
        }
    )

    assert both > single
    assert "NETAPI" in sources and "MISP" in sources


def test_no_netapi_hit_still_scores_as_no_match() -> None:
    contribution, value = _ti_contribution({"netapi": {"hit": False, "matches": []}})

    assert contribution < 0.0
    assert value == "no TI match"


# ─── Link 2: the enricher maps the provider name onto that key ───────────────


def _enrichment_result(source_name: str) -> dict:
    """One result shaped the way services/enrichment answers a feed match.

    ``risk_score`` is 70.0 because that is what the Go threat-intel provider
    assigns a single-feed match; below the enricher's 50.0 floor the result is
    dropped before any source mapping happens, so the number is part of the
    contract rather than decoration.
    """
    return {
        "value": "1.2.3.4",
        "risk_score": 70.0,
        "malicious_votes": 0,
        "tags": ["ti-feed-match", "netapi", "compromised"],
        "sources": [{"name": source_name, "tier": "feed"}],
    }


@pytest.mark.parametrize("source_name", ["netapi", "NetAPI", "NETAPI"])
def test_enricher_maps_the_netapi_provider_onto_the_netapi_key(source_name: str) -> None:
    enricher = AlertEnricher(base_url="http://enrichment:8080")

    enrichments = enricher.to_enrichments([_enrichment_result(source_name)])

    assert enrichments["netapi"] == {"hit": True, "matches": ["1.2.3.4"]}
    assert "netapi" in enrichments["threat_intel"]["sources"]


def test_unknown_feed_name_is_still_ignored() -> None:
    # The mapping stays an allowlist: adding NetAPI must not turn it into
    # "anything a provider calls itself becomes a scored TI source".
    enricher = AlertEnricher(base_url="http://enrichment:8080")

    enrichments = enricher.to_enrichments([_enrichment_result("some-unregistered-feed")])

    assert "some-unregistered-feed" not in enrichments
    assert enrichments["threat_intel"]["sources"] == []


# ─── Links 2 + 3 together ────────────────────────────────────────────────────


def test_netapi_match_raises_the_confidence_score_end_to_end() -> None:
    enricher = AlertEnricher(base_url="http://enrichment:8080")
    scorer = ConfidenceScorer()

    without = scorer.score(_fused(_alert(src_ip="1.2.3.4"), {}))
    with_hit = scorer.score(_fused(_alert(src_ip="1.2.3.4"), enricher.to_enrichments([_enrichment_result("netapi")])))

    assert with_hit.confidence_score > without.confidence_score
    factor = next(f for f in with_hit.confidence_rationale if f.factor == "threat_intel")
    assert factor.contribution > 0.0
    assert "NETAPI" in factor.value
