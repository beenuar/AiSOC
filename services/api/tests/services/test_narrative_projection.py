"""Unit tests for ``app.services.narrative_projection``.

The projection is pure: ORM ``Alert`` row → ``NarrativeInputs`` dataclass.
We use ``SimpleNamespace`` stand-ins for the ORM row so the test stays
hermetic — no SQLAlchemy mapper, no DB. The projection is exercised
through ``project_alert_to_narrative_inputs`` plus the public-builder
contract; we never poke at the underscore helpers directly so the test
keeps tracking the public surface as it evolves.

The contract we're guarding:

1. The denormalised entity columns (``affected_ips``, ``affected_hosts``,
   ``affected_users``) take precedence over ``raw_event`` fallbacks.
2. ``severity`` is lower-cased and clamped to the valid five-tier ladder.
3. ``confidence_label`` is lower-cased and clamped to the three valid
   bands; out-of-range values fall back to ``None`` (the builder skips
   the rationale block).
4. MITRE coverage tolerates both shapes (bare strings *and* dicts).
5. The RBA promotion block and ``exploit_in_wild`` flag are reflected.
6. The end-to-end pipeline (project → ``build_narrative``) produces a
   non-empty, deterministic narrative for a typical alert.

AiSOC — open-source AI Security Operations Center (MIT License)
Author: Beenu Arora <beenu@cyble.com>
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from typing import Any

import pytest
from app.services.narrative_loader import build_narrative
from app.services.narrative_projection import project_alert_to_narrative_inputs

# ─── Test fixtures ───────────────────────────────────────────────────────────


def _alert(**overrides: Any) -> SimpleNamespace:
    """Build a stand-in for the ``Alert`` ORM row.

    Only the attributes the projection accesses are populated. Tests
    override just the field(s) they care about so each assertion stays
    focused on a single behaviour.
    """
    base: dict[str, Any] = {
        "id": uuid.uuid4(),
        "tenant_id": uuid.uuid4(),
        "severity": "high",
        "title": "Suspicious authentication",
        "confidence": 75,
        "confidence_label": "high",
        "confidence_rationale": [],
        "mitre_tactics": [],
        "mitre_techniques": [],
        "tags": [],
        "case_id": None,
        "connector_type": "okta",
        "affected_ips": [],
        "affected_hosts": [],
        "affected_users": [],
        "raw_event": {},
        "enrichment_data": {},
    }
    base.update(overrides)
    return SimpleNamespace(**base)


# ─── Severity / confidence normalisation ─────────────────────────────────────


@pytest.mark.parametrize(
    "raw_severity, expected",
    [
        ("CRITICAL", "critical"),
        ("High", "high"),
        ("medium", "medium"),
        ("LOW", "low"),
        ("info", "info"),
    ],
)
def test_severity_is_lowercased(raw_severity: str, expected: str) -> None:
    inputs = project_alert_to_narrative_inputs(_alert(severity=raw_severity))
    assert inputs.severity == expected


def test_severity_falls_back_to_info_when_unrecognised() -> None:
    """The fusion service always emits a known tier, but we defend in depth.

    A bad value reaching the projection (database hand-edit, future
    schema change, etc.) should *not* break narrative rendering; it
    should degrade to the informational sentence.
    """
    inputs = project_alert_to_narrative_inputs(_alert(severity="nope"))
    assert inputs.severity == "info"


def test_severity_falls_back_to_info_when_null() -> None:
    inputs = project_alert_to_narrative_inputs(_alert(severity=None))
    assert inputs.severity == "info"


@pytest.mark.parametrize("band", ["high", "medium", "low"])
def test_confidence_label_passes_through(band: str) -> None:
    inputs = project_alert_to_narrative_inputs(_alert(confidence_label=band))
    assert inputs.confidence_label == band


def test_confidence_label_is_lowercased() -> None:
    inputs = project_alert_to_narrative_inputs(_alert(confidence_label="HIGH"))
    assert inputs.confidence_label == "high"


def test_confidence_label_falls_back_to_none_for_unrecognised_band() -> None:
    """The builder's Literal type-hint accepts only high/medium/low.

    Anything else (including the legacy ``"unknown"`` we saw in some
    early seeds) drops to ``None`` so the rationale block is skipped
    rather than crashing the renderer.
    """
    inputs = project_alert_to_narrative_inputs(_alert(confidence_label="unknown"))
    assert inputs.confidence_label is None


def test_confidence_score_is_preserved_unchanged() -> None:
    """The 0-100 confidence score round-trips verbatim."""
    inputs = project_alert_to_narrative_inputs(_alert(confidence=42))
    assert inputs.confidence == 42


# ─── Entity precedence ───────────────────────────────────────────────────────


def test_denormalised_column_wins_over_raw_event() -> None:
    """``affected_ips[0]`` must beat ``raw_event.src_ip``.

    The fusion service curates the denormalised columns at correlation
    time — they're the authoritative entity set. The raw_event fallback
    only matters when fusion didn't promote anything to first-class.
    """
    inputs = project_alert_to_narrative_inputs(
        _alert(
            affected_ips=["10.0.0.5"],
            raw_event={"src_ip": "192.168.1.99"},
        )
    )
    assert inputs.src_ip == "10.0.0.5"


def test_raw_event_fallback_when_denormalised_empty() -> None:
    """When ``affected_ips`` is empty we fall through to ``raw_event``."""
    inputs = project_alert_to_narrative_inputs(_alert(raw_event={"source_ip": "192.168.1.99"}))
    # source_ip is one of the accepted aliases per the projection's
    # blob key list — see narrative_projection._from_blob.
    assert inputs.src_ip == "192.168.1.99"


def test_hostname_pulls_from_raw_event_aliases() -> None:
    """``raw_event.computer_name`` is an alias for ``hostname``."""
    inputs = project_alert_to_narrative_inputs(_alert(raw_event={"computer_name": "win-finance-07"}))
    assert inputs.hostname == "win-finance-07"


def test_username_pulls_from_raw_event_aliases() -> None:
    inputs = project_alert_to_narrative_inputs(_alert(raw_event={"account_name": "svc_backup"}))
    assert inputs.username == "svc_backup"


def test_file_hash_url_domain_dst_ip_from_raw_event() -> None:
    """All four "fallback-only" fields come from the raw event blob."""
    inputs = project_alert_to_narrative_inputs(
        _alert(
            raw_event={
                "dst_ip": "203.0.113.7",
                "sha256": "deadbeef" * 8,
                "domain": "evil.example",
                "url": "https://evil.example/payload",
            }
        )
    )
    assert inputs.dst_ip == "203.0.113.7"
    assert inputs.file_hash == "deadbeef" * 8
    assert inputs.domain == "evil.example"
    assert inputs.url == "https://evil.example/payload"


def test_empty_strings_in_columns_are_skipped() -> None:
    """A whitespace-only entity must not poison the narrative.

    Some legacy connectors emit ``""`` for absent fields; the projection
    treats those as "not present" so the builder doesn't render a
    blank entity in the summary line.
    """
    inputs = project_alert_to_narrative_inputs(
        _alert(
            affected_hosts=["   ", ""],
            raw_event={"hostname": "real-host"},
        )
    )
    assert inputs.hostname == "real-host"


# ─── MITRE coverage ──────────────────────────────────────────────────────────


def test_mitre_tactics_accepts_bare_strings() -> None:
    inputs = project_alert_to_narrative_inputs(_alert(mitre_tactics=["initial-access", "execution"]))
    assert inputs.mitre_tactics == ("initial-access", "execution")


def test_mitre_tactics_accepts_dict_shape() -> None:
    """Some connectors send ``{"name": "...", "id": "TA0001"}`` rows.

    The projection flattens both shapes to a bare tuple of names so the
    builder doesn't have to know about the heterogeneity.
    """
    inputs = project_alert_to_narrative_inputs(
        _alert(
            mitre_tactics=[
                {"name": "initial-access", "id": "TA0001"},
                {"id": "TA0002"},  # name missing — id is the fallback
            ]
        )
    )
    assert inputs.mitre_tactics == ("initial-access", "TA0002")


def test_mitre_techniques_strip_whitespace() -> None:
    inputs = project_alert_to_narrative_inputs(_alert(mitre_techniques=["  T1078  ", ""]))
    assert inputs.mitre_techniques == ("T1078",)


# ─── Confidence rationale projection ─────────────────────────────────────────


def test_rationale_factors_keep_label_value_contribution_weight() -> None:
    """The builder consumes only label/value/contribution/weight.

    Extra columns the fusion service might add later (e.g. ``factor``
    enum) are silently dropped — same shape contract as the rest of
    the projection.
    """
    inputs = project_alert_to_narrative_inputs(
        _alert(
            confidence_rationale=[
                {
                    "factor": "asset_criticality",
                    "label": "Asset criticality",
                    "value": "tier-1 critical",
                    "contribution": 0.3,
                    "weight": 0.25,
                },
                {
                    "factor": "threat_intel",
                    "label": "Threat intel match",
                    "value": "2 IOCs matched",
                    "contribution": 0.2,
                    "weight": 0.2,
                },
            ]
        )
    )
    assert len(inputs.rationale) == 2
    assert inputs.rationale[0].label == "Asset criticality"
    assert inputs.rationale[0].value == "tier-1 critical"
    assert inputs.rationale[0].contribution == pytest.approx(0.3)
    assert inputs.rationale[0].weight == pytest.approx(0.25)


def test_rationale_silently_drops_malformed_rows() -> None:
    """A bad row (missing required key, wrong type) doesn't crash.

    The projection skips it. We assert on the *count* so any future
    change that accidentally loosens validation gets caught.
    """
    inputs = project_alert_to_narrative_inputs(
        _alert(
            confidence_rationale=[
                {"label": "ok", "value": "v", "contribution": 0.5, "weight": 0.5},
                {"label": 123, "value": "v", "contribution": 0.1, "weight": 0.1},  # bad label
                "not a dict",
                {"label": "ok2", "value": "v", "contribution": "bad", "weight": 0.1},  # bad number
            ]
        )
    )
    assert len(inputs.rationale) == 1
    assert inputs.rationale[0].label == "ok"


# ─── RBA + exploit-in-wild signals ───────────────────────────────────────────


def test_rba_promotion_is_extracted() -> None:
    inputs = project_alert_to_narrative_inputs(_alert(enrichment_data={"rba_top_promotion": {"entity": "host:web-01", "score": 78.3}}))
    assert inputs.rba_entity == "host:web-01"
    assert inputs.rba_score == pytest.approx(78.3)


def test_rba_promotion_missing_returns_none() -> None:
    inputs = project_alert_to_narrative_inputs(_alert(enrichment_data={}))
    assert inputs.rba_entity is None
    assert inputs.rba_score is None


def test_exploit_in_wild_flag_via_enrichment_data() -> None:
    inputs = project_alert_to_narrative_inputs(_alert(enrichment_data={"exploit_in_wild": True}))
    assert inputs.exploit_in_wild is True


def test_exploit_in_wild_flag_via_tag() -> None:
    """The tag is the back-compat path for older vuln_boost rows."""
    inputs = project_alert_to_narrative_inputs(_alert(tags=["exploit-in-wild"]))
    assert inputs.exploit_in_wild is True


def test_exploit_in_wild_defaults_false() -> None:
    inputs = project_alert_to_narrative_inputs(_alert())
    assert inputs.exploit_in_wild is False


# ─── Correlation context ─────────────────────────────────────────────────────


def test_correlation_decision_is_correlated_when_case_id_set() -> None:
    inputs = project_alert_to_narrative_inputs(_alert(case_id=uuid.uuid4()))
    assert inputs.correlation_decision == "correlated"


def test_correlation_decision_is_none_for_orphan_alerts() -> None:
    inputs = project_alert_to_narrative_inputs(_alert(case_id=None))
    assert inputs.correlation_decision is None


def test_incident_alert_count_is_always_none_in_api_projection() -> None:
    """The API can't recompute the incident's total without an extra query.

    The narrative builder gracefully omits the "n alerts on this
    incident" suffix when ``incident_alert_count`` is ``None`` — that's
    the contract this test pins.
    """
    inputs = project_alert_to_narrative_inputs(_alert(case_id=uuid.uuid4()))
    assert inputs.incident_alert_count is None


# ─── End-to-end: project → build_narrative ───────────────────────────────────


def test_project_then_build_produces_non_empty_narrative() -> None:
    """A typical fusion-emitted alert renders a non-empty narrative.

    This is the integration point between the projection and the
    vendored builder. We don't assert exact prose (the builder is
    tested in services/fusion); we only verify the bridge works and
    keeps the projection wired correctly.
    """
    alert = _alert(
        severity="critical",
        title="Suspicious authentication burst from new geo",
        confidence=82,
        confidence_label="high",
        confidence_rationale=[
            {
                "label": "Asset criticality",
                "value": "tier-1 critical",
                "contribution": 0.3,
                "weight": 0.25,
            }
        ],
        affected_ips=["10.0.0.5"],
        affected_hosts=["win-finance-07"],
        affected_users=["alice@example.com"],
        mitre_tactics=["initial-access"],
        mitre_techniques=["T1078"],
        connector_type="okta",
        case_id=uuid.uuid4(),
    )
    inputs = project_alert_to_narrative_inputs(alert)
    narrative = build_narrative(inputs)

    assert isinstance(narrative, str)
    assert narrative.strip(), "narrative must not be empty"
    # The summary line always names the primary entity. ``src_ip`` wins
    # over hostname/user in the precedence chain, so the IP should be
    # the one rendered.
    assert "10.0.0.5" in narrative


def test_project_then_build_is_deterministic() -> None:
    """Same row → same narrative. Property the lazy-fill path relies on."""
    alert = _alert(
        severity="high",
        title="Suspicious authentication",
        affected_hosts=["win-finance-07"],
        mitre_tactics=["execution"],
    )
    n1 = build_narrative(project_alert_to_narrative_inputs(alert))
    n2 = build_narrative(project_alert_to_narrative_inputs(alert))
    assert n1 == n2
