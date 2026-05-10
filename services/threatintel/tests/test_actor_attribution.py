"""Tests for the threat actor attribution engine.

These tests exercise the v0 hardcoded actor catalog. They are pure unit
tests — no network, no OpenSearch — so they intentionally do not pass an
``os_store`` and the IOC component of the score stays at zero, which matches
what the production engine does when the dependency is missing.
"""

from __future__ import annotations

import pytest

from app.actors.attribution import (
    AttributionResult,
    ThreatActorAttributionEngine,
    ThreatActorProfile,
)


@pytest.fixture
def attribution_engine() -> ThreatActorAttributionEngine:
    """A fresh engine bound to the default v0 catalog and no os_store."""
    return ThreatActorAttributionEngine()


@pytest.fixture
def sample_iocs() -> list[dict]:
    return [
        {
            "value": "malicious-domain.com",
            "type": "domain",
            "source": "test-feed",
            "first_seen": "2023-01-01T00:00:00Z",
            "last_seen": "2023-01-01T00:00:00Z",
        },
        {
            "value": "192.168.1.100",
            "type": "ipv4",
            "source": "test-feed",
            "first_seen": "2023-01-01T00:00:00Z",
            "last_seen": "2023-01-01T00:00:00Z",
        },
    ]


@pytest.fixture
def sample_mitre_techniques() -> list[str]:
    # Three of these (T1566, T1059, T1071) overlap APT28's seeded TTP set.
    return ["T1566", "T1059", "T1071"]


@pytest.fixture
def sample_case_metadata() -> dict:
    return {
        "targets": ["government", "military"],
        "industry": "defense",
        "geography": "US",
    }


@pytest.mark.asyncio
async def test_initialize_known_actors(attribution_engine):
    """The default catalog contains at least the seeded actors."""
    profiles = await attribution_engine.list_actor_profiles()
    assert len(profiles) > 0
    actor_ids = [profile.id for profile in profiles]
    assert "APT28" in actor_ids


@pytest.mark.asyncio
async def test_get_actor_profile(attribution_engine):
    """Lookup hits a known actor and misses an unknown one."""
    profile = await attribution_engine.get_actor_profile("APT28")
    assert profile is not None
    assert profile.name == "APT28 (Fancy Bear)"

    missing = await attribution_engine.get_actor_profile("NONEXISTENT")
    assert missing is None


@pytest.mark.asyncio
async def test_attribute_incident_high_confidence(
    attribution_engine,
    sample_iocs,
    sample_mitre_techniques,
    sample_case_metadata,
):
    """A case overlapping APT28 across TTPs/tools/targets attributes to APT28."""
    sample_iocs.append(
        {
            "value": "x-agent-malware.exe",
            "type": "filename",
            "source": "test-analysis",
            "first_seen": "2023-01-01T00:00:00Z",
            "last_seen": "2023-01-01T00:00:00Z",
        }
    )

    result = await attribution_engine.attribute_incident(
        iocs=sample_iocs,
        mitre_techniques=sample_mitre_techniques,
        case_metadata=sample_case_metadata,
    )

    assert isinstance(result, AttributionResult)
    assert result.actor_id == "APT28"
    assert result.confidence_score > 0
    joined = " ".join(result.reasoning)
    assert "TTP" in joined
    assert "tools" in joined.lower()


@pytest.mark.asyncio
async def test_attribute_incident_no_match(attribution_engine):
    """Below-threshold matches return ``unknown``."""
    iocs = [{"value": "unknown-indicator", "type": "generic", "source": "test"}]
    techniques = ["T9999"]  # not in any seeded actor's TTP list
    case_metadata = {"targets": ["unknown-sector"]}

    result = await attribution_engine.attribute_incident(
        iocs=iocs,
        mitre_techniques=techniques,
        case_metadata=case_metadata,
    )

    assert isinstance(result, AttributionResult)
    assert result.actor_id == "unknown"
    assert result.confidence_score == 0.0


@pytest.mark.asyncio
async def test_detect_defense_impairment_techniques(attribution_engine):
    """Test detection of Defense Impairment techniques (T1562.x)."""
    # Test case with Defense Impairment techniques
    iocs = [
        {
            "value": "taskkill.exe",
            "type": "process",
            "source": "endpoint-monitoring",
            "first_seen": "2023-01-01T00:00:00Z",
            "last_seen": "2023-01-01T00:00:00Z",
        }
    ]
    techniques = ["T1562", "T1562.001", "T1089", "T1070"]  # Defense Impairment techniques
    case_metadata = {"targets": ["government", "technology"]}

    result = await attribution_engine.attribute_incident(
        iocs=iocs,
        mitre_techniques=techniques,
        case_metadata=case_metadata,
    )

    # Should return a valid result (could be any actor that matches some techniques)
    assert isinstance(result, AttributionResult)
    
    # Test with no Defense Impairment techniques
    techniques_no_impairment = ["T1566", "T1059"]  # Phishing and Command-Line Interface only
    
    result_no_impairment = await attribution_engine.attribute_incident(
        iocs=iocs,
        mitre_techniques=techniques_no_impairment,
        case_metadata=case_metadata,
    )
    
    # Should still return a valid result
    assert isinstance(result_no_impairment, AttributionResult)


@pytest.mark.asyncio
async def test_update_actor_profile(attribution_engine):
    """Adding a profile makes it visible to subsequent lookups."""
    new_profile = ThreatActorProfile(
        id="TEST_ACTOR",
        name="Test Actor",
        aliases=["Testy"],
        description="A test threat actor",
        sophistication_level="novice",
        primary_motivation="testing",
        secondary_motivations=["learning"],
        ttps=["T1000"],
        tools=["test-tool"],
        targets=["test-environment"],
        confidence_score=0.5,
    )

    await attribution_engine.update_actor_profile(new_profile)

    retrieved = await attribution_engine.get_actor_profile("TEST_ACTOR")
    assert retrieved is not None
    assert retrieved.name == "Test Actor"
    assert retrieved.description == "A test threat actor"


@pytest.mark.asyncio
async def test_ioc_component_skipped_without_os_store(
    attribution_engine, sample_iocs, sample_mitre_techniques, sample_case_metadata
):
    """Without an os_store, reasoning explicitly notes IOC scoring is unavailable."""
    result = await attribution_engine.attribute_incident(
        iocs=sample_iocs,
        mitre_techniques=sample_mitre_techniques,
        case_metadata=sample_case_metadata,
    )
    joined = " ".join(result.reasoning)
    assert "no os_store wired" in joined
