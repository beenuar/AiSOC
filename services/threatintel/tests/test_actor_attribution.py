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
async def test_ioc_component_skipped_without_os_store(attribution_engine, sample_iocs, sample_mitre_techniques, sample_case_metadata):
    """Without an os_store, reasoning explicitly notes IOC scoring is unavailable."""
    result = await attribution_engine.attribute_incident(
        iocs=sample_iocs,
        mitre_techniques=sample_mitre_techniques,
        case_metadata=sample_case_metadata,
    )
    joined = " ".join(result.reasoning)
    assert "no os_store wired" in joined


@pytest.mark.asyncio
async def test_tool_match_handles_underscore_filenames():
    """Tool matching survives underscore-separated malware filenames.

    Regression test for the regex boundary fix: Python's ``\\b`` treats ``_``
    as a word character, so ``\\bminiduke\\b`` would NOT match
    ``miniduke_v3.dll``. The engine uses an alphanumeric-only lookaround to
    fix this, and this test pins that behaviour.
    """
    engine = ThreatActorAttributionEngine()
    iocs = [
        {"value": "miniduke_v3.dll", "type": "filename", "source": "test"},
        {"value": "cosmicduke.exe", "type": "filename", "source": "test"},
    ]
    result = await engine.attribute_incident(
        iocs=iocs,
        # Pair with one APT29 TTP so total score crosses the default threshold.
        mitre_techniques=["T1059", "T1071", "T1041"],
        case_metadata={"targets": ["government"]},
    )
    assert result.actor_id == "APT29"
    joined = " ".join(result.reasoning).lower()
    assert "miniduke" in joined
    assert "cosmicduke" in joined


@pytest.mark.asyncio
async def test_tool_match_rejects_alphanumeric_neighbours():
    """``x-agent`` must not match ``x-agentic`` (alphanumeric neighbour)."""
    profile = ThreatActorProfile(
        id="TEST",
        name="Test",
        ttps=["T1000"],
        tools=["x-agent"],
        targets=["test"],
        confidence_score=0.8,
    )
    engine = ThreatActorAttributionEngine(catalog={"TEST": profile})
    iocs = [
        # "x-agentic-platform" should NOT match the tool "x-agent".
        {"value": "x-agentic-platform.com", "type": "domain", "source": "test"},
    ]
    result = await engine.attribute_incident(
        iocs=iocs,
        mitre_techniques=[],
        case_metadata={},
    )
    # No TTP, no tool, no target overlap → unknown.
    assert result.actor_id == "unknown"


@pytest.mark.asyncio
async def test_tool_match_uses_description_and_tags():
    """Tool matching scans description and tags, not just IOC value."""
    profile = ThreatActorProfile(
        id="TEST",
        name="Test",
        ttps=["T1059"],
        tools=["mimikatz"],
        targets=["lab"],
        confidence_score=0.9,
    )
    engine = ThreatActorAttributionEngine(catalog={"TEST": profile})
    iocs = [
        {
            "value": "evil.example",
            "type": "domain",
            "source": "test",
            "description": "drops mimikatz on host",
            "tags": ["credential-theft"],
        }
    ]
    result = await engine.attribute_incident(
        iocs=iocs,
        mitre_techniques=["T1059"],
        case_metadata={"targets": ["lab"]},
    )
    assert result.actor_id == "TEST"
    joined = " ".join(result.reasoning).lower()
    assert "mimikatz" in joined


@pytest.mark.asyncio
async def test_env_threshold_overrides_default(monkeypatch):
    """``AISOC_ATTRIBUTION_THRESHOLD`` is honoured when valid."""
    monkeypatch.setenv("AISOC_ATTRIBUTION_THRESHOLD", "0.95")
    engine = ThreatActorAttributionEngine()
    # A weak signal that would normally pass the default 0.3 threshold
    # should now fall under the 0.95 bar and resolve to "unknown".
    result = await engine.attribute_incident(
        iocs=[],
        mitre_techniques=["T1566"],  # one APT28 TTP only
        case_metadata={},
    )
    assert result.actor_id == "unknown"


@pytest.mark.asyncio
async def test_env_threshold_invalid_falls_back_to_default(monkeypatch, caplog):
    """A garbage env value must not silently disable attribution."""
    monkeypatch.setenv("AISOC_ATTRIBUTION_THRESHOLD", "not-a-number")
    engine = ThreatActorAttributionEngine()
    # Default 0.3 threshold should still allow APT28 to attribute on a strong
    # multi-component signal.
    result = await engine.attribute_incident(
        iocs=[],
        mitre_techniques=["T1566", "T1059", "T1071", "T1041"],
        case_metadata={"targets": ["government", "military"]},
    )
    assert result.actor_id == "APT28"


@pytest.mark.asyncio
async def test_empty_catalog_returns_unknown():
    """An empty catalog cannot attribute anything."""
    engine = ThreatActorAttributionEngine(catalog={})
    result = await engine.attribute_incident(
        iocs=[{"value": "x", "type": "y", "source": "z"}],
        mitre_techniques=["T1059"],
        case_metadata={"targets": ["any"]},
    )
    assert result.actor_id == "unknown"
    assert "catalog is empty" in " ".join(result.reasoning).lower()
