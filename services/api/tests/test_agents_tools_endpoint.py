"""Unit tests for the agent tools surface (Workstream 4).

These tests cover the *pure* helpers that shape ``GET /api/v1/agents/tools``
output — group lookup, description fallback, and capability normalisation
across both list-of-strings and list-of-dicts catalog payloads. The
endpoint itself is covered by integration tests once the auth fixtures
land; the helpers are the parts most likely to silently misbehave when
the connectors microservice changes its catalog wire format.
"""

from __future__ import annotations

from app.api.v1.endpoints.agents import (
    _CAPABILITY_GROUP_LOOKUP,
    _capability_descriptions,
    _capability_group_of,
    _default_description,
)

# ----------------------------------------------------------- group lookup


def test_capability_group_lookup_covers_taxonomy() -> None:
    """Every documented capability bucket must have at least one entry.

    If someone adds a new capability bucket and forgets to wire it into
    the lookup, we'd silently surface every verb in that bucket as
    'unknown'. This catches that drift before it ships.
    """
    expected_groups = {
        "read",
        "query",
        "pivot",
        "enrich",
        "contain",
        "remediate",
        "ticket",
        "audit",
    }
    seen_groups = set(_CAPABILITY_GROUP_LOOKUP.values())
    assert expected_groups <= seen_groups


def test_capability_group_of_known_value() -> None:
    assert _capability_group_of("isolate_host") == "contain"
    assert _capability_group_of("pull_alerts") == "read"
    assert _capability_group_of("push_case") == "ticket"


def test_capability_group_of_unknown_value_is_soft_signal() -> None:
    """Unknown capabilities surface as 'unknown' rather than raising.

    Dropping a verb the connector class declared would silently hide
    functionality from the agent. 'unknown' is a soft drift signal — the
    agent layer can log a warning and decide whether to use it anyway.
    """
    assert _capability_group_of("future_capability_we_havent_added_yet") == "unknown"


# ----------------------------------------------------------- descriptions


def test_default_description_humanises_underscores() -> None:
    assert _default_description("isolate_host") == "Invoke 'isolate host' on this connector instance."


def test_capability_descriptions_handles_flat_strings() -> None:
    """Older connectors-service payloads emit ``["pull_alerts", ...]``."""
    entry = {"capabilities": ["pull_alerts", "isolate_host"]}
    out = _capability_descriptions(entry)
    assert set(out.keys()) == {"pull_alerts", "isolate_host"}
    # Defaults must look reasonable, not raw enum values.
    assert "pull alerts" in out["pull_alerts"]


def test_capability_descriptions_handles_object_payload() -> None:
    """Forward-compat: connectors service may switch to richer objects."""
    entry = {
        "capabilities": [
            {"value": "pull_alerts", "description": "Stream new detections."},
            {"value": "isolate_host"},  # description omitted → fallback
        ],
    }
    out = _capability_descriptions(entry)
    assert out["pull_alerts"] == "Stream new detections."
    # Missing description falls back to the auto-generated one.
    assert "isolate host" in out["isolate_host"]


def test_capability_descriptions_skips_unknown_shapes() -> None:
    """Garbage entries shouldn't crash — they should just be ignored."""
    entry = {"capabilities": [123, None, ["nested"]]}
    assert _capability_descriptions(entry) == {}


def test_capability_descriptions_handles_missing_capabilities_key() -> None:
    """Catalog entry without a ``capabilities`` key returns empty dict."""
    assert _capability_descriptions({}) == {}
    assert _capability_descriptions({"capabilities": None}) == {}
