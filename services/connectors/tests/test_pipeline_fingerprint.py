"""Tests for the schema-fingerprint module.

The fingerprint is the foundation of the Schema-Drift Sentinel: it has to be
**stable** across reorderings and value changes, and **distinct** when the set
of top-level keys actually changes. These tests lock those properties down so
the scheduler can safely use the digest as a primary-key for "schema we last
saw on this connector".
"""

from __future__ import annotations

from app.pipeline.fingerprint import compute_fingerprint, diff_fingerprints


def test_fingerprint_stable_across_event_order() -> None:
    a = [{"severity": "high", "host": "h1"}, {"severity": "low", "host": "h2"}]
    b = list(reversed(a))
    assert compute_fingerprint(a) == compute_fingerprint(b)


def test_fingerprint_stable_across_value_changes() -> None:
    a = [{"severity": "high", "host": "h1"}]
    b = [{"severity": "low", "host": "h2"}]
    # Same key set, different values — fingerprint must be identical.
    assert compute_fingerprint(a) == compute_fingerprint(b)


def test_fingerprint_changes_when_field_added() -> None:
    baseline = [{"severity": "high"}]
    drifted = [{"severity": "high", "new_field": "x"}]
    assert compute_fingerprint(baseline) != compute_fingerprint(drifted)


def test_fingerprint_changes_when_field_removed() -> None:
    baseline = [{"severity": "high", "user": "u1"}]
    drifted = [{"severity": "high"}]
    assert compute_fingerprint(baseline) != compute_fingerprint(drifted)


def test_fingerprint_unions_keys_across_events() -> None:
    # The union of keys is what we hash, so an event missing 'user' shouldn't
    # change the fingerprint as long as some other event has it.
    a = [{"severity": "high", "user": "u1"}, {"severity": "low"}]
    b = [{"severity": "high"}, {"severity": "low", "user": "u1"}]
    assert compute_fingerprint(a) == compute_fingerprint(b)


def test_fingerprint_empty_returns_none() -> None:
    assert compute_fingerprint([]) is None
    assert compute_fingerprint([{}]) is None


def test_fingerprint_skips_non_dict_events() -> None:
    # A misbehaving connector returning a plain string shouldn't crash;
    # we just skip the offender and fingerprint the rest.
    a = [{"severity": "high"}, "garbage"]  # type: ignore[list-item]
    b = [{"severity": "high"}]
    assert compute_fingerprint(a) == compute_fingerprint(b)


def test_diff_added_and_removed() -> None:
    diff = diff_fingerprints({"severity", "host"}, {"severity", "user"})
    assert diff["added"] == ["user"]
    assert diff["removed"] == ["host"]
    assert diff["unchanged_count"] == 1


def test_diff_unchanged() -> None:
    diff = diff_fingerprints({"severity", "host"}, {"severity", "host"})
    assert diff["added"] == []
    assert diff["removed"] == []
    assert diff["unchanged_count"] == 2


def test_diff_handles_empty_previous() -> None:
    diff = diff_fingerprints(set(), {"severity", "host"})
    assert sorted(diff["added"]) == ["host", "severity"]
    assert diff["removed"] == []
    assert diff["unchanged_count"] == 0
