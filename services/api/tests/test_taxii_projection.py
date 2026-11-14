"""The STIX 2.1 projection and the TAXII pagination contract (depth 4.2).

These are pure-function tests over ``app.services.taxii`` with no database,
because the projection *is* pure and the defects that matter here are
arithmetic and string-grammar ones: an unstable id, a pattern a consumer's
parser rejects, a cursor that skips rows sharing a timestamp.

The surface that needs a database — tenant scoping, the ``added_after``
boundary against real rows — is covered in
``test_taxii_server_live.py`` against real Postgres, because a mocked
session answers whatever the test asked it to and would hide exactly those.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from app.services.taxii import (
    ALLOWED_FILTER_KEYS,
    DEFAULT_PAGE_LIMIT,
    MAX_PAGE_LIMIT,
    STIX_MEDIA_TYPE,
    TAXII_MEDIA_TYPE,
    UNPUBLISHED_IOC_TYPES,
    FilterError,
    IndicatorRow,
    clamp_limit,
    manifest_entry,
    next_cursor,
    parse_cursor,
    pattern_for,
    stix_id_for,
    to_stix_indicator,
    validate_filter,
)

NOW = datetime(2026, 10, 11, 9, 0, 0, tzinfo=UTC)


def row(**overrides) -> IndicatorRow:
    base: dict[str, Any] = {
        "id": uuid.UUID("11111111-1111-1111-1111-111111111111"),
        "ioc_type": "domain",
        "value": "evil.example.com",
        "confidence": 80,
        "severity": "high",
        "tlp": "amber",
        "threat_actor": None,
        "campaign": None,
        "malware_family": None,
        "tags": None,
        "source": "internal",
        "first_seen": NOW - timedelta(days=2),
        "last_seen": NOW,
        "expires_at": None,
        "updated_at": NOW,
        "created_at": NOW - timedelta(days=2),
    }
    base.update(overrides)
    return IndicatorRow(**base)


# ---------------------------------------------------------------------------
# Identifiers. A client deduplicates on the STIX id.
# ---------------------------------------------------------------------------


def test_the_stix_id_is_stable_across_calls():
    ioc_id = uuid.uuid4()
    assert stix_id_for(ioc_id) == stix_id_for(ioc_id)


def test_the_stix_id_is_derived_from_the_ioc_not_generated():
    # A fresh uuid4 per response would make every poll look like a store
    # full of new indicators, and a client would re-ingest the lot.
    first, second = uuid.uuid4(), uuid.uuid4()
    assert stix_id_for(first) != stix_id_for(second)
    assert stix_id_for(first).startswith("indicator--")


# ---------------------------------------------------------------------------
# Patterns. One malformed pattern usually costs the consumer the whole
# bundle, so this is where a value with a quote in it matters.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("ioc_type", "value", "expected"),
    [
        ("ip", "198.51.100.4", "[ipv4-addr:value = '198.51.100.4']"),
        ("domain", "evil.example.com", "[domain-name:value = 'evil.example.com']"),
        ("url", "http://evil.example.com/a", "[url:value = 'http://evil.example.com/a']"),
        ("file_hash_sha256", "ab" * 32, f"[file:hashes.'SHA-256' = '{'ab' * 32}']"),
        ("email", "a@example.com", "[email-addr:value = 'a@example.com']"),
    ],
)
def test_patterns_match_the_stix_grammar(ioc_type, value, expected):
    assert pattern_for(ioc_type, value) == expected


def test_a_quote_in_a_value_is_escaped_rather_than_ending_the_literal():
    pattern = pattern_for("domain", "ev'il.example.com")
    assert pattern == "[domain-name:value = 'ev\\'il.example.com']"
    # The closing bracket must still be the last character: an unescaped
    # quote would have terminated the literal early and left a pattern the
    # consumer's parser rejects, taking every other indicator in the page.
    assert pattern.endswith("']")


def test_a_backslash_is_escaped_before_the_quote_is():
    # Escaping the quote first and the backslash second would turn
    # `\` + `'` into `\\'`, which re-opens the literal.
    assert pattern_for("domain", "a\\b") == "[domain-name:value = 'a\\\\b']"


def test_an_unpublishable_type_is_skipped_rather_than_malformed():
    assert pattern_for("cve", "CVE-2026-1") is None
    assert to_stix_indicator(row(ioc_type="cve", value="CVE-2026-1")) is None


def test_every_unpublished_type_carries_a_reason():
    assert UNPUBLISHED_IOC_TYPES
    for ioc_type, reason in UNPUBLISHED_IOC_TYPES.items():
        assert reason.strip(), f"{ioc_type} is unpublished with no reason"
        assert pattern_for(ioc_type, "x") is None


# ---------------------------------------------------------------------------
# The indicator object.
# ---------------------------------------------------------------------------


def test_an_indicator_carries_the_fields_a_consumer_reads():
    obj = to_stix_indicator(
        row(
            threat_actor="FIN7",
            malware_family="Carbanak",
            tags=["phishing"],
            expires_at=NOW + timedelta(days=30),
        )
    )
    assert obj["type"] == "indicator"
    assert obj["spec_version"] == "2.1"
    assert obj["pattern_type"] == "stix"
    assert obj["confidence"] == 80
    assert obj["name"] == "FIN7 / Carbanak"
    assert "phishing" in obj["labels"]
    assert "severity:high" in obj["labels"]
    assert obj["valid_until"].endswith("Z")


def test_timestamps_are_rfc3339_with_a_literal_z():
    obj = to_stix_indicator(row())
    for field in ("created", "modified", "valid_from"):
        assert obj[field].endswith("Z"), f"{field} is {obj[field]!r}"
        assert "+00:00" not in obj[field], "several consumers reject the offset form"


def test_a_naive_timestamp_is_treated_as_utc_rather_than_local():
    naive = datetime(2026, 10, 11, 9, 0, 0)
    obj = to_stix_indicator(row(updated_at=naive))
    assert obj["modified"] == "2026-10-11T09:00:00.000Z"


def test_the_tlp_marking_is_the_one_the_specification_fixes():
    obj = to_stix_indicator(row(tlp="red"))
    assert obj["object_marking_refs"] == ["marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"]


def test_confidence_is_clamped_to_the_stix_range():
    assert to_stix_indicator(row(confidence=250))["confidence"] == 100
    assert to_stix_indicator(row(confidence=-5))["confidence"] == 0


def test_an_indicator_with_no_attribution_still_gets_a_name():
    # A STIX indicator without a name renders as a blank row in most
    # consumers, which reads as a broken feed rather than an unattributed
    # indicator.
    assert to_stix_indicator(row())["name"] == "domain evil.example.com"


# ---------------------------------------------------------------------------
# Pagination. This is the part that silently loses a client's indicators.
# ---------------------------------------------------------------------------


def test_a_cursor_round_trips():
    r = row()
    stamp, row_id = parse_cursor(next_cursor(r))
    assert row_id == r.id
    assert stamp == r.updated_at


def test_two_rows_sharing_a_timestamp_get_different_cursors():
    # One feed poll writes many indicators with the same updated_at. A
    # cursor on the timestamp alone would either repeat or skip all but
    # one of them, depending on which side of the boundary it lands.
    a = next_cursor(row(id=uuid.UUID("11111111-1111-1111-1111-111111111111")))
    b = next_cursor(row(id=uuid.UUID("22222222-2222-2222-2222-222222222222")))
    assert a != b


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "not-a-cursor",
        "2026-10-11T09:00:00+00:00|11111111-1111-1111-1111-111111111111",
        "2026-10-11T09:00:00+00:00|11111111-1111-1111-1111-111111111111|deadbeef",
    ],
)
def test_a_corrupt_cursor_fails_loudly_rather_than_paging_from_somewhere_else(bad):
    with pytest.raises(ValueError):
        parse_cursor(bad)


def test_a_hand_edited_cursor_is_refused():
    # Not a security control — the cursor carries no privilege — but a
    # truncated one must not silently restart the collection.
    original = next_cursor(row())
    stamp, row_id, digest = original.split("|")
    tampered = f"{stamp}|22222222-2222-2222-2222-222222222222|{digest}"
    with pytest.raises(ValueError):
        parse_cursor(tampered)


def test_limits_are_bounded_server_side():
    assert clamp_limit(None) == DEFAULT_PAGE_LIMIT
    assert clamp_limit(0) == DEFAULT_PAGE_LIMIT
    assert clamp_limit(-1) == DEFAULT_PAGE_LIMIT
    assert clamp_limit(10) == 10
    # An unbounded limit is a way to exhaust the service's memory from
    # outside, and TAXII allows a server to return fewer than asked.
    assert clamp_limit(10_000_000) == MAX_PAGE_LIMIT


def test_the_manifest_entry_matches_the_object_it_describes():
    r = row()
    entry = manifest_entry(r)
    assert entry["id"] == to_stix_indicator(r)["id"]
    assert entry["version"] == to_stix_indicator(r)["modified"]
    assert entry["media_type"] == STIX_MEDIA_TYPE


# ---------------------------------------------------------------------------
# Collection filters. An ignored restriction publishes more than the tenant
# asked to publish, and does it silently.
# ---------------------------------------------------------------------------


def test_an_unknown_filter_key_is_refused_rather_than_ignored():
    with pytest.raises(FilterError) as exc:
        validate_filter({"ioc_typo": ["ip"]})
    assert "ioc_typo" in str(exc.value)


def test_every_allowed_key_is_accepted():
    accepted = validate_filter(
        {
            "ioc_type": ["ip", "domain"],
            "tlp": ["green"],
            "severity": ["high"],
            "source": ["internal"],
            "tags": ["apt"],
            "min_confidence": 70,
        }
    )
    assert set(accepted) == ALLOWED_FILTER_KEYS


def test_a_single_string_is_accepted_as_a_one_item_list():
    assert validate_filter({"ioc_type": "ip"}) == {"ioc_type": ["ip"]}


@pytest.mark.parametrize(
    "bad",
    [
        {"min_confidence": "high"},
        {"min_confidence": 101},
        {"min_confidence": -1},
        {"min_confidence": True},
        {"ioc_type": []},
        {"ioc_type": [""]},
        {"ioc_type": [1]},
    ],
)
def test_malformed_filter_values_are_refused(bad):
    with pytest.raises(FilterError):
        validate_filter(bad)


def test_the_media_type_is_the_one_taxii_fixes():
    # A plain application/json response is a conformance failure some
    # clients refuse outright.
    assert TAXII_MEDIA_TYPE == "application/taxii+json;version=2.1"
    assert STIX_MEDIA_TYPE == "application/stix+json;version=2.1"
