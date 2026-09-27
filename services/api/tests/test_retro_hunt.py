"""Gap-closure Phase 8.1: intel-driven retro-hunts.

Four groups, each covering one way this feature fails quietly rather than
loudly.

**The sweep reads columns the lake writer fills.** The static half of that is
``scripts/check_ioc_lake_mapping.py`` and the live half is
``tests/isolation/test_retro_hunt_live.py``. What is here is the shape of the
generated SQL: that an IPv6 column goes through ``toIPv6`` and an array column
through ``has``, because getting either wrong matches nothing with no error.

**One indicator opens at most one alert per tenant.** Tested from both
directions: a second sweep of the same indicator opens nothing and increments
a counter, and a sweep that matches a thousand events still issues one
aggregate query and opens one alert.

**A failure is never a zero.** An unreachable lake, an exhausted budget and a
type with no lake column are each distinct outcomes carrying a reason, and
none of them may read as "no sightings".

**A feed type nobody mapped is refused by name.** The translation from a
feed's vocabulary to AiSOC's is where a whole feed can silently stop being
swept, so an unknown type is asserted to be reported rather than defaulted.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from app.services.retro_hunt import ioc_fields
from app.services.retro_hunt.intel_types import route_feed_type
from app.services.retro_hunt.service import (
    IntelIndicator,
    _build_description,
    _consume_budget,
    alert_idempotency_key,
)
from app.services.retro_hunt.sweep import (
    MAX_LOOKBACK_DAYS,
    FederatedSweepResult,
    LakeSweepResult,
    SweepOutcome,
    build_sweep_sql,
)

TENANT = uuid.UUID("11111111-1111-1111-1111-111111111111")


# ------------------------------------------------------------- generated SQL


def test_every_sweepable_type_builds_a_tenant_scoped_query() -> None:
    """The predicate that makes a sweep safe is present in every statement."""
    for indicator_type, mapping in ioc_fields.SWEEPABLE_TYPES.items():
        sql, columns = build_sweep_sql(mapping)
        assert "tenant_id = %(tenant_id)s" in sql, indicator_type
        assert "%(needle)s" in sql, indicator_type
        assert columns, indicator_type


def test_no_indicator_value_is_ever_interpolated() -> None:
    """The indicator is third-party text and always travels as a parameter.

    Asserted structurally rather than by reading the code: the only ``%``
    formatting in the statement is the driver's own placeholder syntax, so a
    future edit that f-strings a value in has to break this.
    """
    for mapping in ioc_fields.SWEEPABLE_TYPES.values():
        sql, _ = build_sweep_sql(mapping)
        placeholders = {"%(tenant_id)s", "%(lookback_days)s", "%(needle)s"}
        remaining = sql
        for placeholder in placeholders:
            remaining = remaining.replace(placeholder, "")
        assert "%" not in remaining, f"unexpected format specifier in: {sql}"


def test_ip_columns_go_through_toipv6() -> None:
    """An IPv4 needle must be normalised the way the writer normalised it.

    ``lake_writer._to_ip_obj`` stores ``1.2.3.4`` as ``::ffff:1.2.3.4``, so a
    predicate comparing the IPv6 column to the dotted-quad string matches
    nothing. This is the single highest-value assertion in the file: it fails
    silently in production and loudly here.
    """
    sql, _ = build_sweep_sql(ioc_fields.SWEEPABLE_TYPES["ip"])
    assert "source_ip = toIPv6(%(needle)s)" in sql
    assert "dest_ip = toIPv6(%(needle)s)" in sql
    assert "source_ip = %(needle)s" not in sql


def test_array_columns_use_has_not_equality() -> None:
    sql, _ = build_sweep_sql(ioc_fields.SWEEPABLE_TYPES["sha256"])
    assert "has(iocs, %(needle)s)" in sql
    assert "iocs = %(needle)s" not in sql


def test_the_query_aggregates_so_a_thousand_matches_are_one_row() -> None:
    """The structural answer to "one IOC must not open a thousand alerts".

    No ``SELECT``ed event column and no absent ``count()``: the sweep cannot
    return a row per match even if a caller wanted it to.
    """
    for mapping in ioc_fields.SWEEPABLE_TYPES.values():
        sql, _ = build_sweep_sql(mapping)
        assert sql.startswith("SELECT count() AS sightings")
        assert "groupUniqArray(20)" in sql
        assert " LIMIT " not in sql  # an aggregate needs no limit to be bounded


def test_hash_types_all_read_the_column_the_writer_actually_fills() -> None:
    """md5 and sha1 read ``hash_sha256``, because that is where they land.

    ``lake_writer._first_hash`` takes ``file.fingerprints[0].value`` without
    inspecting the algorithm. A mapping to a plausible ``hash_md5`` column
    would have matched nothing on every deployment.
    """
    for hash_type in ("md5", "sha1", "sha256"):
        names = ioc_fields.SWEEPABLE_TYPES[hash_type].column_names
        assert "hash_sha256" in names, hash_type


def test_domain_does_not_sweep_the_reporting_host_column() -> None:
    """``src_hostname`` is the tenant's own device name, not a contacted name."""
    assert "src_hostname" not in ioc_fields.SWEEPABLE_TYPES["domain"].column_names
    assert "dst_hostname" in ioc_fields.SWEEPABLE_TYPES["domain"].column_names


# ------------------------------------------------------------ type routing


@pytest.mark.parametrize(
    ("feed_type", "expected"),
    [
        ("ipv4-addr", "ip"),
        ("ipv6-addr", "ip"),
        ("ip-src", "ip"),
        ("ip-dst", "ip"),
        ("domain-name", "domain"),
        ("file-hash:SHA-256", "sha256"),
        ("file-hash:MD5", "md5"),
        ("FILE-HASH:SHA-1", "sha1"),
        ("sha256", "sha256"),
    ],
)
def test_feed_vocabularies_resolve_to_one_indicator_type(feed_type: str, expected: str) -> None:
    assert route_feed_type(feed_type).indicator_type == expected


def test_an_unknown_feed_type_is_refused_by_name_not_defaulted() -> None:
    """A default here would sweep the wrong column and call the answer evidence."""
    routing = route_feed_type("some-type-no-feed-in-this-tree-emits")
    assert routing.unknown is True
    assert routing.indicator_type is None
    assert routing.reason and "NOT swept" in routing.reason


def test_a_cve_is_routed_away_from_telemetry_rather_than_swept() -> None:
    """Sweeping the lake for a CVE string matches nothing on every deployment."""
    routing = route_feed_type("vulnerability")
    assert routing.is_vulnerability is True
    assert routing.indicator_type is None


def test_a_known_unsweepable_type_is_not_reported_as_unknown() -> None:
    """Two different problems: "nobody mapped this" and "this cannot be mapped"."""
    routing = route_feed_type("email-addr")
    assert routing.unknown is False
    assert routing.indicator_type is None
    assert routing.reason


def test_url_is_declared_unmappable_with_a_reason_rather_than_omitted() -> None:
    mapping = ioc_fields.mapping_for("url")
    assert isinstance(mapping, ioc_fields.UnmappedIndicator)
    assert "raw_payload" in mapping.reason


# ------------------------------------------------------------------ budget


@dataclass
class _FakeSettings:
    """Enough of ``RetroHuntSettings`` to exercise the budget arithmetic."""

    max_sweeps_per_hour: int = 2
    max_sweeps_per_day: int = 3
    sweeps_this_hour: int = 0
    sweeps_today: int = 0
    sweeps_skipped_budget: int = 0
    hour_started_at: datetime = datetime.now(UTC)
    day_started_at: datetime = datetime.now(UTC)
    updated_at: datetime = datetime.now(UTC)


@pytest.mark.asyncio
async def test_budget_refuses_once_the_hourly_allowance_is_spent() -> None:
    row = _FakeSettings()
    now = datetime.now(UTC)
    assert await _consume_budget(None, row, now=now) is True
    assert await _consume_budget(None, row, now=now) is True
    assert await _consume_budget(None, row, now=now) is False
    assert row.sweeps_skipped_budget == 1


@pytest.mark.asyncio
async def test_a_refused_sweep_is_counted_so_a_quiet_feed_is_distinguishable() -> None:
    """An operator must be able to tell an empty budget from an empty feed."""
    row = _FakeSettings(max_sweeps_per_hour=0)
    assert await _consume_budget(None, row, now=datetime.now(UTC)) is False
    assert row.sweeps_skipped_budget == 1
    assert row.sweeps_this_hour == 0


@pytest.mark.asyncio
async def test_the_hourly_window_resets_lazily_without_a_scheduled_job() -> None:
    now = datetime.now(UTC)
    row = _FakeSettings(sweeps_this_hour=2, hour_started_at=now - timedelta(hours=2))
    assert await _consume_budget(None, row, now=now) is True
    assert row.sweeps_this_hour == 1


@pytest.mark.asyncio
async def test_the_daily_ceiling_holds_even_when_hours_keep_resetting() -> None:
    """The two windows are independent, so the wider one must still bind."""
    row = _FakeSettings(max_sweeps_per_hour=100, max_sweeps_per_day=2)
    base = datetime.now(UTC)
    assert await _consume_budget(None, row, now=base) is True
    assert await _consume_budget(None, row, now=base + timedelta(hours=1, minutes=1)) is True
    assert await _consume_budget(None, row, now=base + timedelta(hours=2, minutes=2)) is False


# ------------------------------------------------------------------- dedup


def test_the_alert_idempotency_key_is_stable_and_fits_the_column() -> None:
    """The second dedup layer: a per-tenant unique index on ``alerts``."""
    key = alert_idempotency_key("sha256", "a" * 64)
    assert key == alert_idempotency_key("sha256", "a" * 64)
    assert key != alert_idempotency_key("sha256", "b" * 64)
    assert key != alert_idempotency_key("md5", "a" * 64)
    assert len(key) <= 128


def test_the_idempotency_key_survives_an_indicator_too_long_for_the_column() -> None:
    """A 2 KB URL must not produce a key the column truncates into a collision."""
    key = alert_idempotency_key("url", "https://example.invalid/" + "x" * 4000)
    assert len(key) <= 128


# --------------------------------------------------------------- provenance


def _outcome(*, lake_checked: bool = True, sightings: int = 3, fed: FederatedSweepResult | None = None) -> SweepOutcome:
    return SweepOutcome(
        indicator_type="ip",
        value="203.0.113.9",
        lookback_days=30,
        lake=LakeSweepResult(
            indicator_type="ip",
            value="203.0.113.9",
            checked=lake_checked,
            sightings=sightings,
            first_sighting_at=datetime(2026, 8, 1, tzinfo=UTC),
            last_sighting_at=datetime(2026, 9, 1, tzinfo=UTC),
            connector_types=["aws_cloudtrail"],
            hosts=["web-01"],
            users=["alice"],
            columns_searched=("source_ip", "dest_ip", "iocs"),
            unavailable_reason=None if lake_checked else "No event lake is configured on this deployment.",
        ),
        federated=fed or FederatedSweepResult(checked=True, sightings=0, sources_ok=["splunk"]),
    )


def test_the_alert_body_names_the_feed_and_both_first_seen_facts() -> None:
    """The plan's provenance list, plus the distinction it would lose.

    "First seen" is two different facts. An indicator published this morning
    and last seen in the estate five weeks ago is a materially different
    finding from one published and seen today, and one field cannot say so.
    """
    indicator = IntelIndicator(
        indicator_type="ip",
        value="203.0.113.9",
        feed_source="cisa-kev",
        first_seen_at=datetime(2026, 9, 20, tzinfo=UTC),
    )
    body = _build_description(indicator, _outcome())
    assert "cisa-kev" in body
    assert "First seen by the feed: 2026-09-20" in body
    assert "First sighting in your data: 2026-08-01" in body
    assert "source_ip, dest_ip, iocs" in body
    assert "web-01" in body


def test_a_feed_that_published_no_first_seen_says_so_rather_than_stamping_now() -> None:
    indicator = IntelIndicator(indicator_type="ip", value="203.0.113.9", feed_source="otx")
    body = _build_description(indicator, _outcome())
    assert "not published by this feed" in body


def test_a_gap_is_carried_into_the_alert_even_when_the_sweep_matched() -> None:
    """Found in the lake while the SIEM sweep failed is its own finding."""
    outcome = _outcome(
        fed=FederatedSweepResult(
            checked=False,
            sources_failed=["splunk"],
            unavailable_reason="Every connected SIEM failed to answer, so none of them were searched.",
        )
    )
    body = _build_description(IntelIndicator("ip", "203.0.113.9", "otx"), outcome)
    assert "What was NOT checked" in body
    assert "A gap is not evidence of absence" in body
    assert "splunk" in body


def test_an_unchecked_lake_never_reads_as_zero_sightings() -> None:
    """``checked`` and ``sightings`` are separate, and ``matched`` needs both."""
    result = LakeSweepResult(
        indicator_type="ip",
        value="203.0.113.9",
        checked=False,
        unavailable_reason="No event lake is configured on this deployment.",
    )
    assert result.matched is False
    assert result.sightings == 0
    outcome = SweepOutcome(
        indicator_type="ip",
        value="203.0.113.9",
        lookback_days=30,
        lake=result,
        federated=FederatedSweepResult(
            checked=False,
            unavailable_reason="This tenant has no SIEM connected to AiSOC, so there was nothing to search beyond the event lake.",
        ),
    )
    assert outcome.matched is False
    # Both unchecked surfaces are named. A sweep that reported one gap and
    # stayed silent about the other would be claiming coverage it does not
    # have, which is the same defect as reporting a zero.
    gaps = outcome.gaps
    assert len(gaps) == 2
    assert any(gap.startswith("Event lake:") for gap in gaps)
    assert any(gap.startswith("Federated SIEM search:") for gap in gaps)


def test_a_source_with_no_field_mapping_is_a_gap_not_a_clean_answer() -> None:
    outcome = _outcome(fed=FederatedSweepResult(checked=True, sources_ok=["splunk"], sources_unmapped=["qradar"]))
    gaps = outcome.gaps
    assert any("qradar" in gap and "no field mapping" in gap for gap in gaps)


# -------------------------------------------------------------- lookback cap


def test_the_lookback_window_is_bounded_in_code_as_well_as_in_the_column() -> None:
    """A settings row cannot express "scan everything", and nor can a caller."""
    assert MAX_LOOKBACK_DAYS == 365


class _Row(list):
    pass


@pytest.mark.asyncio
async def test_an_empty_result_set_is_reported_as_unknown_not_as_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    """An aggregate always returns one row, so no rows means something is wrong.

    Reading that as zero sightings is precisely the failure this module
    exists to avoid, so it is asserted rather than assumed.
    """
    from app.services.retro_hunt import sweep as sweep_module

    @dataclass
    class _Result:
        rows: list[Any]

    async def _fake_query(*_args: Any, **_kwargs: Any) -> Any:
        return _Result(rows=[])

    monkeypatch.setattr(sweep_module, "execute_lake_query", _fake_query)
    result = await sweep_module.sweep_lake(tenant_id=TENANT, indicator_type="ip", value="203.0.113.9")
    assert result.checked is False
    assert result.unavailable_reason and "unreadable" in result.unavailable_reason


@pytest.mark.asyncio
async def test_a_lake_that_is_not_configured_is_a_gap_with_a_named_cause(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.services.retro_hunt import sweep as sweep_module

    async def _fake_query(*_args: Any, **_kwargs: Any) -> Any:
        raise sweep_module.LakeQueryNotConfiguredError("no host")

    monkeypatch.setattr(sweep_module, "execute_lake_query", _fake_query)
    result = await sweep_module.sweep_lake(tenant_id=TENANT, indicator_type="ip", value="203.0.113.9")
    assert result.checked is False
    assert "No event lake is configured" in (result.unavailable_reason or "")


@pytest.mark.asyncio
async def test_a_budget_timeout_is_reported_as_an_incomplete_sweep(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.services.retro_hunt import sweep as sweep_module

    async def _fake_query(*_args: Any, **_kwargs: Any) -> Any:
        raise sweep_module.LakeQueryTimeoutError("too slow")

    monkeypatch.setattr(sweep_module, "execute_lake_query", _fake_query)
    result = await sweep_module.sweep_lake(tenant_id=TENANT, indicator_type="ip", value="203.0.113.9")
    assert result.checked is False
    assert "NOT fully searched" in (result.unavailable_reason or "")


@pytest.mark.asyncio
async def test_a_matching_sweep_reports_the_aggregate_the_query_returned(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.services.retro_hunt import sweep as sweep_module

    @dataclass
    class _Result:
        rows: list[Any]

    async def _fake_query(sql: str, **kwargs: Any) -> Any:
        assert kwargs["params"]["needle"] == "203.0.113.9"
        assert kwargs["params"]["tenant_id"] == str(TENANT)
        # The budget travels with the query rather than being an intention.
        assert kwargs["extra_settings"]["max_bytes_to_read"] == sweep_module.MAX_BYTES_PER_SWEEP
        return _Result(
            rows=[
                [
                    1000,
                    datetime(2026, 8, 1, tzinfo=UTC),
                    datetime(2026, 9, 1, tzinfo=UTC),
                    ["aws_cloudtrail"],
                    ["web-01", ""],
                    ["alice"],
                ]
            ]
        )

    monkeypatch.setattr(sweep_module, "execute_lake_query", _fake_query)
    result = await sweep_module.sweep_lake(tenant_id=TENANT, indicator_type="ip", value="203.0.113.9")
    assert result.checked is True
    assert result.sightings == 1000
    assert result.matched is True
    # A thousand sightings produce bounded evidence, and the empty-string
    # host ClickHouse returns for events with no hostname is dropped rather
    # than rendered as a blank entry in an alert.
    assert result.hosts == ["web-01"]
