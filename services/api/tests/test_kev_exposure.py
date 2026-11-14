"""Gap-closure Phase 8.2: KEV exposure.

Three groups, each covering a way this reports something it does not know.

**A CVE never reaches the telemetry sweep.** Routing is the whole design
decision: a CVE does not appear in event data, so sweeping the lake for one
returns zero on every tenant forever while looking exactly like a sweep that
worked.

**No vulnerability data is not "no exposure".** The single most damaging thing
this surface could do is tell a tenant with no scanner that they are
unaffected. ``checked`` and ``exposed_asset_count`` are separate for that
reason and ``exposed`` requires both.

**Exposure is drawn from findings, not inferred from software names.** Matching
a KEV entry's vendor and product strings against an asset's OS field would
produce a plausible answer built on string similarity, and a case task an
analyst has to disprove is worse than no task at all.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime

import pytest
from app.services.retro_hunt.intel_types import route_feed_type
from app.services.retro_hunt.kev_exposure import (
    CVE_INDICATOR_TYPE,
    NO_VULN_DATA_REASON,
    ExposureResult,
    is_cve,
)
from app.services.retro_hunt.sweep import DEFAULT_LOOKBACK_DAYS

TENANT = uuid.UUID("11111111-1111-1111-1111-111111111111")


# ------------------------------------------------------------------ routing


@pytest.mark.parametrize("feed_type", ["vulnerability", "Vulnerability", "cve", "CVE"])
def test_a_cve_routes_to_exposure_not_to_a_telemetry_sweep(feed_type: str) -> None:
    """The decision this phase turns on.

    A lake sweep for "CVE-2024-3400" matches nothing on every deployment and
    would report a confident zero. Routing it elsewhere is what stops that.
    """
    routing = route_feed_type(feed_type)
    assert routing.is_vulnerability is True
    assert routing.indicator_type is None
    assert routing.reason and "not against event telemetry" in routing.reason


def test_the_indicator_path_and_the_cve_path_cannot_both_claim_one_event() -> None:
    """A type routes to exactly one of the two paths, never both."""
    for feed_type in ("vulnerability", "ipv4-addr", "sha256", "domain-name", "url"):
        routing = route_feed_type(feed_type)
        assert not (routing.is_vulnerability and routing.indicator_type), feed_type


# ------------------------------------------------------------- value shapes


@pytest.mark.parametrize("value", ["CVE-2024-3400", "cve-2021-44228", "CVE-2019-0708", "CVE-2024-123456"])
def test_real_cve_identifiers_are_accepted(value: str) -> None:
    assert is_cve(value) is True


@pytest.mark.parametrize(
    "value",
    [
        "",
        "   ",
        "Apache HTTP Server path traversal",
        "CVE-24-3400",
        "CVE-2024-",
        "2024-3400",
        "GHSA-xxxx-yyyy-zzzz",
    ],
)
def test_a_value_that_is_not_a_cve_is_refused_rather_than_queried(value: str) -> None:
    """A feed publishing an advisory title under ``type: vulnerability``.

    Querying a scanner's ``cve_id`` column for free text returns zero rows,
    and that zero would be reported as "not exposed".
    """
    assert is_cve(value) is False


def test_a_refused_value_reports_a_reason_rather_than_a_clean_result() -> None:
    result = ExposureResult(
        cve_id="not a cve",
        checked=False,
        unavailable_reason="does not have the shape of a CVE identifier",
    )
    assert result.exposed is False
    assert result.checked is False
    assert result.unavailable_reason


# ------------------------------------------- the distinction that matters


def test_no_vulnerability_data_is_not_no_exposure() -> None:
    """The most damaging thing this surface could report.

    ``exposed`` requires ``checked``, so a tenant with no scanner cannot be
    rendered as clean by any caller that reads the dataclass rather than the
    count.
    """
    result = ExposureResult(cve_id="CVE-2024-3400", checked=False, unavailable_reason="unused")
    assert result.exposed is False
    assert result.exposed_asset_count == 0

    # Asserted against the wording the module actually emits rather than a
    # copy written here. A test that restates a message passes while the
    # message says something else, which is the shape of defect this phase
    # keeps finding.
    assert "could NOT be checked" in NO_VULN_DATA_REASON
    assert "not a statement that the tenant is unaffected" in NO_VULN_DATA_REASON


def test_a_genuine_clean_answer_is_distinguishable_from_an_unchecked_one() -> None:
    """Scanned and clean, versus never scanned. Different facts."""
    clean = ExposureResult(cve_id="CVE-2024-3400", checked=True)
    unchecked = ExposureResult(cve_id="CVE-2024-3400", checked=False, unavailable_reason="no scanner")
    assert clean.exposed is False
    assert unchecked.exposed is False
    # Both are "not exposed" by the boolean, and only one of them is
    # reassuring. The fields that carry the difference must not be equal.
    assert clean.checked != unchecked.checked
    assert (clean.unavailable_reason is None) != (unchecked.unavailable_reason is None)


def test_an_exposed_result_carries_the_assets_it_is_asserting_about() -> None:
    result = ExposureResult(
        cve_id="CVE-2024-3400",
        checked=True,
        exposed_asset_names=["fw-edge-01", "fw-edge-02"],
        exposed_asset_count=2,
        findings_updated=2,
    )
    assert result.exposed is True
    assert result.exposed_asset_names


def test_the_asset_list_is_bounded_while_the_count_is_not() -> None:
    """A task body naming nine hundred hosts is not read by anyone.

    The count stays exact so the task never understates the problem; only the
    enumeration is capped.
    """
    from app.services.retro_hunt.kev_exposure import _MAX_LISTED_ASSETS

    result = ExposureResult(
        cve_id="CVE-2024-3400",
        checked=True,
        exposed_asset_names=[f"host-{i}" for i in range(_MAX_LISTED_ASSETS)],
        exposed_asset_count=900,
    )
    assert len(result.exposed_asset_names) == _MAX_LISTED_ASSETS
    assert result.exposed_asset_count == 900


# ------------------------------------------------------------------- dedup


def test_cve_sightings_share_the_ioc_dedup_table_under_their_own_type() -> None:
    """One CVE opens one case task per tenant, by the same mechanism.

    The type is not one of the Phase 4 searchable types, because nothing
    searches telemetry for it. It shares the table so the UNIQUE constraint
    that stops an IOC alerting twice also stops a KEV entry opening a task a
    day, which it would otherwise do: the catalogue republishes its whole
    contents on every fetch.
    """
    assert CVE_INDICATOR_TYPE == "cve"
    from app.services.retro_hunt.ioc_fields import SWEEPABLE_TYPES

    assert CVE_INDICATOR_TYPE not in SWEEPABLE_TYPES


def test_the_exposure_check_is_not_charged_against_the_sweep_budget() -> None:
    """Two indexed Postgres queries, not a warehouse scan.

    Recorded as a test because the alternative is a plausible mistake: reusing
    the budget would let a busy day of IOCs starve the cheap check that has
    the clearest action attached to it.
    """
    import inspect

    from app.services.retro_hunt import kev_exposure

    source = inspect.getsource(kev_exposure)
    assert "_consume_budget" not in source
    assert "max_sweeps_per_hour" not in source
    # The opt-in still applies; only the budget does not.
    assert "settings_row.enabled" in source


def test_the_lake_sweep_default_window_is_untouched_by_this_phase() -> None:
    """A guard against the exposure path quietly changing sweep behaviour."""
    assert DEFAULT_LOOKBACK_DAYS == 30


# --------------------------------------------------- the consumer's routing


@dataclass
class _Payload:
    data: dict
    source: str = "cisa-kev"

    def as_dict(self) -> dict:
        return {"event_type": "NEW_IOC", "source": self.source, "timestamp": "2026-09-20T00:00:00Z", "data": self.data}


def test_the_consumer_sends_a_kev_entry_to_exposure_and_not_to_a_sweep() -> None:
    from app.workers.retro_hunt_consumer import cve_from_event, indicator_from_event

    payload = _Payload({"type": "vulnerability", "value": "CVE-2024-3400", "date_added": "2026-09-18"}).as_dict()
    kev = cve_from_event(payload)
    assert kev is not None
    cve, source, first_seen = kev
    assert cve == "CVE-2024-3400"
    assert source == "cisa-kev"
    assert isinstance(first_seen, datetime)
    assert first_seen.tzinfo is not None
    # And the indicator path refuses the same event, so the two cannot both
    # act on it.
    assert indicator_from_event(payload) is None


def test_the_consumer_sends_an_ordinary_indicator_to_the_sweep_and_not_to_exposure() -> None:
    from app.workers.retro_hunt_consumer import cve_from_event, indicator_from_event

    payload = _Payload({"type": "ipv4-addr", "value": "203.0.113.9"}, source="otx").as_dict()
    assert cve_from_event(payload) is None
    indicator = indicator_from_event(payload)
    assert indicator is not None
    assert indicator.indicator_type == "ip"


def test_a_feed_that_published_no_date_does_not_get_one_invented() -> None:
    """``first_seen`` falls back to the envelope, never to ``now``."""
    from app.workers.retro_hunt_consumer import cve_from_event

    payload = {"event_type": "NEW_IOC", "source": "cisa-kev", "data": {"type": "vulnerability", "value": "CVE-2024-3400"}}
    kev = cve_from_event(payload)
    assert kev is not None
    assert kev[2] is None


def test_an_empty_value_is_not_routed_anywhere(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.workers.retro_hunt_consumer import cve_from_event

    assert cve_from_event(_Payload({"type": "vulnerability", "value": ""}).as_dict()) is None


def test_the_case_task_body_states_that_unscanned_assets_are_absent() -> None:
    """A floor, not a total, and it says so.

    An analyst reading "3 assets affected" against an estate with 40% scanner
    coverage will act on the 3 and conclude the rest are fine.
    """
    import inspect

    from app.services.retro_hunt import kev_exposure

    source = inspect.getsource(kev_exposure._open_case_task)
    assert "floor rather than a total" in source
    assert "not inferred from software names" in source
