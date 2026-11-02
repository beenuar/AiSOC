"""A payload written in someone else's dialect must still compute.

What this suite is for
----------------------
The sandbox's whole method of use is "run it against my own alert file",
which is exactly how the previous defect was found. So the set of field
spellings it reads is not a detail: a reader who writes ``ts`` instead of
``published`` gets ``not_computable`` on every time-based signal,
concludes the tool computes nothing, and is right to.

That is what shipped. ``_parse_timestamp`` was handed
``event.get("published") or event.get("timestamp")`` — two spellings —
while the actor reader accepted four and the address reader four. The
asymmetry is backwards: a timestamp has *more* ordinary spellings than an
actor, not fewer. Measured against the eleven spellings a stranger might
plausibly write, **one worked.**

Why no existing test could see it
---------------------------------
Every bundled scenario says ``published``, so replaying the bundled
corpus could only ever confirm that ``published`` works. A corpus written
in its parser's own dialect cannot reveal a dialect gap, however
thoroughly it is replayed. These tests therefore derive their fixtures
from :data:`FIELD_VOCABULARY` itself rather than from the corpus, so a
spelling cannot be declared without being exercised — and
``test_an_undeclared_spelling_is_refused_rather_than_scored`` covers the
other direction, that widening the vocabulary did not turn "could not
compute" into a guess.
"""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest

from aisoc_sandbox import Scenario, available_scenarios, load_scenario, run_investigation
from aisoc_sandbox.signals import CONTAINER_ONLY_SPELLINGS, FIELD_VOCABULARY, compute_signals

#: Two sign-ins by one actor from one address in one city, a day and eight
#: hours apart. Spanning two calendar days so that the `date` spelling —
#: which resolves only to midnight — still has a non-zero elapsed time and
#: can be exercised by the same parametrisation as the rest.
_WHEN = ("2026-05-14T09:00:00Z", "2026-05-15T17:00:00Z")


def _benign(**overrides: Any) -> Scenario:
    events = [
        {
            "uuid": f"ev-{n}",
            "published": when,
            "eventType": "user.session.start",
            "actor": "alice@example.com",
            "client_ip": "203.0.113.42",
            "geo": {"city": "New York", "country": "US"},
        }
        for n, when in enumerate(_WHEN)
    ]
    payload: dict[str, Any] = {
        "id": "vocab-benign",
        "title": "Two sign-ins, same actor, same address, same city",
        "severity": "high",
        "mitre_techniques": ["T1078"],
        "entities": {"user": "alice@example.com"},
        "events": events,
    }
    payload.update(overrides)
    return Scenario(**payload)


def _rename(scenario: Scenario, old: str, new: str, *, date_only: bool = False) -> Scenario:
    out = copy.deepcopy(scenario)
    for event in out.events:
        value = event.pop(old)
        event[new] = value[:10] if date_only else value
    return out


def _signals(scenario: Scenario) -> dict[str, Any]:
    return {s.name: s for s in compute_signals(scenario.events)}


def _geo(scenario: Scenario) -> Any:
    return _signals(scenario)["geo_velocity"]


# ---------------------------------------------------------------------------
# Every declared spelling must actually work.
#
# Parametrised over the module's own table rather than a list written out
# here, so adding a spelling without making it work is not expressible.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("spelling", FIELD_VOCABULARY["timestamp"])
def test_every_declared_timestamp_spelling_computes(spelling: str) -> None:
    """The reported gap. Ten of these eleven failed before this change."""

    scenario = _rename(_benign(), "published", spelling, date_only=(spelling == "date"))
    geo = _geo(scenario)
    assert geo.status == "does_not_hold", f"a payload timed with {spelling!r} produced {geo.status}: {geo.summary}"
    assert geo.inputs["implied_speed_kmh"] == 0.0
    assert "do not show impossible travel" in geo.summary


@pytest.mark.parametrize("spelling", FIELD_VOCABULARY["timestamp"])
def test_every_declared_timestamp_spelling_also_feeds_the_burst_signal(spelling: str) -> None:
    """Two signals read the clock, and the narrow vocabulary broke both."""

    if spelling == "date":
        pytest.skip("a bare date cannot answer a question about a 60-second window; covered by its own test")
    burst = _signals(_rename(_benign(), "published", spelling))["event_burst"]
    assert burst.status == "does_not_hold", f"{spelling!r} left event_burst at {burst.status}"


@pytest.mark.parametrize("spelling", FIELD_VOCABULARY["actor"])
def test_every_declared_actor_spelling_computes(spelling: str) -> None:
    geo = _geo(_rename(_benign(), "actor", spelling))
    assert geo.status == "does_not_hold", f"an actor named {spelling!r} produced {geo.status}"
    assert geo.inputs["actor"] == "alice@example.com"


@pytest.mark.parametrize("spelling", FIELD_VOCABULARY["address"])
def test_every_declared_address_spelling_is_counted(spelling: str) -> None:
    diversity = _signals(_rename(_benign(), "client_ip", spelling))["source_diversity"]
    assert diversity.inputs["source_addresses"] == ["203.0.113.42"], f"{spelling!r} was not read as a source address"


@pytest.mark.parametrize("spelling", FIELD_VOCABULARY["city"])
def test_every_declared_city_spelling_resolves(spelling: str) -> None:
    scenario = _benign()
    for event in scenario.events:
        event["geo"] = {spelling: "New York", "country": "US"}
    assert _geo(scenario).status == "does_not_hold", f"a city under {spelling!r} did not resolve"


@pytest.mark.parametrize("spelling", FIELD_VOCABULARY["country"])
def test_every_declared_country_spelling_is_counted(spelling: str) -> None:
    scenario = _benign()
    for event, country in zip(scenario.events, ("US", "RU"), strict=True):
        event["geo"] = {"city": "New York", spelling: country}
    diversity = _signals(scenario)["source_diversity"]
    assert diversity.inputs["countries"] == ["RU", "US"], f"countries under {spelling!r} were not counted"


@pytest.mark.parametrize(
    ("lat_spelling", "lon_spelling"), [(a, b) for a in FIELD_VOCABULARY["latitude"] for b in FIELD_VOCABULARY["longitude"]]
)
def test_every_declared_coordinate_spelling_resolves(lat_spelling: str, lon_spelling: str) -> None:
    scenario = _benign()
    for event in scenario.events:
        event["geo"] = {lat_spelling: 40.7128, lon_spelling: -74.0060}
    geo = _geo(scenario)
    assert geo.status == "does_not_hold", f"coordinates under {lat_spelling}/{lon_spelling} did not resolve"
    assert geo.inputs["distance_km"] == 0.0


@pytest.mark.parametrize("spelling", FIELD_VOCABULARY["domain_age_days"])
def test_every_declared_domain_age_spelling_is_read(spelling: str) -> None:
    scenario = _benign()
    scenario.events[0][spelling] = 9
    scenario.events[0]["domain"] = "acme-paychecks.example"
    age = _signals(scenario)["recorded_domain_age"]
    assert age.status == "holds", f"a domain age under {spelling!r} was not read"
    assert age.inputs["domain_age_days"] == 9


@pytest.mark.parametrize("spelling", FIELD_VOCABULARY["destination"])
def test_every_declared_destination_spelling_labels_the_finding(spelling: str) -> None:
    scenario = _benign()
    scenario.events[0]["domain_age_days"] = 9
    scenario.events[0][spelling] = "acme-paychecks.example"
    assert _signals(scenario)["recorded_domain_age"].inputs["youngest_domain"] == "acme-paychecks.example"


@pytest.mark.parametrize("spelling", CONTAINER_ONLY_SPELLINGS["actor"])
def test_container_only_actor_spellings_work_nested(spelling: str) -> None:
    """`user.name` is how Elastic names the actor and must be read."""

    scenario = _benign()
    for event in scenario.events:
        event.pop("actor")
        event["user"] = {spelling: "alice@example.com"}
    assert _geo(scenario).inputs["actor"] == "alice@example.com"


@pytest.mark.parametrize("spelling", CONTAINER_ONLY_SPELLINGS["actor"])
def test_container_only_actor_spellings_are_ignored_at_the_top_level(spelling: str) -> None:
    """A bare top-level `name` is the event's, not the person's.

    Reading it would put an event type in the actor column, which is a
    wrong answer that looks right — the shape this package exists to
    refuse. The honest outcome is that the actor is simply not found.
    """

    scenario = _benign()
    for event in scenario.events:
        event.pop("actor")
        event[spelling] = "user.session.start"
    assert _geo(scenario).status == "not_computable"


# ---------------------------------------------------------------------------
# Widening must not have bought a guess.
# ---------------------------------------------------------------------------


def test_an_undeclared_spelling_is_refused_rather_than_scored() -> None:
    """The other direction, and the one that keeps the widening honest."""

    geo = _geo(_rename(_benign(), "published", "zzz_when"))
    assert geo.status == "not_computable"
    assert "no timestamp the sandbox could read" in geo.summary
    assert "implied_speed_kmh" not in geo.inputs


def test_a_nested_account_creation_date_is_never_read_as_the_event_time() -> None:
    """`FIELD_CONTAINERS["timestamp"]` is empty on purpose.

    Descending into arbitrary objects for a time would let the age of the
    *account* stand in for the time of the event — not a near-miss but a
    wrong answer that looks right.
    """

    scenario = _benign()
    for event in scenario.events:
        event.pop("published")
        event["user"] = {"name": "alice@example.com", "created_at": "2019-01-01T00:00:00Z"}
    assert _geo(scenario).status == "not_computable"


def test_same_day_date_only_events_refuse_rather_than_report_impossible_travel() -> None:
    """The defect the widening would have introduced, had it not been guarded.

    Two events timed only to the day both land on midnight, so the
    elapsed time is zero and the implied speed infinite. Accepting `date`
    without this guard turns a payload that never carried an hour into a
    confident "physically impossible travel" — the original defect
    reached by a different road.
    """

    scenario = _benign()
    scenario.events[1]["geo"] = {"city": "Saint Petersburg", "country": "RU"}
    for event in scenario.events:
        event["date"] = event.pop("published")[:10]
    scenario.events[1]["date"] = scenario.events[0]["date"]  # same calendar day

    geo = _geo(scenario)
    assert geo.status == "not_computable", f"expected a refusal, got {geo.status}: {geo.summary}"
    assert "physically impossible" not in geo.summary
    assert "no time of day" in geo.summary
    assert geo.inputs["pairs_skipped_for_date_only_precision"] == 1


def test_date_only_events_on_different_days_still_measure() -> None:
    """The guard is about lost precision, not about the `date` spelling."""

    scenario = _benign()
    scenario.events[1]["geo"] = {"city": "Saint Petersburg", "country": "RU"}
    for event in scenario.events:
        event["date"] = event.pop("published")[:10]
    geo = _geo(scenario)
    assert geo.status == "does_not_hold"
    assert geo.inputs["elapsed_hours"] == 24.0  # the two dates are one calendar day apart
    assert 200 < geo.inputs["implied_speed_kmh"] < 400


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (1779181200, "does_not_hold"),  # epoch seconds
        (1779181200000, "does_not_hold"),  # epoch milliseconds
        (12345, "not_computable"),  # below the seconds window: refused, not coerced
        (1e20, "not_computable"),  # above the millisecond window
    ],
)
def test_numeric_timestamps_are_read_only_inside_declared_epoch_windows(value: Any, expected: str) -> None:
    scenario = _benign()
    for offset, event in enumerate(scenario.events):
        event.pop("published")
        event["_time"] = value + offset * 3600 if isinstance(value, int) else value
    assert _geo(scenario).status == expected


# ---------------------------------------------------------------------------
# Coordinates: the most precise input available, and the refusals.
# ---------------------------------------------------------------------------


def test_explicit_coordinates_beat_the_city_table() -> None:
    """Not a weaker input than a centroid — a strictly better one."""

    scenario = _benign()
    for event in scenario.events:
        event["geo"] = {"city": "New York", "country": "US", "lat": 35.6762, "lon": 139.6503}
    geo = _geo(scenario)
    assert geo.status == "does_not_hold"
    assert geo.inputs["distance_km"] == 0.0
    assert "coordinates at" in geo.inputs["position_source"], geo.inputs["position_source"]
    # The label still names the city the payload gave, but the position
    # came from the coordinates — Tokyo's, not New York's.
    scenario.events[1]["geo"] = {"city": "New York", "country": "US", "lat": 40.7128, "lon": -74.0060}
    assert _geo(scenario).inputs["distance_km"] > 10_000


def test_a_null_island_sentinel_is_refused_not_plotted() -> None:
    """0,0 is how several sources spell "unknown"."""

    scenario = _benign()
    scenario.events[0]["geo"] = {"lat": 0.0, "lon": 0.0}
    scenario.events[1]["geo"] = {"lat": 0.0, "lon": 0.0}
    geo = _geo(scenario)
    assert geo.status == "not_computable"
    assert "null-island" in geo.summary


def test_out_of_range_coordinates_are_refused() -> None:
    scenario = _benign()
    for event in scenario.events:
        event["geo"] = {"lat": 999.0, "lon": -74.0}
    geo = _geo(scenario)
    assert geo.status == "not_computable"
    assert "out-of-range" in geo.summary


def test_half_a_coordinate_pair_falls_back_to_the_city_table() -> None:
    """Degrading to the city is right; inventing the missing half is not."""

    scenario = _benign()
    for event in scenario.events:
        event["geo"] = {"lat": 40.7128, "city": "New York", "country": "US"}
    geo = _geo(scenario)
    assert geo.status == "does_not_hold"
    assert "city table" in geo.inputs["position_source"], geo.inputs["position_source"]


def test_half_a_coordinate_pair_with_no_city_names_both_problems() -> None:
    scenario = _benign()
    for event in scenario.events:
        event["geo"] = {"lat": 40.7128}
    geo = _geo(scenario)
    assert geo.status == "not_computable"
    assert "without its pair" in geo.summary
    assert "no city to fall back to" in geo.summary


# ---------------------------------------------------------------------------
# The shapes three real identity providers actually ship.
# ---------------------------------------------------------------------------


def _impossible_travel() -> Scenario:
    """The benign base, with the second sign-in eight minutes later.

    The vendor shapes below put the two events on opposite sides of the
    world, so they need a window that genuinely rules out a flight.
    """

    scenario = _benign()
    scenario.events[1]["published"] = "2026-05-14T09:08:00Z"
    return scenario


def _okta() -> Scenario:
    scenario = _impossible_travel()
    for event, (city, cc, lat, lon) in zip(
        scenario.events, [("New York", "US", 40.7128, -74.0060), ("Saint Petersburg", "RU", 59.9311, 30.3609)], strict=True
    ):
        event.pop("actor"), event.pop("client_ip"), event.pop("geo")
        event["actor"] = {"alternateId": "alice@example.com", "type": "User"}
        event["client"] = {
            "ipAddress": "203.0.113.42",
            "geographicalContext": {"city": city, "country": cc, "geolocation": {"lat": lat, "lon": lon}},
        }
    return scenario


def _entra() -> Scenario:
    scenario = _impossible_travel()
    for event, (city, cc, lat, lon) in zip(
        scenario.events, [("New York", "US", 40.7128, -74.0060), ("Saint Petersburg", "RU", 59.9311, 30.3609)], strict=True
    ):
        event["@timestamp"] = event.pop("published")
        event.pop("actor"), event.pop("client_ip"), event.pop("geo")
        event["userPrincipalName"] = "alice@example.com"
        event["ipAddress"] = "203.0.113.42"
        event["location"] = {"city": city, "countryOrRegion": cc, "geoCoordinates": {"latitude": lat, "longitude": lon}}
    return scenario


def _elastic() -> Scenario:
    scenario = _impossible_travel()
    for event, (city, cc, lat, lon) in zip(
        scenario.events, [("New York", "US", 40.7128, -74.0060), ("Saint Petersburg", "RU", 59.9311, 30.3609)], strict=True
    ):
        event["@timestamp"] = event.pop("published")
        event.pop("actor"), event.pop("client_ip"), event.pop("geo")
        event["user"] = {"name": "alice@example.com"}
        event["source"] = {"ip": "203.0.113.42", "geo": {"city_name": city, "country_iso_code": cc, "location": {"lat": lat, "lon": lon}}}
    return scenario


@pytest.mark.parametrize("build", [_okta, _entra, _elastic], ids=["okta", "entra", "elastic-ecs"])
def test_vendor_shaped_payloads_resolve_actor_address_and_position(build: Any) -> None:
    """None of these is flat, and all three are what a stranger would paste."""

    scenario = build()
    signals = _signals(scenario)
    geo = signals["geo_velocity"]
    assert geo.status == "holds", f"{geo.status}: {geo.summary}"
    assert geo.inputs["actor"] == "alice@example.com"
    assert geo.inputs["distance_km"] > 6000
    assert signals["source_diversity"].inputs["source_addresses"] == ["203.0.113.42"]
    assert signals["source_diversity"].inputs["countries"] == ["RU", "US"]


# ---------------------------------------------------------------------------
# The corpus must not be the only dialect that works.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("scenario_id", sorted(available_scenarios()))
@pytest.mark.parametrize("spelling", ["ts", "_time", "@timestamp", "eventTime"])
def test_every_bundled_scenario_computes_the_same_in_another_dialect(scenario_id: str, spelling: str) -> None:
    """The property the bundled corpus cannot check about itself.

    Every fixture says `published`. Rewriting each one into a different
    spelling and requiring identical signal output is what proves the
    corpus is exercising the parser rather than its own dialect.
    """

    original = load_scenario(scenario_id)
    rewritten = _rename(original, "published", spelling)

    def shape(scenario: Scenario) -> str:
        return json.dumps(
            [{"name": s.name, "status": s.status, "summary": s.summary} for s in compute_signals(scenario.events)],
            sort_keys=True,
        )

    assert shape(rewritten) == shape(original), f"{scenario_id} behaves differently when timed with {spelling!r}"


def test_the_reporters_payload_reads_identically_under_every_timestamp_spelling() -> None:
    """The claim made in the reply to the reporter, as an assertion.

    The reply says their benign payload returns `0.0 km apart, implied
    speed 0.0 km/h`. That was only true if their file happened to say
    `published` or `timestamp`. It has to be true whatever they wrote.
    """

    for spelling in FIELD_VOCABULARY["timestamp"]:
        geo = _geo(_rename(_benign(), "published", spelling, date_only=(spelling == "date")))
        assert geo.inputs["distance_km"] == 0.0, spelling
        assert geo.inputs["implied_speed_kmh"] == 0.0, spelling
        assert "do not show impossible travel" in geo.summary, spelling


def test_no_reader_is_meaningfully_narrower_than_its_siblings() -> None:
    """The asymmetry that caused this, stated as a property.

    Not an arbitrary floor: the point is that one reader accepting two
    spellings while its siblings accepted four is a drift nobody noticed,
    and a timestamp is the field with the *most* ordinary spellings.
    """

    sizes = {concept: len(spellings) for concept, spellings in FIELD_VOCABULARY.items()}
    assert sizes["timestamp"] >= max(sizes.values()), (
        f"the timestamp vocabulary ({sizes['timestamp']}) is no longer the widest ({sizes}); "
        "a timestamp has more ordinary spellings than any other field here, so this is the "
        "direction the drift has already gone once"
    )
    for concept, size in sizes.items():
        assert size >= 2, f"{concept} accepts only {size} spelling(s)"


def test_the_whole_run_still_asserts_nothing_it_did_not_compute() -> None:
    """The previous fix's property, re-checked over the widened readers."""

    for build in (_okta, _entra, _elastic):
        blob = json.dumps(run_investigation(build()).to_dict(), ensure_ascii=False)
        assert "/100" not in blob
        assert "fully autonomous closure" not in blob
        assert "auto-execute" not in blob
