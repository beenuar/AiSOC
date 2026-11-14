"""The sandbox may not assert a finding it did not compute.

What this suite is for
----------------------
A community reviewer fed the offline demo a harmless login — the same
user, the same address, New York both times, eight hours apart, tagged
``T1078`` at severity ``high`` — and got back "the geo pivot between
sequential events is physically impossible", at "high" confidence,
83/100. They then relabelled genuine impossible-travel events ``info``
and got "L4 — fully autonomous closure" and "auto-execute eligible".
Their diagnosis was exact: the reasoning and the score followed the
MITRE tag and the severity that had been *typed into the input file*,
not the events.

All three were reproducible. The cause was structural rather than a
matter of wording, and visible from three signatures alone::

    _confidence_band(*, severity: str, technique_count: int)
    _automation_tier(severity: str)
    DeterministicReasoner.explain(self, *, technique: str | None)

None of the three decision functions could see the events, so none of
them could have been describing them.

Every test here fails on the pre-fix tree, and each one names the
reported symptom it pins. They are behavioural rather than
signature-level wherever a behavioural assertion is possible: a
signature can be widened while the body still ignores what it is
handed, so "the function now takes the events" is the weaker claim and
"the output changes when the events change" is the one worth making.
"""

from __future__ import annotations

import copy
import io
import json
import re
from typing import Any

import pytest
from aisoc_sandbox import Scenario, available_scenarios, load_scenario, run_investigation
from aisoc_sandbox.cli import main

SEVERITIES = ["info", "low", "medium", "high", "critical"]

#: The retired hand-typed corpus size. Kept as a pattern, not a substring:
#: an ISO-8601 timestamp whose microseconds end in `800` reads as
#: `...456800+00:00` and contains the literal. Same shape as the one
#: `scripts/check_sandbox_honesty.py` uses, for the same reason.
RETIRED_RULE_FIGURE = re.compile(r"(?<!\d)800\s*\+(?!\d)")


# ---------------------------------------------------------------------------
# The reporter's two inputs, verbatim in shape.
# ---------------------------------------------------------------------------


def _benign_repeat_login(severity: str = "high") -> Scenario:
    """Same user, same address, same city, eight hours apart.

    Nothing about this is impossible travel, and the only thing in the
    payload suggesting compromise is the ``T1078`` tag the submitter
    typed.
    """

    return Scenario(
        id="benign-repeat-login",
        title="Two sign-ins, same user, same address, same city, 8 hours apart",
        severity=severity,
        mitre_techniques=["T1078", "T1078.004"],
        entities={"user": "alice@example.com", "ip": "203.0.113.42"},
        events=[
            {
                "uuid": "benign-0001",
                "published": "2026-05-14T09:00:00Z",
                "eventType": "user.session.start",
                "actor": "alice@example.com",
                "client_ip": "203.0.113.42",
                "geo": {"city": "New York", "country": "US"},
            },
            {
                "uuid": "benign-0002",
                "published": "2026-05-14T17:00:00Z",
                "eventType": "user.session.start",
                "actor": "alice@example.com",
                "client_ip": "203.0.113.42",
                "geo": {"city": "New York", "country": "US"},
            },
        ],
    )


def _real_impossible_travel(severity: str = "info") -> Scenario:
    """New York to Saint Petersburg in under eight minutes.

    Genuinely impossible, and deliberately labelled ``info`` so that a
    verdict following the label is distinguishable from one following
    the events.
    """

    return Scenario(
        id="real-impossible-travel",
        title="New York then Saint Petersburg, eight minutes apart",
        severity=severity,
        mitre_techniques=["T1078"],
        entities={"user": "alice@example.com", "ip_a": "203.0.113.42", "ip_b": "203.0.113.50"},
        events=[
            {
                "uuid": "real-0001",
                "published": "2026-05-14T09:30:14.123Z",
                "eventType": "user.session.start",
                "actor": "alice@example.com",
                "client_ip": "203.0.113.42",
                "geo": {"city": "New York", "country": "US"},
            },
            {
                "uuid": "real-0002",
                "published": "2026-05-14T09:38:01.000Z",
                "eventType": "user.session.start",
                "actor": "alice@example.com",
                "client_ip": "203.0.113.50",
                "geo": {"city": "Saint Petersburg", "country": "RU"},
            },
        ],
    )


def _text(scenario: Scenario) -> str:
    """Every word one run emits, as one searchable blob."""

    return json.dumps(run_investigation(scenario).to_dict(), ensure_ascii=False)


def _step(scenario: Scenario, stage: str) -> dict[str, Any]:
    return next(s for s in run_investigation(scenario).to_dict() if s["funnel_stage"] == stage)


# ---------------------------------------------------------------------------
# Reported symptom 1 — a benign login called "physically impossible".
# ---------------------------------------------------------------------------


def test_benign_repeat_login_is_not_called_impossible_travel() -> None:
    """The reported input, and the assertion it should never have produced.

    Pre-fix this fails on `_RATIONALES["T1078"]`, which is emitted for
    any alert carrying the tag.
    """

    emitted = _text(_benign_repeat_login())
    assert "physically impossible" not in emitted.lower(), (
        "Two sign-ins from one address in one city eight hours apart were described as physically "
        "impossible travel. The claim is being made from the T1078 tag rather than from the events."
    )
    assert "credential takeover" not in emitted.lower()


def test_benign_repeat_login_reports_the_arithmetic_that_refutes_it() -> None:
    """Saying nothing would be an improvement; saying what was computed is the fix."""

    geo = next(s for s in _step(_benign_repeat_login(), "triage")["evidence"]["signals"] if s["name"] == "geo_velocity")
    assert geo["status"] == "does_not_hold"
    assert geo["inputs"]["distance_km"] == 0.0
    assert geo["inputs"]["elapsed_hours"] == pytest.approx(8.0)
    assert geo["inputs"]["implied_speed_kmh"] == 0.0
    assert "do not show impossible travel" in geo["summary"]


def test_genuine_impossible_travel_is_still_identified() -> None:
    """The honest fix must not be "say less about everything"."""

    geo = next(s for s in _step(_real_impossible_travel(), "triage")["evidence"]["signals"] if s["name"] == "geo_velocity")
    assert geo["status"] == "holds"
    assert geo["inputs"]["distance_km"] > 6000
    assert geo["inputs"]["implied_speed_kmh"] > 1000
    assert "physically impossible travel" in geo["summary"]


# ---------------------------------------------------------------------------
# Reported symptom 2 — 83/100, which is 75 (high) + 4 x 2 techniques.
# ---------------------------------------------------------------------------


def test_no_confidence_score_is_emitted() -> None:
    """There is no model here, so there is no score to publish.

    The reporter's 83 was `{"info":30,"low":45,"medium":60,"high":75,
    "critical":88}[severity] + 4 * technique_count` — arithmetic over
    two strings they had typed themselves.
    """

    emitted = _text(_benign_repeat_login())
    assert not re.search(r"\b\d{1,3}\s*/\s*100\b", emitted), "a confidence score is being published by a package that computes none"
    assert _step(_benign_repeat_login(), "triage")["evidence"]["confidence_score"]["status"] == "not_computed"

    # And in the human view a reader sees the words, not a blank cell.
    rendered = io.StringIO()
    run_investigation(_benign_repeat_login()).render_human(out=rendered)
    assert "confidence_score: not computed in the sandbox" in rendered.getvalue()


def test_the_confidence_field_is_an_explicit_not_computed_never_a_zero() -> None:
    """An unmeasurable value must not render as a confident number — including 0.

    The sibling trap, which has shipped in this repository before: a
    formatter whose "unavailable" escape hatch excludes zero, so a
    hardcoded zero renders as `0%` under a live label.
    """

    for key in ("confidence_score", "related_cases_30d", "entity_risk"):
        value = _step(_benign_repeat_login(), "triage")["evidence"][key]
        assert isinstance(value, dict), f"{key} should be a NotComputed, got {value!r}"
        assert value["status"] == "not_computed"
        assert value["reason"], f"{key} says it was not computed but not why"
        assert value.get("value", None) is None


# ---------------------------------------------------------------------------
# Reported symptom 3 — a self-declared `info` selecting "L4 fully autonomous
# closure" and "auto-execute eligible".
# ---------------------------------------------------------------------------


def test_severity_label_cannot_select_an_autonomy_posture() -> None:
    """The reporter's second case: real events, label turned down to `info`."""

    emitted = _text(_real_impossible_travel(severity="info"))
    assert "fully autonomous closure" not in emitted
    assert "auto-execute eligible" not in emitted
    assert "auto_below_high" not in emitted

    respond = _step(_real_impossible_travel(severity="info"), "respond")["evidence"]
    assert respond["automation_maturity_tier"]["status"] == "not_computed"
    assert respond["approval_posture"]["status"] == "not_computed"


@pytest.mark.parametrize("severity", SEVERITIES)
def test_no_severity_yields_an_autonomy_tier(severity: str) -> None:
    """Behavioural sweep: no label anywhere on the ladder buys a posture."""

    emitted = _text(_real_impossible_travel(severity=severity))
    for banned in (
        "L4 — fully autonomous closure",
        "L3 — auto-respond",
        "L2 — proposed actions",
        "L1 — recommendations only",
        "auto-execute",
    ):
        assert banned not in emitted, f"severity={severity} produced {banned!r}"


def test_changing_only_the_severity_changes_only_where_it_is_echoed() -> None:
    """The sharpest form of the reporter's finding, as an assertion.

    Hold the events constant and move the severity across the whole
    ladder. Everything the run *computes* must be byte-identical; the
    label may appear only where it is explicitly attributed to the
    input. Pre-fix this fails on the confidence score, the automation
    tier and the blast-radius gate, all three of which move.
    """

    def findings(severity: str) -> str:
        """Everything downstream of intake, minus the call shapes.

        The detect step and the `case.create` argument are the two
        places the label is legitimately quoted back, and they are
        excluded by construction rather than by scrubbing the string —
        a substring replace would also hit "below", which contains
        "low", and silently weaken the comparison.
        """

        steps = [s for s in run_investigation(_real_impossible_travel(severity=severity)).to_dict() if s["funnel_stage"] != "detect"]
        return json.dumps(
            [{"rationale": s["rationale"], "evidence": s["evidence"], "decision": s["decision"]} for s in steps],
            sort_keys=True,
            ensure_ascii=False,
        )

    baseline = findings("info")
    for severity in SEVERITIES[1:]:
        assert findings(severity) == baseline, (
            f"moving severity info -> {severity} changed a value the sandbox claims to compute. "
            "A finding is being read off the label rather than off the events."
        )

    # And the label genuinely is absent from those steps, rather than
    # merely constant across them.
    assert "critical" not in findings("critical")


# ---------------------------------------------------------------------------
# The structural claim: no decision can be reached without the events.
# ---------------------------------------------------------------------------


def test_changing_only_the_events_changes_the_finding() -> None:
    """The converse, and the stronger half.

    Three payloads carrying an identical ``T1078`` tag at an identical
    severity, differing only in where and when the second sign-in
    happened. Pre-fix all three produce the same sentence and the same
    83/100, because no rationale, score or tier read the events at all.

    The middle case is the one that shows the threshold is a real
    measurement and not a city-pair lookup: New York to Saint
    Petersburg across eight hours is an ordinary long-haul flight at
    861 km/h, so it must *not* be called impossible even though the
    endpoints are the ones the bundled impossible-travel scenario uses.
    """

    same_place = _benign_repeat_login(severity="high")

    flight = copy.deepcopy(same_place)  # 6,888 km, 8 h
    flight.events[1]["geo"] = {"city": "Saint Petersburg", "country": "RU"}

    teleport = copy.deepcopy(flight)  # 6,888 km, 8 min
    teleport.events[1]["published"] = "2026-05-14T09:08:00Z"

    assert {s.severity for s in (same_place, flight, teleport)} == {"high"}
    assert {tuple(s.mitre_techniques) for s in (same_place, flight, teleport)} == {("T1078", "T1078.004")}

    def geo(scenario: Scenario) -> dict[str, Any]:
        return next(s for s in _step(scenario, "triage")["evidence"]["signals"] if s["name"] == "geo_velocity")

    assert geo(same_place)["status"] == "does_not_hold"
    assert geo(same_place)["inputs"]["implied_speed_kmh"] == 0.0
    assert geo(flight)["status"] == "does_not_hold", "a long-haul flight is not impossible travel"
    assert 800 < geo(flight)["inputs"]["implied_speed_kmh"] < 1000
    assert geo(teleport)["status"] == "holds"
    assert geo(teleport)["inputs"]["implied_speed_kmh"] > 10_000

    rationales = {_step(s, "triage")["rationale"] for s in (same_place, flight, teleport)}
    assert len(rationales) == 3, "three materially different event sets produced fewer than three rationales"


def test_an_empty_event_list_produces_no_findings_at_all() -> None:
    """No events, no statements. Not a default, and not a reassurance."""

    naked = Scenario(id="no-events", title="No events", severity="critical", mitre_techniques=["T1078"], events=[])
    triage = _step(naked, "triage")
    assert all(s["status"] == "not_computable" for s in triage["evidence"]["signals"])
    assert "physically impossible" not in json.dumps(triage, ensure_ascii=False).lower()
    assert triage["evidence"]["technique_support"]["supported"] == []


def test_an_unresolvable_city_is_named_rather_than_guessed() -> None:
    """A coordinate the sandbox does not have must not be substituted.

    A country centroid standing in for a missing city would invent the
    precision the whole measurement rests on, and the resulting number
    would not look wrong — it would look like a measurement.
    """

    scenario = _benign_repeat_login()
    scenario.events[1]["geo"] = {"city": "Nowheresville", "country": "ZZ"}
    geo = next(s for s in _step(scenario, "triage")["evidence"]["signals"] if s["name"] == "geo_velocity")
    assert geo["status"] == "not_computable"
    assert "Nowheresville" in geo["summary"]


def test_an_ambiguous_city_is_refused_rather_than_resolved_to_the_first_match() -> None:
    """Saint Petersburg is in Russia and in Florida. Guessing is not allowed."""

    scenario = _benign_repeat_login()
    scenario.events[1]["geo"] = {"city": "Saint Petersburg"}  # no country
    geo = next(s for s in _step(scenario, "triage")["evidence"]["signals"] if s["name"] == "geo_velocity")
    assert geo["status"] == "not_computable"
    assert "ambiguous" in geo["summary"]


def test_explicit_coordinates_bypass_the_table_entirely() -> None:
    """A user scenario anywhere on earth still measures, table or not."""

    scenario = _benign_repeat_login()
    scenario.events[0]["geo"] = {"city": "Ushuaia", "lat": -54.8019, "lon": -68.3030}
    geo = next(s for s in _step(scenario, "triage")["evidence"]["signals"] if s["name"] == "geo_velocity")
    assert geo["status"] != "not_computable", "explicit coordinates were ignored in favour of the city table"
    assert geo["inputs"]["distance_km"] > 9000  # Ushuaia to New York
    assert "Ushuaia" in geo["summary"]


# ---------------------------------------------------------------------------
# Claims about tools, rules and sweeps that never happened.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("scenario_id", sorted(available_scenarios()))
def test_every_tool_call_is_marked_unexecuted(scenario_id: str) -> None:
    """`tool_calls` shows the shape of a call, never a record of one."""

    for step in run_investigation(load_scenario(scenario_id)).to_dict():
        for call in step["tool_calls"]:
            assert call.get("executed") is False, f"{scenario_id}/{step['funnel_stage']}: {call['name']} does not declare itself unexecuted"


@pytest.mark.parametrize("scenario_id", sorted(available_scenarios()))
def test_no_stale_hand_typed_rule_count(scenario_id: str) -> None:
    """The `rule_count: "800+"` the reporter found, derived rather than retyped.

    Pinned against the generated constant rather than against a literal
    here, or this test becomes the next surface to go stale.

    Matched with a pattern rather than `"800+" in emitted`: the blob carries
    ISO-8601 timestamps, and a microsecond field ending in `800` puts the
    literal inside `...:56.456800+00:00`. That made the assertion fail on
    roughly one run in twenty for a reason no author could act on. The figure
    this guards never has a digit on both sides of it; a timestamp always
    does, which is the distinction the pattern draws.
    """

    from aisoc_sandbox._corpus import LIVE_ENGINE_EXECUTABLE_RULES

    emitted = json.dumps(run_investigation(load_scenario(scenario_id)).to_dict(), ensure_ascii=False)
    assert not RETIRED_RULE_FIGURE.search(emitted)
    assert f"{LIVE_ENGINE_EXECUTABLE_RULES:,}" in emitted


def test_the_retired_figure_pattern_still_catches_the_thing_it_is_for() -> None:
    """The negative control for the pattern above.

    Loosening a check to clear a flake is how a gate stops working, so the
    distinction it now draws is asserted in both directions: every shape the
    retired figure was found in must still match, and the timestamp that
    caused the flake must not.
    """

    for caught in (
        '{"rule_count": "800+"}',
        '"rule_count": "800 +"',
        "matched against 800+ rules",
        '["800+"]',
    ):
        assert RETIRED_RULE_FIGURE.search(caught), caught

    for ignored in (
        '"started_at": "2026-11-02T22:45:56.456800+00:00"',
        '"finished_at": "2026-11-02T22:45:56.800800+00:00"',
        '{"rule_count": "2,538"}',
    ):
        assert not RETIRED_RULE_FIGURE.search(ignored), ignored


@pytest.mark.parametrize("scenario_id", sorted(available_scenarios()))
def test_the_hunt_stage_reports_no_result_because_it_ran_no_search(scenario_id: str) -> None:
    """ "Pivot complete; no additional compromised entities surfaced" was a finding from a search that never ran."""

    hunt = _step(load_scenario(scenario_id), "hunt")
    assert "Pivot complete" not in hunt["decision"]
    assert hunt["evidence"]["matches_found"]["status"] == "not_computed"
    assert hunt["evidence"]["additional_compromised_entities"]["status"] == "not_computed"


@pytest.mark.parametrize("scenario_id", sorted(available_scenarios()))
def test_no_retired_rationale_survives_anywhere(scenario_id: str) -> None:
    """The canned sentences asserted measurements nothing had taken."""

    emitted = json.dumps(run_investigation(load_scenario(scenario_id)).to_dict(), ensure_ascii=False).lower()
    for phrase in (
        "welford",
        "standard deviations",
        "registered less than 14 days ago",
        "file-extension churn",
        "beacon interval is jittered",
        "known lockbit signature",
        "matches known infostealer behaviour",
        "exceeds the baseline confidence threshold",
    ):
        assert phrase not in emitted, f"{scenario_id} still asserts {phrase!r}, which nothing measured"


# ---------------------------------------------------------------------------
# The disclaimer has to be where the verdict is read.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("stage", ["triage", "hunt", "respond"])
def test_the_synthetic_notice_sits_on_every_stage_that_states_a_finding(stage: str) -> None:
    """A banner above the fold is not a disclaimer for a reader who scrolled.

    The reporter read the verdict, which is several screens below the
    header line that said "synthetic offline run".
    """

    decision = _step(load_scenario("lateral-movement"), stage)["decision"]
    assert "synthetic offline run" in decision, f"{stage} states a finding without saying what produced it"


def test_json_output_declares_the_mode_before_the_ledger() -> None:
    """A machine reader has no banner to scroll past, so the keys come first."""

    import io
    from contextlib import redirect_stdout

    buffer = io.StringIO()
    with redirect_stdout(buffer):
        assert main(["demo", "--scenario", "lateral-movement", "--json"]) == 0
    payload = json.loads(buffer.getvalue())

    assert payload["mode"] == "synthetic-offline"
    assert "nothing executed" in payload["disclaimer"]
    keys = list(payload)
    assert keys.index("mode") < keys.index("ledger")
    assert keys.index("disclaimer") < keys.index("ledger")
