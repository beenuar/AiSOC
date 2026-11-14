"""The realistic mix is a mix, and the harness grades it as one (depth 4.4).

The load harness used to send one event shape, every instance of which
became an alert. That measures a pipeline nobody runs: in a real estate
almost every event is routine, and the work fusion actually does is
evaluating the corpus against traffic that matches nothing. An
all-alerting harness over-measures the alert path and *under*-measures
detection, which is the stage parity 6.9 is about.

Three things have to hold for the mix to mean anything, and each has
failed in this repository's harnesses before:

* the Go producer and the Python harness must agree on the marker, or
  the harness counts zero of one population;
* the delivery ratio must be taken against the *alerting* population, or
  a lossless pipeline reports 0.01;
* a ceiling on a figure that was **not measured** must fail, not pass.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
PRODUCER_GO = REPO_ROOT / "services" / "demo-producer" / "main.go"


def _load(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / relative)
    # `spec_from_file_location` is `ModuleSpec | None`, and a None here means
    # the harness file moved — a sentence beats an AttributeError three lines
    # down, and the narrowing is what lets mypy read the rest.
    assert spec is not None and spec.loader is not None, f"no loadable module at {relative}"
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


harness = _load("aisoc_load_harness_mix", "scripts/perf/load_harness.py")


def _go_const(name: str) -> str:
    source = PRODUCER_GO.read_text(encoding="utf-8")
    match = re.search(rf'^const {name} = "([^"]+)"$', source, flags=re.M)
    assert match, f"{name} is not declared in {PRODUCER_GO}"
    return match.group(1)


def test_the_benign_marker_matches_the_one_the_producer_writes():
    # The sibling of the existing marker-parity test. A harness counting a
    # prefix the producer does not write reports zero benign alerts
    # forever, which looks exactly like a clean run.
    assert harness.BENIGN_MARKER_PREFIX == _go_const("BenignMarkerPrefix")


def test_the_two_markers_cannot_be_confused_by_the_sql():
    """The benign prefix *contains* the alerting one.

    `aisoc-load-benign` starts with `aisoc-load`, so the alerting query
    would match benign titles were it not for the space and run id that
    follow. This pins the property rather than trusting it.
    """
    assert harness.BENIGN_MARKER_PREFIX.startswith(harness.MARKER_PREFIX)
    run = "run1"
    alerting_pattern = f"{harness.MARKER_PREFIX} {run} "
    benign_title = f"{harness.BENIGN_MARKER_PREFIX} {run} seq=1 t=2"
    assert not benign_title.startswith(alerting_pattern), (
        "a benign alert would be counted as an alerting one and the mix would measure nothing"
    )


def _summary(**overrides) -> dict:
    base = {
        "run_id": "r",
        "accepted_events": 1000,
        "attempted_events": 1000,
        "wall_seconds": 10.0,
        "accepted_eps": 100.0,
        "alerting_events_sent": 10,
        "benign_events_sent": 990,
        "alert_every": 100,
    }
    base.update(overrides)
    return base


def _report(alerts, *, benign_alerts=0, **summary_overrides) -> dict:
    target = harness.Target(name="t", psql=[], kafka=[], stats=None, ingest_url="")
    return harness.build_report(
        target=target,
        summary=harness.ProducerSummary(_summary(**summary_overrides)),
        alerts=alerts,
        clock_offset=0.0,
        clock_spread=0.0,
        lag_in_flight=(None, "not measured"),
        lag_drained=(None, "not measured"),
        dead_letters=0,
        dead_letter_reason="",
        resources=[],
        drain_seconds=1.0,
        settled=True,
        benign_alerts=benign_alerts,
    )


def _alert_rows(count: int) -> list:
    return [harness.AlertRow(seq=i, sent_epoch=1.0 + i, created_epoch=1.5 + i) for i in range(count)]


def test_delivery_ratio_is_taken_against_the_alerting_population():
    """A lossless pipeline must report 1.0, not 0.01.

    Ten alerting events were sent and ten alerts arrived. Dividing by the
    1,000 accepted events — 990 of which were supposed to produce nothing
    — would report a catastrophic loss for a perfect run, and a floor set
    against that number would be meaningless.
    """
    report = _report(_alert_rows(10))
    ratio = report["metrics"]["delivery_ratio"]
    assert ratio["measured"] is True
    assert ratio["value"] == pytest.approx(1.0)


def test_the_benign_alert_rate_is_measured_and_reported():
    report = _report(_alert_rows(10), benign_alerts=0)
    rate = report["metrics"]["benign_alert_rate"]
    assert rate["measured"] is True
    assert rate["value"] == 0.0
    assert report["run"]["benign_events_sent"] == 990
    assert report["run"]["benign_events_that_alerted"] == 0


def test_benign_events_that_alert_are_counted_not_hidden():
    report = _report(_alert_rows(10), benign_alerts=99)
    assert report["metrics"]["benign_alert_rate"]["value"] == pytest.approx(0.1)


def test_an_all_alerting_run_says_the_benign_rate_is_not_measured():
    # Honest: with alert-every of 1 there are no benign events, so there is
    # no rate. Reporting 0.0 would read as "the corpus fired on nothing",
    # which is a claim this run cannot support.
    report = _report(_alert_rows(10), alerting_events_sent=1000, benign_events_sent=0, alert_every=1)
    rate = report["metrics"]["benign_alert_rate"]
    assert rate["measured"] is False
    assert "alert-every is 1" in rate["reason"]


def test_an_old_summary_without_the_mix_fields_still_grades():
    """A result file written before the mix existed must not be graded
    against a denominator it never had."""
    summary = _summary()
    del summary["alerting_events_sent"]
    del summary["benign_events_sent"]
    del summary["alert_every"]
    target = harness.Target(name="t", psql=[], kafka=[], stats=None, ingest_url="")
    report = harness.build_report(
        target=target,
        summary=harness.ProducerSummary(summary),
        alerts=_alert_rows(1000),
        clock_offset=0.0,
        clock_spread=0.0,
        lag_in_flight=(None, "n/a"),
        lag_drained=(None, "n/a"),
        dead_letters=0,
        dead_letter_reason="",
        resources=[],
        drain_seconds=1.0,
        settled=True,
    )
    assert report["metrics"]["delivery_ratio"]["value"] == pytest.approx(1.0)
    assert report["metrics"]["benign_alert_rate"]["measured"] is False


def test_a_ceiling_on_an_unmeasured_rate_fails_rather_than_passes():
    """The shape this repository keeps finding: a gate reporting success
    for a run it could not grade."""
    source = (REPO_ROOT / "scripts/perf/load_harness.py").read_text(encoding="utf-8")
    block = source.split("if args.assert_benign_alert_rate_max is not None:", 1)[1]
    block = block.split("for failure in failures:", 1)[0]
    assert 'if not body["measured"]:' in block
    assert "failures.append" in block.split('if not body["measured"]:', 1)[1].split("elif", 1)[0], (
        "an unmeasured benign rate does not fail the ceiling"
    )
