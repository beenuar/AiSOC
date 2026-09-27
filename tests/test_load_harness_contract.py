"""The load harness and the producer have to agree, and neither may publish an absence as a number.

Two contracts are pinned here.

**The marker.** ``services/demo-producer`` stamps a run id and a sequence
number into every event title; ``scripts/perf/load_harness.py`` matches alert
rows on that string. If the two spellings drift apart, the harness correlates
nothing and reports that every event was lost. A throughput regression and a
pipeline outage look identical from the outside, and the real cause is a
renamed constant. The Go constant is read out of the source rather than
re-declared here, so this test runs in the direction that actually drifts.

**The zero.** The repository's rule is that a figure which was not measured
reads "not measured", never ``0``. The harness encodes that as a type; this
asserts the serialised form, because that is what a renderer downstream sees.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load(module_name: str, relative: str):
    path = ROOT / relative
    sys.path.insert(0, str(path.parent))
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    # Registered before exec: @dataclass resolves annotations through
    # sys.modules[cls.__module__], and an unregistered module makes that None.
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


harness = _load("aisoc_load_harness", "scripts/perf/load_harness.py")


def test_marker_matches_the_producer_that_writes_it() -> None:
    source = (ROOT / "services" / "demo-producer" / "main.go").read_text(encoding="utf-8")
    declared = re.search(r'const MarkerPrefix = "([^"]+)"', source)
    assert declared, "services/demo-producer no longer declares MarkerPrefix"
    assert declared.group(1) == harness.MARKER_PREFIX, (
        "the producer stamps a different marker than the harness matches on, so every run would report total loss"
    )


def test_the_title_the_producer_formats_is_the_title_the_harness_parses() -> None:
    source = (ROOT / "services" / "demo-producer" / "main.go").read_text(encoding="utf-8")
    # The Go format string, turned into one concrete title. Taking it from the
    # source rather than hand-copying it is the point: a reordered field or a
    # changed separator has to fail here.
    fmt = re.search(r'"title":\s*fmt\.Sprintf\("([^"]+)"', source)
    assert fmt, "the load event no longer formats its title with a recognisable Sprintf"
    concrete = (
        fmt.group(1).replace("%s %s", f"{harness.MARKER_PREFIX} run1", 1).replace("%d", "7", 1).replace("%d", "1700000000123456789", 1)
    )
    match = harness._TITLE_RE.match(concrete)
    assert match, f"the harness cannot parse a title the producer would write: {concrete!r}"
    assert match.group("run") == "run1"
    assert match.group("seq") == "7"
    assert match.group("sent") == "1700000000123456789"


@pytest.fixture
def _empty_report() -> dict:
    return harness.build_report(
        target=harness.Target(name="t", psql=[], kafka=[], stats=None, ingest_url=""),
        summary=harness.ProducerSummary(
            {"run_id": "x", "attempted_events": 10, "accepted_events": 0, "wall_seconds": 1.0, "accepted_eps": 0.0}
        ),
        alerts=[],
        clock_offset=0.0,
        clock_spread=0.0,
        lag_in_flight=(None, "broker unreachable"),
        lag_drained=(None, "broker unreachable"),
        dead_letters=None,
        dead_letter_reason="table unreadable",
        resources=[],
        drain_seconds=0.0,
        settled=False,
    )


def test_a_metric_that_was_not_measured_serialises_without_a_value(_empty_report: dict) -> None:
    for name, body in _empty_report["metrics"].items():
        assert body["measured"] is False, name
        assert "value" not in body, f"{name} would render as a number nobody measured"
        assert body["reason"], f"{name} does not say why it was not measured"


def test_a_measured_zero_is_still_a_zero() -> None:
    report = harness.build_report(
        target=harness.Target(name="t", psql=[], kafka=[], stats=None, ingest_url=""),
        summary=harness.ProducerSummary(
            {"run_id": "x", "attempted_events": 2, "accepted_events": 2, "wall_seconds": 1.0, "accepted_eps": 2.0}
        ),
        alerts=[harness.AlertRow(seq=0, sent_epoch=1.0, created_epoch=1.1), harness.AlertRow(seq=1, sent_epoch=1.0, created_epoch=1.2)],
        clock_offset=0.0,
        clock_spread=0.0,
        lag_in_flight=(0, ""),
        lag_drained=(0, ""),
        dead_letters=0,
        dead_letter_reason="",
        resources=[],
        drain_seconds=0.0,
        settled=True,
    )
    lag = report["metrics"]["consumer_lag_drained"]
    assert lag["measured"] is True and lag["value"] == 0.0, (
        "a drained queue really is zero; collapsing it into 'not measured' would hide a working pipeline"
    )
    assert report["metrics"]["dead_letter_rate"]["value"] == 0.0


def test_every_published_result_declares_it_is_not_an_slo() -> None:
    import json

    results = sorted((ROOT / "docs" / "perf" / "results").glob("*.json"))
    assert results, "no published results; the performance page would be quoting nothing"
    perf = [json.loads(p.read_text(encoding="utf-8")) for p in results]
    perf = [b for b in perf if str(b.get("schema", "")).startswith("aisoc.load_harness")]
    assert perf, "no load-harness results among the published files"
    for blob in perf:
        assert blob["not_a_production_slo"] is True
        assert blob["slo_disclaimer"].strip()
        assert blob["hardware"].get("cpu") or blob["hardware"].get("ci_runner")
