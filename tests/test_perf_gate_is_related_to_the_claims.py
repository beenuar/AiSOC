"""The performance gate's thresholds are derived from the published figures.

Fix pass item 5.8. See `plans/aisoc_fix_pass_plan.plan.md`.

What was wrong
--------------
`perf.yml` asserted `--assert-eps-floor 5` and
`--assert-p95-ceiling-ms 120000`. The published compose steady-state figures
are **80.1 alerts/s** and a **1,091 ms** p95. So the floor sat 16x below the
throughput being claimed and the ceiling 110x above the latency, and a
regression had to be catastrophic by two orders of magnitude before the gate
noticed -- while the job's name said it was measuring.

The workflow's own comment defended this: a gate tuned close to a measurement
flaps on a shared runner and gets disabled. That argument is right, and it
argues for a **stated margin**, not for an arbitrary constant. `5` is a number
that relates to nothing: when the published figure changes, it does not, and
nobody can say what regression it would catch.

`scripts/check_perf_results.py` also accepted a results directory covering one
deployment, and had no freshness bound at all -- so a figure measured years ago
on one of the two supported deployments would keep passing while the page
presented it as current.

What this file asserts
----------------------
The relationship, from the workflow and the published page as they are on
disk: that the floor and ceiling are within a stated factor of the figures the
docs publish, and that the gate requires both deployments and a date.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "perf.yml"
PAGE = ROOT / "apps" / "docs" / "docs" / "operations" / "performance.md"

#: The margins the repository has decided are acceptable, stated once here so
#: the test and the workflow cannot drift apart silently. Generous on purpose:
#: a shared GitHub runner is not the machine the figures came off, and a gate
#: that flaps gets switched off. But bounded, so a regression of this size
#: fails rather than passing unnoticed.
MAX_THROUGHPUT_MARGIN = 8.0
"""The floor may sit at most 8x below the published drain rate."""

MAX_LATENCY_MARGIN = 20.0
"""The ceiling may sit at most 20x above the published p95."""

MAX_HOT_PATH_MARGIN = 25.0
"""The in-process floor may sit at most 25x below the published promote rate.

Wider than the end-to-end margin on purpose, and the reason is a property of
what is being measured rather than a preference: the hot-path harness is a
single-threaded Python microbenchmark, and a shared, throttled runner is
further from an 18-core laptop on that than on a container pipeline whose
ceiling is a broker.

This arm exists because the gate it guards was the one that mattered and the
one nobody had bound. `perf.yml` asserted `--assert-floor 1000` against a
published 140,692 events/s -- 140x -- under a comment claiming a ">200x margin
below the measured number", where that number appeared on no page. And the
end-to-end job the original arm checks is nightly, so on a pull request this
was the *only* throughput gate running at all.
"""


def _harness_args() -> str:
    """The `run:` block that invokes the harness with its assertions.

    Raises rather than falling through: a single exit keeps the return type a
    `str` for both mypy and CodeQL's mixed-return check, and `pytest.fail()`
    as the last statement reads as a value-returning path to both.
    """
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    for job in workflow["jobs"].values():
        for step in job.get("steps") or []:
            run = step.get("run") or ""
            if "load_harness.py" in run and "--assert-eps-floor" in run:
                return str(run)
    raise AssertionError("perf.yml no longer runs load_harness.py with an eps floor")


def _flag(name: str) -> float:
    """One numeric flag out of the harness invocation.

    The `re.search(...).group(1)` chain this replaces is four `union-attr`
    findings and an unhandled `None` on the day somebody renames a flag --
    which would surface as `AttributeError: 'NoneType'` rather than as the
    gate saying what it could not find.
    """
    match = re.search(rf"--{re.escape(name)}\s+([\d.]+)", _harness_args())
    if match is None:
        raise AssertionError(f"perf.yml no longer passes --{name} to the harness")
    return float(match.group(1))


def _hot_path_floor() -> float:
    """The `--assert-floor` the in-process harness is invoked with."""
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    for job in workflow["jobs"].values():
        for step in job.get("steps") or []:
            run = step.get("run") or ""
            if "throughput_harness.py" in run:
                match = re.search(r"--assert-floor\s+([\d.]+)", run)
                if match is None:
                    raise AssertionError("perf.yml runs the hot-path harness with no floor at all")
                return float(match.group(1))
    raise AssertionError("perf.yml no longer runs throughput_harness.py")


def _published_hot_path() -> float:
    """The promote rate out of the page's in-process section.

    Parsed from the page for the same reason as everything else here: a copy
    would agree with itself while the published number moved.
    """
    text = PAGE.read_text(encoding="utf-8")
    try:
        section = text[text.index("## Fusion hot path, in process") :]
    except ValueError:
        raise AssertionError(
            "apps/docs/docs/operations/performance.md no longer publishes a figure for the in-process "
            "hot-path harness, so the floor perf.yml asserts against it is derived from nothing"
        ) from None
    row = re.search(r"^\|\s*Promote rate\s*\|([^|]+)\|", section, flags=re.M)
    if row is None:
        raise AssertionError("no `Promote rate` row in the hot-path section")
    numbers = re.findall(r"[\d.]+", row.group(1).replace(",", ""))
    assert numbers, "no number in the promote-rate cell"
    return float(numbers[0])


def _published(label: str) -> float:
    """Read a figure out of the compose steady-state column of the page.

    Deliberately parsed from the page rather than duplicated here: a copy would
    agree with itself while the published number moved, which is the failure
    this whole gate family exists to prevent.
    """
    text = PAGE.read_text(encoding="utf-8")
    compose = text[text.index("## Single host, Docker Compose") :]
    row = re.search(rf"^\|\s*{re.escape(label)}\s*\|([^|]+)\|([^|]+)\|", compose, flags=re.M)
    if row is None:
        raise AssertionError(f"no `{label}` row in the compose table")
    # Column two is steady state, which the page itself calls "the row to plan
    # against"; saturation is a backlog measurement and a floor set from it
    # would describe the queue rather than the pipeline.
    numbers = re.findall(r"[\d.]+", row.group(2).replace(",", ""))
    assert numbers, f"no number in the steady-state cell for `{label}`"
    return float(numbers[0])


class TestTheThresholdsRelateToWhatIsPublished:
    def test_the_throughput_floor_is_within_a_stated_factor(self) -> None:
        published = _published("Pipeline drain rate")
        floor = _flag("assert-eps-floor")

        margin = published / floor
        assert margin <= MAX_THROUGHPUT_MARGIN, (
            f"the floor is {floor} against a published {published} events/s -- {margin:.0f}x below. "
            f"A regression has to be {margin:.0f}x before this gate notices."
        )

    def test_the_latency_ceiling_is_within_a_stated_factor(self) -> None:
        published = _published("Event-to-alert p95")
        ceiling = _flag("assert-p95-ceiling-ms")

        margin = ceiling / published
        assert margin <= MAX_LATENCY_MARGIN, f"the ceiling is {ceiling} ms against a published {published} ms p95 -- {margin:.0f}x above."

    def test_the_margins_are_still_generous(self) -> None:
        """The negative control. Thresholds tuned to the measurement would flap
        on a shared runner and be switched off within a week, so this asserts
        the gate has *not* been tightened to the published figure."""
        floor = _flag("assert-eps-floor")
        ceiling = _flag("assert-p95-ceiling-ms")

        assert floor < _published("Pipeline drain rate"), "the floor is at or above the published rate"
        assert ceiling > _published("Event-to-alert p95"), "the ceiling is at or below the published p95"


class TestTheHotPathFloorRelatesToWhatIsPublished:
    """The gate that runs on every pull request, which the class above does not.

    `end-to-end` is `if: schedule || workflow_dispatch`, so on a pull request
    the in-process harness is the only throughput assertion that executes. It
    was also the only one whose floor was bound to nothing.
    """

    def test_the_hot_path_floor_is_within_a_stated_factor(self) -> None:
        published = _published_hot_path()
        floor = _hot_path_floor()

        margin = published / floor
        assert margin <= MAX_HOT_PATH_MARGIN, (
            f"the in-process floor is {floor} against a published {published} events/s -- {margin:.0f}x below. "
            f"A regression has to be {margin:.0f}x before the only throughput gate on a pull request notices."
        )

    def test_the_hot_path_margin_is_still_generous(self) -> None:
        """The negative control, matching the one above: a floor tuned to the
        measurement would flap on a shared runner and be switched off."""
        assert _hot_path_floor() < _published_hot_path(), "the floor is at or above the published rate"

    def test_the_two_figures_are_not_confused_for_each_other(self) -> None:
        """The in-process rate is two to three orders of magnitude above the
        pipeline's, because it measures one function rather than ingest, a
        broker, a consumer and a database. Quoting one as the other is the
        mistake the page's own caveat warns about, and it is the mistake that
        would let somebody 'fix' a drifting gate by pointing it at the wrong
        row."""
        assert _published_hot_path() > _published("Pipeline drain rate") * 100


class TestTheResultsGateCoversBothDeploymentsAndIsTimeBound:
    def test_it_requires_both_deployments(self) -> None:
        """One deployment's figures passing is not the page being supported:
        the page publishes two tables."""
        source = (ROOT / "scripts" / "check_perf_results.py").read_text(encoding="utf-8")

        assert "REQUIRED_DEPLOYMENTS" in source, "check_perf_results.py does not require a result per published deployment"

    def test_it_has_a_freshness_bound(self) -> None:
        source = (ROOT / "scripts" / "check_perf_results.py").read_text(encoding="utf-8")

        assert "MAX_RESULT_AGE_DAYS" in source, (
            "check_perf_results.py has no freshness bound, so a figure taken years ago keeps passing while the page presents it as current"
        )
