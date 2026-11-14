#!/usr/bin/env python3
"""Every published performance figure carries its hardware, its date, and the words that stop it reading as an SLO.

What this gate is for
---------------------
A throughput number is only interpretable next to the machine it came off and
the day it was taken. Published alone it becomes a promise, and the first
person to quote it in a sales conversation turns a laptop measurement into a
service-level objective nobody agreed to.

So a committed result under ``docs/perf/results/`` must carry:

* ``measured_at``            an ISO-8601 date;
* ``hardware``               with enough to identify the machine;
* ``not_a_production_slo``   literally ``true``;
* ``slo_disclaimer``         prose a reader will actually see.

And the prose page that presents them (``apps/docs/docs/operations/performance.md``)
must name the same dates the files carry and say, above the first table, that
these are not an SLO. A results directory that drifts from its own page is how
a figure outlives the conditions that produced it.

The rule about zero
-------------------
``scripts/perf/load_harness.py`` emits each metric as measured-with-a-value or
unmeasured-with-a-reason and never both. This gate enforces the half that
matters at rest: an unmeasured metric must carry no ``value`` key, so no
renderer downstream can turn an absence into ``0.00``. The inverse is checked
too, because a measured zero is real information (zero dead letters, zero
consumer lag) and must survive.

Usage::

    python3 scripts/check_perf_results.py            # verdict
    python3 scripts/check_perf_results.py --self-test
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_main  # noqa: E402

#: The deployments `apps/docs/docs/operations/performance.md` publishes a table
#: for. A results directory covering one of them is not the page being
#: supported: a reader comparing the two tables is comparing one measurement
#: against a claim with nothing behind it. Matched against the result
#: filenames, which are `<date>-<deployment>-<scenario>.json`.
REQUIRED_DEPLOYMENTS: tuple[str, ...] = ("compose", "kind")

#: How old the newest result may be before the page is presenting a figure
#: nobody has re-measured. A year is deliberately loose -- this hardware does
#: not change weekly and a tight bound would red the build for a reason no
#: contributor can act on -- but it is a bound, and there was none: a figure
#: taken in 2026 would still have been presented as current in 2030.
MAX_RESULT_AGE_DAYS = 400

RESULTS_DIR = Path("docs/perf/results")
PAGE = Path("apps/docs/docs/operations/performance.md")

#: Present in every result, whatever produced it.
_REQUIRED_TOP = ("schema", "measured_at")

#: Enough to answer "what machine was this?". Not a fixed list, because a CI
#: runner and a laptop describe themselves differently; at least one of these
#: has to be there, and the cpu-count-style fields alone are not enough.
_HARDWARE_IDENTIFIERS = ("cpu", "container_runtime", "ci_runner")

_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}")

#: The phrase the page has to carry. Matched case-insensitively on the words
#: rather than on an exact sentence, so the prose can be rewritten without
#: the gate becoming a spelling test.
_SLO_PHRASE = re.compile(r"not\s+a\s+(production\s+)?service[- ]level objective|not\s+a\s+production\s+slo", re.I)


def _findings_for(path: Path, blob: dict) -> list[str]:
    findings: list[str] = []
    name = path.name

    for key in _REQUIRED_TOP:
        if not blob.get(key):
            findings.append(f"{name}: no {key}")
    measured_at = str(blob.get("measured_at", ""))
    if measured_at and not _DATE_RE.match(measured_at):
        findings.append(f"{name}: measured_at {measured_at!r} does not begin with an ISO date")
    if measured_at[:10] and not name.startswith(measured_at[:10]):
        findings.append(f"{name}: filename does not begin with its own measurement date {measured_at[:10]}")

    schema = str(blob.get("schema", ""))
    # The chaos result is a pass/fail statement about correctness, not a
    # performance figure, so it is not required to carry the SLO apparatus.
    # It is still required to say when it was taken and what it found.
    is_perf = schema.startswith("aisoc.load_harness")

    if is_perf:
        hardware = blob.get("hardware") or {}
        if not isinstance(hardware, dict) or not hardware:
            findings.append(f"{name}: no hardware block, so the numbers describe no machine")
        elif not any(hardware.get(k) for k in _HARDWARE_IDENTIFIERS):
            findings.append(
                f"{name}: hardware block names none of {', '.join(_HARDWARE_IDENTIFIERS)}, so a reader cannot tell what produced the figure"
            )
        if blob.get("not_a_production_slo") is not True:
            findings.append(f"{name}: not_a_production_slo is not true")
        if not str(blob.get("slo_disclaimer", "")).strip():
            findings.append(f"{name}: no slo_disclaimer prose")

        metrics = blob.get("metrics")
        if not isinstance(metrics, dict) or not metrics:
            findings.append(f"{name}: no metrics")
        else:
            for metric, body in metrics.items():
                if not isinstance(body, dict) or "measured" not in body:
                    findings.append(f"{name}: metric {metric} does not say whether it was measured")
                    continue
                if body["measured"] and "value" not in body:
                    findings.append(f"{name}: metric {metric} claims measured with no value")
                if not body["measured"]:
                    if "value" in body:
                        findings.append(
                            f"{name}: metric {metric} was not measured but carries a value, "
                            "which is how an absence gets rendered as a number"
                        )
                    if not str(body.get("reason", "")).strip():
                        findings.append(f"{name}: metric {metric} was not measured and says nothing about why")
    elif schema.startswith("aisoc.chaos"):
        if blob.get("verdict") is None:
            findings.append(f"{name}: chaos result with no verdict")
    else:
        findings.append(f"{name}: unrecognised schema {schema!r}")
    return findings


def check(root: Path) -> tuple[int, list[str]]:
    results_dir = root / RESULTS_DIR
    findings: list[str] = []

    if not results_dir.is_dir():
        return 0, [f"{RESULTS_DIR} does not exist, so there are no published figures to stand behind"]

    files = sorted(results_dir.glob("*.json"))
    if not files:
        return 0, [
            f"{RESULTS_DIR} holds no results; a performance claim with no measurement behind it is the thing this gate exists to stop"
        ]

    dates: set[str] = set()
    for path in files:
        try:
            blob = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            findings.append(f"{path.name}: unreadable ({exc})")
            continue
        findings.extend(_findings_for(path, blob))
        measured_at = str(blob.get("measured_at", ""))[:10]
        if measured_at:
            dates.add(measured_at)

    page = root / PAGE
    if not page.is_file():
        findings.append(f"{PAGE} does not exist, so the results are published as JSON nobody reads")
    else:
        text = page.read_text(encoding="utf-8")
        if not _SLO_PHRASE.search(text):
            findings.append(f"{PAGE} does not say these figures are not a service-level objective")
        for date in sorted(dates):
            if date not in text:
                findings.append(
                    f"{PAGE} does not mention {date}, which a committed result carries. "
                    "A page that has drifted from the files presents figures under the wrong date"
                )

    _check_deployment_coverage(files, findings)
    _check_freshness(dates, findings)

    return len(files), findings


def _check_deployment_coverage(files: list[Path], findings: list[str]) -> None:
    """Every published table needs a measurement behind it."""
    names = " ".join(p.name for p in files)
    for deployment in REQUIRED_DEPLOYMENTS:
        if deployment not in names:
            findings.append(
                f"no committed result names `{deployment}`, but {PAGE} publishes a table for it. "
                "A published figure with no result file behind it is the thing this gate exists to stop"
            )


def _check_freshness(dates: set[str], findings: list[str]) -> None:
    """A figure with no expiry eventually describes a machine nobody runs."""
    if not dates:
        return
    newest = max(dates)
    try:
        measured = datetime.strptime(newest, "%Y-%m-%d").replace(tzinfo=UTC)
    except ValueError:
        findings.append(f"the newest `measured_at` is {newest!r}, which is not a date")
        return

    age = (datetime.now(UTC) - measured).days
    if age > MAX_RESULT_AGE_DAYS:
        findings.append(
            f"the newest committed result is {age} days old (limit {MAX_RESULT_AGE_DAYS}). "
            f"{PAGE} is presenting it as the current performance of the product. "
            "Re-run scripts/perf/load_harness.py and commit the result, or move the figures "
            "to a dated historical section that says they are not current"
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="accepted for symmetry; this gate always renders a verdict")
    parser.parse_args(argv)

    root = repo_root()
    scanned, findings = check(root)

    if findings:
        print(f"check_perf_results: {len(findings)} finding(s) across {scanned} result file(s)\n")
        for finding in findings:
            print(f"  FAIL  {finding}")
        return 1
    print(
        f"OK: {scanned} published performance result(s), each carrying its hardware, its date "
        "and the label that stops it being read as an SLO."
    )
    return 0


def _self_test() -> int:
    """Inject each violation this gate exists for and require it to be caught."""
    good = {
        "schema": "aisoc.load_harness/v1",
        "measured_at": "2026-09-27T13:45:36+00:00",
        "hardware": {"cpu": "Apple M5 Max", "container_runtime": "docker 29.5.2"},
        "not_a_production_slo": True,
        "slo_disclaimer": "One deployment, this hardware, this date.",
        "metrics": {
            "pipeline_eps": {"unit": "events/s", "measured": True, "samples": 10, "value": 176.9},
            "latency_p99_ms": {"unit": "ms", "measured": False, "samples": 0, "reason": "no alerts landed"},
        },
    }
    path = Path("2026-09-27-example.json")
    checks = [("a well-formed result passes", not _findings_for(path, good))]

    def breaks(mutate) -> bool:
        blob = json.loads(json.dumps(good))
        mutate(blob)
        return bool(_findings_for(path, blob))

    checks += [
        ("a result with no hardware block is rejected", breaks(lambda b: b.pop("hardware"))),
        (
            "a hardware block that names only a core count is rejected, since it identifies no machine",
            breaks(lambda b: b.update(hardware={"cpu_count": 8})),
        ),
        ("a result with no date is rejected", breaks(lambda b: b.pop("measured_at"))),
        (
            "a result whose filename disagrees with its date is rejected",
            breaks(lambda b: b.update(measured_at="2020-01-01T00:00:00+00:00")),
        ),
        ("not_a_production_slo set to false is rejected", breaks(lambda b: b.update(not_a_production_slo=False))),
        ("a missing disclaimer is rejected", breaks(lambda b: b.update(slo_disclaimer="  "))),
        (
            "an unmeasured metric carrying a value is rejected, because that is how an absence becomes a zero",
            breaks(lambda b: b["metrics"]["latency_p99_ms"].update(value=0.0)),
        ),
        (
            "an unmeasured metric with no reason is rejected",
            breaks(lambda b: b["metrics"]["latency_p99_ms"].pop("reason")),
        ),
        (
            "a measured metric with no value is rejected",
            breaks(lambda b: b["metrics"]["pipeline_eps"].pop("value")),
        ),
    ]

    # A measured zero must survive: it is a real result, not an absence.
    zeroed = json.loads(json.dumps(good))
    zeroed["metrics"]["pipeline_eps"] = {"unit": "events/s", "measured": True, "samples": 10, "value": 0.0}
    checks.append(("a measured zero is not mistaken for an unmeasured metric", not _findings_for(path, zeroed)))

    ok = True
    for description, passed in checks:
        ok &= passed
        print(f"  {'PASS' if passed else 'FAIL'}  {description}")
    print()
    print("check_perf_results.py: self-test " + ("OK" if ok else "FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    if "--self-test" in sys.argv[1:]:
        sys.exit(_self_test() or self_test_main("check_perf_results.py", ["--check"]))
    sys.exit(main())
