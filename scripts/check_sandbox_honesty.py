#!/usr/bin/env python3
"""`aisoc-sandbox` may not assert a finding it did not compute.

The defect this exists for
--------------------------
A community reviewer fed the offline demo a harmless login — same user,
same address, New York both times, eight hours apart, tagged ``T1078``
at severity ``high`` — and it answered "the geo pivot between sequential
events is physically impossible", high confidence, 83/100. Relabelling
genuine impossible-travel events ``info`` produced "L4 — fully autonomous
closure" and "auto-execute eligible". Every claim reproduced.

The cause was that all three decision functions were keyed on strings the
*input file* declared and none of them could see the events:

    _confidence_band(*, severity: str, technique_count: int)
    _automation_tier(severity: str)
    DeterministicReasoner.explain(self, *, technique: str | None)

83 is ``75 (high) + 4 x 2 techniques``. The rationale table also asserted
measurements nothing had taken — a Welford-online baseline, a domain
registration age, a file-extension churn rate — and the class docstring
named the goal outright: that "a buyer comparing the sandbox to the live
demo can't tell the rendered ledger apart at a glance".

This is the family this repository deletes rather than rewords —
``_synthetic_reply``'s canned paragraphs about an estate it never read,
``AlertDetailView``'s catch block rendering an invented APT verdict as
``status: completed``, its ``CaseWorkspace`` twin. A fallback that
invents evidence is worse than one that says it cannot answer.

Why a gate and not only the unit tests
--------------------------------------
``packages/aisoc-sandbox/tests/test_honesty.py`` pins the behaviour, and
it is the stronger evidence for the cases it covers. Two things it cannot
do, which is what this adds:

* It runs in a job filtered on ``packages/aisoc-sandbox/**``. This runs in
  ``python-lint``, which has no path filter, so a change elsewhere that
  reintroduces the shape is still graded.
* It tests the behaviour that exists. The static arm below refuses the
  *shape* — a lookup table keyed on a MITRE technique or a severity name
  whose values are sentences or scores — so a reintroduction is caught in
  a brand-new module before anything calls it. The original table was
  exactly that shape, and no behavioural test written against the old
  code would have objected to it, because the behaviour was the point.

What it checks
--------------
Behavioural, by running the real CLI out of process over the bundled
scenarios and four adversarial fixtures:

  1. No tool call may omit ``executed: false``.
  2. No confidence score may be emitted at all.
  3. No automation tier or approval posture may be emitted.
  4. Every ``not_computed`` value must carry a reason, and nothing
     unmeasurable may render as a bare number — including zero.
  5. The retired rationales may not reappear.
  6. The reporter's benign payload may not be called impossible travel.
  7. Holding the events fixed and sweeping severity across the whole
     ladder must not change one computed finding.
  8. Changing the events must change the finding.
  9. Every stage that states a finding must carry the synthetic notice.
 10. The ruleset figure must match the generated constant, never a
     hand-typed one.

Static, over every module in the package:

 11. No dict literal maps a technique id or a severity name to a
     sentence or a number.
 12. No module derives a published figure from a hash or an RNG.

Usage
-----

    python3 scripts/check_sandbox_honesty.py
    python3 scripts/check_sandbox_honesty.py --self-test
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

# `scripts/` is on sys.path when this file is run as a program, but not when a
# test loads it by path with importlib. gate_toolkit sits beside it either way.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_main

PACKAGE_REL = Path("packages") / "aisoc-sandbox"
SEVERITIES = ("info", "low", "medium", "high", "critical")

#: Sentences the retired table asserted. Each one states a measurement
#: the sandbox never took; none may come back under any wording that
#: keeps the measurement word.
RETIRED_CLAIMS = (
    "welford",
    "standard deviations",
    "registered less than 14 days ago",
    "file-extension churn",
    "beacon interval is jittered",
    "known lockbit signature",
    "matches known infostealer behaviour",
    "exceeds the baseline confidence threshold",
    "classic credential takeover",
)

#: Autonomy vocabulary that may only ever appear attached to an explicit
#: statement that the tier was *not* determined. The gate checks the
#: surrounding value, so "the L0–L4 tier is not computed here" passes and
#: "L4 — fully autonomous closure" does not.
TIER_CLAIMS = (
    "fully autonomous closure",
    "auto-respond with audit",
    "proposed actions, human confirms",
    "recommendations only, human executes",
    "auto-execute",
    "auto_below_high",
    "human_approval_required",
)

#: Evidence keys the sandbox structurally cannot measure: it has no
#: model, no case store, no behavioural baseline, no tenant policy and no
#: event lake. Each must be a ``not_computed`` value carrying a reason —
#: never a number, and *especially* never a zero. The zero is the
#: dangerous one: this repository has shipped a formatter whose
#: "unavailable" escape hatch excluded zero, so hardcoded zeros rendered
#: as `0%` under a live label, and a `matches_found: 0` here reads as a
#: sweep that ran and found nothing rather than a sweep that never ran.
UNMEASURABLE_KEYS = (
    "additional_compromised_entities",
    "approval_posture",
    "automation_maturity_tier",
    "blast_radius_gate",
    "confidence_score",
    "entity_risk",
    "matches_found",
    "rba_entity_risk",
    "related_cases_30d",
)

_TECHNIQUE_KEY = re.compile(r"^T\d{4}(\.\d{3})?$")
_SCORE = re.compile(r"\b\d{1,3}\s*/\s*100\b")
#: "800+", "2,500+", "1200 +" — the shape of a corpus size written by hand.
_HAND_TYPED_COUNT = re.compile(r"^\s*\d[\d,]{1,}\s*\+\s*$")
#: The specific retired figure, searched across a whole JSON blob rather than
#: against one field. A plain `"800+" in blob` also matches the middle of an
#: ISO-8601 timestamp — `...:56.456800+00:00` contains it — so the check fired
#: on roughly one run in twenty for a reason no author could act on. In a
#: timestamp the digits are surrounded by digits on both sides; in the figure
#: this guards they are not, so requiring a non-digit on each side separates
#: them without loosening what it catches.
_RETIRED_RULE_FIGURE = re.compile(r"(?<!\d)800\s*\+(?!\d)")


# ---------------------------------------------------------------------------
# Driving the real package.
# ---------------------------------------------------------------------------


def _fixture(name: str, *, severity: str, events: list[dict[str, Any]], techniques: list[str] | None = None) -> dict[str, Any]:
    return {
        "id": name,
        "title": name,
        "severity": severity,
        "mitre_techniques": techniques if techniques is not None else ["T1078", "T1078.004"],
        "entities": {"user": "alice@example.com"},
        "events": events,
    }


def _login(when: str, city: str, country: str, address: str = "203.0.113.42") -> dict[str, Any]:
    return {
        "uuid": f"ev-{when}",
        "published": when,
        "eventType": "user.session.start",
        "actor": "alice@example.com",
        "client_ip": address,
        "geo": {"city": city, "country": country},
    }


#: The reporter's own payload, and the variants that separate "the verdict
#: followed the events" from "the verdict followed the label".
ADVERSARIAL = {
    # Same user, same address, same city, eight hours apart. The payload
    # that produced "physically impossible ... 83/100".
    "benign-repeat-login": _fixture(
        "benign-repeat-login",
        severity="high",
        events=[_login("2026-05-14T09:00:00Z", "New York", "US"), _login("2026-05-14T17:00:00Z", "New York", "US")],
    ),
    # Genuine impossible travel, label turned down to `info`. Produced
    # "L4 — fully autonomous closure" and "auto-execute eligible".
    "real-travel-labelled-info": _fixture(
        "real-travel-labelled-info",
        severity="info",
        techniques=["T1078"],
        events=[
            _login("2026-05-14T09:30:14Z", "New York", "US"),
            _login("2026-05-14T09:38:01Z", "Saint Petersburg", "RU", "203.0.113.50"),
        ],
    ),
    # Nothing to compute at all. The honest answer is silence with a
    # reason, never a default.
    "no-events": _fixture("no-events", severity="critical", events=[]),
    # A city the built-in table does not carry. Must be named, not
    # substituted with a country centroid.
    "unresolvable-city": _fixture(
        "unresolvable-city",
        severity="low",
        events=[_login("2026-05-14T09:00:00Z", "New York", "US"), _login("2026-05-14T09:05:00Z", "Nowheresville", "ZZ")],
    ),
}


def _run_sandbox(root: Path, payload: dict[str, Any], workdir: Path) -> dict[str, Any]:
    """Run the tree's own copy of the CLI and return the parsed ledger."""

    src = root / PACKAGE_REL / "src"
    if not (src / "aisoc_sandbox" / "cli.py").exists():
        raise FileNotFoundError(f"no sandbox package under {root / PACKAGE_REL}")

    scenario_file = workdir / f"{payload['id']}.json"
    scenario_file.write_text(json.dumps(payload), encoding="utf-8")

    env = {**os.environ, "PYTHONPATH": str(src), "PYTHONDONTWRITEBYTECODE": "1"}
    done = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "aisoc_sandbox.cli", "demo", "--file", str(scenario_file), "--json"],
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
        check=False,
    )
    if done.returncode != 0:
        raise RuntimeError(f"sandbox exited {done.returncode} on {payload['id']}: {done.stderr.strip()[:400]}")
    return dict(json.loads(done.stdout))


def _findings(payload: dict[str, Any]) -> str:
    """Everything the run *computed*, with intake and call shapes removed.

    The detect step and the `case.create` argument are the two places the
    declared severity is legitimately quoted back, so they are excluded
    by construction. Scrubbing the string instead would also hit "below",
    which contains "low", and weaken the comparison without saying so.
    """

    steps = [s for s in payload["ledger"] if s["funnel_stage"] != "detect"]
    return json.dumps([{k: s[k] for k in ("rationale", "evidence", "decision")} for s in steps], sort_keys=True)


def _not_computed_values(step: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    return [(k, v) for k, v in step["evidence"].items() if isinstance(v, dict) and v.get("status") == "not_computed"]


# ---------------------------------------------------------------------------
# The behavioural arm.
# ---------------------------------------------------------------------------


def _check_behaviour(root: Path, workdir: Path) -> list[str]:
    problems: list[str] = []

    scenarios_dir = root / PACKAGE_REL / "src" / "aisoc_sandbox" / "scenarios"
    bundled = {p.stem: json.loads(p.read_text(encoding="utf-8")) for p in sorted(scenarios_dir.glob("*.json"))}
    if not bundled:
        problems.append(f"no bundled scenarios under {scenarios_dir} — refusing to report a clean result over nothing")
        return problems

    runs = {name: _run_sandbox(root, payload, workdir) for name, payload in {**bundled, **ADVERSARIAL}.items()}

    expected_rules = _expected_rule_figure(root)

    for name, run in runs.items():
        blob = json.dumps(run, ensure_ascii=False)
        lowered = blob.lower()

        if _SCORE.search(blob):
            problems.append(f"{name}: publishes an N/100 confidence score; the package computes none")
        if _RETIRED_RULE_FIGURE.search(blob):
            problems.append(f"{name}: carries the hand-typed '800+' rule count")
        if expected_rules and expected_rules not in blob:
            problems.append(
                f"{name}: does not carry the generated ruleset figure {expected_rules!r} — the number is being typed rather than derived"
            )
        for claim in RETIRED_CLAIMS:
            if claim in lowered:
                problems.append(f"{name}: asserts {claim!r}, which nothing in the sandbox measures")

        for step in run["ledger"]:
            stage = step["funnel_stage"]
            for call in step["tool_calls"]:
                if call.get("executed") is not False:
                    problems.append(f"{name}/{stage}: tool call {call.get('name')!r} does not declare executed=false")
            for key, value in _not_computed_values(step):
                if not str(value.get("reason", "")).strip():
                    problems.append(f"{name}/{stage}: {key} is not_computed but gives no reason")
            for key in UNMEASURABLE_KEYS:
                if key not in step["evidence"]:
                    continue
                value = step["evidence"][key]
                if not (isinstance(value, dict) and value.get("status") == "not_computed"):
                    problems.append(
                        f"{name}/{stage}: {key} is published as {value!r}. The sandbox cannot measure it, so the"
                        " honest render is an explicit not_computed with a reason — a bare number here, and zero"
                        " above all, reads as a measurement that was taken"
                    )
            if stage != "detect" and "synthetic offline run" not in (step["decision"] or ""):
                problems.append(f"{name}/{stage}: states a finding without saying what produced it")
            for banned in TIER_CLAIMS:
                for key, value in step["evidence"].items():
                    if isinstance(value, str) and banned in value:
                        problems.append(f"{name}/{stage}: evidence {key} asserts {banned!r}")
                if banned in (step["decision"] or ""):
                    problems.append(f"{name}/{stage}: decision asserts {banned!r}")

    # 6 — the reported payload, named explicitly so a failure says which
    # input broke rather than only which rule.
    benign = json.dumps(runs["benign-repeat-login"], ensure_ascii=False).lower()
    if "physically impossible" in benign:
        problems.append(
            "benign-repeat-login: two sign-ins from one address in one city eight hours apart are described as physically impossible travel"
        )

    # 7 — sweep the label across the ladder with the events held fixed.
    baseline, baseline_severity = None, None
    for severity in SEVERITIES:
        payload = dict(ADVERSARIAL["real-travel-labelled-info"], id=f"severity-sweep-{severity}", severity=severity)
        findings = _findings(_run_sandbox(root, payload, workdir))
        if baseline is None:
            baseline, baseline_severity = findings, severity
        elif findings != baseline:
            problems.append(f"severity {baseline_severity} -> {severity} changed a computed finding; the verdict is following the label")
        # Whole word, not substring: "below" contains "low", and a
        # substring test here reports a violation on the burst signal's
        # own wording. The weaker-looking check is the correct one.
        if re.search(rf"\b{severity}\b", findings):
            problems.append(f"severity sweep: the declared label {severity!r} reaches a computed finding")

    # 8 — and the converse, which is the half a "say less" fix would miss.
    moved = dict(ADVERSARIAL["benign-repeat-login"], id="severity-sweep-moved")
    moved["events"] = [moved["events"][0], _login("2026-05-14T09:08:00Z", "Saint Petersburg", "RU", "203.0.113.50")]
    if _findings(_run_sandbox(root, moved, workdir)) == _findings(runs["benign-repeat-login"]):
        problems.append("moving the second sign-in to another continent changed nothing; the findings do not read the events")

    return problems


def _expected_rule_figure(root: Path) -> str:
    """The ruleset figure as the generated constant spells it, or "".

    Empty when the constant is absent, so the behavioural arm reports the
    missing module through the import rather than through a confusing
    mismatch against a number it made up.
    """

    corpus = root / PACKAGE_REL / "src" / "aisoc_sandbox" / "_corpus.py"
    if not corpus.exists():
        return ""
    match = re.search(r"^LIVE_ENGINE_EXECUTABLE_RULES\s*=\s*(\d+)", corpus.read_text(encoding="utf-8"), re.MULTILINE)
    return f"{int(match.group(1)):,}" if match else ""


# ---------------------------------------------------------------------------
# The static arm — refuse the *shape*, not only the instance.
# ---------------------------------------------------------------------------


def _check_shape(root: Path) -> list[str]:
    problems: list[str] = []
    modules = sorted((root / PACKAGE_REL / "src" / "aisoc_sandbox").glob("*.py"))
    if not modules:
        problems.append(f"no modules under {root / PACKAGE_REL} — refusing to report a clean result over nothing")
        return problems

    for module in modules:
        tree = ast.parse(module.read_text(encoding="utf-8"))
        generated = module.name == "_corpus.py"
        for node in ast.walk(tree):
            if isinstance(node, ast.Dict):
                verdict = _verdict_table(node)
                if verdict:
                    problems.append(
                        f"{module.name}:{node.lineno} maps {verdict} to a sentence or a score — a verdict keyed on what the input declares"
                    )
                for key in node.keys:
                    if isinstance(key, ast.Constant) and key.value == "rule_count":
                        problems.append(
                            f"{module.name}:{key.lineno} carries a 'rule_count' argument; the figure belongs in the"
                            " generated _corpus.py, derived rather than retyped"
                        )
            # Only `_corpus.py` may carry a corpus size, and even there it
            # is written by the sync script. Anywhere else it is a figure
            # someone typed, which is how '800+' outlived a corpus that
            # had grown past 2,500.
            if not generated and isinstance(node, ast.Constant) and isinstance(node.value, str):
                if _HAND_TYPED_COUNT.match(node.value):
                    problems.append(
                        f"{module.name}:{node.lineno} hand-types the count {node.value!r};"
                        " derive it through scripts/sync_sandbox_corpus_figures.py"
                    )
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "hash":
                problems.append(f"{module.name}:{node.lineno} calls builtin hash(); a published figure must not come from one")
            if isinstance(node, ast.Import) and any(a.name in {"hashlib", "random"} for a in node.names):
                names = ", ".join(a.name for a in node.names)
                problems.append(f"{module.name}:{node.lineno} imports {names}; a published figure must not come from one")
            if isinstance(node, ast.ImportFrom) and node.module in {"hashlib", "random"}:
                problems.append(f"{module.name}:{node.lineno} imports from {node.module}; a published figure must not come from one")
    return problems


def _verdict_table(node: ast.Dict) -> str | None:
    """Whether a dict literal is "declared input -> assertion".

    Narrow on purpose. A mapping of techniques to *data* — the signal
    names that bear on each, a list of aliases — is legitimate and
    common; what is not is a mapping straight to a sentence a reader
    will take as a finding, or to a number a reader will take as a
    score. So the value side has to look like an assertion before the
    key side matters.
    """

    keys = [k.value for k in node.keys if isinstance(k, ast.Constant) and isinstance(k.value, str)]
    if not keys or len(keys) != len(node.keys):
        return None

    if all(_TECHNIQUE_KEY.match(key) for key in keys):
        kind = "MITRE techniques"
    elif set(keys) >= {"info", "high", "critical"}:
        kind = "severity labels"
    else:
        return None

    asserts = any(
        (isinstance(v, ast.Constant) and isinstance(v.value, str) and len(v.value) > 40)
        or (isinstance(v, ast.Constant) and isinstance(v.value, (int, float)) and not isinstance(v.value, bool))
        for v in node.values
    )
    return kind if asserts else None


# ---------------------------------------------------------------------------
# Entry points.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# The vocabulary arm — a payload in someone else's dialect must still compute.
#
# The sandbox is used by running it against your own alert file, so the set
# of field spellings it reads is load-bearing. It shipped reading exactly
# two timestamp spellings while reading four actor spellings and four
# address spellings, and a reader who wrote `ts` got `not_computable` on
# every time-based signal. Measured over eleven ordinary spellings, one
# worked.
#
# No replay of the bundled corpus could have found that, because every
# bundled fixture says `published`: a corpus written in its parser's own
# dialect cannot reveal a dialect gap. So this arm derives its fixtures
# from the module's own declared `FIELD_VOCABULARY` instead, which also
# makes declaring a spelling without making it work inexpressible.
# ---------------------------------------------------------------------------

#: Driven in the package's own interpreter so it reads the tree under test
#: rather than anything installed. One process for the whole sweep: sixty
#: CLI invocations would make a fast gate slow for no extra coverage.
_VOCAB_PROBE = """
import copy, json, sys
from aisoc_sandbox.signals import CONTAINER_ONLY_SPELLINGS, FIELD_VOCABULARY, compute_signals
from aisoc_sandbox.scenarios import available_scenarios, load_scenario

BASE = [
    {"uuid": "a", "published": "2026-05-14T09:00:00Z", "actor": "alice@example.com",
     "client_ip": "203.0.113.42", "geo": {"city": "New York", "country": "US"}},
    {"uuid": "b", "published": "2026-05-15T17:00:00Z", "actor": "alice@example.com",
     "client_ip": "203.0.113.42", "geo": {"city": "New York", "country": "US"}},
]
problems = []

def rename(events, old, new, date_only=False):
    out = copy.deepcopy(events)
    for ev in out:
        v = ev.pop(old)
        ev[new] = v[:10] if date_only else v
    return out

def sig(events, name):
    return next(s for s in compute_signals(events) if s.name == name)

for spelling in FIELD_VOCABULARY["timestamp"]:
    events = rename(BASE, "published", spelling, spelling == "date")
    if sig(events, "geo_velocity").status == "not_computable":
        problems.append("declared timestamp spelling %r does not feed geo_velocity" % spelling)
    if spelling != "date" and sig(events, "event_burst").status == "not_computable":
        problems.append("declared timestamp spelling %r does not feed event_burst" % spelling)

for spelling in FIELD_VOCABULARY["actor"]:
    if sig(rename(BASE, "actor", spelling), "geo_velocity").status == "not_computable":
        problems.append("declared actor spelling %r is not read" % spelling)

for spelling in FIELD_VOCABULARY["address"]:
    got = sig(rename(BASE, "client_ip", spelling), "source_diversity").inputs.get("source_addresses")
    if got != ["203.0.113.42"]:
        problems.append("declared address spelling %r is not read" % spelling)

for spelling in FIELD_VOCABULARY["city"]:
    ev = copy.deepcopy(BASE)
    for e in ev:
        e["geo"] = {spelling: "New York", "country": "US"}
    if sig(ev, "geo_velocity").status == "not_computable":
        problems.append("declared city spelling %r does not resolve" % spelling)

for spelling in FIELD_VOCABULARY["country"]:
    ev = copy.deepcopy(BASE)
    for e, cc in zip(ev, ("US", "RU")):
        e["geo"] = {"city": "New York", spelling: cc}
    if sig(ev, "source_diversity").inputs.get("countries") != ["RU", "US"]:
        problems.append("declared country spelling %r is not counted" % spelling)

for lat in FIELD_VOCABULARY["latitude"]:
    for lon in FIELD_VOCABULARY["longitude"]:
        ev = copy.deepcopy(BASE)
        for e in ev:
            e["geo"] = {lat: 40.7128, lon: -74.0060}
        if sig(ev, "geo_velocity").status == "not_computable":
            problems.append("declared coordinate spelling %r/%r does not resolve" % (lat, lon))

for spelling in FIELD_VOCABULARY["domain_age_days"]:
    ev = copy.deepcopy(BASE)
    ev[0][spelling] = 9
    if sig(ev, "recorded_domain_age").status != "holds":
        problems.append("declared domain-age spelling %r is not read" % spelling)

# Container-only spellings: honoured nested, refused at the top level.
for spelling in CONTAINER_ONLY_SPELLINGS.get("actor", ()):
    nested = copy.deepcopy(BASE)
    for e in nested:
        e.pop("actor"); e["user"] = {spelling: "alice@example.com"}
    if sig(nested, "geo_velocity").status == "not_computable":
        problems.append("container-only actor spelling %r is not read when nested" % spelling)
    flat = copy.deepcopy(BASE)
    for e in flat:
        e.pop("actor"); e[spelling] = "user.session.start"
    if sig(flat, "geo_velocity").status != "not_computable":
        problems.append(
            "container-only actor spelling %r was honoured at the top level, where it is far more "
            "likely to name the event than the person" % spelling
        )

# An undeclared spelling must refuse, naming the field, and must not score.
unknown = sig(rename(BASE, "published", "zzz_when"), "geo_velocity")
if unknown.status != "not_computable":
    problems.append("an undeclared timestamp spelling produced %r rather than a refusal" % unknown.status)
elif "timestamp" not in unknown.summary:
    problems.append("the refusal for an undeclared timestamp spelling does not name the missing field")
if "implied_speed_kmh" in unknown.inputs:
    problems.append("an undeclared spelling still produced a speed")

# A nested account-creation date is not the event time.
acct = copy.deepcopy(BASE)
for e in acct:
    e.pop("published"); e["user"] = {"name": "alice@example.com", "created_at": "2019-01-01T00:00:00Z"}
if sig(acct, "geo_velocity").status != "not_computable":
    problems.append("an account creation date under `user` was read as the time of the event")

# Precision: two events timed only to the day share midnight, so the elapsed
# time is zero. Reporting that as impossible travel is the original defect
# reached by a different road.
same_day = copy.deepcopy(BASE)
same_day[1]["geo"] = {"city": "Saint Petersburg", "country": "RU"}
for e in same_day:
    e["date"] = e.pop("published")[:10]
same_day[1]["date"] = same_day[0]["date"]
guard = sig(same_day, "geo_velocity")
if guard.status != "not_computable" or "physically impossible" in guard.summary:
    problems.append(
        "two events carrying only a date were scored (%s) instead of refused; the elapsed time is "
        "zero only because the payload never carried an hour" % guard.status
    )

# Null island and out-of-range coordinates are refusals, not positions.
for name, geo in (("null-island", {"lat": 0.0, "lon": 0.0}), ("out-of-range", {"lat": 999.0, "lon": -74.0})):
    ev = copy.deepcopy(BASE)
    for e in ev:
        e["geo"] = geo
    if sig(ev, "geo_velocity").status != "not_computable":
        problems.append("%s coordinates were plotted rather than refused" % name)

# The bundled corpus must not be the only dialect that works.
def shape(events):
    return json.dumps([(s.name, s.status, s.summary) for s in compute_signals(events)], sort_keys=True)

for sid in available_scenarios():
    original = load_scenario(sid).events
    for spelling in ("ts", "_time", "@timestamp"):
        if shape(rename(original, "published", spelling)) != shape(original):
            problems.append("bundled scenario %r behaves differently when timed with %r" % (sid, spelling))

print(json.dumps(problems))
"""


def _check_vocabulary(root: Path, workdir: Path) -> list[str]:
    src = root / PACKAGE_REL / "src"
    probe = workdir / "vocabulary_probe.py"
    probe.write_text(_VOCAB_PROBE, encoding="utf-8")
    env = {**os.environ, "PYTHONPATH": str(src), "PYTHONDONTWRITEBYTECODE": "1"}
    done = subprocess.run(  # noqa: S603
        [sys.executable, str(probe)], capture_output=True, text=True, env=env, timeout=180, check=False
    )
    if done.returncode != 0:
        # Fail loudly rather than skipping: a probe that cannot import the
        # package has not checked the vocabulary, and "no findings" would
        # be indistinguishable from "no run".
        raise RuntimeError(f"vocabulary probe exited {done.returncode}: {done.stderr.strip()[:500]}")
    return [str(problem) for problem in json.loads(done.stdout)]


def check(root: Path) -> list[str]:
    with tempfile.TemporaryDirectory(prefix="aisoc-sandbox-gate-") as tmp:
        return _check_shape(root) + _check_behaviour(root, Path(tmp)) + _check_vocabulary(root, Path(tmp))


def _with_patch(root: Path, relative: str, old: str, new: str) -> tuple[bool, str]:
    """Copy the package, apply one edit, and ask whether the gate objects."""

    with tempfile.TemporaryDirectory(prefix="aisoc-sandbox-inject-") as tmp:
        fake = Path(tmp) / "tree"
        (fake / PACKAGE_REL).parent.mkdir(parents=True)
        shutil.copytree(root / PACKAGE_REL, fake / PACKAGE_REL)
        target = fake / PACKAGE_REL / relative
        source = target.read_text(encoding="utf-8")
        if old not in source:
            return False, f"could not inject: {old!r} not found in {relative}"
        target.write_text(source.replace(old, new, 1), encoding="utf-8")
        try:
            found = check(fake)
        except Exception as exc:  # noqa: BLE001 — a crash is not a detection.
            return False, f"gate crashed instead of reporting: {exc}"
        return bool(found), (found[0] if found else "gate reported clean")


def _self_test(root: Path) -> int:
    clean = check(root)
    extra = [(f"the tree as committed passes ({len(clean)} problem(s))", not clean)]

    # The retired-figure pattern needs its own control. The injection below
    # that puts the figure back exercises the `rule_count`-argument detector,
    # not this one, so tightening this pattern against the timestamp false
    # positive would otherwise be unobserved. Both directions, because the
    # tightening is only correct if it still catches every shape the figure
    # was actually found in.
    extra.append(
        (
            "the retired rule figure is still caught in every shape it was found in",
            all(
                _RETIRED_RULE_FIGURE.search(blob)
                for blob in ('{"rule_count": "800+"}', '"rule_count": "800 +"', "matched against 800+ rules")
            ),
        )
    )
    extra.append(
        (
            "a timestamp whose microseconds end in 800 is not the retired figure",
            not _RETIRED_RULE_FIGURE.search('"at": "2026-11-02T22:45:56.456800+00:00"'),
        )
    )

    # Each injection restores one half of the reported defect. A gate that
    # has only ever seen a clean tree has not been shown to fail.
    injections = [
        (
            "a canned rationale keyed on a MITRE technique is refused",
            "src/aisoc_sandbox/signals.py",
            "__all__ = [",
            '_RATIONALES = {"T1078": "the geo pivot between sequential events is physically impossible,'
            ' a classic takeover."}\n\n__all__ = [',
        ),
        (
            "an automation tier keyed on severity is refused",
            "src/aisoc_sandbox/signals.py",
            "__all__ = [",
            '_TIERS = {"info": 4, "low": 3, "medium": 2, "high": 1, "critical": 1}\n\n__all__ = [',
        ),
        (
            "a confidence score reappearing in the ledger is refused",
            "src/aisoc_sandbox/investigation.py",
            'f" Confidence score: not computed.',
            'f" Confidence: high (83/100).',
        ),
        (
            "a tool call that stops declaring itself unexecuted is refused",
            "src/aisoc_sandbox/investigation.py",
            '{"name": "qdrant.semantic_search", "args": {"k": 5, "collection": "cases"}, "executed": False},',
            '{"name": "qdrant.semantic_search", "args": {"k": 5, "collection": "cases"}, "executed": True},',
        ),
        (
            "an unmeasurable value rendered as a bare zero is refused",
            "src/aisoc_sandbox/investigation.py",
            '"matches_found": NotComputed(',
            '"matches_found": 0,  # injected\n            "matches_found_reason": NotComputed(',
        ),
        (
            "the hand-typed rule count is refused where it used to live",
            "src/aisoc_sandbox/investigation.py",
            '{"name": "rules.match", "args": {"technique_set": s.mitre_techniques}, "executed": False},',
            '{"name": "rules.match", "args": {"rule_count": "800+", "technique_set": s.mitre_techniques}, "executed": False},',
        ),
        (
            "narrowing the timestamp vocabulary back to what shipped is refused",
            "src/aisoc_sandbox/signals.py",
            '    "timestamp": (\n        "published",',
            '    "timestamp": (\n        "ONLY_THE_TWO_THAT_SHIPPED",\n        "published",\n    ),\n'
            '    "_retired_timestamp": (\n        "published",',
        ),
        (
            "removing the date-only precision guard is refused",
            "src/aisoc_sandbox/signals.py",
            "            if hours == 0.0 and (i0.date_only or i1.date_only):\n"
            "                precision_skipped += 1\n                continue\n",
            "",
        ),
        (
            "honouring a container-only spelling at the top level is refused",
            "src/aisoc_sandbox/signals.py",
            "        spellings = top_level if depth == 0 else nested",
            "        spellings = nested",
        ),
    ]
    for description, relative, old, new in injections:
        caught, detail = _with_patch(root, relative, old, new)
        extra.append((f"{description} [{detail[:90]}]", caught))

    return self_test_main("check_sandbox_honesty.py", (), extra=extra)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="prove the gate catches injected violations")
    args = parser.parse_args()

    root = repo_root()
    if args.self_test:
        return _self_test(root)

    try:
        problems = check(root)
    except (FileNotFoundError, RuntimeError) as exc:
        print(f"check_sandbox_honesty: {exc}", file=sys.stderr)
        return 1

    if problems:
        print(
            f"check_sandbox_honesty: {len(problems)} problem(s) — the sandbox is asserting something it did not compute.\n", file=sys.stderr
        )
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1

    print("OK: aisoc-sandbox asserts nothing it did not compute.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
