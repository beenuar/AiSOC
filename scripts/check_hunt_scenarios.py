#!/usr/bin/env python3
"""A hunt's negative scenario must invert the clause the hunt is about.

Why this exists
---------------

``services/agents/tests/test_hunt_corpus.py`` grades every hunt against a
positive and a negative synthetic scenario, and a hunt passes when it fires on
the first and not on the second. That is necessary and it is not sufficient,
because the second half is trivially satisfiable. A negative scenario drawn
from a different log source entirely will never fire on any hunt, so a corpus
of those would show a perfect false-positive rate while testing nothing.

This repository already knows how that goes. Roughly 600 of its 825 detection
fixtures are synthesised from the rule they test, which makes replay circular,
and over a hundred negative fixtures had never been replayed at all under a
test whose name said they were. The way out both times was to make the corpus
prove a property the grading could not fake.

So the rule here is the one the adversarial injection corpus already uses for
its clean twins: **a negative differs from its positive in exactly one
indicator field**, and that field is not the one selecting the log source. A
negative shaped that way is a near miss, which is the only kind of negative
that tests a hunt's discrimination rather than its aim.

What it checks
--------------

``no-negative``
    A hunt declares no negative scenario, or declares one with no events. It
    can only ever be graded in one direction.

``negative-wrong-source``
    The negative fails the hunt's log-source indicator, so it is an unrelated
    event and the hunt would not have fired on it whatever its logic was.

``negative-fires``
    The negative matches every indicator. It is a positive with another name.

``negative-too-far``
    The negative differs from the positive in more than one indicator field.
    Each extra difference is another reason the hunt did not fire, and with
    two the scenario no longer says which clause did the work.

``negative-not-a-near-miss``
    The negative matches less than half the hunt's indicators. Technically a
    non-firing event, practically an unrelated one.

``positive-does-not-fire``
    Restated from the corpus test so this gate is not vacuous when run alone.
"""

from __future__ import annotations

import json
import sys
import types
from dataclasses import dataclass
from pathlib import Path

from gate_toolkit import repo_root, self_test_if_requested

self_test_if_requested(__file__)

_HUNTS = Path("hunts")
_TELEMETRY = Path("services/agents/tests/eval_data/synthetic_hunt_telemetry.jsonl")
_ENGINE = Path("services/agents/app/hunt/engine.py")
_LOADER = Path("services/agents/app/hunt/loader.py")

REQUIRED = (_HUNTS, _TELEMETRY, _ENGINE, _LOADER)

#: Indicator fields that select *which telemetry* rather than *what happened*.
#: A negative that differs here is a different kind of event, not a near miss.
_SOURCE_FIELDS = frozenset({"source", "log_source"})

#: A negative matching fewer than this fraction of a hunt's indicators is not
#: a near miss. Half is deliberately generous: the binding rule is the
#: one-field difference below, and this catches a scenario that drifted.
_NEAR_MISS_FLOOR = 0.5


@dataclass
class Finding:
    kind: str
    hunt_id: str
    detail: str

    def __str__(self) -> str:
        return f"  [{self.kind}] {self.hunt_id}: {self.detail}"


def _load_engine(root: Path):  # noqa: ANN202 - returns (loader, engine) modules
    """Load the hunt engine and loader by path, leaving ``sys.modules`` clean.

    The engine is the production matcher, so this gate asks the same question
    the scheduler would. Re-implementing indicator matching here would make
    the gate agree with itself rather than with the engine, which is the exact
    circularity it exists to detect.

    The relative import inside ``engine.py`` needs its package to resolve, so
    two namespace modules are registered and then removed. Leaving a synthetic
    name behind has previously broken 21 unrelated tests in this repository
    while every test in its own file passed.
    """
    import importlib.util  # noqa: PLC0415 - only needed on this path

    created: list[str] = []
    for name in ("app", "app.hunt"):
        if name not in sys.modules:
            module = types.ModuleType(name)
            module.__path__ = []  # type: ignore[attr-defined]
            sys.modules[name] = module
            created.append(name)

    def _load(rel: Path, alias: str):  # noqa: ANN202
        spec = importlib.util.spec_from_file_location(alias, root / rel)
        if spec is None or spec.loader is None:
            raise RuntimeError(f"cannot load {rel}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[alias] = module
        spec.loader.exec_module(module)
        return module

    try:
        loader = _load(_LOADER, "app.hunt.loader")
        engine = _load(_ENGINE, "app.hunt.engine")
        return loader, engine
    finally:
        for name in ("app.hunt.engine", "app.hunt.loader", *created):
            sys.modules.pop(name, None)


def _events_by_incident(root: Path) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    with (root / _TELEMETRY).open(encoding="utf-8") as handle:
        for line_no, raw in enumerate(handle, 1):
            line = raw.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise SystemExit(f"{_TELEMETRY}:{line_no} is not valid JSON: {exc}") from exc
            out.setdefault(str(event.get("incident_id")), []).append(event)
    return out


def judge(root: Path) -> tuple[list[Finding], dict[str, int]]:
    loader_mod, engine_mod = _load_engine(root)
    corpus = loader_mod.HuntCorpus(root / _HUNTS)
    corpus.reload()
    hunts = corpus.list()
    events = _events_by_incident(root)

    findings: list[Finding] = []
    stats = {"hunts": len(hunts), "one_field": 0, "graded_both_ways": 0}

    if not hunts:
        raise SystemExit(f"no hunts loaded from {root / _HUNTS}; refusing to report a corpus clean")

    for hunt in hunts:
        indicators = hunt.hypothesis.indicators
        pos_id = hunt.expected.positive_incident_id
        neg_id = hunt.expected.negative_incident_id
        pos_events = events.get(pos_id or "", [])
        neg_events = events.get(neg_id or "", [])

        if not pos_events:
            findings.append(Finding("positive-does-not-fire", hunt.id, f"no events for positive scenario {pos_id!r}"))
            continue
        if not neg_id or not neg_events:
            findings.append(
                Finding(
                    "no-negative",
                    hunt.id,
                    "declares no negative scenario, so it can only be graded in one direction",
                )
            )
            continue

        # The best positive event, so a multi-event scenario is judged on the
        # one the hunt is about rather than on an incidental first row.
        best_pos = max(pos_events, key=lambda e: sum(1 for i in indicators if engine_mod._indicator_matches(e, i)))
        pos_hits = [engine_mod._indicator_matches(best_pos, i) for i in indicators]
        if not all(pos_hits):
            missed = [i.field for i, hit in zip(indicators, pos_hits, strict=True) if not hit]
            findings.append(Finding("positive-does-not-fire", hunt.id, f"positive scenario fails indicator(s) on {missed}"))
            continue

        # The negative event closest to firing: if any negative event is a
        # near miss the scenario is doing its job, and judging the weakest one
        # would report a corpus worse than it is.
        best_neg = max(neg_events, key=lambda e: sum(1 for i in indicators if engine_mod._indicator_matches(e, i)))
        neg_hits = [engine_mod._indicator_matches(best_neg, i) for i in indicators]
        score = sum(neg_hits) / len(indicators) if indicators else 0.0

        if all(neg_hits):
            findings.append(
                Finding("negative-fires", hunt.id, "the negative scenario matches every indicator; it is a positive under another name")
            )
            continue

        source_failures = [i.field for i, hit in zip(indicators, neg_hits, strict=True) if not hit and i.field in _SOURCE_FIELDS]
        if source_failures:
            findings.append(
                Finding(
                    "negative-wrong-source",
                    hunt.id,
                    f"the negative fails the log-source indicator on {source_failures}, so it is an "
                    f"unrelated event rather than a near miss",
                )
            )
            continue

        if score < _NEAR_MISS_FLOOR:
            findings.append(
                Finding(
                    "negative-not-a-near-miss",
                    hunt.id,
                    f"the negative matches only {score:.0%} of the hunt's indicators; it is not testing the discriminating clause",
                )
            )
            continue

        # The binding rule. Compare on indicator fields only: incidental
        # context (a different hostname, a different user) is fine and
        # expected, but every *indicator* the hunt names must hold constant
        # except the one the scenario is about.
        differing = sorted({i.field for i in indicators if _get(best_pos, i.field) != _get(best_neg, i.field)})
        if len(differing) > 1:
            findings.append(
                Finding(
                    "negative-too-far",
                    hunt.id,
                    f"the negative differs from the positive on {len(differing)} indicator fields ({differing}); "
                    f"with more than one difference the scenario no longer says which clause did the work",
                )
            )
            continue

        stats["one_field"] += 1
        stats["graded_both_ways"] += 1

    return findings, stats


def _get(event: dict, dotted: str):  # noqa: ANN202
    cur = event
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _self_test() -> int:
    """Prove the gate detects each violation, against the committed corpus."""
    from gate_toolkit import self_test_main  # noqa: PLC0415

    root = repo_root()
    extra: list[tuple[str, bool]] = []

    findings, stats = judge(root)
    extra.append((f"the committed corpus of {stats['hunts']} hunts has no findings", not findings))
    for finding in findings:
        print(f"        {finding}")

    loader_mod, engine_mod = _load_engine(root)
    corpus = loader_mod.HuntCorpus(root / _HUNTS)
    corpus.reload()
    sample = corpus.list()[0]
    events = _events_by_incident(root)

    # A negative drawn from another log source is the tautology this exists
    # to catch. Built here rather than committed, so the corpus stays clean.
    pos = events[sample.expected.positive_incident_id][0]
    unrelated = {**pos, "source": "a-log-source-this-hunt-never-reads"}
    indicators = sample.hypothesis.indicators
    fails_source = any(not engine_mod._indicator_matches(unrelated, i) for i in indicators if i.field in _SOURCE_FIELDS)
    extra.append(("a negative from an unrelated log source is recognisable as such", fails_source))

    # And a negative identical to the positive fires, which is the other end.
    fires = all(engine_mod._indicator_matches(pos, i) for i in indicators)
    extra.append(("a negative identical to the positive would match every indicator", fires))

    extra.append(("every graded hunt differs from its negative in exactly one indicator field", stats["one_field"] == stats["hunts"]))

    return self_test_main(Path(__file__).name, ["--check"], extra=extra)


def main(argv: list[str] | None = None) -> int:
    args = list(argv if argv is not None else sys.argv[1:])
    if "--self-test" in args:
        return _self_test()

    root = repo_root()
    missing = [str(rel) for rel in REQUIRED if not (root / rel).exists()]
    if missing:
        print("check_hunt_scenarios: refusing to render a verdict — these paths are missing:")
        for path in missing:
            print(f"  {path}")
        return 2

    findings, stats = judge(root)
    if findings:
        print(f"check_hunt_scenarios: {len(findings)} finding(s)\n")
        for finding in findings:
            print(finding)
        print("\nA negative scenario that fails for an unrelated reason grades a hunt's aim rather than")
        print("its discrimination, and a corpus of those reports a perfect false-positive rate while")
        print("testing nothing.")
        return 1

    print(
        f"check_hunt_scenarios: OK — {stats['hunts']} hunts, all graded in both directions, "
        f"every negative inverting exactly one indicator field of its positive."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
