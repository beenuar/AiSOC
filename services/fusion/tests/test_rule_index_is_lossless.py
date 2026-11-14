"""The rule index must not drop a detection (parity 6.9 / depth 4.4).

This is the only thing that makes the index safe to ship. A pre-filter on
this corpus has been tried once before and reverted for silently dropping
real matches, and "silently" is the word that matters: a detection that
stops firing produces no error, no log line and no failing test unless
something is comparing the filtered path against the unfiltered one.

So that comparison is the test. Every committed detection fixture is
replayed through the real engine twice — once with the index and once
with the index bypassed — and the hit lists must be identical, in the
same order.

A second property is checked on random events rather than fixtures,
because fixtures are synthesised from the rules they test and therefore
only ever exercise the matching case. The interesting direction is an
event that matches *nothing*: that is where an over-eager index saves the
most work and where a wrong one is invisible.
"""

from __future__ import annotations

import json
import random
from pathlib import Path

import pytest
from app.services.detection_engine import DetectionEngine
from app.services.detection_matcher import matches
from app.services.rule_index import RuleIndex, required_fields

REPO_ROOT = Path(__file__).resolve().parents[3]
FIXTURE_ROOT = REPO_ROOT / "detections"


@pytest.fixture(scope="module")
def engine() -> DetectionEngine:
    return DetectionEngine()


def _all_hits_unindexed(engine: DetectionEngine, fields: dict) -> list[str]:
    """What the whole corpus would have said, in corpus order."""
    return [rule["id"] for rule in engine.rules if _safe_match(rule, fields)]


def _safe_match(rule: dict, fields: dict) -> bool:
    try:
        return bool(matches(rule["match_when"], fields))
    except Exception:
        # The engine swallows a raising rule too, so the comparison has to
        # as well or it would report a difference the engine cannot have.
        return False


def _indexed_hits(engine: DetectionEngine, fields: dict) -> list[str]:
    return [rule["id"] for rule in engine._candidates(fields) if _safe_match(rule, fields)]


def _fixture_events(limit: int | None = None) -> list[dict]:
    """Every committed positive fixture, as the flat field namespace."""
    events: list[dict] = []
    if not FIXTURE_ROOT.is_dir():
        return events
    for path in sorted(FIXTURE_ROOT.rglob("*.json")):
        if "fixture" not in path.as_posix() and "fixtures" not in path.as_posix():
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        for candidate in _flatten_fixture(payload):
            events.append(candidate)
            if limit is not None and len(events) >= limit:
                return events
    return events


def _flatten_fixture(payload) -> list[dict]:
    """Pull event-shaped dicts out of whatever the fixture file holds."""
    out: list[dict] = []
    if isinstance(payload, dict):
        for key in ("positive", "negative", "events", "event"):
            value = payload.get(key)
            if isinstance(value, dict):
                out.append(value)
            elif isinstance(value, list):
                out.extend(item for item in value if isinstance(item, dict))
        if not out and payload:
            out.append(payload)
    elif isinstance(payload, list):
        out.extend(item for item in payload if isinstance(item, dict))
    return out


# ---------------------------------------------------------------------------


#: Measured on this corpus, not chosen: 1,751 of 2,511 loaded rules carry
#: at least one required field, which is 0.6974. The floor sits just under
#: the measurement so the figure can only be ratcheted up, and so a change
#: that moves it down has to say so in the same commit. A floor chosen
#: comfortably below reality is a gate that can never fail, which this
#: repository has measured the cost of on the performance workflow.
MEASURED_INDEXED_FRACTION = 0.6974
INDEXED_FRACTION_FLOOR = 0.69


def test_the_corpus_is_actually_indexed(engine):
    """An index that indexes nothing is a no-op wearing a name."""
    stats = engine.index_stats
    assert stats.rules > 500, f"only {stats.rules} rules loaded; the corpus did not load"
    assert stats.indexed_fraction >= INDEXED_FRACTION_FLOOR, (
        f"only {stats.indexed} of {stats.rules} rules carry a required field "
        f"({stats.indexed_fraction:.4f}); the measurement this floor was set from was "
        f"{MEASURED_INDEXED_FRACTION}"
    )


def test_every_fixture_gets_the_same_hits_both_ways(engine):
    events = _fixture_events()
    assert events, "no fixtures were found, so this test proves nothing"
    differing: list[tuple[int, list[str], list[str]]] = []
    for position, fields in enumerate(events):
        indexed = _indexed_hits(engine, fields)
        full = _all_hits_unindexed(engine, fields)
        if indexed != full:
            differing.append((position, full, indexed))
            if len(differing) >= 5:
                break
    assert not differing, (
        f"the index changed the verdict on {len(differing)} fixture(s); first: full={differing[0][1]} indexed={differing[0][2]}"
    )


def test_a_random_event_that_matches_nothing_also_agrees(engine):
    """Fixtures are synthesised from the rules they test, so they only
    exercise the matching case. The direction that matters for an index
    is the event that matches nothing."""
    rng = random.Random(20261011)
    vocabulary = ["user", "src_ip", "action", "message", "host", "Image", "EventID", "CommandLine"]
    for _ in range(200):
        fields = {rng.choice(vocabulary): rng.choice(["alice", "198.51.100.4", "login", "ok", "7", ""]) for _ in range(rng.randint(1, 4))}
        assert _indexed_hits(engine, fields) == _all_hits_unindexed(engine, fields), fields


def test_an_event_with_no_fields_at_all_agrees(engine):
    # The degenerate case the index's own definition is built on.
    assert _indexed_hits(engine, {}) == _all_hits_unindexed(engine, {})


# ---------------------------------------------------------------------------
# The classification itself.
# ---------------------------------------------------------------------------


def test_a_positive_clause_makes_its_field_required():
    assert required_fields({"Image_contains_any": ["cmd.exe"]}) == {"Image"}
    assert required_fields({"user": "root"}) == {"user"}


@pytest.mark.parametrize(
    "clause",
    [
        {"user_not_in": ["root"]},
        {"user": None},
        {"any_of": [{"user": "root"}]},
    ],
)
def test_a_clause_satisfiable_without_the_field_does_not_require_it(clause):
    # Each of these is true of an event that has no `user` at all. Treating
    # the field as required would drop a rule that should have fired.
    assert required_fields(clause) == set()


def test_neq_requires_its_field_in_this_matcher_whatever_the_name_suggests():
    """The reason the classification is executed rather than written down.

    ``neq`` reads like a negation and would be in anyone's hand-written
    list of absence-tolerant operators. This matcher's ``neq`` returns
    False for a missing field on purpose — its own comment says a rule
    using it must not fire on absence of data — so the field *is*
    required, and a hand-maintained list would have got it wrong in the
    direction that drops detections.

    Writing this test is how that was found: the first version asserted
    the opposite and failed.
    """
    assert required_fields({"user_neq": "root"}) == {"user"}


def test_classification_runs_the_matcher_rather_than_naming_operators():
    """The definition is executed, not restated.

    A matcher that grows an operator is classified correctly the day it is
    added. This asserts the property the implementation rests on: for
    every required field, the real matcher says False on an empty event.
    """
    from app.services.detection_matcher import _check, _split_op  # noqa: PLC0415

    engine = DetectionEngine()
    checked = 0
    for rule in engine.rules:
        clauses = rule.get("match_when") or {}
        for field in required_fields(clauses):
            # At least one clause on this field must refuse the empty
            # event. A rule can carry several clauses on one field - a
            # `contains_any` and a `not_contains_any` on `TargetName`,
            # say - and only one of them has to be the reason the field
            # is required. Requiring all of them was this test's own bug
            # on the first run.
            refusals = [
                key
                for key, expected in clauses.items()
                if _split_op(key)[0] == field and _check(field, _split_op(key)[1], expected, {}) is False
            ]
            assert refusals, f"{rule['id']} treats {field} as required but no clause on it refuses an empty event"
            checked += 1
    assert checked > 100, f"only {checked} fields walked; the corpus did not load"


def test_the_index_puts_unconstrained_rules_in_every_candidate_list():
    rules = [
        {"id": "needs-image", "match_when": {"Image": "cmd.exe"}},
        # `not_in` is genuinely satisfied by absence in this matcher, so
        # this rule has no required field and must be in every list.
        {"id": "needs-nothing", "match_when": {"user_not_in": ["root"]}},
    ]
    index = RuleIndex(rules)
    assert [r["id"] for r in index.candidates({})] == ["needs-nothing"]
    assert [r["id"] for r in index.candidates({"Image": "x"})] == ["needs-image", "needs-nothing"]


def test_candidates_come_back_in_corpus_order():
    # The hits a caller gets are in rule order, and an index returning
    # them bucket by bucket would change behaviour while claiming only to
    # change cost.
    rules = [
        {"id": "a", "match_when": {"z_field": "1"}},
        {"id": "b", "match_when": {"a_field": "1"}},
        {"id": "c", "match_when": {"z_field": "2"}},
    ]
    index = RuleIndex(rules)
    got = [r["id"] for r in index.candidates({"a_field": "1", "z_field": "1"})]
    assert got == ["a", "b", "c"]
