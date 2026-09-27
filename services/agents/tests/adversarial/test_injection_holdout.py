"""The held-out corpus, and the properties that make its number mean anything.

There is deliberately no floor here and no assertion that the rate is good.
The rate is 7.1% and that is the finding; a test that required it to be
higher would be a standing instruction to tune against this corpus, which is
the one thing that would destroy it. What is asserted instead is everything
that has to be true for the number to be readable at all: the payloads are
disjoint from the corpus the guard was hardened against, the twins differ in
one field so a hit is attributable, and the recorded misses describe this
tree in both directions.
"""

from __future__ import annotations

import json

import pytest
from app.prompting.envelope import PromptInjectionGuard

from .injection_holdout import HOLDOUT, HOLDOUT_UNDETECTED, build_holdout_pairs, holdout_digest
from .injection_incidents import INJECTIONS, build_pairs
from .injection_metrics import attributable_hits, score

#: Pinned on the same terms as the corpus digest next door: a corpus that can
#: change silently is not a measurement.
EXPECTED_DIGEST = "4601dada34b787269459768f130ceee0900cc30cafd044106735d47fda3550dc"


@pytest.fixture(scope="module")
def pairs():
    return build_holdout_pairs()


@pytest.fixture(scope="module")
def hits(pairs):
    return attributable_hits(pairs, PromptInjectionGuard().scan)


class TestHeldOut:
    """The property the whole file rests on: these payloads are not those."""

    def test_no_payload_is_shared_with_the_tuned_corpus(self) -> None:
        tuned = {i.payload for i in INJECTIONS}
        shared = sorted(i.id for i in HOLDOUT if i.payload in tuned)
        assert not shared, f"held-out payloads copied from the corpus the guard was tuned on: {shared}"

    def test_no_id_is_shared_with_the_tuned_corpus(self) -> None:
        assert not {i.id for i in HOLDOUT} & {i.id for i in INJECTIONS}

    def test_every_surface_the_corpus_uses_is_exercised(self) -> None:
        """A held-out set that skipped the weak surfaces would flatter the guard."""
        tuned_surfaces = {i.surface for i in INJECTIONS}
        missing = sorted(tuned_surfaces - {i.surface for i in HOLDOUT})
        assert not missing, f"held-out corpus does not reach {missing}, where the original measurement was worst"

    def test_every_goal_the_corpus_uses_is_exercised(self) -> None:
        tuned_goals = {i.goal for i in INJECTIONS if i.must_flag}
        missing = sorted(tuned_goals - {i.goal for i in HOLDOUT if i.must_flag})
        assert not missing, f"held-out corpus does not reach the {missing} goal(s)"

    def test_the_corpus_is_not_trivially_passable(self) -> None:
        adversarial = [i for i in HOLDOUT if i.must_flag]
        benign = [i for i in HOLDOUT if not i.must_flag]
        assert len(adversarial) >= 20, "too small to distinguish a guard from luck"
        assert len(benign) >= 5, (
            "without benign lookalikes the corpus rewards a guard that flags everything, which is the failure mode that gets it disabled"
        )


class TestDeterminism:
    def test_building_twice_gives_the_same_corpus(self, pairs) -> None:
        assert holdout_digest(build_holdout_pairs()) == holdout_digest(pairs)

    def test_the_digest_is_the_pinned_one(self, pairs) -> None:
        digest = holdout_digest(pairs)
        assert digest == EXPECTED_DIGEST, (
            f"held-out digest moved to {digest}. If the change was deliberate, update EXPECTED_DIGEST "
            "in the same commit, and re-publish the rate: a corpus that moves silently is not held out from anything."
        )

    def test_pairing_is_the_corpus_pairing(self) -> None:
        """Imported, not reimplemented. Two definitions of a twin would make
        the two rates incomparable, which is the only thing this file does."""
        assert build_holdout_pairs.__module__.endswith("injection_holdout")
        assert build_pairs(injections=HOLDOUT)[0].pair_id == build_holdout_pairs()[0].pair_id


class TestAttributability:
    def test_twins_differ_in_exactly_one_field(self, pairs) -> None:
        for pair in pairs:
            clean = json.loads(json.dumps(pair.clean))
            index = int(pair.field_path.split("[")[1].split("]")[0])
            field = pair.field_path.split(".")[-1]
            clean["telemetry"][index][field] = pair.injected["telemetry"][index][field]
            assert clean == pair.injected, f"{pair.pair_id}: twins differ somewhere other than {pair.field_path}"

    def test_the_payload_really_lands_in_the_field(self, pairs) -> None:
        for pair in pairs:
            index = int(pair.field_path.split("[")[1].split("]")[0])
            field = pair.field_path.split(".")[-1]
            assert pair.payload in pair.injected["telemetry"][index][field], f"{pair.pair_id}: payload is not in its own field"

    def test_no_clean_twin_already_flags_at_the_target_field(self, pairs) -> None:
        """The measurement error the corpus next door found in itself. A field
        whose original content trips the guard would credit every payload
        placed in it, and the held-out rate would be an artefact."""
        scan = PromptInjectionGuard().scan
        for pair in pairs:
            target = f"$.{pair.field_path}"
            flagged = [s.kind for s in scan(pair.clean).signals if s.field_path == target]
            assert not flagged, f"{pair.pair_id}: clean twin already flags at {target} with {flagged}"


class TestTheRecordDescribesThisTree:
    def test_recorded_misses_are_exact_in_both_directions(self, pairs, hits) -> None:
        missed = {p.injection_id for p in pairs if p.must_flag and not hits[p.pair_id]}
        assert missed == set(HOLDOUT_UNDETECTED), (
            f"held-out misses: {sorted(missed)}; recorded: {sorted(HOLDOUT_UNDETECTED)}. "
            "Update the record and re-publish the rate. This list is an observation, not a ratchet: "
            "the right response to an entry here is a structural change and a new held-out set, "
            "never a pattern written for that exact string."
        )

    def test_the_rate_is_reported_rather_than_floored(self, pairs, hits) -> None:
        """No floor, by design. This asserts only that a rate exists and
        travels with the count behind it, which is the repository's rule for
        every published number."""
        result = score(pairs, hits, holdout_digest(pairs))
        assert result.guard_detection.measured
        assert result.guard_detection.numerator is not None and result.guard_detection.denominator is not None
        print(f"\nheld-out guard detection: {result.guard_detection.render()}, benign flagged {result.guard_false_positive.render()}")
