"""The verdict corpus measures judgement, and the all-malicious ones still do not.

Depth plan 1.1.

`scripts/check_verdict_corpus.py` asserts the corpus's *structure*. This
suite asserts what that structure buys: that the scorer accepts this corpus,
that no constant answer scores well on it, and that accepting it changed
nothing about the two corpora the scorer is right to refuse.

The last of those is the one worth stating. `synthetic_incidents.json` and
`adversary_incidents.json` are 200 attacks each with no `expected_disposition`
at all, and `score_replay_set.assert_gradeable` refuses both. That refusal is
a feature, and the easiest way to break it would be to make the guard more
permissive so a new corpus slides past. So the new corpus is required to pass
*and* the old ones are required to keep failing, in one file, where loosening
the guard to fix the first breaks the second.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "packages" / "aisoc-benchmark"))

from aisoc_benchmark.replay import (  # noqa: E402
    GRADED_DISPOSITIONS,
    MALICIOUS,
    MIN_MALICIOUS_FOR_HEADLINE,
    score_replay,
)
from score_replay_set import CorpusNotGradeable, assert_gradeable, grade  # noqa: E402

CORPUS = ROOT / "services" / "agents" / "tests" / "eval_data" / "verdict" / "verdict_corpus_v1.json"

#: The plan's bar. No class above this, so a constant answer cannot beat it.
MAX_CLASS_SHARE = 0.60


def _corpus() -> dict[str, Any]:
    return json.loads(CORPUS.read_text(encoding="utf-8"))


def _items() -> list[dict[str, Any]]:
    items = _corpus()["decisions"]
    assert items, "the corpus is empty — this suite would prove nothing"
    return items


def _grade(verdict_for) -> dict[str, Any]:
    return score_replay([{**item, "verdict": verdict_for(item)} for item in _items()]).as_dict()


class TestTheScorerAcceptsIt:
    def test_assert_gradeable_does_not_raise(self) -> None:
        """The plan's acceptance criterion, in one line."""
        assert_gradeable(_items())  # does not raise, which is the assertion

    def test_the_file_is_shaped_so_the_runner_reads_it_directly(self) -> None:
        """`score_replay_set.py --decisions <file>` takes a list, or a dict
        under `decisions`. Shipping the second means the corpus can carry its
        own provenance header without a conversion step nobody would run."""
        doc = _corpus()
        assert isinstance(doc, dict)
        assert isinstance(doc["decisions"], list)

    def test_it_grades_end_to_end_through_the_published_entry_point(self) -> None:
        report = grade(_items(), model="none-no-agent-run", dataset="aisoc-verdict-v1", commit="test", synthetic=True)
        assert report["synthetic"] is True
        assert "Synthetic corpus" in report["provenance"]
        assert report["score"]["labelled"] == len(_items())

    def test_every_row_is_labelled_so_none_is_silently_skipped(self) -> None:
        """`score_replay` grades only rows carrying `labelled`. A corpus of
        72 rows where 70 lack it reports on two and looks like it worked."""
        assert all(item.get("labelled") is True for item in _items())

    def test_every_label_is_in_the_canonical_vocabulary(self) -> None:
        for item in _items():
            assert item["expected_disposition"] in GRADED_DISPOSITIONS, (
                f"{item['id']} is labelled {item['expected_disposition']!r}, which score_replay cannot grade"
            )


class TestNoConstantAnswerScoresWell:
    """The property the whole item exists for."""

    @pytest.mark.parametrize("label", GRADED_DISPOSITIONS)
    def test_answering_one_class_to_everything_stays_under_the_ceiling(self, label: str) -> None:
        score = _grade(lambda item, chosen=label: chosen)
        assert score["headline_accuracy"] <= MAX_CLASS_SHARE, (
            f"answering {label!r} to everything scores {score['headline_accuracy']:.1%}, over the {MAX_CLASS_SHARE:.0%} the plan allows"
        )

    def test_the_best_constant_answer_is_the_malicious_one_at_fifty_percent(self) -> None:
        """Named rather than left as an inequality, so a corpus edit that
        moves it shows up as a changed number instead of a still-true bound."""
        score = _grade(lambda item: MALICIOUS)
        assert score["headline_accuracy"] == pytest.approx(0.500, abs=0.001)
        assert score["malicious_recall"] == 1.0, "it still catches everything, trivially"
        assert score["malicious_precision"] == pytest.approx(0.500, abs=0.001), "and the precision is what exposes it"

    def test_answering_benign_to_everything_scores_badly(self) -> None:
        """A corpus that only punished one failure mode would be half a corpus."""
        score = _grade(lambda item: "benign")
        assert score["headline_accuracy"] == pytest.approx(0.250, abs=0.001)
        assert score["malicious_recall"] == 0.0

    def test_a_perfect_agent_scores_perfectly(self) -> None:
        """The negative control for every assertion above: without it, a
        corpus nobody can score would satisfy them all."""
        score = _grade(lambda item: item["expected_disposition"])
        assert score["headline_accuracy"] == 1.0
        assert score["malicious_recall"] == 1.0
        assert score["malicious_precision"] == 1.0

    def test_the_corpus_is_thick_enough_for_a_headline(self) -> None:
        """Below 30 malicious cases the report withholds headline accuracy,
        and a corpus that can never print one is a corpus nobody will use."""
        score = _grade(lambda item: item["expected_disposition"])
        assert score["malicious_support"] >= MIN_MALICIOUS_FOR_HEADLINE
        assert score["headline_withheld_reason"] is None
        assert score["headline_accuracy"] is not None


class TestTheOldCorporaAreStillRefused:
    """Accepting a new corpus must not have loosened the guard."""

    @pytest.mark.parametrize("name", ["synthetic_incidents", "adversary_incidents"])
    def test_the_all_malicious_corpora_still_cannot_be_graded(self, name: str) -> None:
        path = ROOT / "services" / "agents" / "tests" / "eval_data" / f"{name}.json"
        raw = json.loads(path.read_text(encoding="utf-8"))
        items = raw if isinstance(raw, list) else next((v for v in raw.values() if isinstance(v, list)), [])
        decisions = [{"expected_disposition": i.get("expected_disposition"), "verdict": MALICIOUS} for i in items if isinstance(i, dict)]
        with pytest.raises(CorpusNotGradeable):
            assert_gradeable(decisions)


class TestTheBenignHalfIsWhatARealQueueHolds:
    def test_each_non_malicious_item_has_a_malicious_twin(self) -> None:
        """The plan's wording: a benign item has a malicious twin that
        differs in the decisive evidence."""
        by_id = {item["id"]: item for item in _items()}
        for item in _items():
            if item["expected_disposition"] == MALICIOUS:
                continue
            twin = by_id[item["twin_of"]]
            assert twin["expected_disposition"] == MALICIOUS
            assert twin["twin_of"] == item["id"]
            assert twin["evidence"] != item["evidence"]

    def test_a_twin_pair_cannot_be_separated_without_reading_the_evidence(self) -> None:
        """Same rule, same vendor, same severity, same title. Everything the
        detection decided is held constant so only the facts can separate them."""
        by_id = {item["id"]: item for item in _items()}
        for item in _items():
            twin = by_id[item["twin_of"]]
            for field in ("rule_id", "vendor", "family", "severity", "title"):
                assert item[field] == twin[field], f"{item['id']} differs from its twin in {field}"

    def test_severity_alone_separates_nothing(self) -> None:
        """A corpus whose attacks are critical and whose noise is low is
        separable on one integer, and measures nothing about judgement."""
        malicious = Counter(i["severity"] for i in _items() if i["expected_disposition"] == MALICIOUS)
        other = Counter(i["severity"] for i in _items() if i["expected_disposition"] != MALICIOUS)
        assert malicious == other
        assert len(malicious) >= 3
        assert "critical" in malicious

    def test_the_benign_shapes_real_queues_are_full_of_are_present(self) -> None:
        present = {i.get("benign_archetype") for i in _items() if i["expected_disposition"] != MALICIOUS}
        for archetype in (
            "admin_bulk_change",
            "scanner_or_security_tooling",
            "ci_service_account",
            "travel_sign_in",
            "break_glass_with_ticket",
            "backup_job",
        ):
            assert archetype in present


class TestWhereTheItemsComeFrom:
    def test_at_least_half_are_cloud_identity_or_saas(self) -> None:
        items = _items()
        in_scope = [i for i in items if i["family"] in ("cloud", "identity", "saas")]
        assert len(in_scope) / len(items) >= 0.50

    def test_all_ten_named_sources_appear(self) -> None:
        vendors = {i["vendor"] for i in _items()}
        for vendor in (
            "aws_cloudtrail",
            "gcp_audit",
            "azure_activity",
            "entra_id",
            "okta",
            "google_workspace",
            "m365",
            "github",
            "slack",
            "kubernetes_audit",
        ):
            assert vendor in vendors


class TestItSaysWhatItIs:
    def test_every_item_is_marked_synthetic_and_the_header_agrees(self) -> None:
        """Version 1 is entirely hand-authored. The binding rule is not that
        it must be sourced, it is that it must never imply it was."""
        doc = _corpus()
        items = doc["decisions"]
        assert all(item["is_synthetic"] is True for item in items)
        assert doc["synthetic_items"] == len(items)
        assert doc["sourced_items"] == 0
        assert doc["sourced_datasets"] == []

    def test_every_item_carries_provenance_with_a_licence(self) -> None:
        for item in _items():
            provenance = item["provenance"]
            assert provenance["source"] == "hand-authored"
            assert provenance["license"]
            assert provenance["license_url"]

    def test_the_answer_is_declared_as_held_out_from_the_model(self) -> None:
        """`decisive_evidence` states the verdict. A harness that passed it
        to the agent would measure reading comprehension of the answer key."""
        held_out = _corpus()["held_out_from_the_model"]
        assert "decisive_evidence" in held_out
        assert "expected_disposition" in held_out

    def test_no_routable_address_ships_in_the_corpus(self) -> None:
        """RFC 5737 documentation ranges only. A corpus carrying a real
        address eventually gets somebody scanned."""
        import re

        text = CORPUS.read_text(encoding="utf-8")
        for octets in re.findall(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.\d{1,3}\b", text):
            a, b, c = (int(x) for x in octets)
            documentation = (
                (a, b, c) in {(192, 0, 2), (198, 51, 100), (203, 0, 113)}
                or a in (0, 10, 127)
                or (a == 192 and b == 168)
                or (a == 172 and 16 <= b <= 31)
                or a >= 224
                or (a, b) == (169, 254)
                or (a, b) == (198, 18)
            )
            assert documentation, f"{a}.{b}.{c}.x is outside the documentation and private ranges"
