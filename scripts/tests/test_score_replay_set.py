"""A labelled set is graded, or refused for a reason that is stated.

Parity 3.2. The guard is the point of the module: every labelled corpus
in this repository is entirely malicious by construction, so an agent
that answers "true positive" to everything without reading anything
would post 100% accuracy and 100% malicious recall.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from score_replay_set import (  # noqa: E402
    MIN_MINORITY_SHARE,
    CorpusNotGradeable,
    assert_gradeable,
    grade,
)


def _decision(expected: str, verdict: str | None = None, **extra):
    base = {
        "expected_disposition": expected,
        "verdict": verdict if verdict is not None else expected,
        "evidence": {"src_ip": "198.51.100.4"},
        "findings": ["saw 198.51.100.4"],
    }
    base.update(extra)
    return base


def _balanced(n: int = 40):
    """Half malicious, half not — enough to grade."""
    return [_decision("true_positive") for _ in range(n // 2)] + [_decision("false_positive") for _ in range(n // 2)]


class TestItRefusesACorpusThatWouldFlatter:
    def test_an_all_malicious_corpus_is_refused(self) -> None:
        """The shape every labelled set in this tree actually has."""
        with pytest.raises(CorpusNotGradeable, match="answers 'true_positive' to everything"):
            assert_gradeable([_decision("true_positive") for _ in range(200)])

    def test_an_all_benign_corpus_is_refused_too(self) -> None:
        """The same failure from the other side. A guard that only
        caught one direction would be half a guard."""
        with pytest.raises(CorpusNotGradeable, match="to everything"):
            assert_gradeable([_decision("false_positive") for _ in range(200)])

    def test_a_corpus_with_no_labels_is_refused(self) -> None:
        """A set without analyst labels can measure whether the agent
        answered, not whether it was right."""
        with pytest.raises(CorpusNotGradeable, match="expected_disposition"):
            assert_gradeable([{"verdict": "true_positive"} for _ in range(50)])

    def test_an_empty_set_is_refused(self) -> None:
        with pytest.raises(CorpusNotGradeable, match="nothing to grade"):
            assert_gradeable([])

    def test_a_corpus_below_the_minority_floor_is_refused(self) -> None:
        """One benign case in two hundred reports the base rate, not the
        agent."""
        decisions = [_decision("true_positive") for _ in range(199)] + [_decision("false_positive")]
        with pytest.raises(CorpusNotGradeable, match="below the"):
            assert_gradeable(decisions)

    def test_the_refusal_names_the_counts(self) -> None:
        """So whoever hits it can see how far off the corpus is rather
        than guessing."""
        decisions = [_decision("true_positive") for _ in range(199)] + [_decision("false_positive")]
        with pytest.raises(CorpusNotGradeable) as caught:
            assert_gradeable(decisions)
        assert "1 of 200" in str(caught.value)


class TestItGradesACorpusThatCan:
    def test_a_balanced_corpus_is_accepted(self) -> None:
        """The negative control for every refusal above: without it they
        would all pass against a guard that refuses everything."""
        assert_gradeable(_balanced())  # does not raise, which is the assertion

    def test_an_imbalanced_but_gradeable_corpus_is_accepted(self) -> None:
        """Real queues are imbalanced. Refusing those would make the tool
        useless on exactly the data it is for."""
        decisions = [_decision("true_positive") for _ in range(10)] + [_decision("false_positive") for _ in range(90)]
        assert_gradeable(decisions)  # does not raise, which is the assertion

    def test_exactly_at_the_floor_is_accepted(self) -> None:
        minority = int(100 * MIN_MINORITY_SHARE)
        decisions = [_decision("true_positive") for _ in range(100 - minority)] + [_decision("false_positive") for _ in range(minority)]
        assert_gradeable(decisions)  # does not raise, which is the assertion


class TestTheReport:
    def test_it_carries_the_model_dataset_and_commit(self) -> None:
        """The spec's publication clause: a number without its model and
        dataset describes nothing."""
        report = grade(_balanced(), model="llama3.2:3b", dataset="demo", commit="abc1234", synthetic=True)
        assert report["model"] == "llama3.2:3b"
        assert report["dataset"] == "demo"
        assert report["commit"] == "abc1234"

    def test_a_synthetic_corpus_says_so_prominently(self) -> None:
        report = grade(_balanced(), model="m", dataset="d", commit="c", synthetic=True)
        assert report["synthetic"] is True
        assert "Synthetic corpus" in report["provenance"]

    def test_a_real_corpus_says_that_instead(self) -> None:
        report = grade(_balanced(), model="m", dataset="d", commit="c", synthetic=False)
        assert report["synthetic"] is False
        assert "closed by analysts" in report["provenance"]

    def test_it_scores_through_the_benchmark_package(self) -> None:
        """Not a second scorer. A different definition of accuracy would
        drift from the scoreboard's while looking like the same number."""
        report = grade(_balanced(), model="m", dataset="d", commit="c", synthetic=True)
        assert "decisions" in report["score"]
        assert report["report_markdown"].startswith("#")

    def test_it_is_json_serialisable(self) -> None:
        """It gets written to a file and read by the docs build."""
        json.dumps(grade(_balanced(), model="m", dataset="d", commit="c", synthetic=True))


class TestTheCorporaThisTreeActuallyHas:
    @pytest.mark.parametrize("name", ["synthetic_incidents", "adversary_incidents"])
    def test_they_are_refused_and_that_is_the_finding(self, name: str) -> None:
        """Not a bug in the corpora — they were built to exercise MITRE
        mapping and response selection, not verdict accuracy. The point
        is that nothing may publish an accuracy number from them.
        """
        path = ROOT / "services" / "agents" / "tests" / "eval_data" / f"{name}.json"
        raw = json.loads(path.read_text(encoding="utf-8"))
        items = raw if isinstance(raw, list) else next((v for v in raw.values() if isinstance(v, list)), [])

        decisions = [
            {"expected_disposition": i.get("expected_disposition"), "verdict": "true_positive"} for i in items if isinstance(i, dict)
        ]
        with pytest.raises(CorpusNotGradeable):
            assert_gradeable(decisions)
