"""The corpus can tell a good agent from a bad one.

Gap-closure wave 2.

Before this, every labelled corpus in the repository was malicious by
construction, and the benchmark corpus only appeared not to be:
`build_corpus._disposition` derived a "benign" class from
``response_class == "monitor"``, and those eight incidents are
BloodHound domain enumeration tagged T1087.002. A real attack with a
monitoring response is not a benign event.

The consequence is the thing this file pins. **An agent that answers
"true positive" to everything, without reading anything, used to score
1.000.** It now scores 0.727, and the gap between that and 1.000 is the
only reason any accuracy figure from this corpus means something.

Vocabulary was broken too, separately and silently: the corpus used
``malicious | suspicious | benign`` while `replay` grades
``true_positive | benign_true_positive | false_positive | benign``.
One label of four in common, so the corpus was ungradeable by this
package's own scorer and nothing anywhere noticed.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from collections.abc import Callable
from typing import Any

import pytest
from aisoc_benchmark.replay import GRADED_DISPOSITIONS, MALICIOUS, score_replay

CORPUS = Path(__file__).resolve().parents[1] / "corpus" / "soc-agent-benchmark-v1.json"


def _incidents() -> list[dict[str, Any]]:
    raw = json.loads(CORPUS.read_text(encoding="utf-8"))
    items = raw if isinstance(raw, list) else next((v for v in raw.values() if isinstance(v, list)), [])
    assert items, "the corpus is empty — this suite would prove nothing"
    return items


def _grade(verdict_for: Callable[[dict[str, Any]], str]) -> dict[str, Any]:
    decisions = [
        {
            "expected_disposition": i["expected_disposition"],
            "verdict": verdict_for(i),
            "labelled": True,
            "evidence": {},
            "findings": [],
        }
        for i in _incidents()
    ]
    return score_replay(decisions).as_dict()


class TestTheCorpusHasMoreThanOneAnswer:
    def test_it_carries_a_real_benign_class(self) -> None:
        labels = {i["expected_disposition"] for i in _incidents()}
        assert "benign" in labels
        assert "false_positive" in labels

    def test_benign_and_false_positive_are_distinguished(self) -> None:
        """They need different actions: a stream of `benign` means tuning
        an allowlist, a stream of `false_positive` means fixing a rule.
        A single "not malicious" label loses that."""
        counts = dict.fromkeys(GRADED_DISPOSITIONS, 0)
        for i in _incidents():
            counts[i["expected_disposition"]] = counts.get(i["expected_disposition"], 0) + 1
        assert counts["benign"] > 0
        assert counts["false_positive"] > 0

    def test_every_label_is_in_the_canonical_vocabulary(self) -> None:
        """The corpus used `malicious | suspicious | benign`, which shares
        exactly one label with what `replay` grades."""
        for incident in _incidents():
            assert incident["expected_disposition"] in GRADED_DISPOSITIONS, (
                f"{incident['id']} is labelled {incident['expected_disposition']!r}, which score_replay cannot grade"
            )

    def test_the_minority_class_clears_the_gradeability_floor(self) -> None:
        """`score_replay_set.assert_gradeable` refuses a corpus whose
        smallest class is under 5%, because that reports the base rate
        rather than the agent."""
        incidents = _incidents()
        counts: dict[str, int] = {}
        for i in incidents:
            counts[i["expected_disposition"]] = counts.get(i["expected_disposition"], 0) + 1
        assert min(counts.values()) / len(incidents) >= 0.05


class TestItSeparatesAgents:
    """Four reference agents, four distinct scores. If any two collapsed
    onto the same number the corpus would not be measuring judgement."""

    def test_answering_malicious_to_everything_no_longer_scores_perfectly(self) -> None:
        """The headline result of this wave. This was 1.000."""
        score = _grade(lambda i: MALICIOUS)
        assert score["headline_accuracy"] == pytest.approx(0.727, abs=0.01)
        assert score["malicious_recall"] == 1.0, "it still catches everything, trivially"
        assert score["malicious_precision"] == pytest.approx(0.727, abs=0.01), "and the precision is what exposes it"

    def test_answering_benign_to_everything_scores_badly(self) -> None:
        """The other direction. A corpus that only punished one failure
        mode would be half a corpus."""
        score = _grade(lambda i: "benign")
        assert score["headline_accuracy"] == pytest.approx(0.182, abs=0.01)
        assert score["malicious_recall"] == 0.0

    def test_a_perfect_agent_scores_perfectly(self) -> None:
        """The negative control for every assertion above: without it,
        a corpus nobody can score would satisfy them all."""
        score = _grade(lambda i: i["expected_disposition"])
        assert score["headline_accuracy"] == 1.0
        assert score["malicious_recall"] == 1.0
        assert score["malicious_precision"] == 1.0

    def test_guessing_lands_between_the_two(self) -> None:
        score = _grade(lambda i: MALICIOUS if hash(i["id"]) % 2 else "benign")
        assert 0.3 < score["headline_accuracy"] < 0.9

    def test_per_class_recall_is_reported_for_the_benign_classes(self) -> None:
        """Not just the headline. An agent can hold accuracy up on the
        majority class while never once identifying a false positive,
        and the per-class figures are where that shows."""
        score = _grade(lambda i: MALICIOUS)
        by_label = {c["label"]: c for c in score["per_class"]}
        assert by_label["false_positive"]["recall"] == 0.0
        assert by_label["benign"]["recall"] == 0.0


class TestTheBenignCasesAreRealistic:
    """A benign corpus of obviously boring events measures formatting,
    not judgement. Each of these must plausibly fire a detection."""

    def test_benign_cases_carry_attack_techniques(self) -> None:
        """They look like attacks — that is the point. A benign case
        tagged with no technique is one no rule would have raised."""
        benign = [i for i in _incidents() if i["expected_disposition"] in ("benign", "false_positive") and i["id"].startswith("INC-")]
        with_techniques = [i for i in benign if i.get("expected_techniques")]
        assert len(with_techniques) / len(benign) > 0.9

    def test_benign_cases_span_severities(self) -> None:
        """Including critical. A benign class that is uniformly low
        severity is separable on severity alone."""
        severities = {i["severity"] for i in _incidents() if i["expected_disposition"] in ("benign", "false_positive")}
        assert "critical" in severities
        assert len(severities) >= 2

    def test_no_routable_address_ships_in_the_corpus(self) -> None:
        """RFC 5737 documentation ranges only. A corpus carrying a real
        address eventually gets somebody scanned."""
        text = CORPUS.read_text(encoding="utf-8")
        for octets in re.findall(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.\d{1,3}\b", text):
            a, b, c = (int(x) for x in octets)
            documentation = (
                (a, b, c) in {(192, 0, 2), (198, 51, 100), (203, 0, 113)}
                or a == 10
                or (a == 192 and b == 168)
                or (a == 172 and 16 <= b <= 31)
                or a == 127
                or a >= 224
                or (a, b) == (169, 254)
                or (a, b) == (198, 18)
            )
            assert documentation, f"{a}.{b}.{c}.x is outside the documentation and private ranges"
