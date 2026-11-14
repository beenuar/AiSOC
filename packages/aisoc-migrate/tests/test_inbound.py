"""Inbound translation from SPL, KQL and EQL, measured on the real corpus.

Gap-closure wave 16. Translators existed in one direction only — AiSOC
rules become SPL, KQL, ESQL and AQL for federated search — so a team
arriving with 400 Splunk searches rewrote all of them by hand, which
is the cost that decides whether a migration happens.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from inbound import GOOD, HIGH, NONE, PARTIAL, translate  # noqa: E402

REPO = Path(__file__).resolve().parents[3]


class TestRefusingIsAFeature:
    """A translator that produces something for every input is worse
    than one that refuses: an almost-right detection sits in the
    catalogue, fires on the wrong thing, and nobody checks it against
    the original."""

    @pytest.mark.parametrize(
        ("query", "dialect"),
        [
            ("index=windows | transaction host maxspan=5m", "spl"),
            ("index=proxy | lookup bad_domains domain", "spl"),
            ("SecurityEvent | join kind=inner Heartbeat on Computer", "kql"),
            ("sequence by host [process where true] [network where true]", "eql"),
        ],
    )
    def test_an_unsupported_construct_yields_no_rule(self, query: str, dialect: str) -> None:
        result = translate(query, dialect)
        assert result.confidence == NONE
        assert not result.usable

    def test_a_refusal_says_what_stopped_it(self) -> None:
        """A reviewer cannot act on 'could not translate'."""
        result = translate("index=windows | transaction host", "spl")
        assert result.unsupported
        assert "transaction" in result.unsupported[0]

    def test_a_field_named_like_a_keyword_is_not_mistaken_for_one(self) -> None:
        """`join_key` is not a `join`. Without word bounds this refuses
        a translatable rule, which is the opposite failure."""
        result = translate('index=win join_key="abc" user="x" host_role="dc"', "spl")
        assert result.confidence != NONE


class TestWhatItCarriesAcross:
    def test_field_comparisons_become_match_clauses(self) -> None:
        result = translate('index=windows EventCode=4625 Account_Name="svc" LogonType=3', "spl")
        assert result.match_when["EventCode"] == 4625
        assert result.match_when["Account_Name"] == "svc"

    def test_operators_are_mapped_not_dropped(self) -> None:
        result = translate("index=win Count>=5 Status!=0 Level<3", "spl")
        assert "Count_gte" in result.match_when
        assert "Status_neq" in result.match_when
        assert "Level_lt" in result.match_when

    def test_splunk_routing_fields_are_dropped_with_a_note(self) -> None:
        """`index` and `sourcetype` address Splunk's own storage and
        are not event fields; carrying them would make every rule
        match on a field no connector emits."""
        result = translate('index=windows sourcetype=WinEventLog EventCode=4625 User="x"', "spl")
        assert "index" not in result.match_when
        assert any("routing field" in n for n in result.notes)

    def test_aggregation_is_flagged_rather_than_silently_lost(self) -> None:
        """The field matches carry; the threshold does not. A rule
        missing its threshold matches far more than the original."""
        result = translate('index=win EventCode=4625 user="x" | stats count by src', "spl")
        assert result.confidence == PARTIAL
        assert any("aggregation" in u for u in result.unsupported)

    def test_more_clauses_means_more_confidence(self) -> None:
        assert translate('process where a == "1" and b == "2" and c == "3"', "eql").confidence == HIGH
        assert translate('process where a == "1" and b == "2"', "eql").confidence == GOOD
        assert translate('process where a == "1"', "eql").confidence == PARTIAL


class TestAgainstTheRealCorpus:
    """2,005 Splunk rules are stored and quarantined in this
    repository and have never been translated. They are the obvious
    first corpus, and measuring on them is the only way to know
    whether this is useful or a demo."""

    @staticmethod
    def _real_spl() -> list[str]:
        queries: list[str] = []
        for path in (REPO / "detections").rglob("*.yaml"):
            if "_quarantine" not in str(path):
                continue
            try:
                doc = yaml.safe_load(path.read_text(encoding="utf-8"))
            except Exception:  # noqa: BLE001 - a malformed fixture is not this suite's subject
                continue
            if not isinstance(doc, dict):
                continue
            spl = (doc.get("detection") or {}).get("splunk_spl")
            if isinstance(spl, str) and spl.strip():
                queries.append(spl)
        return queries

    def test_the_corpus_is_there(self) -> None:
        """Without this the measurement below could pass against an
        empty list."""
        assert len(self._real_spl()) > 1500

    def test_most_of_it_translates_to_something(self) -> None:
        """Measured at 86.5% on 2,005 rules. The floor is well below
        that: this pins that the translator works on real input, not
        the exact figure, which moves as the corpus does."""
        queries = self._real_spl()
        usable = sum(1 for q in queries if translate(q, "spl").usable)
        assert usable / len(queries) > 0.70

    def test_most_of_what_translates_still_needs_review(self) -> None:
        """The honest half of the number. 1,711 of the 1,734 usable
        results are `partial`, because the corpus is overwhelmingly
        aggregation-based — so 'translated' mostly means 'fields
        carried, threshold did not'. Reporting 86.5% without this
        would imply a migration that is almost done."""
        queries = self._real_spl()
        partial = sum(1 for q in queries if translate(q, "spl").confidence == PARTIAL)
        usable = sum(1 for q in queries if translate(q, "spl").usable)
        assert partial / usable > 0.8

    def test_refusals_all_carry_a_reason(self) -> None:
        for query in self._real_spl():
            result = translate(query, "spl")
            if not result.usable:
                assert result.unsupported or result.notes, f"silent refusal: {query[:80]}"
