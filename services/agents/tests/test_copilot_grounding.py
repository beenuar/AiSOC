"""A copilot answer cites what it was given, or says it did not.

Parity 3.6. The spec's clause is "citations to ledger entries for every
factual claim. An answer with no citation is labelled uncited."

Each class below is one way that could go wrong quietly.
"""

from __future__ import annotations

from app.api.copilot_grounding import (
    EvidenceSource,
    ground_answer,
    sources_from_context,
    sources_from_ledger,
)

LEDGER = [
    {
        "run_id": "11111111-1111-1111-1111-111111111111",
        "seq": 1,
        "kind": "tool_call",
        "summary": "lake query for WIN-FIN-02",
        "payload": {"rows": 4, "src_ip": "198.51.100.4"},
    },
    {
        "run_id": "11111111-1111-1111-1111-111111111111",
        "seq": 2,
        "kind": "llm_response",
        "summary": "verdict: true positive",
        "payload": {"technique": "T1059.001"},
    },
]


class TestAClaimCitesItsSource:
    def test_a_grounded_indicator_gets_a_citation(self) -> None:
        answer = "The host contacted 198.51.100.4 before the alert fired."
        result = ground_answer(answer, sources_from_ledger(LEDGER))

        assert result.label == "cited"
        assert result.fully_cited
        claim = next(c for c in result.citations if c.claim == "198.51.100.4")
        assert claim.refs == ("ledger:11111111-1111-1111-1111-111111111111#1",)

    def test_the_reference_is_one_an_analyst_can_open(self) -> None:
        """`ledger:<run>#<seq>` is the coordinate `aisoc_explain_step` and
        the console's replay view both address a step by. A citation
        nobody can paste anywhere is not much of a citation."""
        refs = {s.ref for s in sources_from_ledger(LEDGER)}
        assert refs == {
            "ledger:11111111-1111-1111-1111-111111111111#1",
            "ledger:11111111-1111-1111-1111-111111111111#2",
        }

    def test_an_indicator_only_in_the_payload_still_cites(self) -> None:
        """Summary and payload are both searched. A citation that read
        only the summary would call a supported claim uncited."""
        result = ground_answer("Technique T1059.001 was used.", sources_from_ledger(LEDGER))
        assert result.fully_cited, result


class TestAnUncitedClaimIsLabelled:
    def test_an_invented_indicator_is_uncited(self) -> None:
        """The reason this module exists. The analyst has no other way to
        tell a claim drawn from evidence from one that sounded right."""
        result = ground_answer("The host also contacted 203.0.113.99.", sources_from_ledger(LEDGER))

        assert result.label == "uncited"
        assert not result.fully_cited
        assert result.uncited == ("203.0.113.99",)

    def test_a_half_supported_answer_says_partially(self) -> None:
        """Not 'cited'. An answer where one of two claims is invented is
        the dangerous case, and calling it cited would be the worst
        possible rounding."""
        answer = "198.51.100.4 talked to the DC, then 203.0.113.99 exfiltrated."
        result = ground_answer(answer, sources_from_ledger(LEDGER))

        assert result.label == "partially uncited"
        assert not result.fully_cited
        assert result.uncited == ("203.0.113.99",)
        assert [c.claim for c in result.citations] == ["198.51.100.4"]

    def test_the_uncited_claim_is_named_not_just_counted(self) -> None:
        """So an analyst can check the specific one rather than
        re-reading the whole answer suspiciously."""
        result = ground_answer("Try 203.0.113.99 and CVE-2026-9999.", sources_from_ledger(LEDGER))
        assert set(result.uncited) == {"203.0.113.99", "cve-2026-9999"}

    def test_an_ungrounded_answer_is_returned_not_suppressed(self) -> None:
        """Hiding it would show the analyst a different answer than the
        model gave, edited by something that cannot reliably tell which
        half was wrong."""
        result = ground_answer("203.0.113.99 is the C2.", [])
        assert result.uncited
        assert result.as_dict()["uncited"] == ["203.0.113.99"]


class TestProseIsNotAClaim:
    def test_an_answer_asserting_nothing_concrete_is_its_own_outcome(self) -> None:
        """Three outcomes, not two. "Asserted nothing" and "asserted
        things and supported all of them" deserve different words, or the
        label goes silent on exactly the prose answers where it should
        be."""
        result = ground_answer("This looks like credential access. Check the DC logs.", sources_from_ledger(LEDGER))

        assert result.no_claims
        assert result.label == "no checkable claims"
        assert not result.fully_cited, "an answer with nothing to check is not a cited answer"

    def test_an_empty_answer_claims_nothing(self) -> None:
        assert ground_answer("", sources_from_ledger(LEDGER)).no_claims


class TestTheContextTheConsoleSends:
    def test_an_alert_in_context_is_citable(self) -> None:
        sources = sources_from_context({"alert": {"id": "a-1", "title": "Encoded PowerShell", "host": "WIN-FIN-02"}})
        assert [s.ref for s in sources] == ["alert:a-1"]

    def test_free_text_context_is_not_citable(self) -> None:
        """Pointing a citation at a page title gives the analyst nothing
        to open, so context without an identifier is context for the
        model and nothing more."""
        assert sources_from_context({"page": "Alerts", "query": "powershell"}) == []

    def test_a_malformed_context_does_not_raise(self) -> None:
        """The console sends this; a copilot that 500s on an unexpected
        shape is worse than one that grounds against less."""
        assert sources_from_context(None) == []
        assert sources_from_context({"alert": "not-a-dict"}) == []


class TestItUsesOneDefinitionOfCheckable:
    def test_the_extractor_is_the_groundedness_one(self) -> None:
        """Imported, not re-implemented. A second definition of
        "checkable" would drift from the first, and the two numbers would
        stop being comparable while still looking like they were."""
        from app.api import copilot_grounding
        from app.confidence import groundedness

        assert copilot_grounding._extract is groundedness._extract


class TestASourceCanSupportSeveralClaims:
    def test_two_claims_from_one_source_both_cite_it(self) -> None:
        source = EvidenceSource(ref="alert:a-1", kind="alert", text="198.51.100.4 ran T1059.001")
        result = ground_answer("198.51.100.4 used T1059.001.", [source])

        assert result.fully_cited
        assert {c.claim for c in result.citations} == {"198.51.100.4", "t1059.001"}
        assert all(c.refs == ("alert:a-1",) for c in result.citations)

    def test_a_claim_in_two_sources_cites_both(self) -> None:
        """An analyst checking a claim should see every record that
        supports it, not the first one that happened to match."""
        sources = [
            EvidenceSource(ref="ledger:r#1", kind="ledger", text="198.51.100.4 seen"),
            EvidenceSource(ref="alert:a-1", kind="alert", text="src 198.51.100.4"),
        ]
        citation = ground_answer("198.51.100.4 again.", sources).citations[0]
        assert citation.refs == ("ledger:r#1", "alert:a-1")
