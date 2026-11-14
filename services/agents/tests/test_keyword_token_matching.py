"""Keyword matching must read tokens, not substrings (issue #1607).

Reported by Rudy Mizrahi Celekli.

``_score_alert`` and ``_has_critical_keyword`` tested their critical
keywords as substrings of ``alert_summary + str(raw_alert)``. One of those
keywords is ``c2``, which occurs in every AWS private hostname
(``ip-10-0-1-7.ec2.internal``), in EC2 instance ids, and in hashes and
base64 blobs. An alert with nothing critical about it was therefore scored
``("critical", 0.9)``, proposed ``isolate_host`` against the hostname, and
took a +0.35 confidence boost.

The expensive consequence is the one that leaves no trace. The model cascade
uses the deterministic scorer as tier 1 and escalates only when its
confidence falls below ``DEFAULT_CONFIDENCE_FLOOR`` (0.85). A spurious 0.9
clears the floor, so the alert is answered by the heuristic and **never
reaches the ML or LLM tier at all**. A wrong severity is visible on the
queue; an alert that silently skips analysis is not. So the routing
assertions below are the point of this file, not the severity ones.

Every test here fails on the pre-fix tree, which was verified by reverting
``app/keywords.py``'s boundary rule to ``kw in text`` and watching them go
red — the negative control is recorded in the pull request rather than
being left as a claim.
"""

from __future__ import annotations

import asyncio
import sys
import unittest
from pathlib import Path
from uuid import uuid4

_AGENTS_ROOT = Path(__file__).parent.parent
if str(_AGENTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_AGENTS_ROOT))

from app.agents.triage_agent import _score_alert, run_triage  # noqa: E402
from app.confidence.scoring import _has_critical_keyword  # noqa: E402
from app.investigator.strategies import select_strategy  # noqa: E402
from app.investigator.tools import map_to_mitre  # noqa: E402
from app.keywords import (  # noqa: E402
    CRITICAL_KEYWORDS,
    HIGH_KEYWORDS,
    alert_text,
    display,
    matches,
    normalise,
)
from app.models.state import InvestigationState  # noqa: E402
from app.routing.model_router import (  # noqa: E402
    DEFAULT_CONFIDENCE_FLOOR,
    ModelTier,
    RoutingRequest,
    TierResult,
    build_router,
)

#: The hostname from ``services/connectors/tests/fixtures/sysdig/sample_event.json``.
EC2_HOST = "ip-10-0-1-7.ec2.internal"

#: Identifiers that contain the characters ``c2`` and mean nothing by it.
INCIDENTAL = (
    EC2_HOST,
    "i-0ab2c2d3e4f5a6b7",
    "00:1a:c2:3b:4c:5d",
    "c2a4e6b8-1234-4567-89ab-cdef01234567",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "c2VjcmV0LXRva2VuLXZhbHVl",
    "DESKTOP-C2A4B6",
    "aks-syspool-c2f4a1b6-vmss000003",
)

#: Ways a real command-and-control reference is written.
GENUINE = (
    "Outbound C2 traffic to 203.0.113.9",
    "c2-server contacted",
    "falco.c2_connection fired",
    "beaconing to c2",
    "suspected c2.",
    "channel (c2) established",
)


def _unremarkable_alert(host: str = EC2_HOST) -> InvestigationState:
    """An alert with nothing critical about it, on a host named like a cloud instance.

    A file read flagged by a runtime sensor: no risk score, no MITRE
    technique, no IOC, and no word in it that any vocabulary claims.
    """

    return InvestigationState(
        incident_id=uuid4(),
        tenant_id=uuid4(),
        alert_summary=f"Sysdig: Read sensitive file untrusted on {host}",
        raw_alert={"rule_id": "sysdig.read_sensitive_file", "hostname": host},
    )


class TestIdentifiersAreNotEvidence(unittest.TestCase):
    """A keyword inside an identifier is a coincidence, not a finding."""

    def test_unremarkable_cloud_host_alert_is_not_critical(self) -> None:
        severity, risk = _score_alert(_unremarkable_alert())
        self.assertNotEqual(severity, "critical", f"an ordinary file-read alert on {EC2_HOST} was scored critical")
        self.assertLess(risk, 0.9)

    def test_no_keyword_fires_on_an_incidental_identifier(self) -> None:
        for identifier in INCIDENTAL:
            text = normalise(f"routine activity involving {identifier}")
            for keyword in CRITICAL_KEYWORDS | HIGH_KEYWORDS:
                self.assertFalse(
                    matches(text, keyword),
                    f"{display(keyword)!r} matched inside {identifier!r}",
                )

    def test_confidence_scorer_gives_no_critical_bonus(self) -> None:
        self.assertFalse(_has_critical_keyword(_unremarkable_alert()))

    def test_no_isolate_host_is_proposed(self) -> None:
        state = asyncio.run(run_triage(_unremarkable_alert()))
        proposed = [a.action_type for a in state.proposed_actions]
        self.assertNotIn(
            "isolate_host",
            proposed,
            f"containment proposed against {EC2_HOST} on the strength of its name",
        )

    def test_strategy_selection_is_not_hijacked(self) -> None:
        """The chosen strategy sets the investigation's guidance and its recorded id."""

        chosen = select_strategy(summary=f"Sysdig: Read sensitive file untrusted on {EC2_HOST}")
        self.assertNotEqual(chosen.id, "c2-beaconing")

        guardduty = select_strategy(summary="GuardDuty: UnauthorizedAccess:EC2/SSHBruteForce on i-0abc")
        self.assertNotEqual(guardduty.id, "c2-beaconing")

    def test_no_technique_is_attributed_to_a_hostname(self) -> None:
        self.assertEqual(map_to_mitre(f"process activity on {EC2_HOST}"), [])


class TestEscalationIsNotShortCircuited(unittest.TestCase):
    """The real harm: tier 1 answering confidently means no tier 2 or 3.

    These assert the *routing outcome*, because a wrong severity is visible
    and a skipped analysis is not.
    """

    @staticmethod
    def _route(state: InvestigationState):  # noqa: ANN205 - RoutingDecision
        reached: list[str] = []

        def llm(request: RoutingRequest) -> TierResult:
            reached.append("llm")
            return TierResult(output={"verdict": "analysed"}, confidence=0.95, model="test-llm")

        router = build_router(llm_fn=llm)
        decision = asyncio.run(router.route(RoutingRequest(payload={"alert_summary": state.alert_summary, "raw_alert": state.raw_alert})))
        return decision, reached

    def test_unremarkable_cloud_host_alert_escalates_past_tier_one(self) -> None:
        decision, reached = self._route(_unremarkable_alert())
        self.assertEqual(
            decision.tier,
            ModelTier.LLM,
            "the alert was resolved on the deterministic tier; a spurious 0.9 clears the "
            f"{DEFAULT_CONFIDENCE_FLOOR} escalation floor and the alert is never analysed",
        )
        self.assertIn("llm", reached, "the LLM tier was never called")

    def test_a_genuine_critical_still_resolves_on_tier_one(self) -> None:
        """The positive control for the routing change: real criticals must not start paying for an LLM call."""

        state = InvestigationState(
            incident_id=uuid4(),
            tenant_id=uuid4(),
            alert_summary="Cobalt Strike beacon observed with outbound C2 traffic",
            raw_alert={"rule_id": "edr.beacon", "hostname": EC2_HOST},
        )
        decision, _ = self._route(state)
        self.assertEqual(decision.tier, ModelTier.DETERMINISTIC)
        self.assertGreaterEqual(decision.confidence, DEFAULT_CONFIDENCE_FLOOR)


class TestGenuineReferencesStillMatch(unittest.TestCase):
    """The positive control. A fix that stopped matching real C2 would be worse."""

    def test_real_c2_references_match(self) -> None:
        for phrase in GENUINE:
            self.assertTrue(matches(normalise(phrase), "c2"), f"{phrase!r} no longer matches")

    def test_real_c2_alert_is_still_critical(self) -> None:
        state = InvestigationState(
            incident_id=uuid4(),
            tenant_id=uuid4(),
            alert_summary="Outbound C2 traffic to a known controller",
            raw_alert={"rule_id": "net.c2", "hostname": "web-01"},
        )
        severity, risk = _score_alert(state)
        self.assertEqual(severity, "critical")
        self.assertGreaterEqual(risk, 0.9)
        self.assertTrue(_has_critical_keyword(state))

    def test_beaconing_strategy_still_selected_for_real_beaconing(self) -> None:
        chosen = select_strategy(summary="Periodic outbound beaconing with jitter to an external controller")
        self.assertEqual(chosen.id, "c2-beaconing")

    def test_stems_reach_their_inflections(self) -> None:
        for text, keyword in (
            ("credential dumping from lsass", "credential dump*"),
            ("C2 beaconing observed overnight", "beacon*"),
            ("exploitation of CVE-2026-0001", "exploit*"),
            ("the account was brute forced", "brute force*"),
        ):
            self.assertTrue(matches(normalise(text), keyword), f"{keyword!r} missed {text!r}")


class TestOneVocabulary(unittest.TestCase):
    """The second defect: the vocabulary was declared twice and had drifted.

    ``triage_agent`` held 13 critical keywords and ``confidence/scoring``
    held 11 — ``beacon`` and ``domain admin`` were in one and not the other,
    so an alert could be scored critical by triage while the confidence
    scorer declined to credit the same evidence.
    """

    def test_both_scorers_agree_on_every_keyword(self) -> None:
        for keyword in CRITICAL_KEYWORDS:
            state = InvestigationState(
                incident_id=uuid4(),
                tenant_id=uuid4(),
                alert_summary=f"Observed {display(keyword)}ing activity" if keyword.endswith("*") else f"Observed {keyword}",
                raw_alert={"rule_id": "t"},
            )
            severity, _ = _score_alert(state)
            self.assertEqual(severity, "critical", f"triage did not treat {display(keyword)!r} as critical")
            self.assertTrue(
                _has_critical_keyword(state),
                f"the confidence scorer did not credit {display(keyword)!r} that triage called critical",
            )

    def test_the_two_sets_are_disjoint(self) -> None:
        self.assertEqual(CRITICAL_KEYWORDS & HIGH_KEYWORDS, frozenset())

    def test_alert_text_reads_the_raw_payload(self) -> None:
        """The haystack includes the payload — which is why the bug reached so far."""

        text = alert_text("nothing here", {"hostname": "web-01", "note": "ransomware"})
        self.assertIn("ransomware", text)


if __name__ == "__main__":
    unittest.main()
