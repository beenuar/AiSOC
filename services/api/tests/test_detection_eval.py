"""Phase 4 — the anti-circularity gate for detection-rule promotion.

The Phase 0 reality audit's #1 circular gate: the detection-proposal promote
path shelled out to the eval harness **without ever passing the proposed rule
body**, so a rule that matches nothing (blind) or matches everything (noisy)
passed its own exam. `app.services.detection_eval.evaluate_candidate_rule`
closes that hole by running the *candidate rule body itself* through the real
runtime engine (`app.services.rule_engine.execute_rule`) against its fixtures.

This suite is the mutation test that proves the gate is no longer circular: a
deliberately-broken rule is REJECTED, and a correct rule is accepted. It uses
the real engine, so the verdict genuinely depends on the rule body.
"""

from __future__ import annotations

from app.services.detection_eval import evaluate_candidate_rule

# A correct Sigma rule: fires on a root console login, silent on an IAM-user
# login. Evaluated by the runtime engine's Sigma path (pySigma if present, else
# the substring fallback — the assertions hold for both).
GOOD_RULE = """
title: AWS Root Console Login
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    event_name: ConsoleLogin
    user_type: Root
  condition: selection
"""

POSITIVE = {"event_name": "ConsoleLogin", "user_type": "Root", "src_ip": "203.0.113.7"}
NEGATIVE = {"event_name": "ConsoleLogin", "user_type": "IAMUser", "src_ip": "203.0.113.7"}


def test_good_rule_passes_its_own_fixtures():
    result = evaluate_candidate_rule(
        rule_language="sigma",
        rule_body=GOOD_RULE,
        positive_fixtures=[POSITIVE],
        negative_fixtures=[NEGATIVE],
    )
    assert result.passed, result.reason
    assert result.positives_fired == 1
    assert result.negatives_fired == 0


def test_blind_rule_is_rejected():
    """A rule that never fires on its positive fixture must fail — the core
    circular-gate refutation: a blind rule no longer 'passes'."""
    blind = """
title: Never Matches Anything
logsource:
  product: aws
detection:
  selection:
    event_name: EventThatNeverOccursZZZ
  condition: selection
"""
    result = evaluate_candidate_rule(
        rule_language="sigma",
        rule_body=blind,
        positive_fixtures=[POSITIVE],
        negative_fixtures=[NEGATIVE],
    )
    assert not result.passed
    assert result.positives_fired == 0
    assert "blind" in result.reason


def test_noisy_rule_is_rejected():
    """A rule that also fires on its negative (benign) fixture must fail."""
    noisy = """
title: Fires On Any Console Login
logsource:
  product: aws
detection:
  selection:
    event_name: ConsoleLogin
  condition: selection
"""
    result = evaluate_candidate_rule(
        rule_language="sigma",
        rule_body=noisy,
        positive_fixtures=[POSITIVE],
        negative_fixtures=[NEGATIVE],
    )
    assert not result.passed
    assert result.negatives_fired == 1
    assert "noisy" in result.reason


def test_no_positive_fixtures_is_rejected_not_vacuous():
    """A rule with no positive fixture has proven nothing — it must not pass."""
    result = evaluate_candidate_rule(
        rule_language="sigma",
        rule_body=GOOD_RULE,
        positive_fixtures=[],
        negative_fixtures=[NEGATIVE],
    )
    assert not result.passed
    assert result.positives_total == 0
    assert "no positive" in result.reason.lower()


def test_verdict_is_json_serialisable_with_per_fixture_detail():
    result = evaluate_candidate_rule(
        rule_language="sigma",
        rule_body=GOOD_RULE,
        positive_fixtures=[POSITIVE],
        negative_fixtures=[NEGATIVE],
    )
    d = result.to_dict()
    assert d["passed"] is True
    assert len(d["outcomes"]) == 2
    kinds = {o["kind"] for o in d["outcomes"]}
    assert kinds == {"positive", "negative"}
    assert all(o["ok"] for o in d["outcomes"])


def test_the_gate_verdict_depends_on_the_rule_body():
    """The property the circular gate lacked: two different rule bodies against
    the *same* fixtures yield different verdicts. If the verdict were
    independent of the rule (the old bug), these would be identical."""
    good = evaluate_candidate_rule(
        rule_language="sigma",
        rule_body=GOOD_RULE,
        positive_fixtures=[POSITIVE],
        negative_fixtures=[NEGATIVE],
    )
    bad = evaluate_candidate_rule(
        rule_language="sigma",
        rule_body="title: X\ndetection:\n  selection:\n    event_name: NopeZZZ\n  condition: selection\n",
        positive_fixtures=[POSITIVE],
        negative_fixtures=[NEGATIVE],
    )
    assert good.passed and not bad.passed
