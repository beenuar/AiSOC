"""Okta identity rules can see the field they match on (issue #1279).

The report was "identity events are invisible in the core profile": an
Okta ``user.session.start`` FAILURE is accepted and produces no alert.
Half of that is the promoter working as designed — an authentication
event normalised to OCSF category 3 at medium severity is archived and
not promoted, and nobody wants an alert per login.

The other half is a reachability bug one layer below the engine, and it
is the same shape as the Windows ``CommandLine``/``Image`` fix. Okta
carries its result inside an ``outcome`` *object*. ``normalize()`` read
``outcome["result"]`` only to choose a severity and discarded it, and the
engine flattens ``raw_event`` exactly one level — so the matcher saw
``outcome`` as ``{"result": "FAILURE", ...}`` and compared a dict against
the string ``"FAILURE"``.

Seven shipped Okta rules clause on that value. None of them could fire on
any deployment, which is why a stock install reads as having no identity
detections rather than unreachable ones.

This test drives the **real** engine field resolution, the **real**
matcher and the **real** shipped rulesets. It cannot also drive the real
connector: ``services/connectors`` and ``services/fusion`` both name
their top-level package ``app``, so importing one inside the other's
interpreter shadows it. The connector half is pinned separately by
``services/connectors/tests/test_okta_outcome_reaches_detection.py``,
which drives ``OktaConnector.normalize()`` itself and asserts exactly the
payload below — so a connector change that drops the field again reds
that test rather than silently passing this one.
"""

from __future__ import annotations

import json
from typing import Any

from app.services.detection_engine import DetectionEngine, _load_ruleset
from app.services.detection_matcher import matches
from app.services.windowed_detection import load_window_rules

#: A real Okta System Log row, trimmed. Shape taken from the vendor's
#: documented payload, not from what the rules want.
OKTA_FAILED_LOGIN = {
    "uuid": "f7b1a0de-0000-4000-8000-000000000001",
    "published": "2026-10-10T09:15:00.000Z",
    "eventType": "user.session.start",
    "displayMessage": "User login to Okta",
    "outcome": {"result": "FAILURE", "reason": "INVALID_CREDENTIALS"},
    "actor": {"displayName": "Alice Example", "alternateId": "alice@example.com"},
    "client": {"ipAddress": "203.0.113.42"},
}

OKTA_SUCCESSFUL_LOGIN = {
    **OKTA_FAILED_LOGIN,
    "outcome": {"result": "SUCCESS", "reason": "OK"},
}


def _normalised(raw: dict[str, Any]) -> dict[str, Any]:
    """What ``OktaConnector.normalize()`` emits for ``raw``.

    A transcription, not a reimplementation — the connector's own test
    asserts this exact mapping against the real class. The alternative was
    to invent an event in the shape the engine wants, which is how a
    reachability bug stays invisible: the fixture would pass while the
    product does not.
    """
    outcome = raw.get("outcome", {})
    result = outcome.get("result", "SUCCESS")
    actor = raw.get("actor", {})
    return {
        "source": "okta",
        "external_id": raw.get("uuid", ""),
        "title": raw.get("displayMessage", "Okta Event"),
        "description": f"{raw.get('eventType')} - {outcome.get('reason', result)}",
        "severity": "medium" if result in ("FAILURE", "DENY") else "info",
        "src_ip": raw.get("client", {}).get("ipAddress"),
        "actor": actor.get("displayName"),
        "actor_email": actor.get("alternateId"),
        "event_type": raw.get("eventType"),
        "outcome": result,
        "outcome_reason": outcome.get("reason"),
        "raw_event": raw,
        "created_at": raw.get("published"),
    }


def _match_namespace(raw: dict[str, Any]) -> dict[str, Any]:
    """What the engine really gives the matcher for that event."""
    return DetectionEngine._raw_fields({"raw_data": json.dumps(_normalised(raw))})


def _window_rule(rule_id: str) -> Any:
    for rule in load_window_rules():
        if rule.id == rule_id:
            return rule
    raise AssertionError(f"{rule_id} is not in the shipped windowed ruleset")


def _stateless_rule(rule_id: str) -> dict[str, Any]:
    for rule in _load_ruleset():
        if rule["id"] == rule_id:
            return rule
    raise AssertionError(f"{rule_id} is not in the shipped ruleset")


class TestTheFieldReachesTheMatcher:
    def test_outcome_is_a_comparable_value_not_the_vendor_object(self) -> None:
        """The defect in one assertion. `_check` does `event.get(field)` and
        compares — a dict never equals a string."""
        resolved = _match_namespace(OKTA_FAILED_LOGIN)["outcome"]
        assert resolved == "FAILURE"
        assert not isinstance(resolved, dict)

    def test_the_reason_survives_too(self) -> None:
        assert _match_namespace(OKTA_FAILED_LOGIN)["outcome_reason"] == "INVALID_CREDENTIALS"

    def test_the_vendor_object_is_still_preserved_verbatim(self) -> None:
        """Hoisting a scalar must not cost the original payload — the raw
        event is what an analyst reads and what a future rule may need."""
        assert _normalised(OKTA_FAILED_LOGIN)["raw_event"]["outcome"] == {
            "result": "FAILURE",
            "reason": "INVALID_CREDENTIALS",
        }

    def test_the_grouping_keys_the_windowed_rules_need_are_populated(self) -> None:
        """A rule that matches but cannot group is still inert."""
        ns = _match_namespace(OKTA_FAILED_LOGIN)
        assert ns["actor_email"] == "alice@example.com"
        assert ns["src_ip"] == "203.0.113.42"


class TestTheShippedRulesNowFire:
    """Every one of these is a rule the product ships and that could not
    fire on any deployment."""

    def test_the_brute_force_rule_matches_a_failed_login(self) -> None:
        rule = _window_rule("wd-brute-force-login")
        assert matches(rule.match_when, _match_namespace(OKTA_FAILED_LOGIN))

    def test_the_password_spray_rule_matches_a_failed_login(self) -> None:
        rule = _window_rule("wd-okta-password-spray")
        assert matches(rule.match_when, _match_namespace(OKTA_FAILED_LOGIN))

    def test_a_successful_login_does_not_match_the_failure_rules(self) -> None:
        """The negative control that matters most. Hoisting a constant
        string would satisfy every assertion above and alert on every
        sign-in — which is exactly the behaviour the promoter policy exists
        to avoid."""
        namespace = _match_namespace(OKTA_SUCCESSFUL_LOGIN)
        assert namespace["outcome"] == "SUCCESS"
        for rule_id in ("wd-brute-force-login", "wd-okta-password-spray"):
            assert not matches(_window_rule(rule_id).match_when, namespace)

    def test_the_success_gated_identity_rules_can_now_see_their_clause(self) -> None:
        """Four native rules clause on `outcome: SUCCESS` and were equally
        unreachable. They carry further clauses this one event does not
        satisfy, so the assertion is on the clause that was broken."""
        namespace = _match_namespace(OKTA_SUCCESSFUL_LOGIN)
        for rule_id in ("det-identity-002", "det-identity-005", "det-identity-006", "det-identity-015"):
            clause = _stateless_rule(rule_id)["match_when"]
            assert clause.get("outcome") == "SUCCESS"
            assert matches({"outcome": clause["outcome"]}, namespace), rule_id


class TestTheEngineIsUnchanged:
    def test_only_the_intended_field_is_newly_displaced(self) -> None:
        """`_raw_fields` lets connector keys win over nested ones, so a new
        top-level key shadows its nested namesake in the match namespace.
        Two keys are shadowed here and only one of them is new: `actor` was
        already a display-name string over Okta's actor *object*, which
        this change does not touch."""
        normalised = _normalised(OKTA_FAILED_LOGIN)
        nested = normalised["raw_event"]
        shadowed = {k for k in normalised if k in nested and normalised[k] != nested[k]}
        assert shadowed == {"actor", "outcome"}

        pre_existing = {k: v for k, v in normalised.items() if k not in ("outcome", "outcome_reason")}
        assert {k for k in pre_existing if k in nested and pre_existing[k] != nested[k]} == {"actor"}
