"""``OktaConnector.normalize()`` emits the result the rules match on.

Issue #1279. Okta carries its result inside an ``outcome`` *object*.
``normalize()`` read ``outcome["result"]`` to choose a severity and then
discarded it, so the value never appeared at the top level — and the
detection engine flattens ``raw_event`` exactly one level, which meant
the matcher saw the dict and compared it to a string.

Seven shipped Okta rules clause on that value. None could fire on any
deployment, which is why a default install reads as having no identity
detections rather than unreachable ones.

This is the connector half of the proof and it drives the real class.
The engine half lives in
``services/fusion/tests/test_okta_identity_rules_are_reachable.py``,
which runs the shipped rules through the real matcher — the two services
both name their top-level package ``app``, so one interpreter cannot
import both. The payload asserted here is the payload that file uses.
"""

from __future__ import annotations

from typing import Any

import pytest
from app.connectors.okta import OktaConnector

OKTA_FAILED_LOGIN = {
    "uuid": "f7b1a0de-0000-4000-8000-000000000001",
    "published": "2026-10-10T09:15:00.000Z",
    "eventType": "user.session.start",
    "displayMessage": "User login to Okta",
    "outcome": {"result": "FAILURE", "reason": "INVALID_CREDENTIALS"},
    "actor": {"displayName": "Alice Example", "alternateId": "alice@example.com"},
    "client": {"ipAddress": "203.0.113.42"},
}


def _normalize(raw: dict[str, Any]) -> dict[str, Any]:
    return OktaConnector(domain="example.okta.com", api_token="t").normalize(raw)


class TestTheResultIsEmittedWhereTheMatcherLooks:
    def test_the_outcome_is_a_top_level_scalar(self) -> None:
        assert _normalize(OKTA_FAILED_LOGIN)["outcome"] == "FAILURE"

    def test_a_successful_login_says_so(self) -> None:
        """Not a constant. Hoisting `"FAILURE"` unconditionally would pass
        the test above and alert on every sign-in."""
        raw = {**OKTA_FAILED_LOGIN, "outcome": {"result": "SUCCESS", "reason": "OK"}}
        assert _normalize(raw)["outcome"] == "SUCCESS"

    def test_the_reason_travels_too(self) -> None:
        assert _normalize(OKTA_FAILED_LOGIN)["outcome_reason"] == "INVALID_CREDENTIALS"

    def test_an_event_with_no_outcome_object_defaults_the_same_way_severity_does(self) -> None:
        """`result` already defaulted to SUCCESS for the severity decision;
        the hoisted value must not disagree with it."""
        raw = {k: v for k, v in OKTA_FAILED_LOGIN.items() if k != "outcome"}
        normalized = _normalize(raw)
        assert normalized["outcome"] == "SUCCESS"
        assert normalized["severity"] == "info"
        assert normalized["outcome_reason"] is None


class TestNothingElseChanged:
    def test_the_vendor_object_is_preserved_verbatim(self) -> None:
        """An analyst reads `raw_event`, and a future rule may need the
        nested form. Hoisting a scalar must not cost the original."""
        assert _normalize(OKTA_FAILED_LOGIN)["raw_event"]["outcome"] == {
            "result": "FAILURE",
            "reason": "INVALID_CREDENTIALS",
        }

    def test_the_envelope_is_still_raw_event_not_raw(self) -> None:
        """`raw` is the known bug class: it misses the ingest normalizer's
        canonical-envelope check and the event falls through to the generic
        profile."""
        normalized = _normalize(OKTA_FAILED_LOGIN)
        assert "raw_event" in normalized
        assert "raw" not in normalized

    def test_severity_is_unchanged_for_both_outcomes(self) -> None:
        assert _normalize(OKTA_FAILED_LOGIN)["severity"] == "medium"
        raw = {**OKTA_FAILED_LOGIN, "outcome": {"result": "SUCCESS"}}
        assert _normalize(raw)["severity"] == "info"

    @pytest.mark.parametrize(
        ("key", "expected"),
        [
            ("source", "okta"),
            ("event_type", "user.session.start"),
            ("actor_email", "alice@example.com"),
            ("src_ip", "203.0.113.42"),
            ("external_id", "f7b1a0de-0000-4000-8000-000000000001"),
        ],
    )
    def test_the_existing_fields_still_carry_what_they_did(self, key: str, expected: str) -> None:
        assert _normalize(OKTA_FAILED_LOGIN)[key] == expected

    def test_the_payload_matches_what_the_fusion_test_replays(self) -> None:
        """The two halves of this proof live in different interpreters, so
        this is the seam. If `normalize()` changes shape, this reds here
        rather than letting the fusion test replay a payload the connector
        no longer produces."""
        assert _normalize(OKTA_FAILED_LOGIN) == {
            "source": "okta",
            "external_id": "f7b1a0de-0000-4000-8000-000000000001",
            "title": "User login to Okta",
            "description": "user.session.start - INVALID_CREDENTIALS",
            "severity": "medium",
            "src_ip": "203.0.113.42",
            "actor": "Alice Example",
            "actor_email": "alice@example.com",
            "event_type": "user.session.start",
            "outcome": "FAILURE",
            "outcome_reason": "INVALID_CREDENTIALS",
            "raw_event": OKTA_FAILED_LOGIN,
            "created_at": "2026-10-10T09:15:00.000Z",
        }
