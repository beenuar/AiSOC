"""The session, network and client fields an AiTM rule needs survive normalize().

The connector half of depth 7.3. Its sibling,
``services/fusion/tests/test_aitm_session_rules.py``, drives the real
windowed engine over the payload this file asserts the connector produces.
They are separate files because ``services/connectors`` and
``services/fusion`` both name their top-level package ``app``, so importing
one inside the other's interpreter shadows it — the arrangement
``test_okta_outcome_reaches_detection.py`` already uses for the same reason.

The reproduction
----------------
Before this change ``OktaConnector.normalize()`` returned ``None`` for
``session_id``, ``src_asn``, ``user_agent``, ``client_browser`` and
``mfa_satisfied`` on a System Log row carrying all five. The engine flattens
``raw_event`` exactly one level, so ``authenticationContext`` and
``securityContext`` arrive as dicts and a rule clausing on a session id
compares a string against ``{...}``.

The payloads below are **hand-authored from the vendors' documented event
shapes**, not generated from the rules they exercise. Around 600 of the
corpus's fixtures are synthesised from the rule under test, which makes
replay tautological: the fixture contains the clause because the clause was
copied into it. These were written as an Okta System Log row and a Microsoft
Graph ``signIn`` resource first, and the rules were written against what
those carry.
"""

from __future__ import annotations

import pytest
from app.connectors.azure_entra import AzureEntraConnector
from app.connectors.okta import OktaConnector

# ── Okta System Log, hand-authored ───────────────────────────────────────────
#
# One AiTM story in three events, all sharing `externalSessionId`:
#   1. the victim signs in through the proxy and satisfies MFA, from their
#      own ISP in a browser;
#   2. the attacker replays the stolen cookie from a hosting provider;
#   3. the attacker, having the session, reads the directory.

_SESSION = "102AbCdEfGhIjKlMnOpQrSt"
_VICTIM = "alice@example.com"

OKTA_MFA_SIGNIN = {
    "uuid": "aa000000-0000-4000-8000-000000000001",
    "published": "2026-10-11T09:15:00.000Z",
    "eventType": "user.session.start",
    "displayMessage": "User login to Okta",
    "severity": "INFO",
    "outcome": {"result": "SUCCESS", "reason": "OK"},
    "actor": {"id": "00u1", "type": "User", "displayName": "Alice Example", "alternateId": _VICTIM},
    "client": {
        "ipAddress": "203.0.113.42",
        "userAgent": {"rawUserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/141.0", "os": "Windows 10", "browser": "CHROME"},
        "geographicalContext": {"country": "United States", "city": "Boston"},
        "device": "Computer",
    },
    "authenticationContext": {"authenticationStep": 0, "externalSessionId": _SESSION},
    "securityContext": {"asNumber": 64500, "asOrg": "example telecom", "isp": "example telecom", "domain": "example.net", "isProxy": False},
    "debugContext": {"debugData": {"factor": "OKTA_VERIFY_PUSH", "authnRequestId": "req-1"}},
}

OKTA_REPLAYED_FROM_HOSTING = {
    "uuid": "aa000000-0000-4000-8000-000000000002",
    "published": "2026-10-11T09:21:00.000Z",
    "eventType": "user.session.access_admin_app",
    "displayMessage": "User accessing Okta admin app",
    "severity": "INFO",
    "outcome": {"result": "SUCCESS", "reason": "OK"},
    "actor": {"id": "00u1", "type": "User", "displayName": "Alice Example", "alternateId": _VICTIM},
    "client": {
        "ipAddress": "198.51.100.77",
        "userAgent": {"rawUserAgent": "python-requests/2.32.0", "os": "Unknown", "browser": "UNKNOWN"},
        "geographicalContext": {"country": "Netherlands", "city": "Amsterdam"},
        "device": "Unknown",
    },
    "authenticationContext": {"authenticationStep": 0, "externalSessionId": _SESSION},
    "securityContext": {"asNumber": 64512, "asOrg": "example hosting", "isp": "example hosting", "domain": "", "isProxy": True},
}

#: The negative twin. Same session, same user, **same network and same client
#: family** — which is what an ordinary second request inside a session looks
#: like. It inverts the clause each rule is about (the distinct network, the
#: distinct client, the distinct country) and nothing else: the event type,
#: the outcome, the actor and the session are deliberately identical to the
#: positive, so a rule that fired on any of those would still fire here.
OKTA_SAME_SESSION_SAME_NETWORK = {
    **OKTA_REPLAYED_FROM_HOSTING,
    "uuid": "aa000000-0000-4000-8000-000000000003",
    "published": "2026-10-11T09:22:00.000Z",
    "client": {
        "ipAddress": "203.0.113.51",
        "userAgent": {"rawUserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/141.0", "os": "Windows 10", "browser": "CHROME"},
        "geographicalContext": {"country": "United States", "city": "Boston"},
        "device": "Computer",
    },
    "securityContext": {"asNumber": 64500, "asOrg": "example telecom", "isp": "example telecom", "domain": "example.net", "isProxy": False},
}

# ── Microsoft Graph signIn, hand-authored ────────────────────────────────────

ENTRA_MFA_SIGNIN = {
    "_aisoc_event_kind": "riskySignIn",
    "id": "bb000000-0000-4000-8000-000000000001",
    "createdDateTime": "2026-10-11T09:15:00Z",
    "userPrincipalName": _VICTIM,
    "userDisplayName": "Alice Example",
    "sessionId": "9f2c4d7a-0000-4000-8000-00000000aaaa",
    "correlationId": "11111111-0000-4000-8000-000000000001",
    "ipAddress": "203.0.113.42",
    "autonomousSystemNumber": 64500,
    "clientAppUsed": "Browser",
    "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/141.0",
    "authenticationRequirement": "multiFactorAuthentication",
    "incomingTokenType": "none",
    "riskLevelAggregated": "medium",
    "riskState": "atRisk",
    "riskEventTypes_v2": ["unfamiliarFeatures"],
    "deviceDetail": {"deviceId": "", "operatingSystem": "Windows 10", "browser": "Chrome 141.0", "isCompliant": False, "isManaged": False},
    "location": {"city": "Boston", "state": "Massachusetts", "countryOrRegion": "US"},
    "status": {"errorCode": 0, "failureReason": "Other."},
}

ENTRA_REPLAYED = {
    **ENTRA_MFA_SIGNIN,
    "id": "bb000000-0000-4000-8000-000000000002",
    "createdDateTime": "2026-10-11T09:21:00Z",
    "correlationId": "11111111-0000-4000-8000-000000000002",
    "ipAddress": "198.51.100.77",
    "autonomousSystemNumber": 64512,
    "clientAppUsed": "Mobile Apps and Desktop clients",
    "userAgent": "python-requests/2.32.0",
    "authenticationRequirement": "singleFactorAuthentication",
    "incomingTokenType": "primaryRefreshToken",
    "deviceDetail": {"deviceId": "", "operatingSystem": "Unknown", "browser": "Unknown", "isCompliant": False, "isManaged": False},
    "location": {"city": "Amsterdam", "state": "", "countryOrRegion": "NL"},
}


def _okta(raw: dict) -> dict:
    return OktaConnector(domain="example.okta.com", api_token="unit-test-placeholder").normalize(raw)


def _entra(raw: dict) -> dict:
    return AzureEntraConnector(tenant_id="t", client_id="c", client_secret="unit-test-placeholder").normalize(raw)


class TestOktaEmitsWhatTheRulesGroupBy:
    def test_the_session_identity_survives_normalisation(self) -> None:
        """The reproduction: this returned ``None`` before depth 7.3."""
        assert _okta(OKTA_MFA_SIGNIN)["session_id"] == _SESSION

    def test_the_network_is_an_asn_not_only_an_address(self) -> None:
        """A residential ISP rotates addresses within one ASN all day."""
        event = _okta(OKTA_MFA_SIGNIN)
        assert event["src_asn"] == 64500
        assert event["src_asn_org"] == "example telecom"
        assert event["src_ip"] == "203.0.113.42"

    def test_the_client_family_is_emitted_separately_from_the_raw_string(self) -> None:
        """A Chrome auto-update changes the string and not the family."""
        event = _okta(OKTA_MFA_SIGNIN)
        assert event["client_browser"] == "CHROME"
        assert event["user_agent"].startswith("Mozilla/5.0")

    def test_a_replay_differs_from_the_sign_in_on_every_clause_the_family_reads(self) -> None:
        first, second = _okta(OKTA_MFA_SIGNIN), _okta(OKTA_REPLAYED_FROM_HOSTING)
        assert first["session_id"] == second["session_id"]
        assert first["src_asn"] != second["src_asn"]
        assert first["client_browser"] != second["client_browser"]
        assert first["src_country"] != second["src_country"]

    def test_the_negative_twin_shares_the_session_and_the_network(self) -> None:
        """A negative fixture must invert the clause the rule is *about*."""
        first, benign = _okta(OKTA_MFA_SIGNIN), _okta(OKTA_SAME_SESSION_SAME_NETWORK)
        assert first["session_id"] == benign["session_id"]
        assert first["src_asn"] == benign["src_asn"]
        assert first["client_browser"] == benign["client_browser"]
        assert first["src_country"] == benign["src_country"]


class TestMfaSatisfiedIsThreeValued:
    def test_a_session_start_with_a_recorded_factor_is_satisfied(self) -> None:
        assert _okta(OKTA_MFA_SIGNIN)["mfa_satisfied"] is True

    def test_a_session_start_with_no_factor_is_not_satisfied(self) -> None:
        no_factor = {**OKTA_MFA_SIGNIN, "debugContext": {"debugData": {"authnRequestId": "req-2"}}}
        assert _okta(no_factor)["mfa_satisfied"] is False

    def test_an_event_that_says_nothing_about_mfa_answers_none(self) -> None:
        """Treating silence as False would fire on every directory read."""
        assert _okta(OKTA_REPLAYED_FROM_HOSTING)["mfa_satisfied"] is None

    def test_a_denied_push_is_an_mfa_event_and_not_a_satisfied_one(self) -> None:
        """Folding this in would make the field true for the MFA-fatigue sequence."""
        denied = {**OKTA_MFA_SIGNIN, "eventType": "user.mfa.okta_verify.deny_push"}
        assert _okta(denied)["mfa_satisfied"] is False


class TestEntraEmitsTheSameVocabulary:
    def test_the_graph_session_id_is_read_and_the_correlation_id_is_not_a_fallback(self) -> None:
        """One identifies a request, the other a session. Substituting is a silent defect."""
        event = _entra(ENTRA_MFA_SIGNIN)
        assert event["session_id"] == ENTRA_MFA_SIGNIN["sessionId"]
        assert event["correlation_id"] == ENTRA_MFA_SIGNIN["correlationId"]

        without = {k: v for k, v in ENTRA_MFA_SIGNIN.items() if k != "sessionId"}
        degraded = _entra(without)
        assert degraded["session_id"] is None, "a correlation id standing in as a session id would make every sign-in its own session"
        assert degraded["correlation_id"] == ENTRA_MFA_SIGNIN["correlationId"]

    def test_graph_states_the_authentication_requirement_so_nothing_is_inferred(self) -> None:
        assert _entra(ENTRA_MFA_SIGNIN)["mfa_satisfied"] is True
        assert _entra(ENTRA_REPLAYED)["mfa_satisfied"] is False

    def test_an_absent_requirement_is_none_rather_than_single_factor(self) -> None:
        """An older API version must not make every sign-in look unchallenged."""
        without = {k: v for k, v in ENTRA_MFA_SIGNIN.items() if k != "authenticationRequirement"}
        assert _entra(without)["mfa_satisfied"] is None

    def test_the_replay_differs_on_network_and_client(self) -> None:
        first, second = _entra(ENTRA_MFA_SIGNIN), _entra(ENTRA_REPLAYED)
        assert first["session_id"] == second["session_id"]
        assert first["src_asn"] != second["src_asn"]
        assert first["client_browser"] != second["client_browser"]
        assert first["src_country"] != second["src_country"]

    @pytest.mark.parametrize("field", ["session_id", "src_asn", "client_browser", "src_country", "mfa_satisfied"])
    def test_both_vendors_use_one_field_name_per_concept(self, field: str) -> None:
        """Otherwise the rule needs a vendor clause, which is the thing normalisation is for."""
        assert field in _okta(OKTA_MFA_SIGNIN)
        assert field in _entra(ENTRA_MFA_SIGNIN)
