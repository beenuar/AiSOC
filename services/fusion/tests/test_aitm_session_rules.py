"""The AiTM family fires on a replayed session and not on an ordinary one.

The engine half of depth 7.3. Its sibling,
``services/connectors/tests/connectors/test_aitm_session_fields_reach_detection.py``,
drives the real ``OktaConnector.normalize()`` and
``AzureEntraConnector.normalize()`` over the same vendor payloads and asserts
exactly the dictionaries transcribed below. The two cannot be one file:
``services/connectors`` and ``services/fusion`` both name their top-level
package ``app``, so importing one inside the other's interpreter shadows it.

What this drives
----------------
The **real** ``WindowedDetectionEngine``, the **real** matcher, and the
**shipped** ruleset loaded off disk — not a hand-made rule list. A test that
declares its own copy of the rule proves the engine works and says nothing
about what the product ships.

Why the fixtures are hand-authored
-----------------------------------
Around 600 of the corpus's fixtures are synthesised from the rule they test,
which makes replay tautological: the fixture matches because the clause was
copied into it, and an unreachable field is invisible. These started as an
Okta System Log row and a Microsoft Graph ``signIn`` resource, and the rules
were written against what those carry.

The negative fixture inverts the clause each rule is **about** — the distinct
network, the distinct client family, the distinct country — and nothing else.
Same session, same user, same event type, same outcome. A rule that had
secretly keyed on any of those would still fire on it, which is the point of
holding them constant.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from app.services.windowed_detection import (
    WindowedDetectionEngine,
    load_sequence_rules,
    load_window_rules,
)

from tests.redis_doubles import FakeRedis

#: Transcribed from what the connector emits. A transcription rather than a
#: reimplementation: the connector's own test asserts this exact mapping
#: against the real class, so a connector change that drops a field reds that
#: test rather than silently passing this one.
_SESSION = "102AbCdEfGhIjKlMnOpQrSt"
_VICTIM = "alice@example.com"

MFA_SIGNIN = {
    "source": "okta",
    "external_id": "aa000000-0000-4000-8000-000000000001",
    "title": "User login to Okta",
    "event_type": "user.session.start",
    "outcome": "SUCCESS",
    "actor_email": _VICTIM,
    "src_ip": "203.0.113.42",
    "session_id": _SESSION,
    "src_asn": 64500,
    "src_asn_org": "example telecom",
    "src_country": "United States",
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/141.0",
    "client_browser": "CHROME",
    "client_os": "Windows 10",
    "is_proxy": False,
    "mfa_satisfied": True,
}

REPLAYED_FROM_HOSTING = {
    **MFA_SIGNIN,
    "external_id": "aa000000-0000-4000-8000-000000000002",
    "title": "User accessing Okta admin app",
    "event_type": "user.session.access_admin_app",
    "src_ip": "198.51.100.77",
    "src_asn": 64512,
    "src_asn_org": "example hosting",
    "src_country": "Netherlands",
    "user_agent": "python-requests/2.32.0",
    "client_browser": "UNKNOWN",
    "client_os": "Unknown",
    "is_proxy": True,
    "mfa_satisfied": None,
}

#: The negative twin: the same session used again from the same network, in
#: the same browser, in the same country. This is what an ordinary second
#: request inside a session looks like, and it is the only thing that
#: separates this family from "a session was used twice".
SAME_SESSION_SAME_NETWORK = {
    **REPLAYED_FROM_HOSTING,
    "external_id": "aa000000-0000-4000-8000-000000000003",
    "src_ip": "203.0.113.51",
    "src_asn": MFA_SIGNIN["src_asn"],
    "src_asn_org": MFA_SIGNIN["src_asn_org"],
    "src_country": MFA_SIGNIN["src_country"],
    "user_agent": MFA_SIGNIN["user_agent"],
    "client_browser": MFA_SIGNIN["client_browser"],
    "client_os": MFA_SIGNIN["client_os"],
    "is_proxy": False,
}

#: A different session entirely, from the hosting provider. Proves the
#: grouping is by session and not by user: this shares the actor with the
#: positive and must not complete its sequence.
OTHER_SESSION_SAME_USER = {**REPLAYED_FROM_HOSTING, "external_id": "aa000000-0000-4000-8000-000000000004", "session_id": "999OtherSession"}

AITM_RULE_IDS = (
    "wd-aitm-session-replayed-from-new-asn",
    "wd-aitm-session-replayed-from-new-client",
    "wd-aitm-session-left-the-country-it-started-in",
    "wd-aitm-mfa-then-session-from-new-asn",
)


def _shipped_engine() -> WindowedDetectionEngine:
    """The engine, loaded with what the product ships."""
    return WindowedDetectionEngine(FakeRedis(), rules=load_window_rules(), sequences=load_sequence_rules())


def _message(tenant: str, event: dict[str, Any], when: float) -> dict[str, Any]:
    return {
        "tenant_id": tenant,
        "ocsf_event": {"tenant_uid": tenant, "raw_data": json.dumps({**event, "event_time": when})},
    }


async def _fired(engine: WindowedDetectionEngine, tenant: str, events: list[tuple[dict[str, Any], float]]) -> set[str]:
    hits: set[str] = set()
    for event, when in events:
        for hit in await engine.evaluate(_message(tenant, event, when)):
            hits.add(hit.rule_id)
    return hits


class TestTheFamilyIsActuallyShipped:
    """A rule the engine does not load is a rule that detects nothing."""

    @pytest.mark.parametrize("rule_id", AITM_RULE_IDS)
    def test_each_rule_is_in_the_artefact_the_engine_loads(self, rule_id: str) -> None:
        loaded = {r.id for r in load_window_rules()} | {r.id for r in load_sequence_rules()}
        assert rule_id in loaded

    def test_the_committed_json_is_what_the_exporter_produces(self) -> None:
        """Otherwise the deployed engine and the committed corpus can diverge."""
        path = Path(__file__).resolve().parents[2] / "fusion" / "app" / "data" / "windowed_ruleset.json"
        if not path.is_file():  # pragma: no cover - layout guard
            path = Path(__file__).resolve().parents[1] / "app" / "data" / "windowed_ruleset.json"
        shipped = {str(r.get("id")) for r in json.loads(path.read_text(encoding="utf-8")).get("rules") or []}
        assert set(AITM_RULE_IDS) <= shipped

    @pytest.mark.parametrize("rule_id", AITM_RULE_IDS[:3])
    def test_the_threshold_rules_group_by_the_session(self, rule_id: str) -> None:
        rule = next(r for r in load_window_rules() if r.id == rule_id)
        assert rule.group_by == "session_id"
        assert rule.distinct_by, "a threshold over events would fire on an ordinary busy session"
        assert rule.threshold == 2, "two *different* values is the whole signal; three only catches a careless attacker"


class TestTheReplayFires:
    @pytest.mark.asyncio
    async def test_a_session_used_from_two_networks_fires(self) -> None:
        hits = await _fired(_shipped_engine(), str(uuid4()), [(MFA_SIGNIN, 1000.0), (REPLAYED_FROM_HOSTING, 1300.0)])
        assert "wd-aitm-session-replayed-from-new-asn" in hits

    @pytest.mark.asyncio
    async def test_a_session_used_from_two_client_families_fires(self) -> None:
        hits = await _fired(_shipped_engine(), str(uuid4()), [(MFA_SIGNIN, 1000.0), (REPLAYED_FROM_HOSTING, 1300.0)])
        assert "wd-aitm-session-replayed-from-new-client" in hits

    @pytest.mark.asyncio
    async def test_a_session_used_from_two_countries_fires(self) -> None:
        hits = await _fired(_shipped_engine(), str(uuid4()), [(MFA_SIGNIN, 1000.0), (REPLAYED_FROM_HOSTING, 1300.0)])
        assert "wd-aitm-session-left-the-country-it-started-in" in hits

    @pytest.mark.asyncio
    async def test_the_mfa_then_replay_sequence_fires(self) -> None:
        """The ordering is the detection, and a threshold cannot express it."""
        hits = await _fired(_shipped_engine(), str(uuid4()), [(MFA_SIGNIN, 1000.0), (REPLAYED_FROM_HOSTING, 1300.0)])
        assert "wd-aitm-mfa-then-session-from-new-asn" in hits


class TestTheNegativeTwinDoesNotFire:
    """Each assertion inverts the clause its rule is about, and nothing else."""

    @pytest.mark.asyncio
    async def test_the_same_session_on_the_same_network_fires_nothing(self) -> None:
        hits = await _fired(_shipped_engine(), str(uuid4()), [(MFA_SIGNIN, 1000.0), (SAME_SESSION_SAME_NETWORK, 1300.0)])
        assert hits & set(AITM_RULE_IDS[:3]) == set()

    @pytest.mark.asyncio
    async def test_one_event_alone_fires_nothing(self) -> None:
        """A single sign-in is not a replay, however unusual the network."""
        hits = await _fired(_shipped_engine(), str(uuid4()), [(REPLAYED_FROM_HOSTING, 1000.0)])
        assert hits & set(AITM_RULE_IDS) == set()

    @pytest.mark.asyncio
    async def test_two_sessions_for_one_user_are_not_one_session(self) -> None:
        """Proves the grouping is the session, not the actor they share."""
        hits = await _fired(_shipped_engine(), str(uuid4()), [(MFA_SIGNIN, 1000.0), (OTHER_SESSION_SAME_USER, 1300.0)])
        assert hits & set(AITM_RULE_IDS) == set()

    @pytest.mark.asyncio
    async def test_an_event_with_no_session_id_is_not_grouped_at_all(self) -> None:
        """``session_id_neq: None`` is the clause; without it every event would group under None."""
        no_session = {k: v for k, v in REPLAYED_FROM_HOSTING.items() if k != "session_id"}
        other = {k: v for k, v in MFA_SIGNIN.items() if k != "session_id"}
        hits = await _fired(_shipped_engine(), str(uuid4()), [(other, 1000.0), (no_session, 1300.0)])
        assert hits & set(AITM_RULE_IDS) == set()

    @pytest.mark.asyncio
    async def test_the_sequence_does_not_fire_without_the_mfa_stage(self) -> None:
        """Otherwise the sequence is its final stage with extra machinery."""
        unchallenged = {**MFA_SIGNIN, "mfa_satisfied": False}
        hits = await _fired(_shipped_engine(), str(uuid4()), [(unchallenged, 1000.0), (REPLAYED_FROM_HOSTING, 1300.0)])
        assert "wd-aitm-mfa-then-session-from-new-asn" not in hits

    @pytest.mark.asyncio
    async def test_the_sequence_does_not_fire_in_the_wrong_order(self) -> None:
        """A session used elsewhere and *then* challenged is a re-auth, not a theft."""
        hits = await _fired(_shipped_engine(), str(uuid4()), [(REPLAYED_FROM_HOSTING, 1000.0), (MFA_SIGNIN, 1300.0)])
        assert "wd-aitm-mfa-then-session-from-new-asn" not in hits

    @pytest.mark.asyncio
    async def test_a_replay_outside_the_sequence_window_does_not_fire(self) -> None:
        """Half an hour is the sequence's stated budget, measured on event time.

        Only the **sequence** rule is asserted here, and the reason is a
        property of the engine worth stating rather than working around. The
        threshold rules window by *arrival*: ``_evaluate_thresholds`` scores
        each member with ``time.time()``, while ``_evaluate_sequences`` reads
        ``parse_event_time``. So feeding two events whose ``event_time``
        fields are two hours apart does not move the threshold window at all
        — both land at "now" — and an earlier version of this test asserted
        otherwise and failed, which is how the difference was found.

        That is not a defect to patch here. Arrival-time windowing is what
        makes a threshold cheap, and a connector polling every five minutes
        delivers a burst whose arrival order is the only clock fusion has.
        It does mean the one-hour figure on the threshold rules is a budget
        on *ingestion*, not on the vendor's timestamps, and the rules say an
        hour because that is how long a session cookie stays worth replaying.
        """
        engine = _shipped_engine()
        tenant = str(uuid4())
        hits = await _fired(engine, tenant, [(MFA_SIGNIN, 1000.0), (REPLAYED_FROM_HOSTING, 1000.0 + 7200)])
        assert "wd-aitm-mfa-then-session-from-new-asn" not in hits


class TestTenantsDoNotShareASession:
    @pytest.mark.asyncio
    async def test_one_tenants_sign_in_cannot_complete_anothers_replay(self) -> None:
        engine = _shipped_engine()
        first, second = str(uuid4()), str(uuid4())
        assert not await engine.evaluate(_message(first, MFA_SIGNIN, 1000.0))
        hits = {h.rule_id for h in await engine.evaluate(_message(second, REPLAYED_FROM_HOSTING, 1300.0))}
        assert hits & set(AITM_RULE_IDS) == set()
