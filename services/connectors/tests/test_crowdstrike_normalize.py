"""CrowdStrike detections must carry the acting identity through to fusion.

Falcon puts the user on each behavior, not on the detection, and the envelope
omitted it entirely. That is not a cosmetic gap: fusion's correlation key is
``{tenant}:{entity}:{tactic}``, so an EDR detection against a named user
arrived with the entity segment blank and correlated into the same bucket as
every other CrowdStrike alert in the tenant.
"""

from __future__ import annotations

from app.connectors.crowdstrike import CrowdStrikeConnector


def _connector() -> CrowdStrikeConnector:
    return CrowdStrikeConnector(client_id="id", client_secret="secret")


def _detection(**overrides) -> dict:
    detection = {
        "detection_id": "ldt:abc:123",
        "max_severity_displayname": "High",
        "created_timestamp": "2026-09-23T10:00:00Z",
        "device": {"hostname": "WKSTN-01", "external_ip": "203.0.113.7"},
        "behaviors": [
            {
                "display_name": "Suspicious PowerShell",
                "technique_id": "T1059.001",
                "user_name": "alice",
                "user_id": "S-1-5-21-1",
            }
        ],
    }
    detection.update(overrides)
    return detection


class TestActor:
    def test_actor_comes_from_the_behavior(self):
        event = _connector().normalize(_detection())
        assert event["actor"] == "alice"

    def test_first_behavior_with_a_user_wins(self):
        event = _connector().normalize(
            _detection(
                behaviors=[
                    {"display_name": "Stage one", "user_name": ""},
                    {"display_name": "Stage two", "user_name": "bob"},
                ]
            )
        )
        assert event["actor"] == "bob"

    def test_missing_actor_is_none_not_an_empty_string(self):
        # An empty string is a value the normalizer would map onto
        # actor.user.name, producing an alert that claims to name a user and
        # names nobody. None is absent, which is the truth.
        event = _connector().normalize(_detection(behaviors=[{"display_name": "No user"}]))
        assert event["actor"] is None

    def test_no_behaviors_at_all_is_handled(self):
        event = _connector().normalize(_detection(behaviors=[]))
        assert event["actor"] is None
        assert event["title"] == "CrowdStrike Detection"


class TestEnvelope:
    def test_still_emits_the_canonical_envelope(self):
        # `source` + `raw_event` is what makes the normalizer take the
        # canonical path, which is what gives the event OCSF class 2001 and
        # therefore makes it promotable to an alert at all.
        event = _connector().normalize(_detection())
        assert event["source"] == "crowdstrike"
        assert isinstance(event["raw_event"], dict)

    def test_severity_and_host_survive(self):
        event = _connector().normalize(_detection())
        assert event["severity"] == "high"
        assert event["hostname"] == "WKSTN-01"
        assert event["src_ip"] == "203.0.113.7"
        assert event["mitre_techniques"] == ["T1059.001"]
