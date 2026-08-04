"""Okta MFA fatigue / push-bombing detection (Python)."""

ID = "py-okta-mfa-fatigue"
TITLE = "Okta MFA fatigue (push bombing)"
SEVERITY = "high"
MITRE = ["T1621"]
DESCRIPTION = "An unusually high number of MFA push challenges to a single user in a short window — a hallmark of push-bombing to wear the user down into approving."

_THRESHOLD = 5


def rule(event: dict) -> bool:
    return (
        event.get("eventType") == "user.mfa.attempt"
        and str(event.get("outcome", "")).lower() in {"challenge", "sent"}
        and int(event.get("attempts", 0)) >= _THRESHOLD
    )


def title(event: dict) -> str:
    user = event.get("actor", {}).get("alternateId") or event.get("user") or "unknown user"
    return f"MFA fatigue: {event.get('attempts', '?')} push challenges to {user}"


def dedup(event: dict) -> str:
    return f"mfa-fatigue:{event.get('actor', {}).get('alternateId') or event.get('user')}"


TESTS = [
    {
        "name": "fires on 6 push challenges",
        "event": {"eventType": "user.mfa.attempt", "outcome": "challenge", "attempts": 6, "user": "ceo@corp.com"},
        "expect": True,
    },
    {
        "name": "quiet on a single legitimate challenge",
        "event": {"eventType": "user.mfa.attempt", "outcome": "challenge", "attempts": 1, "user": "ceo@corp.com"},
        "expect": False,
    },
    {
        "name": "quiet on an unrelated event type",
        "event": {"eventType": "user.session.start", "attempts": 9},
        "expect": False,
    },
]
