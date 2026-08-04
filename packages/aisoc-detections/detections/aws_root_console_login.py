"""AWS root account console login detection (Python)."""

ID = "py-aws-root-console-login"
TITLE = "AWS root account console login"
SEVERITY = "critical"
MITRE = ["T1078.004"]
DESCRIPTION = "The AWS account root user signed in to the console. Root should be locked away behind hardware MFA and never used for day-to-day work; an interactive root login warrants immediate review."


def rule(event: dict) -> bool:
    if event.get("eventName") != "ConsoleLogin" or event.get("eventSource") != "signin.amazonaws.com":
        return False
    identity = event.get("userIdentity", {})
    return identity.get("type") == "Root"


def title(event: dict) -> str:
    ip = event.get("sourceIPAddress", "unknown IP")
    return f"AWS root console login from {ip}"


TESTS = [
    {
        "name": "fires on root console login",
        "event": {
            "eventName": "ConsoleLogin",
            "eventSource": "signin.amazonaws.com",
            "userIdentity": {"type": "Root"},
            "sourceIPAddress": "203.0.113.9",
        },
        "expect": True,
    },
    {
        "name": "quiet on an IAM user console login",
        "event": {
            "eventName": "ConsoleLogin",
            "eventSource": "signin.amazonaws.com",
            "userIdentity": {"type": "IAMUser"},
        },
        "expect": False,
    },
    {
        "name": "quiet on a non-login API call",
        "event": {"eventName": "DescribeInstances", "eventSource": "ec2.amazonaws.com", "userIdentity": {"type": "Root"}},
        "expect": False,
    },
]
