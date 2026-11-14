"""Synthetic attack simulation catalogue for the BAS-style validation agent.

Each :class:`Simulation` represents a tiny, fully-deterministic scenario:
one or more OCSF-shaped events that, when replayed through the live
:class:`~app.detections.engine.DetectionEngine`, should fire at least one
of ``expected_rule_ids``. The agent runs the catalogue on a schedule and
compares the live outcome against the most recent green baseline; any
simulation that was previously OK but no longer fires is flagged as
**detection drift** and opens a proactive case.

The catalogue is intentionally hand-written rather than parameter-driven
so that:

* Each scenario is auditable — a SOC engineer can read the events and
  understand exactly what is being attested.
* Adding a new rule to the rule-pack only counts as "covered" once the
  author adds the matching simulation here; you can't ship blind
  coverage.
* MITRE technique mapping is explicit per-simulation, so the
  coverage-by-technique report (used for the heatmap in t2k) is grounded
  in tested behaviour, not just rule metadata.

These events match the field-paths the in-tree Sigma rules look at
(``event.action``, ``event.outcome``, ``process.command_line`` etc.) —
see ``app/detections/rules/`` for the rule definitions.
"""
from __future__ import annotations

from app.agents.detection_validation.models import Simulation

# Each event is an OCSF-shaped dict. We use nested keys (``event.action``,
# ``enrich.spray.unique_users``) because the in-process Sigma engine
# walks dotted paths — see ``app/detections/sigma.py:_extract_field``.

_PASSWORD_SPRAY = Simulation(
    sim_id="sim-id-password-spray",
    name="Password Spray (20+ users from one source)",
    description=(
        "A single source IP attempts logins against many user accounts. "
        "Expected to trigger the password-spray rule once the spray "
        "enrichment counter crosses the threshold."
    ),
    events=(
        {
            "event": {"action": "login", "outcome": "failure"},
            "src": {"ip": "203.0.113.42"},
            "enrich": {"spray": {"unique_users": 27}},
        },
    ),
    expected_rule_ids=("aisoc-id-id-0022-password-spray",),
    expected_techniques=("T1110.003",),
)

_IMPOSSIBLE_TRAVEL = Simulation(
    sim_id="sim-id-impossible-travel",
    name="Impossible Travel Between Successful Logins",
    description=(
        "Two successful logins for the same user from cities far enough "
        "apart that the implied geo-velocity exceeds 900 km/h."
    ),
    events=(
        {
            "event": {"action": "login", "outcome": "success"},
            "user": {"name": "alice@corp.example"},
            "enrich": {"geo_velocity": {"kmh": 1450.0}},
        },
    ),
    expected_rule_ids=("aisoc-id-id-0021-impossible-travel",),
    expected_techniques=("T1078",),
)

_POWERSHELL_ENCODED = Simulation(
    sim_id="sim-ep-powershell-encoded",
    name="PowerShell EncodedCommand Execution",
    description=(
        "powershell.exe launched with -enc and a base64 payload, the "
        "canonical defence-evasion + execution combination."
    ),
    events=(
        {
            "process": {
                "name": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "command_line": (
                    "powershell.exe -nop -w hidden -enc "
                    "JABjAGwAaQBlAG4AdAA9AE4AZQB3AC0ATwBiAGoAZQBjAHQA"
                ),
            },
            "user": {"name": "WORKGROUP\\alice"},
            "host": {"name": "WIN-FINANCE-01"},
        },
    ),
    expected_rule_ids=("aisoc-id-ep-0026-ps-encoded",),
    expected_techniques=("T1059.001",),
)

_LSASS_ACCESS = Simulation(
    sim_id="sim-ep-lsass-access",
    name="LSASS Memory Access from Unsigned Process",
    description=(
        "An unsigned process opens a PROCESS_VM_READ-capable handle on "
        "lsass.exe — the textbook Mimikatz / ProcDump signal."
    ),
    events=(
        {
            "target": {
                "process": {"executable": "C:\\Windows\\System32\\lsass.exe"}
            },
            "process": {
                "access_mask": "0x1410",
                "name": "procdump64.exe",
            },
            "source": {
                "process": {"signature": {"signer": "Sysinternals"}}
            },
            "host": {"name": "WIN-FINANCE-01"},
        },
    ),
    expected_rule_ids=("aisoc-id-ep-0004-lsass-access",),
    expected_techniques=("T1003.001",),
)

_AWS_IAM_USER_CREATE = Simulation(
    sim_id="sim-cl-aws-iam-user-create",
    name="AWS IAM User Created with Console Login",
    description=(
        "CreateUser followed by CreateLoginProfile in CloudTrail — "
        "classic cloud persistence."
    ),
    events=(
        {
            "event": {"module": "aws", "action": "CreateUser"},
            "aws": {"event_source": "iam.amazonaws.com"},
            "user": {"name": "ci-bootstrap"},
        },
        {
            "event": {"module": "aws", "action": "CreateLoginProfile"},
            "aws": {"event_source": "iam.amazonaws.com"},
            "user": {"name": "ci-bootstrap"},
        },
    ),
    expected_rule_ids=("aisoc-id-cl-0004-iam-user-create",),
    expected_techniques=("T1136.003",),
)

_AWS_CONSOLE_NO_MFA = Simulation(
    sim_id="sim-cl-aws-console-no-mfa",
    name="AWS Console Login Without MFA",
    description=(
        "Successful ConsoleLogin with MFAUsed=No — initial access / "
        "policy-violation signal."
    ),
    events=(
        {
            "event": {"module": "aws", "action": "ConsoleLogin"},
            "aws": {
                "event_source": "signin.amazonaws.com",
                "additional_event_data": {"MFAUsed": "No"},
                "response_elements": {"ConsoleLogin": "Success"},
            },
            "user": {"name": "arn:aws:iam::111122223333:user/contractor"},
        },
    ),
    expected_rule_ids=("aisoc-id-cl-0007-console-no-mfa",),
    expected_techniques=("T1078.004",),
)


# Public, ordered catalogue. The agent iterates in declaration order so
# trace timelines are stable run-to-run, which makes screenshot-based
# regression review possible in PRs that touch detection content.
SIMULATIONS: tuple[Simulation, ...] = (
    _PASSWORD_SPRAY,
    _IMPOSSIBLE_TRAVEL,
    _POWERSHELL_ENCODED,
    _LSASS_ACCESS,
    _AWS_IAM_USER_CREATE,
    _AWS_CONSOLE_NO_MFA,
)


def get_simulations() -> tuple[Simulation, ...]:
    """Return the active simulation catalogue.

    Wrapped in a function so tests (and future tenant-scoped overrides)
    can monkey-patch this without mutating the module-level tuple.
    """
    return SIMULATIONS


__all__ = ["SIMULATIONS", "get_simulations"]
