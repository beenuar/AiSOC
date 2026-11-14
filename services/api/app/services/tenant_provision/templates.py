"""Declarative seed-content templates for new managed tenants — T6.1.

These templates describe what a *freshly provisioned* tenant looks like
before any human operator (or connector) starts pushing real data into
it. They are intentionally **pure data**: no DB imports, no I/O, no
random IDs at module-load time. The provisioner consumes them and
projects them into ORM rows.

Three buckets:

1. **RBAC roles** (``DEFAULT_INITIAL_RBAC_ROLES``) — the role / permission
   tuples we materialise the first time a new tenant boots so the
   organisation can immediately log in as an admin and start handing out
   scoped access. We do not try to mirror the entire static
   ``ROLE_PERMISSIONS`` map here; the goal is a minimal viable RBAC
   surface that maps onto ``has_permission_db`` checks across the API.

2. **Detections** (``DEFAULT_INITIAL_DETECTIONS``) — half a dozen
   high-signal sigma-style starter rules so the alerts page is not
   empty on day one. They are *content* descriptions, not executable
   sigma; the detection engine ingests them from the marketplace at
   the next sync cycle and turns them into real rules.

3. **Playbooks** (``DEFAULT_INITIAL_PLAYBOOKS``) — three response
   templates (phishing triage, suspicious login, ransomware tabletop)
   that are good defaults for a first-day SOC team. Each lists the
   ordered ``steps`` a runbook UI can render without trying to be a
   real automation engine; the SOAR studio (WS-F4) is where operators
   will actually wire them up.

All templates collapse into one :class:`TenantTemplateBundle` exposed
through :func:`get_default_template_bundle`. Tests pin against the
exported defaults so a regression that silently shrinks the seed set
(e.g. a typo that drops a role) fails loudly.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# RBAC seed roles
# ---------------------------------------------------------------------------

DEFAULT_INITIAL_RBAC_ROLES: tuple[dict[str, object], ...] = (
    {
        "name": "tenant_admin",
        "description": "Full administrative access to the tenant.",
        "permissions": ["*"],
    },
    {
        "name": "soc_manager",
        "description": "Manage analysts, playbooks, and incident lifecycle.",
        "permissions": [
            "cases:read",
            "cases:write",
            "alerts:read",
            "alerts:write",
            "playbooks:read",
            "playbooks:write",
            "detections:read",
            "settings:read",
        ],
    },
    {
        "name": "soc_analyst",
        "description": "Triage and investigate alerts; cannot manage settings.",
        "permissions": [
            "cases:read",
            "cases:write",
            "alerts:read",
            "alerts:write",
            "playbooks:read",
            "detections:read",
        ],
    },
    {
        "name": "viewer",
        "description": "Read-only access; useful for stakeholders / auditors.",
        "permissions": [
            "cases:read",
            "alerts:read",
            "playbooks:read",
            "detections:read",
        ],
    },
)


# ---------------------------------------------------------------------------
# Detection seed content
# ---------------------------------------------------------------------------

DEFAULT_INITIAL_DETECTIONS: tuple[dict[str, object], ...] = (
    {
        "rule_id": "aisoc-bootstrap-suspicious-powershell",
        "title": "Suspicious PowerShell encoded command",
        "severity": "high",
        "tactic": "TA0002",
        "technique": "T1059.001",
        "description": (
            "Triggers on PowerShell invocations with `-enc` or "
            "`-EncodedCommand` flags. Encoded PowerShell is a common "
            "obfuscation technique for droppers and post-exploitation."
        ),
    },
    {
        "rule_id": "aisoc-bootstrap-impossible-travel",
        "title": "Impossible travel for a single user",
        "severity": "medium",
        "tactic": "TA0006",
        "technique": "T1078",
        "description": (
            "Two successful logins for the same identity from "
            "geo-distant IPs within a window shorter than physical "
            "travel between them would allow."
        ),
    },
    {
        "rule_id": "aisoc-bootstrap-okta-mfa-bombing",
        "title": "Okta MFA push bombing",
        "severity": "high",
        "tactic": "TA0006",
        "technique": "T1621",
        "description": (
            "Five or more denied Okta push challenges followed by a "
            "successful one within five minutes — strong signal of an "
            "MFA-fatigue attack."
        ),
    },
    {
        "rule_id": "aisoc-bootstrap-aws-iam-privesc",
        "title": "AWS IAM privilege escalation primitive",
        "severity": "high",
        "tactic": "TA0004",
        "technique": "T1078.004",
        "description": (
            "Detects AttachUserPolicy / PutUserPolicy / CreateAccessKey "
            "actions against a freshly-created IAM user — a textbook "
            "cloud privilege-escalation sequence."
        ),
    },
    {
        "rule_id": "aisoc-bootstrap-edr-defense-evasion",
        "title": "EDR / AV service tamper",
        "severity": "critical",
        "tactic": "TA0005",
        "technique": "T1562.001",
        "description": (
            "Stops, disables, or uninstalls a security agent (Defender, "
            "CrowdStrike, SentinelOne, Carbon Black). Almost always "
            "either a human admin acting suspiciously or active malware."
        ),
    },
    {
        "rule_id": "aisoc-bootstrap-mass-failed-login",
        "title": "Password spray — many users, single source",
        "severity": "medium",
        "tactic": "TA0006",
        "technique": "T1110.003",
        "description": (
            "A single source IP attempts authentication against 20+ "
            "distinct user accounts within ten minutes. Classic "
            "low-and-slow password spray."
        ),
    },
)


# ---------------------------------------------------------------------------
# Playbook seed content
# ---------------------------------------------------------------------------

DEFAULT_INITIAL_PLAYBOOKS: tuple[dict[str, object], ...] = (
    {
        "name": "Phishing email triage",
        "description": (
            "Standard intake flow for a reported phishing email: "
            "verify the report, extract IOCs, sandbox attachments, "
            "block the sender at the email gateway, and post a Slack "
            "summary back to the reporter."
        ),
        "category": "email",
        "steps": [
            "Verify the email exists in the mailbox and was not auto-quarantined.",
            "Extract URLs, attachments, and the sending domain.",
            "Detonate attachments in the sandbox; verdict feeds the case.",
            "Cross-check the sender domain against the threat-intel feed.",
            "Quarantine the message tenant-wide if verdict is malicious.",
            "Notify the reporter via Slack with the final verdict.",
        ],
    },
    {
        "name": "Suspicious login investigation",
        "description": (
            "Triage a flagged login (impossible travel, new device, "
            "blocked country) by correlating with recent activity, "
            "verifying with the user, and forcing re-MFA if needed."
        ),
        "category": "identity",
        "steps": [
            "Pull the last 24h of logins for the affected identity.",
            "Check geolocation and ASN for the source IP.",
            "DM the user through Slack to confirm the login.",
            "If the user denies it: invalidate the session and force MFA reset.",
            "If the user confirms: tag the case as `expected_behavior` and close.",
        ],
    },
    {
        "name": "Ransomware tabletop response",
        "description": (
            "First-responder steps when a host shows ransomware "
            "behaviour (file-encryption signatures, ransom note, "
            "EDR detection). Default actions: contain, capture, "
            "communicate."
        ),
        "category": "endpoint",
        "steps": [
            "Network-isolate the affected host via the EDR.",
            "Capture volatile memory and disk image for forensics.",
            "Identify lateral-movement indicators across the fleet.",
            "Open an incident bridge and page the on-call SOC manager.",
            "Notify legal / comms per the IR retainer if scope exceeds five hosts.",
        ],
    },
)


# ---------------------------------------------------------------------------
# Bundle wrapper
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TenantTemplateBundle:
    """Frozen view of every seed-content list the provisioner uses.

    The bundle exists to keep the provisioner's signature small and so
    tests can pass in a *shrunken* bundle (e.g. one role, one detection)
    without re-implementing the template module. The default bundle is
    a thin shim over the public module-level tuples.
    """

    rbac_roles: tuple[dict[str, object], ...] = field(default=DEFAULT_INITIAL_RBAC_ROLES)
    detections: tuple[dict[str, object], ...] = field(default=DEFAULT_INITIAL_DETECTIONS)
    playbooks: tuple[dict[str, object], ...] = field(default=DEFAULT_INITIAL_PLAYBOOKS)


def get_default_template_bundle() -> TenantTemplateBundle:
    """Return the read-only seed-content bundle baked into the build."""
    return TenantTemplateBundle()


__all__ = [
    "DEFAULT_INITIAL_DETECTIONS",
    "DEFAULT_INITIAL_PLAYBOOKS",
    "DEFAULT_INITIAL_RBAC_ROLES",
    "TenantTemplateBundle",
    "get_default_template_bundle",
]
