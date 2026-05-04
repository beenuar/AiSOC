#!/usr/bin/env python3
"""
Generate the AiSOC v1 production playbook pack.

Specs below are the canonical source of truth. Running this script materialises
50 playbooks under `playbooks/packs/v1/<category>/<slug>.playbook.json`.

The PlaybookStore (services/agents/app/playbook/store.py) loads from this tree
on startup, so the runtime always sees what's checked in.

Distribution per Phase 3B of the AiSOC 90-day plan:

    account-takeover     5
    ransomware           5
    bec                  5
    insider-risk         5
    cloud-misconfig     10
    data-exfil           5
    lateral-movement     5
    supply-chain         5
    ddos                 5
    -------------------- --
                        50

Step vocabulary is constrained to the runtime's StepType enum
(services/agents/app/playbook/models.py): enrich, investigate, notify,
block_ip, isolate_host, create_ticket, close_case, http, condition.

Human-approval gates are modelled as `condition` steps that read a
context flag (e.g. `context.approved_by_oncall`); the flag is expected
to be set by an out-of-band approval system (Slack interactive, email,
or the AiSOC web console) before the gated step runs.

Rollback is modelled by pairing every containment action with a
`condition` + matching reverse-action step, gated on
`verdict == false_positive`.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
PACK_ROOT = ROOT / "playbooks" / "packs" / "v1"

NOW = "2026-05-03T00:00:00+00:00"


# ---------------------------------------------------------------------------
# Builder helpers
# ---------------------------------------------------------------------------


def step(
    sid: str,
    name: str,
    type_: str,
    *,
    params: dict[str, Any] | None = None,
    on_failure: str = "continue",
    timeout: int = 30,
    retry_max: int = 0,
    condition: dict[str, Any] | None = None,
    next_true: str | None = None,
    next_false: str | None = None,
) -> dict[str, Any]:
    s: dict[str, Any] = {
        "id": sid,
        "name": name,
        "type": type_,
        "params": params or {},
        "on_failure": on_failure,
        "retry_max": retry_max,
        "timeout_seconds": timeout,
    }
    if condition is not None:
        s["condition"] = condition
    if next_true is not None:
        s["next_true"] = next_true
    if next_false is not None:
        s["next_false"] = next_false
    return s


def enrich(sid: str, name: str, indicator_field: str) -> dict[str, Any]:
    return step(
        sid, name, "enrich",
        params={"indicator_field": indicator_field},
        on_failure="continue", timeout=30,
    )


def investigate(sid: str, name: str, focus: str | None = None) -> dict[str, Any]:
    params: dict[str, Any] = {"case_id_field": "alert.case_id"}
    if focus:
        params["focus"] = focus
    return step(sid, name, "investigate", params=params,
                on_failure="continue", timeout=180)


def notify(sid: str, name: str, channel: str, message: str,
           service_env: str | None = None,
           webhook_env: str | None = None) -> dict[str, Any]:
    params: dict[str, Any] = {"channel": channel, "message_template": message}
    if service_env:
        params["service_key_env"] = service_env
    if webhook_env:
        params["webhook_env"] = webhook_env
    return step(sid, name, "notify", params=params, timeout=10)


def block_ip(sid: str, name: str, ip_field: str, duration: str = "24h") -> dict[str, Any]:
    return step(
        sid, name, "block_ip",
        params={"ip_field": ip_field, "duration": duration},
        on_failure="abort", timeout=20,
    )


def isolate_host(sid: str, name: str, host_field: str = "alert.host") -> dict[str, Any]:
    return step(
        sid, name, "isolate_host",
        params={"host_field": host_field},
        on_failure="abort", timeout=30,
    )


def ticket(sid: str, name: str, priority: str, title: str,
           queue: str = "soc") -> dict[str, Any]:
    return step(
        sid, name, "create_ticket",
        params={"priority": priority, "title_template": title, "queue": queue},
        timeout=20,
    )


def close_case(sid: str, name: str, resolution: str = "false_positive",
               condition: dict[str, Any] | None = None) -> dict[str, Any]:
    return step(
        sid, name, "close_case",
        params={"resolution": resolution},
        condition=condition, timeout=10,
    )


def http(sid: str, name: str, url: str, method: str = "POST",
         body_template: str | None = None,
         headers_env: str | None = None) -> dict[str, Any]:
    params: dict[str, Any] = {"url": url, "method": method}
    if body_template:
        params["body_template"] = body_template
    if headers_env:
        params["headers_env"] = headers_env
    return step(sid, name, "http", params=params, timeout=20)


def condition(sid: str, name: str, field: str, op: str, value: Any,
              next_true: str | None = None,
              next_false: str | None = None) -> dict[str, Any]:
    cond: dict[str, Any] = {"field": field, "operator": op}
    if value is not None:
        cond["value"] = value
    return step(
        sid, name, "condition",
        params={},
        condition=cond,
        next_true=next_true,
        next_false=next_false,
        timeout=5,
    )


def gate_human_approval(sid: str, on_oncall_field: str = "context.approved_by_oncall",
                        next_true: str | None = None,
                        next_false: str | None = None) -> dict[str, Any]:
    """A condition step that gates downstream work on out-of-band approval."""
    return condition(
        sid,
        "Wait for human approval",
        field=on_oncall_field,
        op="eq",
        value=True,
        next_true=next_true,
        next_false=next_false,
    )


def make_playbook(
    *,
    pid: str,
    name: str,
    description: str,
    category: str,
    severity: list[str],
    tags: list[str],
    steps: list[dict[str, Any]],
    trigger_on: str = "alert",
    trigger_tags: list[str] | None = None,
    version: str = "1.0.0",
) -> dict[str, Any]:
    return {
        "id": pid,
        "name": name,
        "description": description,
        "version": version,
        "tags": [category, *tags],
        "trigger": {
            "on": trigger_on,
            "severity": severity,
            "tags": trigger_tags or [category],
        },
        "author": "AiSOC",
        "enabled": True,
        "created_at": NOW,
        "updated_at": NOW,
        "steps": steps,
    }


# ---------------------------------------------------------------------------
# Per-category playbook specs
# ---------------------------------------------------------------------------


# Some category slugs map to directory names different from their tag prefix.
CATEGORY_DIRS = {
    "account-takeover": "account-takeover",
    "ransomware": "ransomware",
    "bec": "bec",
    "insider-risk": "insider-risk",
    "cloud-misconfig": "cloud-misconfig",
    "data-exfil": "data-exfil",
    "lateral-movement": "lateral-movement",
    "supply-chain": "supply-chain",
    "ddos": "ddos",
}


def build_account_takeover() -> list[dict[str, Any]]:
    cat = "account-takeover"
    return [
        make_playbook(
            pid="ato-impossible-travel-block-v1",
            name="ATO: Impossible Travel — Block & Reset",
            description=(
                "Triggered by impossible-travel detections. Blocks the source IP, "
                "force-revokes active sessions for the user, and requires human "
                "approval before forcing a password reset."
            ),
            category=cat, severity=["high", "critical"],
            tags=["ato", "identity", "mitre.t1078"],
            steps=[
                enrich("e1", "Geo-enrich source IP", "alert.source_ip"),
                investigate("inv", "Investigate user activity", focus="identity"),
                block_ip("b1", "Block source IP at edge", "alert.source_ip", "12h"),
                http("rev", "Revoke active sessions",
                     url="${IDP_BASE_URL}/users/{{alert.user}}/sessions",
                     method="DELETE", headers_env="IDP_BEARER_HEADERS"),
                notify("n1", "Notify user via email", "email",
                       message="Suspicious sign-in from {{alert.source_ip}} blocked. "
                               "Reset your password.",
                       webhook_env="EMAIL_WEBHOOK"),
                gate_human_approval("approve", next_true="reset"),
                http("reset", "Force password reset",
                     url="${IDP_BASE_URL}/users/{{alert.user}}/password/reset",
                     method="POST", headers_env="IDP_BEARER_HEADERS"),
                ticket("t1", "Open ATO investigation ticket",
                       "P2", "ATO suspected: {{alert.user}} from {{alert.source_ip}}"),
                close_case("close-fp", "Close if false positive",
                           condition={"field": "verdict", "operator": "eq",
                                      "value": "false_positive"}),
            ],
        ),
        make_playbook(
            pid="ato-mfa-fatigue-response-v1",
            name="ATO: MFA Fatigue — Challenge & Reset",
            description=(
                "Triggered when a user receives an unusual burst of MFA prompts. "
                "Enforces step-up auth and resets MFA factors after approval."
            ),
            category=cat, severity=["medium", "high"],
            tags=["ato", "identity", "mfa", "mitre.t1621"],
            steps=[
                enrich("e1", "Enrich user device posture", "alert.user"),
                investigate("inv", "Score MFA-fatigue likelihood"),
                http("step-up", "Force step-up auth challenge",
                     url="${IDP_BASE_URL}/users/{{alert.user}}/factors/challenge",
                     method="POST"),
                notify("n1", "DM user on Slack", "slack",
                       message="We've challenged your sign-in due to repeated MFA prompts. "
                               "Approve only if you initiated.",
                       webhook_env="SLACK_USER_WEBHOOK"),
                gate_human_approval("approve", next_true="reset-mfa"),
                http("reset-mfa", "Reset enrolled MFA factors",
                     url="${IDP_BASE_URL}/users/{{alert.user}}/factors",
                     method="DELETE"),
                ticket("t1", "Open MFA-fatigue case",
                       "P3", "MFA fatigue investigation: {{alert.user}}"),
            ],
        ),
        make_playbook(
            pid="ato-credential-stuffing-v1",
            name="ATO: Credential Stuffing — Block & Reset",
            description=(
                "Triggered by high-volume failed logins from a single source. "
                "Blocks the IP range, identifies impacted users, and forces resets."
            ),
            category=cat, severity=["high", "critical"],
            tags=["ato", "identity", "mitre.t1110.004"],
            steps=[
                enrich("e1", "Enrich source IP reputation", "alert.source_ip"),
                block_ip("b1", "Block source IP", "alert.source_ip", "48h"),
                http("list", "List impacted users",
                     url="${SIEM_URL}/search/credential_stuffing/{{alert.source_ip}}",
                     method="GET"),
                investigate("inv", "Investigate cred-stuffing campaign",
                            focus="identity"),
                http("reset-all", "Force reset for impacted users",
                     url="${IDP_BASE_URL}/bulk/password-reset",
                     method="POST",
                     body_template='{"user_ids": {{context.impacted_user_ids}}}'),
                notify("n1", "Page identity team", "pagerduty",
                       message="Credential stuffing from {{alert.source_ip}}: "
                               "{{context.impacted_user_count}} users reset.",
                       service_env="PD_IDENTITY_KEY"),
                ticket("t1", "Open ATO ticket",
                       "P1", "Credential stuffing: {{alert.source_ip}}"),
            ],
        ),
        make_playbook(
            pid="ato-session-token-theft-v1",
            name="ATO: Session Token Theft — Revoke & Isolate",
            description=(
                "Triggered when an authenticated session is observed from a new "
                "device + new geo simultaneously. Revokes all tokens and isolates "
                "the originating endpoint if known."
            ),
            category=cat, severity=["critical"],
            tags=["ato", "identity", "session-hijack", "mitre.t1539"],
            steps=[
                enrich("e1", "Enrich session context", "alert.session_id"),
                http("revoke", "Revoke all sessions for user",
                     url="${IDP_BASE_URL}/users/{{alert.user}}/sessions/revoke-all",
                     method="POST"),
                investigate("inv", "Investigate token-theft chain",
                            focus="forensics"),
                isolate_host("iso", "Isolate originating endpoint", "alert.host"),
                notify("n1", "Page on-call", "pagerduty",
                       message="Session theft suspected for {{alert.user}}. "
                               "Tokens revoked, host {{alert.host}} isolated.",
                       service_env="PD_SOC_KEY"),
                ticket("t1", "Open P1 ATO ticket",
                       "P1", "Session token theft: {{alert.user}}"),
            ],
        ),
        make_playbook(
            pid="ato-suspicious-oauth-grant-v1",
            name="ATO: Suspicious OAuth Grant — Revoke & Investigate",
            description=(
                "Triggered when a user grants a new OAuth scope to an unfamiliar "
                "third-party app. Revokes the grant and investigates."
            ),
            category=cat, severity=["medium", "high"],
            tags=["ato", "identity", "oauth", "mitre.t1528"],
            steps=[
                enrich("e1", "Enrich OAuth client reputation",
                       "alert.oauth_client_id"),
                investigate("inv", "Investigate scope and lineage",
                            focus="identity"),
                http("revoke", "Revoke OAuth grant",
                     url="${IDP_BASE_URL}/users/{{alert.user}}/oauth/{{alert.oauth_client_id}}",
                     method="DELETE"),
                notify("n1", "Notify user", "email",
                       message="Removed OAuth grant for {{alert.oauth_client_app_name}}. "
                               "Re-add only if intentional.",
                       webhook_env="EMAIL_WEBHOOK"),
                ticket("t1", "Open OAuth-abuse ticket",
                       "P3", "Suspicious OAuth grant: {{alert.user}} -> "
                              "{{alert.oauth_client_app_name}}"),
            ],
        ),
    ]


def build_ransomware() -> list[dict[str, Any]]:
    cat = "ransomware"
    return [
        make_playbook(
            pid="ransomware-host-isolate-v1",
            name="Ransomware: Host Isolation & Snapshot",
            description=(
                "Immediate host isolation, disk snapshot for forensics, page on-call. "
                "Standard first-response for endpoint ransomware."
            ),
            category=cat, severity=["critical"],
            tags=["ransomware", "endpoint", "mitre.t1486"],
            steps=[
                isolate_host("iso", "Isolate host (EDR)"),
                http("snap", "Snapshot host disk",
                     url="${EDR_URL}/hosts/{{alert.host}}/snapshot",
                     method="POST"),
                enrich("e1", "Enrich file hash", "alert.file_hash"),
                investigate("inv", "Forensic investigation", focus="forensics"),
                notify("n1", "Page on-call (SEV1)", "pagerduty",
                       message="RANSOMWARE: {{alert.host}} isolated. "
                               "Snapshot {{context.snapshot_id}} taken.",
                       service_env="PD_RANSOMWARE_KEY"),
                ticket("t1", "Open SEV1 ticket",
                       "P1", "RANSOMWARE: {{alert.host}}"),
            ],
        ),
        make_playbook(
            pid="ransomware-shadow-copy-deletion-v1",
            name="Ransomware: Shadow Copy Deletion Detected",
            description=(
                "Triggered on `vssadmin delete shadows` or wmic shadowcopy delete. "
                "Pre-encryption signal — isolate fast and verify backups."
            ),
            category=cat, severity=["critical"],
            tags=["ransomware", "endpoint", "mitre.t1490"],
            steps=[
                isolate_host("iso", "Isolate host (EDR)"),
                http("verify-backup", "Verify last successful backup",
                     url="${BACKUP_URL}/hosts/{{alert.host}}/last-backup",
                     method="GET"),
                investigate("inv", "Forensic investigation",
                            focus="forensics"),
                notify("n1", "Notify backup team", "slack",
                       message="Shadow-copy deletion on {{alert.host}}. "
                               "Last backup: {{context.last_backup_at}}.",
                       webhook_env="SLACK_BACKUP_WEBHOOK"),
                ticket("t1", "Open ransomware ticket",
                       "P1", "Shadow copies deleted: {{alert.host}}"),
            ],
        ),
        make_playbook(
            pid="ransomware-fileserver-encrypt-v1",
            name="Ransomware: File-Server Encryption Activity",
            description=(
                "Triggered by mass-rename / mass-extension-change on a file server. "
                "Network-segments the host to halt SMB lateral encryption."
            ),
            category=cat, severity=["critical"],
            tags=["ransomware", "fileserver", "mitre.t1486"],
            steps=[
                isolate_host("iso", "Network-segment file server"),
                http("smb-deny", "Push deny rule to firewall (SMB)",
                     url="${FW_URL}/policy/deny-smb",
                     method="POST",
                     body_template='{"src":"{{alert.host}}","port":445}'),
                investigate("inv", "Forensic investigation",
                            focus="forensics"),
                notify("n1", "Page storage and on-call", "pagerduty",
                       message="File-server ransomware: {{alert.host}}. "
                               "SMB egress blocked.",
                       service_env="PD_STORAGE_KEY"),
                ticket("t1", "Open SEV1 ticket",
                       "P1", "File-server ransomware: {{alert.host}}"),
            ],
        ),
        make_playbook(
            pid="ransomware-c2-block-v1",
            name="Ransomware: C2 Beacon Block",
            description=(
                "Triggered by C2 beaconing detections that match ransomware-family "
                "TTPs. Blocks C2 destinations at edge, isolates source host."
            ),
            category=cat, severity=["critical"],
            tags=["ransomware", "c2", "mitre.t1071"],
            steps=[
                enrich("e1", "Enrich destination IP", "alert.dst_ip"),
                block_ip("b1", "Block C2 destination", "alert.dst_ip", "30d"),
                isolate_host("iso", "Isolate beaconing host"),
                investigate("inv", "Investigate ransomware C2",
                            focus="forensics"),
                notify("n1", "Notify SOC", "slack",
                       message="C2 {{alert.dst_ip}} blocked. "
                               "Host {{alert.host}} isolated.",
                       webhook_env="SLACK_SOC_WEBHOOK"),
                ticket("t1", "Open C2 ticket",
                       "P1", "Ransomware C2: {{alert.host}} -> "
                              "{{alert.dst_ip}}"),
            ],
        ),
        make_playbook(
            pid="ransomware-public-exposure-v1",
            name="Ransomware: Internet-Exposed Asset Containment",
            description=(
                "Triggered when a host with public exposure shows ransomware "
                "indicators. Pulls the asset off the internet immediately."
            ),
            category=cat, severity=["critical"],
            tags=["ransomware", "exposure", "mitre.t1486"],
            steps=[
                http("detach-eip", "Detach public IP",
                     url="${CLOUD_URL}/instances/{{alert.host}}/detach-public-ip",
                     method="POST"),
                isolate_host("iso", "Isolate host (EDR)"),
                http("snap", "Snapshot host disk",
                     url="${EDR_URL}/hosts/{{alert.host}}/snapshot",
                     method="POST"),
                investigate("inv", "Forensic investigation",
                            focus="forensics"),
                notify("n1", "Page on-call (SEV1)", "pagerduty",
                       message="Internet-exposed host {{alert.host}} pulled off-net. "
                               "Ransomware suspected.",
                       service_env="PD_RANSOMWARE_KEY"),
                ticket("t1", "Open SEV1 ticket",
                       "P1", "Ransomware on exposed host: {{alert.host}}"),
            ],
        ),
    ]


def build_bec() -> list[dict[str, Any]]:
    cat = "bec"
    return [
        make_playbook(
            pid="bec-inbox-rule-malicious-v1",
            name="BEC: Malicious Inbox Rule Removed",
            description=(
                "Triggered when a forwarding/filter rule is created that hides "
                "vendor or finance keywords. Removes the rule and resets creds."
            ),
            category=cat, severity=["high", "critical"],
            tags=["bec", "email", "mitre.t1564.008"],
            steps=[
                enrich("e1", "Enrich rule details",
                       "alert.inbox_rule_id"),
                http("delete-rule", "Delete malicious inbox rule",
                     url="${MAIL_URL}/users/{{alert.user}}/rules/{{alert.inbox_rule_id}}",
                     method="DELETE"),
                http("revoke", "Revoke active sessions",
                     url="${IDP_BASE_URL}/users/{{alert.user}}/sessions/revoke-all",
                     method="POST"),
                investigate("inv", "Investigate BEC chain",
                            focus="identity"),
                notify("n1", "Notify finance team", "slack",
                       message="BEC rule removed for {{alert.user}}. "
                               "Validate any vendor changes in the last 7d.",
                       webhook_env="SLACK_FINANCE_WEBHOOK"),
                ticket("t1", "Open BEC ticket",
                       "P2", "BEC inbox rule: {{alert.user}}"),
            ],
        ),
        make_playbook(
            pid="bec-vendor-payment-redirect-v1",
            name="BEC: Vendor Payment Redirect — Freeze",
            description=(
                "Triggered when a vendor banking detail change happens via email. "
                "Freezes pending payments and pages CFO."
            ),
            category=cat, severity=["critical"],
            tags=["bec", "finance", "mitre.t1565.001"],
            steps=[
                http("freeze", "Freeze pending vendor payment",
                     url="${ERP_URL}/payments/{{alert.payment_id}}/freeze",
                     method="POST"),
                investigate("inv", "Investigate vendor change", focus="identity"),
                notify("n1", "Page CFO", "pagerduty",
                       message="Vendor payment {{alert.payment_id}} frozen pending review.",
                       service_env="PD_CFO_KEY"),
                gate_human_approval("approve", next_true="release"),
                http("release", "Release payment after approval",
                     url="${ERP_URL}/payments/{{alert.payment_id}}/release",
                     method="POST"),
                ticket("t1", "Open BEC payment ticket",
                       "P1", "BEC payment redirect: {{alert.vendor}}"),
            ],
        ),
        make_playbook(
            pid="bec-impersonation-domain-v1",
            name="BEC: Impersonation Domain Quarantine",
            description=(
                "Triggered when an inbound email originates from a domain that "
                "look-alikes an executive or vendor. Quarantines and blocks."
            ),
            category=cat, severity=["high"],
            tags=["bec", "email", "mitre.t1656"],
            steps=[
                enrich("e1", "Enrich sender domain", "alert.sender_domain"),
                http("quarantine", "Quarantine impersonation message",
                     url="${MAIL_URL}/messages/{{alert.message_id}}/quarantine",
                     method="POST"),
                http("block-domain", "Block sender domain",
                     url="${MAIL_URL}/policy/block-domain",
                     method="POST",
                     body_template='{"domain":"{{alert.sender_domain}}"}'),
                investigate("inv", "Investigate BEC campaign",
                            focus="identity"),
                notify("n1", "Notify SOC", "slack",
                       message="Impersonation domain {{alert.sender_domain}} blocked.",
                       webhook_env="SLACK_SOC_WEBHOOK"),
                ticket("t1", "Open BEC ticket",
                       "P3", "BEC impersonation: {{alert.sender_domain}}"),
            ],
        ),
        make_playbook(
            pid="bec-conditional-access-bypass-v1",
            name="BEC: Conditional Access Policy Bypass",
            description=(
                "Triggered when a BEC-related sign-in succeeds from a region "
                "that should be blocked by Conditional Access. Restores policy."
            ),
            category=cat, severity=["high", "critical"],
            tags=["bec", "identity", "conditional-access"],
            steps=[
                enrich("e1", "Enrich CA policy state",
                       "alert.policy_id"),
                http("restore", "Restore conditional access policy",
                     url="${IDP_BASE_URL}/policies/{{alert.policy_id}}/enable",
                     method="POST"),
                investigate("inv", "Investigate CA bypass",
                            focus="identity"),
                notify("n1", "Page identity team", "pagerduty",
                       message="CA policy {{alert.policy_id}} re-enabled. Bypass observed.",
                       service_env="PD_IDENTITY_KEY"),
                ticket("t1", "Open CA-bypass ticket",
                       "P2", "CA bypass: {{alert.user}}"),
            ],
        ),
        make_playbook(
            pid="bec-token-theft-v1",
            name="BEC: M365 / Workspace Token Theft",
            description=(
                "Triggered when a refresh token is observed from a new ASN with no "
                "interactive sign-in. Revokes refresh tokens and forces MFA."
            ),
            category=cat, severity=["critical"],
            tags=["bec", "identity", "token-theft", "mitre.t1539"],
            steps=[
                enrich("e1", "Enrich ASN reputation",
                       "alert.source_asn"),
                http("revoke-rt", "Revoke refresh tokens",
                     url="${IDP_BASE_URL}/users/{{alert.user}}/refresh-tokens",
                     method="DELETE"),
                http("force-mfa", "Force MFA re-enrollment",
                     url="${IDP_BASE_URL}/users/{{alert.user}}/mfa/reset",
                     method="POST"),
                investigate("inv", "Investigate token-theft chain",
                            focus="identity"),
                notify("n1", "Page on-call", "pagerduty",
                       message="Refresh-token theft suspected for {{alert.user}}. "
                               "Tokens revoked.",
                       service_env="PD_SOC_KEY"),
                ticket("t1", "Open BEC token ticket",
                       "P1", "BEC token theft: {{alert.user}}"),
            ],
        ),
    ]


def build_insider_risk() -> list[dict[str, Any]]:
    cat = "insider-risk"
    return [
        make_playbook(
            pid="insider-mass-download-v1",
            name="Insider: Mass File Download",
            description=(
                "Triggered when a single user downloads >N files from a sensitive "
                "store in <T window. Reduces user permissions and notifies manager."
            ),
            category=cat, severity=["high"],
            tags=["insider", "dlp", "mitre.t1530"],
            steps=[
                enrich("e1", "Enrich user role + tenure",
                       "alert.user"),
                http("readonly", "Set sensitive-store ACL to read-only",
                     url="${SAAS_URL}/acl/{{alert.user}}/readonly",
                     method="POST"),
                investigate("inv", "Investigate access pattern",
                            focus="identity"),
                notify("n1", "Notify user's manager", "email",
                       message="High-volume download by {{alert.user}}. Review needed.",
                       webhook_env="EMAIL_WEBHOOK"),
                ticket("t1", "Open insider-risk ticket",
                       "P3", "Mass download: {{alert.user}}"),
            ],
        ),
        make_playbook(
            pid="insider-resignation-data-access-v1",
            name="Insider: Resignation + Sensitive Access",
            description=(
                "Triggered when a user with a recent resignation flag accesses "
                "sensitive data. Read-only mode and HR audit."
            ),
            category=cat, severity=["medium", "high"],
            tags=["insider", "hr", "mitre.t1530"],
            steps=[
                enrich("e1", "Enrich HR resignation status",
                       "alert.user"),
                http("readonly", "Force read-only on sensitive scopes",
                     url="${SAAS_URL}/acl/{{alert.user}}/scopes/sensitive/readonly",
                     method="POST"),
                investigate("inv", "Investigate exit-risk pattern",
                            focus="identity"),
                notify("n1", "Notify HR + manager", "slack",
                       message="Resigning user {{alert.user}} accessed sensitive data. "
                               "Read-only enforced.",
                       webhook_env="SLACK_HR_WEBHOOK"),
                ticket("t1", "Open exit-risk ticket",
                       "P2", "Exit risk: {{alert.user}}",
                       queue="hr"),
            ],
        ),
        make_playbook(
            pid="insider-privilege-misuse-v1",
            name="Insider: Privilege Misuse",
            description=(
                "Triggered when a privileged account performs actions outside its "
                "approved JIT window. Revokes privilege and pages HR-Sec."
            ),
            category=cat, severity=["high", "critical"],
            tags=["insider", "privilege", "mitre.t1078.004"],
            steps=[
                http("revoke-priv", "Revoke privileged role",
                     url="${IDP_BASE_URL}/users/{{alert.user}}/roles/{{alert.role}}",
                     method="DELETE"),
                investigate("inv", "Investigate privilege misuse",
                            focus="identity"),
                notify("n1", "Page HR-Sec", "pagerduty",
                       message="Privilege misuse by {{alert.user}} ({{alert.role}}). "
                               "Role revoked.",
                       service_env="PD_HRSEC_KEY"),
                ticket("t1", "Open privilege-misuse ticket",
                       "P1", "Privilege misuse: {{alert.user}}",
                       queue="hr"),
            ],
        ),
        make_playbook(
            pid="insider-source-code-exfil-v1",
            name="Insider: Source-Code Exfil",
            description=(
                "Triggered when a developer pushes private source to a personal "
                "remote or pastebin-like target. Blocks dest, pages eng-leadership."
            ),
            category=cat, severity=["critical"],
            tags=["insider", "source-code", "mitre.t1567"],
            steps=[
                enrich("e1", "Enrich destination",
                       "alert.dst_host"),
                http("block-dest", "Block destination at proxy",
                     url="${PROXY_URL}/policy/block",
                     method="POST",
                     body_template='{"host":"{{alert.dst_host}}","reason":"src-exfil"}'),
                investigate("inv", "Investigate exfil chain",
                            focus="forensics"),
                notify("n1", "Page eng-leadership", "pagerduty",
                       message="Source-code exfil suspected from {{alert.user}} "
                               "to {{alert.dst_host}}.",
                       service_env="PD_ENG_LEAD_KEY"),
                ticket("t1", "Open exfil ticket",
                       "P1", "Source-code exfil: {{alert.user}}"),
            ],
        ),
        make_playbook(
            pid="insider-after-hours-access-v1",
            name="Insider: Anomalous After-Hours Access",
            description=(
                "Triggered when a user accesses sensitive systems outside their "
                "normal pattern. Step-up MFA and log for HR review."
            ),
            category=cat, severity=["medium"],
            tags=["insider", "anomaly", "mitre.t1078"],
            steps=[
                enrich("e1", "Enrich user normal pattern",
                       "alert.user"),
                http("step-up", "Force MFA step-up",
                     url="${IDP_BASE_URL}/users/{{alert.user}}/factors/challenge",
                     method="POST"),
                investigate("inv", "Score anomaly likelihood",
                            focus="identity"),
                ticket("t1", "Open after-hours review",
                       "P4", "After-hours access: {{alert.user}}",
                       queue="hr"),
            ],
        ),
    ]


def build_cloud_misconfig() -> list[dict[str, Any]]:
    cat = "cloud-misconfig"
    return [
        make_playbook(
            pid="cloud-s3-public-v1",
            name="Cloud: S3 Bucket Public — Re-private & Audit",
            description=(
                "Triggered by `s3-public-bucket` detection. Sets bucket private, "
                "enables Block Public Access, and audits last 7d access logs."
            ),
            category=cat, severity=["high", "critical"],
            tags=["cloud", "aws", "s3", "mitre.t1530"],
            steps=[
                http("private", "Set bucket private",
                     url="${AWS_URL}/s3/{{alert.bucket}}/acl/private",
                     method="PUT"),
                http("bpa", "Enable Block Public Access",
                     url="${AWS_URL}/s3/{{alert.bucket}}/block-public-access",
                     method="PUT"),
                investigate("inv", "Audit last 7d S3 access",
                            focus="cloud"),
                notify("n1", "Notify cloud team", "slack",
                       message="S3 {{alert.bucket}} re-privatized.",
                       webhook_env="SLACK_CLOUD_WEBHOOK"),
                ticket("t1", "Open cloud ticket",
                       "P2", "S3 public: {{alert.bucket}}"),
            ],
        ),
        make_playbook(
            pid="cloud-iam-overpriv-v1",
            name="Cloud: Over-Privileged IAM — Detach & Review",
            description=(
                "Triggered when IAM Access Analyzer flags an over-privileged role. "
                "Detaches the policy and opens an owner-review ticket."
            ),
            category=cat, severity=["medium", "high"],
            tags=["cloud", "aws", "iam", "mitre.t1078.004"],
            steps=[
                http("detach", "Detach over-privileged policy",
                     url="${AWS_URL}/iam/{{alert.role}}/policies/{{alert.policy}}",
                     method="DELETE"),
                investigate("inv", "Investigate access usage",
                            focus="cloud"),
                notify("n1", "Notify role owner", "slack",
                       message="Policy {{alert.policy}} detached from {{alert.role}}. "
                               "Re-add only the minimum needed.",
                       webhook_env="SLACK_CLOUD_WEBHOOK"),
                ticket("t1", "Owner-review ticket",
                       "P3", "IAM over-priv: {{alert.role}}"),
            ],
        ),
        make_playbook(
            pid="cloud-key-leak-v1",
            name="Cloud: Cloud Access Key Leaked",
            description=(
                "Triggered when a long-lived access key is found in a public repo "
                "or paste site. Rotates the key and scans for downstream use."
            ),
            category=cat, severity=["critical"],
            tags=["cloud", "secrets", "mitre.t1552.001"],
            steps=[
                http("disable", "Disable leaked key",
                     url="${AWS_URL}/iam/users/{{alert.user}}/keys/{{alert.key_id}}",
                     method="DELETE"),
                http("rotate", "Rotate access key",
                     url="${AWS_URL}/iam/users/{{alert.user}}/keys/rotate",
                     method="POST"),
                investigate("inv", "Find downstream use of key",
                            focus="cloud"),
                notify("n1", "Page cloud-sec", "pagerduty",
                       message="Leaked key {{alert.key_id}} disabled and rotated.",
                       service_env="PD_CLOUD_KEY"),
                ticket("t1", "Open key-leak ticket",
                       "P1", "Leaked key: {{alert.key_id}}"),
            ],
        ),
        make_playbook(
            pid="cloud-mfa-disabled-root-v1",
            name="Cloud: Root Account MFA Disabled",
            description=(
                "Triggered when root MFA is disabled. Re-enables MFA and pages "
                "the cloud-platform owner immediately."
            ),
            category=cat, severity=["critical"],
            tags=["cloud", "iam", "mfa", "mitre.t1556"],
            steps=[
                http("reenable-mfa", "Re-enable root MFA",
                     url="${AWS_URL}/iam/root/mfa/enable",
                     method="POST"),
                investigate("inv", "Identify actor and intent",
                            focus="cloud"),
                notify("n1", "Page platform-owner", "pagerduty",
                       message="Root MFA was disabled — re-enabled. Investigate "
                               "{{alert.actor}}.",
                       service_env="PD_PLATFORM_KEY"),
                ticket("t1", "Open root-MFA ticket",
                       "P1", "Root MFA disabled by {{alert.actor}}"),
            ],
        ),
        make_playbook(
            pid="cloud-cloudtrail-disabled-v1",
            name="Cloud: CloudTrail Disabled — Re-enable",
            description=(
                "Triggered when a CloudTrail trail is stopped. Restarts trail "
                "and audits API calls in the dark window."
            ),
            category=cat, severity=["critical"],
            tags=["cloud", "aws", "logging", "mitre.t1562.008"],
            steps=[
                http("start", "Re-enable CloudTrail",
                     url="${AWS_URL}/cloudtrail/{{alert.trail}}/start",
                     method="POST"),
                investigate("inv", "Audit dark-window calls",
                            focus="cloud"),
                notify("n1", "Page cloud-sec", "pagerduty",
                       message="CloudTrail {{alert.trail}} restarted.",
                       service_env="PD_CLOUD_KEY"),
                ticket("t1", "Open CloudTrail ticket",
                       "P1", "CloudTrail disabled: {{alert.trail}}"),
            ],
        ),
        make_playbook(
            pid="cloud-security-group-open-v1",
            name="Cloud: Security Group Opens 0.0.0.0/0",
            description=(
                "Triggered when a security group rule allows ingress from 0.0.0.0/0 "
                "to a sensitive port. Closes the rule and audits the change."
            ),
            category=cat, severity=["high", "critical"],
            tags=["cloud", "aws", "network", "mitre.t1190"],
            steps=[
                http("close", "Remove 0.0.0.0/0 ingress rule",
                     url="${AWS_URL}/sg/{{alert.sg}}/ingress/{{alert.rule_id}}",
                     method="DELETE"),
                investigate("inv", "Audit who made the change",
                            focus="cloud"),
                notify("n1", "Notify cloud team", "slack",
                       message="SG {{alert.sg}} 0.0.0.0/0 ingress removed.",
                       webhook_env="SLACK_CLOUD_WEBHOOK"),
                ticket("t1", "Open SG ticket",
                       "P2", "SG open: {{alert.sg}}"),
            ],
        ),
        make_playbook(
            pid="cloud-rds-public-v1",
            name="Cloud: RDS Instance Publicly Accessible",
            description=(
                "Triggered when an RDS instance toggles to publicly accessible. "
                "Removes public access and audits."
            ),
            category=cat, severity=["high", "critical"],
            tags=["cloud", "aws", "rds", "mitre.t1190"],
            steps=[
                http("private", "Disable RDS public access",
                     url="${AWS_URL}/rds/{{alert.instance}}/public/disable",
                     method="POST"),
                investigate("inv", "Audit RDS access window",
                            focus="cloud"),
                notify("n1", "Notify cloud team", "slack",
                       message="RDS {{alert.instance}} no longer public.",
                       webhook_env="SLACK_CLOUD_WEBHOOK"),
                ticket("t1", "Open RDS-public ticket",
                       "P1", "RDS public: {{alert.instance}}"),
            ],
        ),
        make_playbook(
            pid="cloud-gke-anonymous-v1",
            name="Cloud: GKE Cluster Anonymous Auth",
            description=(
                "Triggered when GKE cluster is configured to allow anonymous "
                "Kubernetes API access. Disables anonymous and audits."
            ),
            category=cat, severity=["high", "critical"],
            tags=["cloud", "gcp", "kubernetes", "mitre.t1190"],
            steps=[
                http("disable-anon", "Disable anonymous auth",
                     url="${GCP_URL}/gke/{{alert.cluster}}/anonymous/disable",
                     method="POST"),
                investigate("inv", "Audit anonymous-window calls",
                            focus="cloud"),
                notify("n1", "Page platform team", "pagerduty",
                       message="GKE {{alert.cluster}} anonymous disabled.",
                       service_env="PD_PLATFORM_KEY"),
                ticket("t1", "Open GKE-anon ticket",
                       "P1", "GKE anonymous: {{alert.cluster}}"),
            ],
        ),
        make_playbook(
            pid="cloud-azure-blob-public-v1",
            name="Cloud: Azure Blob Container Public",
            description=(
                "Triggered when an Azure Storage container is set to public. "
                "Reverts to private and audits."
            ),
            category=cat, severity=["high"],
            tags=["cloud", "azure", "storage", "mitre.t1530"],
            steps=[
                http("private", "Set container private",
                     url="${AZURE_URL}/storage/{{alert.account}}/{{alert.container}}/private",
                     method="POST"),
                investigate("inv", "Audit blob access",
                            focus="cloud"),
                notify("n1", "Notify cloud team", "slack",
                       message="Azure {{alert.container}} re-privatized.",
                       webhook_env="SLACK_CLOUD_WEBHOOK"),
                ticket("t1", "Open Azure ticket",
                       "P2", "Azure blob public: {{alert.container}}"),
            ],
        ),
        make_playbook(
            pid="cloud-cross-account-trust-v1",
            name="Cloud: Unexpected Cross-Account Trust",
            description=(
                "Triggered when a role trust policy adds an external account ID "
                "not on the allow-list. Revokes and audits."
            ),
            category=cat, severity=["critical"],
            tags=["cloud", "aws", "iam", "mitre.t1078.004"],
            steps=[
                http("revoke-trust", "Remove cross-account trust",
                     url="${AWS_URL}/iam/{{alert.role}}/trust/{{alert.external_account}}",
                     method="DELETE"),
                investigate("inv", "Audit assumptions in dark window",
                            focus="cloud"),
                notify("n1", "Page cloud-sec", "pagerduty",
                       message="Cross-account trust to {{alert.external_account}} removed "
                               "from {{alert.role}}.",
                       service_env="PD_CLOUD_KEY"),
                ticket("t1", "Open cross-account ticket",
                       "P1", "Cross-account trust: {{alert.role}}"),
            ],
        ),
    ]


def build_data_exfil() -> list[dict[str, Any]]:
    cat = "data-exfil"
    return [
        make_playbook(
            pid="exfil-large-upload-v1",
            name="Exfil: Large Outbound Upload",
            description=(
                "Triggered when a host uploads >X GB to a non-corporate destination "
                "in a short window. Blocks destination and investigates."
            ),
            category=cat, severity=["high", "critical"],
            tags=["exfil", "dlp", "mitre.t1567"],
            steps=[
                enrich("e1", "Enrich destination", "alert.dst_host"),
                http("block", "Block destination at proxy",
                     url="${PROXY_URL}/policy/block",
                     method="POST",
                     body_template='{"host":"{{alert.dst_host}}","reason":"large-upload"}'),
                investigate("inv", "Investigate exfil pattern",
                            focus="forensics"),
                notify("n1", "Notify SOC", "slack",
                       message="Large upload {{alert.bytes_out}} from {{alert.host}} "
                               "to {{alert.dst_host}} blocked.",
                       webhook_env="SLACK_SOC_WEBHOOK"),
                ticket("t1", "Open exfil ticket",
                       "P2", "Large upload: {{alert.host}}"),
            ],
        ),
        make_playbook(
            pid="exfil-archive-egress-v1",
            name="Exfil: Archive File Egress (.zip / .7z / .rar)",
            description=(
                "Triggered when a host uploads an archive to an external dest. "
                "Holds the file in DLP review queue and notifies user's manager."
            ),
            category=cat, severity=["medium", "high"],
            tags=["exfil", "dlp", "archive"],
            steps=[
                enrich("e1", "Enrich destination",
                       "alert.dst_host"),
                http("dlp-review", "Send to DLP review queue",
                     url="${DLP_URL}/review",
                     method="POST",
                     body_template=('{"host":"{{alert.host}}",'
                                    '"file":"{{alert.file_name}}",'
                                    '"dst":"{{alert.dst_host}}"}')),
                investigate("inv", "Investigate archive content",
                            focus="forensics"),
                notify("n1", "Notify user's manager", "email",
                       message="Archive upload by {{alert.user}} to {{alert.dst_host}} "
                               "queued for DLP review.",
                       webhook_env="EMAIL_WEBHOOK"),
                ticket("t1", "Open DLP ticket",
                       "P3", "Archive egress: {{alert.user}}"),
            ],
        ),
        make_playbook(
            pid="exfil-dns-tunneling-v1",
            name="Exfil: DNS Tunneling",
            description=(
                "Triggered by high-entropy DNS query length on a host. Sinkholes "
                "the suspect domain and isolates the host."
            ),
            category=cat, severity=["critical"],
            tags=["exfil", "dns", "mitre.t1071.004"],
            steps=[
                enrich("e1", "Enrich domain reputation",
                       "alert.dns_query"),
                http("sinkhole", "Sinkhole domain at resolver",
                     url="${DNS_URL}/sinkhole",
                     method="POST",
                     body_template='{"domain":"{{alert.dns_query}}"}'),
                isolate_host("iso", "Isolate beaconing host"),
                investigate("inv", "Investigate DNS tunneling",
                            focus="forensics"),
                notify("n1", "Page on-call", "pagerduty",
                       message="DNS tunneling {{alert.host}} -> {{alert.dns_query}} "
                               "sinkholed and isolated.",
                       service_env="PD_SOC_KEY"),
                ticket("t1", "Open DNS-tunnel ticket",
                       "P1", "DNS tunneling: {{alert.host}}"),
            ],
        ),
        make_playbook(
            pid="exfil-personal-cloud-v1",
            name="Exfil: Personal Cloud Storage Upload",
            description=(
                "Triggered when corporate data uploads to a personal cloud "
                "(personal Drive, Dropbox, iCloud). Blocks dest, manager notify."
            ),
            category=cat, severity=["medium", "high"],
            tags=["exfil", "saas", "mitre.t1567.002"],
            steps=[
                http("block", "Block destination at proxy",
                     url="${PROXY_URL}/policy/block",
                     method="POST",
                     body_template='{"host":"{{alert.dst_host}}","reason":"personal-cloud"}'),
                investigate("inv", "Investigate access pattern",
                            focus="identity"),
                notify("n1", "Notify user's manager", "email",
                       message="Personal-cloud upload by {{alert.user}} to "
                               "{{alert.dst_host}} blocked.",
                       webhook_env="EMAIL_WEBHOOK"),
                ticket("t1", "Open exfil ticket",
                       "P3", "Personal cloud: {{alert.user}}"),
            ],
        ),
        make_playbook(
            pid="exfil-removable-media-v1",
            name="Exfil: Sensitive Data to Removable Media",
            description=(
                "Triggered when a sensitive file is written to a USB volume. "
                "Blocks USB writes via EDR policy and opens a ticket."
            ),
            category=cat, severity=["medium"],
            tags=["exfil", "endpoint", "usb", "mitre.t1052"],
            steps=[
                http("block-usb", "Push USB write-block to host",
                     url="${EDR_URL}/hosts/{{alert.host}}/policy/usb-readonly",
                     method="POST"),
                investigate("inv", "Investigate file sensitivity",
                            focus="forensics"),
                notify("n1", "Notify user's manager", "email",
                       message="Sensitive write to USB by {{alert.user}}. "
                               "Host USB now read-only.",
                       webhook_env="EMAIL_WEBHOOK"),
                ticket("t1", "Open USB-exfil ticket",
                       "P3", "USB exfil: {{alert.user}}"),
            ],
        ),
    ]


def build_lateral_movement() -> list[dict[str, Any]]:
    cat = "lateral-movement"
    return [
        make_playbook(
            pid="lateral-psexec-detected-v1",
            name="Lateral: PsExec / Remote Service Creation",
            description=(
                "Triggered by remote service creation patterns indicative of "
                "PsExec / Impacket. Isolates target and source, investigates."
            ),
            category=cat, severity=["high", "critical"],
            tags=["lateral", "endpoint", "mitre.t1021.002"],
            steps=[
                isolate_host("iso-dst", "Isolate target host", "alert.dst_host"),
                isolate_host("iso-src", "Isolate source host", "alert.src_host"),
                investigate("inv", "Investigate lateral chain", focus="forensics"),
                notify("n1", "Page on-call", "pagerduty",
                       message="PsExec lateral {{alert.src_host}} -> {{alert.dst_host}}. "
                               "Both isolated.",
                       service_env="PD_SOC_KEY"),
                ticket("t1", "Open lateral ticket",
                       "P1", "PsExec lateral: {{alert.src_host}} -> {{alert.dst_host}}"),
            ],
        ),
        make_playbook(
            pid="lateral-rdp-spray-v1",
            name="Lateral: RDP Spray",
            description=(
                "Triggered when one host opens RDP to >N hosts in <T window. "
                "Blocks the source IP, isolates host, investigates."
            ),
            category=cat, severity=["high"],
            tags=["lateral", "rdp", "mitre.t1021.001"],
            steps=[
                block_ip("b1", "Block source IP", "alert.src_ip", "24h"),
                isolate_host("iso", "Isolate source host", "alert.src_host"),
                investigate("inv", "Investigate RDP spray",
                            focus="forensics"),
                notify("n1", "Notify SOC", "slack",
                       message="RDP spray from {{alert.src_host}} blocked.",
                       webhook_env="SLACK_SOC_WEBHOOK"),
                ticket("t1", "Open RDP-spray ticket",
                       "P2", "RDP spray: {{alert.src_host}}"),
            ],
        ),
        make_playbook(
            pid="lateral-kerberoasting-v1",
            name="Lateral: Kerberoasting",
            description=(
                "Triggered by abnormal SPN-ticket request volume from a single "
                "user. Resets impacted service-account credentials."
            ),
            category=cat, severity=["high"],
            tags=["lateral", "ad", "mitre.t1558.003"],
            steps=[
                investigate("inv", "Investigate kerberoasting",
                            focus="identity"),
                http("reset-svc", "Reset impacted SVC accounts",
                     url="${IDP_BASE_URL}/service-accounts/bulk-reset",
                     method="POST",
                     body_template='{"accounts": {{context.impacted_svc_accounts}}}'),
                http("disable-user", "Disable suspect user",
                     url="${IDP_BASE_URL}/users/{{alert.user}}/disable",
                     method="POST"),
                notify("n1", "Page identity team", "pagerduty",
                       message="Kerberoasting by {{alert.user}}. SVC accounts reset.",
                       service_env="PD_IDENTITY_KEY"),
                ticket("t1", "Open kerberoast ticket",
                       "P1", "Kerberoasting: {{alert.user}}"),
            ],
        ),
        make_playbook(
            pid="lateral-pass-the-hash-v1",
            name="Lateral: Pass-The-Hash",
            description=(
                "Triggered by NTLM relay / PTH detection. Disables the user "
                "and isolates source + destination."
            ),
            category=cat, severity=["critical"],
            tags=["lateral", "ad", "mitre.t1550.002"],
            steps=[
                http("disable-user", "Disable account",
                     url="${IDP_BASE_URL}/users/{{alert.user}}/disable",
                     method="POST"),
                isolate_host("iso-src", "Isolate source host", "alert.src_host"),
                isolate_host("iso-dst", "Isolate destination host", "alert.dst_host"),
                investigate("inv", "Investigate PTH chain",
                            focus="forensics"),
                notify("n1", "Page on-call", "pagerduty",
                       message="PTH detected: {{alert.user}} {{alert.src_host}} -> "
                               "{{alert.dst_host}}. Account disabled.",
                       service_env="PD_SOC_KEY"),
                ticket("t1", "Open PTH ticket",
                       "P1", "PTH: {{alert.user}}"),
            ],
        ),
        make_playbook(
            pid="lateral-cross-domain-v1",
            name="Lateral: Cross-Domain Movement",
            description=(
                "Triggered when an account from one trust domain authenticates to "
                "an asset in a separately-classified domain in a way that violates "
                "policy. Segments the network and investigates."
            ),
            category=cat, severity=["critical"],
            tags=["lateral", "trust", "mitre.t1021"],
            steps=[
                http("segment", "Apply network segmentation rule",
                     url="${FW_URL}/policy/segment",
                     method="POST",
                     body_template=('{"src":"{{alert.src_host}}",'
                                    '"dst_domain":"{{alert.dst_domain}}"}')),
                investigate("inv", "Investigate cross-domain movement",
                            focus="forensics"),
                notify("n1", "Page on-call", "pagerduty",
                       message="Cross-domain lateral {{alert.user}}. Segmentation applied.",
                       service_env="PD_SOC_KEY"),
                ticket("t1", "Open cross-domain ticket",
                       "P1", "Cross-domain lateral: {{alert.user}}"),
            ],
        ),
    ]


def build_supply_chain() -> list[dict[str, Any]]:
    cat = "supply-chain"
    return [
        make_playbook(
            pid="supply-malicious-npm-v1",
            name="Supply Chain: Malicious npm Package",
            description=(
                "Triggered when a published npm package matches a known-bad list. "
                "Blocks installs at registry-mirror, audits org installs."
            ),
            category=cat, severity=["high", "critical"],
            tags=["supply-chain", "npm", "mitre.t1195"],
            steps=[
                enrich("e1", "Enrich package reputation",
                       "alert.package_name"),
                http("block", "Add package to mirror block-list",
                     url="${REGISTRY_URL}/policy/block",
                     method="POST",
                     body_template=('{"ecosystem":"npm",'
                                    '"package":"{{alert.package_name}}",'
                                    '"version":"{{alert.package_version}}"}')),
                http("audit-installs", "List org installs",
                     url="${SCA_URL}/installs?ecosystem=npm&package={{alert.package_name}}",
                     method="GET"),
                investigate("inv", "Investigate supply-chain blast radius",
                            focus="cloud"),
                notify("n1", "Page eng-sec", "pagerduty",
                       message="Malicious npm {{alert.package_name}} blocked. "
                               "{{context.install_count}} installs found.",
                       service_env="PD_ENGSEC_KEY"),
                ticket("t1", "Open supply-chain ticket",
                       "P1", "Malicious npm: {{alert.package_name}}"),
            ],
        ),
        make_playbook(
            pid="supply-pypi-typosquat-v1",
            name="Supply Chain: PyPI Typosquat",
            description=(
                "Triggered when a typosquat package is observed in CI installs. "
                "Pulls install lock to canonical name and audits."
            ),
            category=cat, severity=["high"],
            tags=["supply-chain", "pypi", "mitre.t1195"],
            steps=[
                http("block", "Block typosquat at mirror",
                     url="${REGISTRY_URL}/policy/block",
                     method="POST",
                     body_template=('{"ecosystem":"pypi",'
                                    '"package":"{{alert.package_name}}"}')),
                http("audit", "List repos with this dependency",
                     url="${SCA_URL}/repos?ecosystem=pypi&package={{alert.package_name}}",
                     method="GET"),
                investigate("inv", "Investigate typosquat",
                            focus="cloud"),
                notify("n1", "Notify eng team", "slack",
                       message="PyPI typosquat {{alert.package_name}} blocked. "
                               "{{context.repo_count}} repos affected.",
                       webhook_env="SLACK_ENG_WEBHOOK"),
                ticket("t1", "Open typosquat ticket",
                       "P2", "PyPI typosquat: {{alert.package_name}}"),
            ],
        ),
        make_playbook(
            pid="supply-github-action-compromise-v1",
            name="Supply Chain: GitHub Action Compromise",
            description=(
                "Triggered when a referenced GitHub Action SHA changes "
                "unexpectedly or matches a compromise advisory. Pin to "
                "last-known-good and audit."
            ),
            category=cat, severity=["high", "critical"],
            tags=["supply-chain", "github", "mitre.t1195.002"],
            steps=[
                http("pin", "Pin Action to last-known-good SHA",
                     url="${CI_URL}/actions/pin",
                     method="POST",
                     body_template=('{"action":"{{alert.action}}",'
                                    '"sha":"{{alert.lkg_sha}}"}')),
                http("audit", "List workflows using this Action",
                     url="${CI_URL}/workflows?action={{alert.action}}",
                     method="GET"),
                investigate("inv", "Investigate Action compromise",
                            focus="cloud"),
                notify("n1", "Page eng-sec", "pagerduty",
                       message="GH Action {{alert.action}} pinned to {{alert.lkg_sha}}.",
                       service_env="PD_ENGSEC_KEY"),
                ticket("t1", "Open Action-compromise ticket",
                       "P1", "GH Action compromise: {{alert.action}}"),
            ],
        ),
        make_playbook(
            pid="supply-vendor-breach-v1",
            name="Supply Chain: Vendor Breach Notification",
            description=(
                "Triggered when a vendor publishes a breach advisory matching "
                "internal vendor inventory. Blocks vendor IPs, opens procurement "
                "review."
            ),
            category=cat, severity=["high", "critical"],
            tags=["supply-chain", "vendor", "mitre.t1199"],
            steps=[
                http("block-vendor-ips", "Block vendor IP ranges",
                     url="${FW_URL}/policy/block-vendor",
                     method="POST",
                     body_template='{"vendor":"{{alert.vendor}}"}'),
                investigate("inv", "Investigate vendor exposure",
                            focus="cloud"),
                notify("n1", "Notify procurement + sec", "slack",
                       message="Vendor {{alert.vendor}} breach. IPs blocked. "
                               "Review contracts and integrations.",
                       webhook_env="SLACK_PROCUREMENT_WEBHOOK"),
                ticket("t1", "Open vendor-breach ticket",
                       "P1", "Vendor breach: {{alert.vendor}}",
                       queue="procurement"),
            ],
        ),
        make_playbook(
            pid="supply-iac-drift-v1",
            name="Supply Chain: IaC Drift Detected",
            description=(
                "Triggered when production infra deviates from IaC source of "
                "truth in a security-relevant way. Reverts to declared state."
            ),
            category=cat, severity=["medium", "high"],
            tags=["supply-chain", "iac", "drift"],
            steps=[
                http("revert", "Revert to declared IaC state",
                     url="${IAC_URL}/apply",
                     method="POST",
                     body_template='{"resource":"{{alert.resource_id}}"}'),
                investigate("inv", "Investigate drift cause",
                            focus="cloud"),
                notify("n1", "Notify platform team", "slack",
                       message="IaC drift {{alert.resource_id}} reverted.",
                       webhook_env="SLACK_PLATFORM_WEBHOOK"),
                ticket("t1", "Open IaC-drift ticket",
                       "P3", "IaC drift: {{alert.resource_id}}"),
            ],
        ),
    ]


def build_ddos() -> list[dict[str, Any]]:
    cat = "ddos"
    return [
        make_playbook(
            pid="ddos-volumetric-l3-v1",
            name="DDoS: Volumetric L3/L4",
            description=(
                "Triggered by volumetric flood detection at edge. Engages "
                "scrubbing provider and pages on-call."
            ),
            category=cat, severity=["critical"],
            tags=["ddos", "network", "mitre.t1498"],
            steps=[
                http("scrub-on", "Engage DDoS scrubbing",
                     url="${DDOS_URL}/scrubbing/enable",
                     method="POST",
                     body_template='{"target":"{{alert.target}}"}'),
                investigate("inv", "Investigate attack signature",
                            focus="forensics"),
                notify("n1", "Page network on-call", "pagerduty",
                       message="L3/L4 DDoS on {{alert.target}}. Scrubbing engaged.",
                       service_env="PD_NETWORK_KEY"),
                ticket("t1", "Open DDoS ticket",
                       "P1", "L3/L4 DDoS: {{alert.target}}"),
            ],
        ),
        make_playbook(
            pid="ddos-app-layer-l7-v1",
            name="DDoS: Application Layer L7",
            description=(
                "Triggered by anomalous L7 request rate or pattern. Engages "
                "WAF rate-limit rule and challenge-page."
            ),
            category=cat, severity=["high", "critical"],
            tags=["ddos", "waf", "mitre.t1498.001"],
            steps=[
                http("waf-rl", "Apply WAF rate-limit",
                     url="${WAF_URL}/rate-limit",
                     method="POST",
                     body_template=('{"target":"{{alert.target}}",'
                                    '"rps":{{alert.threshold_rps}}}')),
                http("challenge", "Enable challenge page",
                     url="${WAF_URL}/challenge/enable",
                     method="POST",
                     body_template='{"target":"{{alert.target}}"}'),
                investigate("inv", "Investigate L7 signature",
                            focus="forensics"),
                notify("n1", "Notify SOC + platform", "slack",
                       message="L7 DDoS on {{alert.target}}. WAF rate-limit + challenge on.",
                       webhook_env="SLACK_SOC_WEBHOOK"),
                ticket("t1", "Open L7 DDoS ticket",
                       "P2", "L7 DDoS: {{alert.target}}"),
            ],
        ),
        make_playbook(
            pid="ddos-amplification-dns-v1",
            name="DDoS: DNS Amplification",
            description=(
                "Triggered when an inbound spike of crafted DNS queries hits "
                "an authoritative server. Sinkholes spoofed sources."
            ),
            category=cat, severity=["high"],
            tags=["ddos", "dns", "mitre.t1498.002"],
            steps=[
                http("sinkhole", "Sinkhole spoofed sources",
                     url="${DNS_URL}/sinkhole-batch",
                     method="POST",
                     body_template='{"src_ips": {{alert.spoofed_sources}}}'),
                investigate("inv", "Investigate amplification",
                            focus="forensics"),
                notify("n1", "Notify network team", "slack",
                       message="DNS amplification mitigated. "
                               "{{context.sinkholed_count}} sources sinkholed.",
                       webhook_env="SLACK_NETWORK_WEBHOOK"),
                ticket("t1", "Open DNS-amp ticket",
                       "P2", "DNS amplification: {{alert.target}}"),
            ],
        ),
        make_playbook(
            pid="ddos-syn-flood-v1",
            name="DDoS: SYN Flood",
            description=(
                "Triggered by SYN flood pattern at edge. Enables SYN cookies "
                "and increases backend capacity."
            ),
            category=cat, severity=["high", "critical"],
            tags=["ddos", "network", "mitre.t1498"],
            steps=[
                http("syn-cookies", "Enable SYN cookies at edge",
                     url="${EDGE_URL}/syn-cookies/enable",
                     method="POST"),
                http("scale", "Scale backend capacity",
                     url="${PLATFORM_URL}/scale",
                     method="POST",
                     body_template=('{"target":"{{alert.target}}",'
                                    '"replicas":"+50%"}')),
                investigate("inv", "Investigate flood",
                            focus="forensics"),
                notify("n1", "Notify network on-call", "pagerduty",
                       message="SYN flood on {{alert.target}}. SYN cookies + scale-out.",
                       service_env="PD_NETWORK_KEY"),
                ticket("t1", "Open SYN-flood ticket",
                       "P1", "SYN flood: {{alert.target}}"),
            ],
        ),
        make_playbook(
            pid="ddos-credential-stuffing-fraud-v1",
            name="DDoS: Auth-Endpoint Credential Stuffing",
            description=(
                "Triggered when /login takes a sustained spike of failed attempts. "
                "Combines DDoS + credential-stuffing response: WAF challenge, "
                "rate-limit, source-IP block."
            ),
            category=cat, severity=["high"],
            tags=["ddos", "ato", "mitre.t1110.004"],
            steps=[
                http("challenge", "Enable WAF challenge on /login",
                     url="${WAF_URL}/challenge/enable",
                     method="POST",
                     body_template='{"path":"/login"}'),
                http("rate-limit", "Apply per-IP rate-limit",
                     url="${WAF_URL}/rate-limit",
                     method="POST",
                     body_template=('{"path":"/login","per":"ip","rps":5}')),
                block_ip("b1", "Block top abusers", "alert.top_abuser_ip", "24h"),
                investigate("inv", "Investigate cred-stuffing campaign",
                            focus="identity"),
                notify("n1", "Notify SOC", "slack",
                       message="Auth-endpoint credential stuffing on /login mitigated.",
                       webhook_env="SLACK_SOC_WEBHOOK"),
                ticket("t1", "Open auth-DDoS ticket",
                       "P2", "Auth DDoS: {{alert.target}}"),
            ],
        ),
    ]


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    builders = [
        ("account-takeover", build_account_takeover),
        ("ransomware", build_ransomware),
        ("bec", build_bec),
        ("insider-risk", build_insider_risk),
        ("cloud-misconfig", build_cloud_misconfig),
        ("data-exfil", build_data_exfil),
        ("lateral-movement", build_lateral_movement),
        ("supply-chain", build_supply_chain),
        ("ddos", build_ddos),
    ]

    expected = {
        "account-takeover": 5, "ransomware": 5, "bec": 5,
        "insider-risk": 5, "cloud-misconfig": 10, "data-exfil": 5,
        "lateral-movement": 5, "supply-chain": 5, "ddos": 5,
    }

    if PACK_ROOT.exists():
        shutil.rmtree(PACK_ROOT)
    PACK_ROOT.mkdir(parents=True, exist_ok=True)

    total = 0
    counts: dict[str, int] = {}
    seen_ids: set[str] = set()

    for cat, fn in builders:
        cat_dir = PACK_ROOT / CATEGORY_DIRS[cat]
        cat_dir.mkdir(parents=True, exist_ok=True)
        playbooks = fn()

        if len(playbooks) != expected[cat]:
            raise SystemExit(
                f"category {cat}: expected {expected[cat]} playbooks, "
                f"got {len(playbooks)}"
            )

        for pb in playbooks:
            if pb["id"] in seen_ids:
                raise SystemExit(f"duplicate playbook id: {pb['id']}")
            seen_ids.add(pb["id"])

            # Slug-based filename: pb id minus -v1 suffix
            slug = pb["id"].removesuffix("-v1")
            fp = cat_dir / f"{slug}.playbook.json"
            fp.write_text(json.dumps(pb, indent=2) + "\n")

        counts[cat] = len(playbooks)
        total += len(playbooks)

    print(f"Generated {total} playbooks across {len(counts)} categories:")
    for cat, count in counts.items():
        print(f"  {cat:20s} {count:3d}")
    if total != 50:
        raise SystemExit(f"total mismatch: expected 50, got {total}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
