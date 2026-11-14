"""Deterministic mock connectors — offline / no-credentials fallback.

These mocks are the default when a tenant has not configured a vendor
for a given `ConnectorKind`. They reproduce the *exact* payloads the
pre-SDK tool handlers in ``app/tools/{siem,edr,idp,email_tool}.py``
returned, so:

  - the LLM tool surface keeps the same shape during the cutover, and
  - regression tests written against the old handlers continue to pass.

DO NOT change the shapes returned here without also updating the JSON
schemas in ``app/tools/*.py`` and the corresponding LLM tool definitions
— the runtime payloads cross the LLM boundary and changes will surface
as prompt-following regressions, not type errors.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from app.connectors.sdk.base import ConnectorConfig
from app.connectors.sdk.protocols import (
    BaseCloudConnector,
    BaseEdrConnector,
    BaseEmailConnector,
    BaseForensicsConnector,
    BaseIdpConnector,
    BaseSaaSConnector,
    BaseSiemConnector,
)


# ─── SIEM ────────────────────────────────────────────────────────────────


class MockSiemConnector(BaseSiemConnector):
    """Drop-in replacement for ``app/tools/siem.py`` mock outputs.

    Matches the response shapes documented at
    ``BaseSiemConnector.search_events`` and ``get_related_alerts``.
    """

    vendor = "mock"

    async def health_check(self) -> dict[str, Any]:
        return {"ok": True, "vendor": self.vendor, "kind": self.kind.value}

    async def search_events(
        self, *, entity: str, entity_type: str, minutes: int = 60
    ) -> dict[str, Any]:
        # Timestamps are relative to "now" to match the original mock
        # exactly; downstream consumers (graph, narrative) rely on the
        # events being inside the requested window.
        now = datetime.now(timezone.utc)
        return {
            "entity": entity,
            "entity_type": entity_type,
            "window_minutes": minutes,
            "events": [
                {
                    "ts": (now - timedelta(minutes=42)).isoformat(),
                    "type": "auth_success",
                    "src_ip": "10.4.21.118",
                    "user_agent": "Mozilla/5.0",
                },
                {
                    "ts": (now - timedelta(minutes=18)).isoformat(),
                    "type": "process_start",
                    "process": "powershell.exe",
                    "cmdline": (
                        "powershell -EncodedCommand "
                        "JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdA=="
                    ),
                    "parent": "winword.exe",
                },
                {
                    "ts": (now - timedelta(minutes=12)).isoformat(),
                    "type": "network_connection",
                    "dst_ip": "185.220.101.42",
                    "dst_port": 443,
                    "bytes_out": 184_320,
                },
            ],
        }

    async def get_related_alerts(
        self, *, entity: str, hours: int = 24
    ) -> dict[str, Any]:
        return {
            "entity": entity,
            "related_count": 2,
            "related": [
                {
                    "id": "ALR-9821",
                    "title": "Suspicious PowerShell encoded command",
                    "severity": "high",
                },
                {
                    "id": "ALR-9844",
                    "title": "Outbound to known TOR exit node",
                    "severity": "high",
                },
            ],
        }


# ─── EDR ─────────────────────────────────────────────────────────────────


class MockEdrConnector(BaseEdrConnector):
    """Drop-in replacement for ``app/tools/edr.py`` mock outputs.

    Adds a deterministic ``release_host`` payload — the protocol requires
    it (used by the reverse-actions handler) but the legacy mock module
    never exposed it. Tickets are namespaced ``REL-`` to make audit-log
    review obvious.
    """

    vendor = "mock"

    async def health_check(self) -> dict[str, Any]:
        return {"ok": True, "vendor": self.vendor, "kind": self.kind.value}

    async def get_process_tree(
        self, *, host: str, process_name: str | None = None
    ) -> dict[str, Any]:
        return {
            "host": host,
            "tree": [
                {
                    "pid": 4112,
                    "name": "outlook.exe",
                    "user": "tina.lee",
                    "children": [
                        {
                            "pid": 5240,
                            "name": "winword.exe",
                            "cmdline": "WINWORD.EXE /n /dde",
                            "children": [
                                {
                                    "pid": 6014,
                                    "name": "powershell.exe",
                                    "cmdline": (
                                        "powershell -EncodedCommand <REDACTED>"
                                    ),
                                    "signed": True,
                                    "suspicious": True,
                                    "children": [
                                        {
                                            "pid": 6190,
                                            "name": "rundll32.exe",
                                            "cmdline": (
                                                "rundll32 "
                                                "C:\\Users\\tina.lee\\AppData\\"
                                                "Local\\Temp\\a.dll,Run"
                                            ),
                                            "signed": False,
                                            "suspicious": True,
                                        }
                                    ],
                                }
                            ],
                        }
                    ],
                }
            ],
        }

    async def isolate_host(self, *, host: str, reason: str) -> dict[str, Any]:
        return {
            "host": host,
            "isolated": True,
            "reason": reason,
            "ticket": "ISO-44128",
        }

    async def release_host(self, *, host: str) -> dict[str, Any]:
        # No legacy mock for this — it's introduced by the SDK protocol so
        # the reverse-actions handler (t1-reverse-actions) has a symmetric
        # call to ``isolate_host``. Shape mirrors ``isolate_host`` minus
        # ``reason`` and flips ``isolated`` to False.
        return {
            "host": host,
            "isolated": False,
            "ticket": "REL-44128",
        }

    async def quarantine_file(self, *, sha256: str) -> dict[str, Any]:
        return {
            "sha256": sha256,
            "quarantined_on_endpoints": 3,
            "ticket": "QUA-7733",
        }

    async def restore_file(self, *, sha256: str) -> dict[str, Any]:
        # Reverse of quarantine_file. The hash-affected endpoints count is
        # echoed back from the legacy quarantine mock so paired rows are
        # symmetric.
        return {
            "sha256": sha256,
            "restored_on_endpoints": 3,
            "ticket": "REST-7733",
        }

    async def kill_process(self, *, host: str, pid: int) -> dict[str, Any]:
        return {"host": host, "pid": pid, "terminated": True}


# ─── IdP ─────────────────────────────────────────────────────────────────


class MockIdpConnector(BaseIdpConnector):
    """Drop-in replacement for ``app/tools/idp.py`` mock outputs."""

    vendor = "mock"

    async def health_check(self) -> dict[str, Any]:
        return {"ok": True, "vendor": self.vendor, "kind": self.kind.value}

    async def get_user(self, *, user: str) -> dict[str, Any]:
        return {
            "user": user,
            # Email format mirrors the legacy mock. Real IdP connectors
            # will resolve the actual primary email from the directory.
            "email": f"{user}@cyble.com",
            "department": "Finance",
            "manager": "marc.aldred",
            "groups": ["finance-prod", "okta-admins-no", "vpn-users"],
            "last_signin": {
                "ts": "2026-04-28T17:14:00Z",
                "src_ip": "203.0.113.55",
                "country": "VN",
                "asn": "AS45899 VNPT",
                "anomaly_score": 0.81,
            },
            "mfa_factors": ["webauthn", "okta_verify"],
        }

    async def revoke_sessions(self, *, user: str) -> dict[str, Any]:
        return {"user": user, "sessions_revoked": 4, "ticket": "REVOKE-22910"}

    async def disable_user(self, *, user: str, reason: str) -> dict[str, Any]:
        return {"user": user, "disabled": True, "reason": reason}

    async def reset_password(self, *, user: str) -> dict[str, Any]:
        return {"user": user, "reset_email_sent": True}

    async def enable_user(self, *, user: str) -> dict[str, Any]:
        # Reverse of disable_user. Ticket prefix `ENABLE-` keeps audit-log
        # filtering trivial.
        return {"user": user, "disabled": False, "ticket": "ENABLE-22910"}

    # ── ITDR mocks (t2c-itdr) ──────────────────────────────────────────
    # Deterministic story: one benign in-country session (corp laptop),
    # one obvious AitM session (Vietnam ASN, evilginx user-agent
    # fingerprint, mfa "satisfied" via stolen cookie), and one stale
    # session from a country the user has visited before. The ITDR
    # sub-agent should flag exactly the AitM session for targeted
    # revoke and keep the others.
    async def list_user_sessions(self, *, user: str) -> dict[str, Any]:
        return {
            "user": user,
            "count": 3,
            "sessions": [
                {
                    "session_id": "sess-corp-mbp-001",
                    "ts_created": "2026-04-28T08:02:11Z",
                    "last_seen": "2026-04-28T17:01:45Z",
                    "src_ip": "10.42.7.55",
                    "country": "US",
                    "asn": "AS-CYBLE-CORP",
                    "user_agent": (
                        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) "
                        "AppleWebKit/605.1.15 Safari/605.1.15"
                    ),
                    "mfa_method": "webauthn",
                    "anomaly_score": 0.05,
                    "suspected_aitm": False,
                    "device_managed": True,
                },
                {
                    "session_id": "sess-aitm-vn-9912",
                    "ts_created": "2026-04-28T17:14:02Z",
                    "last_seen": "2026-04-28T17:18:33Z",
                    "src_ip": "203.0.113.55",
                    "country": "VN",
                    "asn": "AS45899 VNPT",
                    # Evilginx2 fingerprint: missing sec-ch-ua headers
                    # and re-uses a stale Chrome UA string.
                    "user_agent": (
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/119.0.0.0 Safari/537.36"
                    ),
                    # MFA "satisfied" via stolen session cookie, not a
                    # real factor challenge — the give-away.
                    "mfa_method": "cookie_replay",
                    "anomaly_score": 0.94,
                    "suspected_aitm": True,
                    "device_managed": False,
                },
                {
                    "session_id": "sess-mobile-uk-7733",
                    "ts_created": "2026-04-26T09:21:08Z",
                    "last_seen": "2026-04-27T22:11:09Z",
                    "src_ip": "82.40.12.7",
                    "country": "GB",
                    "asn": "AS5089 VIRGINMEDIA",
                    "user_agent": (
                        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) "
                        "AppleWebKit/605.1.15"
                    ),
                    "mfa_method": "okta_verify",
                    "anomaly_score": 0.21,
                    "suspected_aitm": False,
                    "device_managed": True,
                },
            ],
        }

    async def revoke_session(
        self, *, user: str, session_id: str, reason: str | None = None
    ) -> dict[str, Any]:
        return {
            "user": user,
            "session_id": session_id,
            "revoked": True,
            "reason": reason,
            "ticket": f"SESSREV-{session_id[-4:]}",
        }

    async def list_oauth_grants(self, *, user: str) -> dict[str, Any]:
        # One legit grant (Slack, verified publisher, narrow scopes,
        # in active use), one classic illicit-consent-grant red flag
        # (unverified publisher, mailbox-wide read, granted right
        # after the AitM session above, never used since).
        return {
            "user": user,
            "grants": [
                {
                    "grant_id": "grant-slack-001",
                    "client_id": "0oa1slackclient",
                    "app_name": "Slack for Workspaces",
                    "scopes": ["openid", "profile", "email"],
                    "granted_at": "2025-11-03T12:00:00Z",
                    "last_used": "2026-04-28T16:55:00Z",
                    "publisher_verified": True,
                    "risk_score": 0.02,
                },
                {
                    "grant_id": "grant-mailrelay-9912",
                    "client_id": "0oa9mailrelay",
                    # Looks legitimate-ish, but publisher is
                    # unverified and scopes are catastrophic.
                    "app_name": "Mail Relay Sync",
                    "scopes": [
                        "Mail.ReadWrite",
                        "Mail.Send",
                        "MailboxSettings.ReadWrite",
                        "offline_access",
                    ],
                    "granted_at": "2026-04-28T17:14:30Z",
                    "last_used": None,
                    "publisher_verified": False,
                    "risk_score": 0.91,
                },
            ],
        }

    async def revoke_oauth_grant(
        self, *, user: str, grant_id: str, reason: str | None = None
    ) -> dict[str, Any]:
        return {
            "user": user,
            "grant_id": grant_id,
            "revoked": True,
            "reason": reason,
            "ticket": f"GRANTREV-{grant_id[-4:]}",
        }

    async def list_oauth_apps(self) -> dict[str, Any]:
        return {
            "apps": [
                {
                    "client_id": "0oa1slackclient",
                    "app_name": "Slack for Workspaces",
                    "publisher": "Slack Technologies, LLC",
                    "publisher_verified": True,
                    "scopes_requested": ["openid", "profile", "email"],
                    "total_users_granted": 412,
                    "first_seen": "2024-02-11T00:00:00Z",
                },
                {
                    "client_id": "0oa9mailrelay",
                    "app_name": "Mail Relay Sync",
                    "publisher": "MRS Holdings",
                    "publisher_verified": False,
                    "scopes_requested": [
                        "Mail.ReadWrite",
                        "Mail.Send",
                        "MailboxSettings.ReadWrite",
                        "offline_access",
                    ],
                    "total_users_granted": 3,
                    "first_seen": "2026-04-26T03:11:22Z",
                },
            ],
        }


# ─── Cloud (CDR / t2d) ──────────────────────────────────────────────────


class MockCloudConnector(BaseCloudConnector):
    """Deterministic AWS-shaped cloud connector for the CDR sub-agent.

    Story baked into the mock (so the CDR agent has something concrete
    to grade against):

      * Two human IAM users — ``finance.tina`` (normal) and
        ``svc.legacy-deploy`` (a forgotten service-account-style user
        with an Active, unused-for-90d access key — classic abandoned
        credential).
      * One legit role ``role/ReadOnlyAnalyst`` and one over-privileged
        role ``role/PowerUser-temp`` with wildcard policy.
      * STS sessions include a *suspicious assume-role chain*:
        ``svc.legacy-deploy`` → ``role/PowerUser-temp`` → ``role/Admin-bootstrap``
        sourced from a Vietnam ASN — the canonical "leaked key pivots
        to admin" pattern the CDR agent must catch.
      * One ClusterRoleBinding binding a default ServiceAccount to
        cluster-admin (the kubectl-equivalent of the AWS chain).

    All write methods return ``deactivated``/``attached``/``deleted``
    True so HITL approval paths can be exercised end-to-end.
    """

    vendor = "mock"

    async def health_check(self) -> dict[str, Any]:
        return {"ok": True, "vendor": self.vendor, "kind": self.kind.value}

    async def list_iam_principals(
        self, *, limit: int = 200
    ) -> dict[str, Any]:
        principals = [
            {
                "principal_id": "AIDA1111EXAMPLE",
                "principal_type": "user",
                "name": "finance.tina",
                "arn": "arn:aws:iam::123456789012:user/finance.tina",
                "created_at": "2024-09-12T11:02:00Z",
                "last_used": "2026-04-28T16:50:00Z",
                "mfa_enabled": True,
                "tags": {"team": "finance"},
                "attached_policies": ["arn:aws:iam::aws:policy/ReadOnlyAccess"],
                "risk_score": 0.04,
            },
            {
                "principal_id": "AIDA2222LEGACY",
                "principal_type": "user",
                "name": "svc.legacy-deploy",
                "arn": "arn:aws:iam::123456789012:user/svc.legacy-deploy",
                "created_at": "2022-01-04T08:15:00Z",
                # Unused for >90 days — classic abandoned credential.
                "last_used": "2025-12-30T09:11:00Z",
                "mfa_enabled": False,
                "tags": {"team": "platform", "owner": "ex-employee"},
                "attached_policies": [
                    "arn:aws:iam::123456789012:policy/LegacyDeployPolicy",
                ],
                "risk_score": 0.78,
            },
            {
                "principal_id": "AROA3333READONLY",
                "principal_type": "role",
                "name": "ReadOnlyAnalyst",
                "arn": "arn:aws:iam::123456789012:role/ReadOnlyAnalyst",
                "created_at": "2024-03-01T00:00:00Z",
                "last_used": "2026-04-28T15:00:00Z",
                "mfa_enabled": False,
                "tags": {},
                "attached_policies": ["arn:aws:iam::aws:policy/ReadOnlyAccess"],
                "risk_score": 0.05,
            },
            {
                "principal_id": "AROA4444POWERTEMP",
                "principal_type": "role",
                "name": "PowerUser-temp",
                "arn": "arn:aws:iam::123456789012:role/PowerUser-temp",
                "created_at": "2023-07-19T00:00:00Z",
                "last_used": "2026-04-28T17:15:00Z",
                "mfa_enabled": False,
                "tags": {"created_for": "one-off-migration-2023"},
                # Wildcard policy on a "temporary" role that never left.
                "attached_policies": [
                    "arn:aws:iam::123456789012:policy/WildcardActionStar",
                ],
                "risk_score": 0.88,
            },
        ]
        return {"principals": principals[:limit], "count": len(principals)}

    async def get_iam_principal(
        self, *, principal: str
    ) -> dict[str, Any]:
        # Mock returns a concrete shape for either pivot principal in the
        # baked story; everything else gets a stub.
        if "svc.legacy-deploy" in principal:
            return {
                "principal_id": "AIDA2222LEGACY",
                "principal_type": "user",
                "name": "svc.legacy-deploy",
                "arn": "arn:aws:iam::123456789012:user/svc.legacy-deploy",
                "attached_policies": [
                    "arn:aws:iam::123456789012:policy/LegacyDeployPolicy",
                ],
                "inline_policies": [],
                "access_keys": [
                    {
                        "key_id": "AKIALEGACY1111",
                        "status": "Active",
                        "created_at": "2022-01-04T08:15:00Z",
                        "last_used": "2025-12-30T09:11:00Z",
                    },
                ],
                "assumed_by": [],
                "can_assume": [
                    "arn:aws:iam::123456789012:role/PowerUser-temp",
                ],
                "tags": {"team": "platform", "owner": "ex-employee"},
            }
        if "PowerUser-temp" in principal:
            return {
                "principal_id": "AROA4444POWERTEMP",
                "principal_type": "role",
                "name": "PowerUser-temp",
                "arn": "arn:aws:iam::123456789012:role/PowerUser-temp",
                "attached_policies": [
                    "arn:aws:iam::123456789012:policy/WildcardActionStar",
                ],
                "inline_policies": [],
                "access_keys": [],
                "assumed_by": [
                    "arn:aws:iam::123456789012:user/svc.legacy-deploy",
                ],
                "can_assume": [
                    "arn:aws:iam::123456789012:role/Admin-bootstrap",
                ],
                "tags": {"created_for": "one-off-migration-2023"},
            }
        return {
            "principal_id": "AIDAUNKNOWN",
            "principal_type": "user",
            "name": principal,
            "arn": f"arn:aws:iam::123456789012:user/{principal}",
            "attached_policies": [],
            "inline_policies": [],
            "access_keys": [],
            "assumed_by": [],
            "can_assume": [],
            "tags": {},
        }

    async def list_access_keys(
        self, *, user: str
    ) -> dict[str, Any]:
        if "svc.legacy-deploy" in user:
            return {
                "user": user,
                "keys": [
                    {
                        "key_id": "AKIALEGACY1111",
                        "status": "Active",
                        "created_at": "2022-01-04T08:15:00Z",
                        "last_used": "2025-12-30T09:11:00Z",
                        "last_used_service": "sts",
                        "last_used_region": "ap-southeast-1",
                        # Asia-Pacific use from a US-only finance org →
                        # high anomaly score.
                        "anomaly_score": 0.92,
                    }
                ],
            }
        return {"user": user, "keys": []}

    async def list_sts_sessions(
        self, *, principal: str | None = None, hours: int = 24
    ) -> dict[str, Any]:
        sessions = [
            {
                "session_id": "sts-legacy-pivot-aaaa",
                "started_at": "2026-04-28T17:15:02Z",
                "source_principal": (
                    "arn:aws:iam::123456789012:user/svc.legacy-deploy"
                ),
                "assumed_role": (
                    "arn:aws:iam::123456789012:role/PowerUser-temp"
                ),
                "source_ip": "203.0.113.55",
                "country": "VN",
                "asn": "AS45899 VNPT",
                "user_agent": "aws-cli/2.15.0 Python/3.11 Linux/5.15",
                "mfa_used": False,
                "chain_depth": 1,
                "anomaly_score": 0.93,
            },
            {
                "session_id": "sts-legacy-pivot-bbbb",
                "started_at": "2026-04-28T17:16:30Z",
                "source_principal": (
                    "arn:aws:iam::123456789012:role/PowerUser-temp"
                ),
                "assumed_role": (
                    "arn:aws:iam::123456789012:role/Admin-bootstrap"
                ),
                "source_ip": "203.0.113.55",
                "country": "VN",
                "asn": "AS45899 VNPT",
                "user_agent": "aws-cli/2.15.0 Python/3.11 Linux/5.15",
                "mfa_used": False,
                # Chain depth 2 from a non-admin starting point → very
                # high anomaly.
                "chain_depth": 2,
                "anomaly_score": 0.97,
            },
            {
                "session_id": "sts-normal-cccc",
                "started_at": "2026-04-28T15:00:00Z",
                "source_principal": (
                    "arn:aws:iam::123456789012:user/finance.tina"
                ),
                "assumed_role": (
                    "arn:aws:iam::123456789012:role/ReadOnlyAnalyst"
                ),
                "source_ip": "10.42.7.55",
                "country": "US",
                "asn": "AS-CYBLE-CORP",
                "user_agent": "aws-cli/2.15.0 Python/3.11 Darwin/23.6",
                "mfa_used": True,
                "chain_depth": 1,
                "anomaly_score": 0.05,
            },
        ]
        if principal:
            sessions = [
                s
                for s in sessions
                if principal in s["source_principal"]
                or principal in s["assumed_role"]
            ]
        return {"sessions": sessions, "count": len(sessions)}

    async def trace_assume_role_chain(
        self, *, session_id: str
    ) -> dict[str, Any]:
        # Walk the baked chain back. For the second hop (Admin-bootstrap)
        # we surface both legs so the agent can see the full pivot.
        if session_id in {"sts-legacy-pivot-bbbb"}:
            return {
                "session_id": session_id,
                "chain": [
                    {
                        "principal_arn": (
                            "arn:aws:iam::123456789012:user/svc.legacy-deploy"
                        ),
                        "action": "AssumeRole",
                        "ts": "2026-04-28T17:15:02Z",
                    },
                    {
                        "principal_arn": (
                            "arn:aws:iam::123456789012:role/PowerUser-temp"
                        ),
                        "action": "AssumeRole",
                        "ts": "2026-04-28T17:16:30Z",
                    },
                    {
                        "principal_arn": (
                            "arn:aws:iam::123456789012:role/Admin-bootstrap"
                        ),
                        "action": "session-active",
                        "ts": "2026-04-28T17:16:31Z",
                    },
                ],
                "origin_principal": (
                    "arn:aws:iam::123456789012:user/svc.legacy-deploy"
                ),
                "depth": 2,
                "suspicious": True,
                "reasons": [
                    "Chain originates from abandoned IAM user "
                    "(no MFA, key unused >90d).",
                    "Each hop sourced from VN ASN, never seen for this account.",
                    "Final role is Admin-bootstrap (privileged), reached via "
                    "PowerUser-temp wildcard policy.",
                ],
            }
        if session_id == "sts-legacy-pivot-aaaa":
            return {
                "session_id": session_id,
                "chain": [
                    {
                        "principal_arn": (
                            "arn:aws:iam::123456789012:user/svc.legacy-deploy"
                        ),
                        "action": "AssumeRole",
                        "ts": "2026-04-28T17:15:02Z",
                    },
                    {
                        "principal_arn": (
                            "arn:aws:iam::123456789012:role/PowerUser-temp"
                        ),
                        "action": "session-active",
                        "ts": "2026-04-28T17:15:03Z",
                    },
                ],
                "origin_principal": (
                    "arn:aws:iam::123456789012:user/svc.legacy-deploy"
                ),
                "depth": 1,
                "suspicious": True,
                "reasons": [
                    "Source principal is unused for 90d, no MFA, VN source IP.",
                ],
            }
        return {
            "session_id": session_id,
            "chain": [],
            "origin_principal": None,
            "depth": 0,
            "suspicious": False,
            "reasons": [],
        }

    async def list_k8s_rolebindings(
        self, *, namespace: str | None = None
    ) -> dict[str, Any]:
        bindings = [
            {
                "name": "default-cluster-admin",
                "namespace": None,  # cluster-scoped
                "kind": "ClusterRoleBinding",
                "role_ref": "ClusterRole/cluster-admin",
                "subjects": [
                    {
                        "kind": "ServiceAccount",
                        "name": "default",
                        "namespace": "kube-system",
                    }
                ],
                "created_at": "2026-04-28T17:18:00Z",
                # Default SA bound to cluster-admin, freshly created,
                # right after the AWS pivot above. Classic K8s breakout.
                "risk_score": 0.96,
                "reasons": [
                    "ServiceAccount 'default' bound to cluster-admin.",
                    "Binding created <5 minutes ago — outside change window.",
                ],
            },
            {
                "name": "finance-readonly",
                "namespace": "finance",
                "kind": "RoleBinding",
                "role_ref": "ClusterRole/view",
                "subjects": [
                    {
                        "kind": "Group",
                        "name": "finance-analysts",
                    }
                ],
                "created_at": "2024-03-12T00:00:00Z",
                "risk_score": 0.03,
                "reasons": [],
            },
        ]
        if namespace is not None:
            bindings = [
                b
                for b in bindings
                if b["namespace"] == namespace
                or (namespace == "*" and b["namespace"] is None)
            ]
        return {"bindings": bindings, "count": len(bindings)}

    async def deactivate_access_key(
        self,
        *,
        user: str,
        key_id: str,
        reason: str | None = None,
    ) -> dict[str, Any]:
        return {
            "user": user,
            "key_id": key_id,
            "deactivated": True,
            "reason": reason,
            "ticket": f"AKDEACT-{key_id[-4:]}",
        }

    async def attach_deny_policy(
        self,
        *,
        principal: str,
        reason: str | None = None,
    ) -> dict[str, Any]:
        return {
            "principal": principal,
            "policy_arn": "arn:aws:iam::123456789012:policy/AiSOC-Quarantine-Deny",
            "attached": True,
            "reason": reason,
            "ticket": f"DENY-{abs(hash(principal)) % 10_000:04d}",
        }

    async def delete_k8s_rolebinding(
        self,
        *,
        name: str,
        namespace: str | None = None,
        reason: str | None = None,
    ) -> dict[str, Any]:
        return {
            "name": name,
            "namespace": namespace,
            "kind": "RoleBinding" if namespace else "ClusterRoleBinding",
            "deleted": True,
            "reason": reason,
            "ticket": f"RBDEL-{abs(hash(name)) % 10_000:04d}",
        }


# ─── Email ───────────────────────────────────────────────────────────────


class MockEmailConnector(BaseEmailConnector):
    """Drop-in replacement for ``app/tools/email_tool.py`` mock outputs."""

    vendor = "mock"

    async def health_check(self) -> dict[str, Any]:
        return {"ok": True, "vendor": self.vendor, "kind": self.kind.value}

    async def analyze_message(self, *, message_id: str) -> dict[str, Any]:
        return {
            "message_id": message_id,
            "from": "billing@m1crosoft-secure.com",
            "auth": {"spf": "fail", "dkim": "none", "dmarc": "fail"},
            "links": [
                {"url": "https://evil-update.duckdns.org/login", "risk": "high"},
            ],
            "attachments": [
                {
                    "filename": "Invoice_April.docm",
                    "sha256": (
                        "9c2a4e1a7b8d3f6e0c1b5a9d8e7f6c5b"
                        "4a3d2e1f0c9b8a7d6e5f4c3b2a1d0e9f"
                    ),
                    "macros": True,
                },
            ],
            "suspicion_score": 0.94,
        }

    async def clawback_message(self, *, message_id: str) -> dict[str, Any]:
        return {
            "message_id": message_id,
            "recipients_affected": 47,
            "status": "quarantined",
        }

    async def block_sender(self, *, sender: str) -> dict[str, Any]:
        return {"sender": sender, "blocked": True}

    async def restore_message(self, *, message_id: str) -> dict[str, Any]:
        # Reverse of clawback_message. Real providers (M365, Proofpoint)
        # only restore from quarantine, not from purged mailboxes — the
        # mock reflects best-case "fully restored" so HITL paths can be
        # tested deterministically.
        return {
            "message_id": message_id,
            "recipients_affected": 47,
            "status": "restored",
        }

    async def unblock_sender(self, *, sender: str) -> dict[str, Any]:
        return {"sender": sender, "blocked": False}


# ─── SaaS Security Posture (SSPM) ────────────────────────────────────────


class MockSaaSConnector(BaseSaaSConnector):
    """Deterministic SSPM story spanning M365, Workspace, Salesforce, GitHub, Slack.

    Multiplexes across all five providers in v1 (Theme 2e). The fixture
    is shaped so the SaaS Posture agent (and its deterministic backstop)
    can show meaningful cross-provider findings: a high-risk un-verified
    OAuth app on M365, a public Workspace Drive folder with payroll
    data, a Salesforce admin profile with MFA off, a public GitHub
    repository containing an exposed secret, and a Slack workspace with
    a wide-scope third-party app installed by a non-admin.
    """

    vendor = "mock"

    async def health_check(self) -> dict[str, Any]:
        return {"ok": True, "vendor": self.vendor, "kind": self.kind.value}

    # All providers we know how to answer for. Anything outside this set
    # gets a clean empty response with a `provider_supported=False` hint
    # so the agent can route around it without crashing.
    _PROVIDERS = ("m365", "workspace", "salesforce", "github", "slack")

    @classmethod
    def _filter_provider(cls, provider: str | None) -> tuple[str, ...]:
        if provider is None:
            return cls._PROVIDERS
        provider = provider.lower()
        if provider not in cls._PROVIDERS:
            return ()
        return (provider,)

    async def list_applications(
        self, *, provider: str | None = None
    ) -> dict[str, Any]:
        now = datetime.now(timezone.utc)
        catalog: dict[str, list[dict[str, Any]]] = {
            "m365": [
                {
                    "app_id": "m365-app-0001",
                    "provider": "m365",
                    "name": "ContosoDocSign",
                    "vendor": "Unverified Publisher",
                    "installed_at": (now - timedelta(days=3)).isoformat(),
                    "scopes": [
                        "Mail.Read",
                        "Files.Read.All",
                        "User.Read.All",
                    ],
                    "install_user_count": 1,
                    "publisher_verified": False,
                    "risk_score": 0.91,
                    "reasons": [
                        "Unverified publisher",
                        "Broad scopes incl. Mail.Read + Files.Read.All",
                        "Installed 3 days ago by a non-admin user",
                    ],
                },
                {
                    "app_id": "m365-app-0002",
                    "provider": "m365",
                    "name": "Microsoft Teams",
                    "vendor": "Microsoft",
                    "installed_at": (now - timedelta(days=420)).isoformat(),
                    "scopes": ["User.Read"],
                    "install_user_count": 540,
                    "publisher_verified": True,
                    "risk_score": 0.05,
                    "reasons": [],
                },
            ],
            "workspace": [
                {
                    "app_id": "gw-app-0001",
                    "provider": "workspace",
                    "name": "DriveSyncPro",
                    "vendor": "drivesyncpro.io",
                    "installed_at": (now - timedelta(days=14)).isoformat(),
                    "scopes": [
                        "https://www.googleapis.com/auth/drive",
                        "https://www.googleapis.com/auth/gmail.readonly",
                    ],
                    "install_user_count": 38,
                    "publisher_verified": False,
                    "risk_score": 0.84,
                    "reasons": [
                        "Drive full-access scope",
                        "Gmail readonly scope",
                        "Publisher domain registered <90d ago",
                    ],
                },
            ],
            "salesforce": [
                {
                    "app_id": "sf-app-0001",
                    "provider": "salesforce",
                    "name": "DataLoader.io",
                    "vendor": "Mulesoft",
                    "installed_at": (now - timedelta(days=180)).isoformat(),
                    "scopes": ["api", "refresh_token"],
                    "install_user_count": 12,
                    "publisher_verified": True,
                    "risk_score": 0.30,
                    "reasons": [
                        "Long-lived refresh_token scope (informational)",
                    ],
                },
            ],
            "github": [
                {
                    "app_id": "gh-app-0001",
                    "provider": "github",
                    "name": "MarketplaceCIBot",
                    "vendor": "Unverified Publisher",
                    "installed_at": (now - timedelta(days=6)).isoformat(),
                    "scopes": ["repo", "admin:org", "workflow"],
                    "install_user_count": 1,
                    "publisher_verified": False,
                    "risk_score": 0.88,
                    "reasons": [
                        "admin:org granted",
                        "Unverified publisher",
                        "Single installer, recent",
                    ],
                },
            ],
            "slack": [
                {
                    "app_id": "slack-app-0001",
                    "provider": "slack",
                    "name": "ExternalChatBridge",
                    "vendor": "bridgechat.app",
                    "installed_at": (now - timedelta(days=2)).isoformat(),
                    "scopes": [
                        "channels:history",
                        "channels:read",
                        "im:history",
                        "files:read",
                        "chat:write",
                    ],
                    "install_user_count": 1,
                    "publisher_verified": False,
                    "risk_score": 0.90,
                    "reasons": [
                        "im:history + channels:history (read all DMs/channels)",
                        "Installed 2 days ago by non-admin",
                        "Publisher unverified",
                    ],
                },
            ],
        }
        wanted = self._filter_provider(provider)
        apps: list[dict[str, Any]] = []
        for p in wanted:
            apps.extend(catalog.get(p, []))
        return {"applications": apps, "count": len(apps)}

    async def list_misconfigurations(
        self, *, provider: str | None = None
    ) -> dict[str, Any]:
        now = datetime.now(timezone.utc).isoformat()
        catalog: dict[str, list[dict[str, Any]]] = {
            "m365": [
                {
                    "provider": "m365",
                    "control_id": "M365-IAM-001",
                    "control_name": "Legacy auth blocked org-wide",
                    "severity": "high",
                    "current_value": "Allowed",
                    "recommended_value": "Blocked",
                    "evidence_url": "https://entra.example/policies/legacyAuth",
                    "last_checked": now,
                    "remediation_hint": (
                        "Set Conditional Access policy to block legacy "
                        "authentication for all users."
                    ),
                },
            ],
            "workspace": [
                {
                    "provider": "workspace",
                    "control_id": "GW-IAM-002",
                    "control_name": "Less-secure-apps disabled",
                    "severity": "medium",
                    "current_value": "Enabled",
                    "recommended_value": "Disabled",
                    "evidence_url": "https://admin.example/security/lsa",
                    "last_checked": now,
                    "remediation_hint": (
                        "Disable access for less-secure apps in Admin "
                        "Console → Security."
                    ),
                },
            ],
            "salesforce": [
                {
                    "provider": "salesforce",
                    "control_id": "SF-IAM-003",
                    "control_name": "System Administrator profile MFA",
                    "severity": "critical",
                    "current_value": "Not Required",
                    "recommended_value": "Required",
                    "evidence_url": (
                        "https://login.example/setup/profile/SysAdmin"
                    ),
                    "last_checked": now,
                    "remediation_hint": (
                        "Enable 'Multi-Factor Authentication for User "
                        "Interface Logins' on the System Administrator "
                        "profile."
                    ),
                },
            ],
            "github": [
                {
                    "provider": "github",
                    "control_id": "GH-SCM-001",
                    "control_name": "Branch protection on default branch",
                    "severity": "high",
                    "current_value": "Disabled (main)",
                    "recommended_value": "Required reviews + status checks",
                    "evidence_url": (
                        "https://github.example/contoso/payroll/settings/"
                        "branches"
                    ),
                    "last_checked": now,
                    "remediation_hint": (
                        "Enable branch protection on `main` with required "
                        "PR reviews and signed commits."
                    ),
                },
            ],
            "slack": [
                {
                    "provider": "slack",
                    "control_id": "SLACK-APP-001",
                    "control_name": "Non-admin app install allowed",
                    "severity": "high",
                    "current_value": "Anyone can install",
                    "recommended_value": "Admin approval required",
                    "evidence_url": (
                        "https://contoso.slack.example/admin/settings"
                    ),
                    "last_checked": now,
                    "remediation_hint": (
                        "Require admin approval for all app installations "
                        "in workspace settings."
                    ),
                },
            ],
        }
        wanted = self._filter_provider(provider)
        findings: list[dict[str, Any]] = []
        for p in wanted:
            findings.extend(catalog.get(p, []))
        return {"findings": findings, "count": len(findings)}

    async def list_external_shares(
        self, *, provider: str | None = None, limit: int = 200
    ) -> dict[str, Any]:
        now = datetime.now(timezone.utc)
        catalog: dict[str, list[dict[str, Any]]] = {
            "m365": [
                {
                    "share_id": "m365-share-0001",
                    "provider": "m365",
                    "resource_type": "onedrive-file",
                    "resource_name": "Q4-board-deck.pptx",
                    "resource_url": (
                        "https://contoso.sharepoint.example/personal/"
                        "ceo/Documents/Q4-board-deck.pptx"
                    ),
                    "shared_with": "anyone-with-link",
                    "external_principals": [],
                    "created_at": (now - timedelta(days=2)).isoformat(),
                    "last_accessed": (now - timedelta(hours=4)).isoformat(),
                    "contains_sensitive": True,
                    "risk_score": 0.88,
                    "reasons": [
                        "Anyone-with-link share on file labeled "
                        "'Confidential'",
                        "Accessed from non-corporate ASN in last 24h",
                    ],
                },
            ],
            "workspace": [
                {
                    "share_id": "gw-share-0001",
                    "provider": "workspace",
                    "resource_type": "drive-folder",
                    "resource_name": "/Payroll/2026",
                    "resource_url": (
                        "https://drive.example/d/folders/0Ax1payroll2026"
                    ),
                    "shared_with": "public",
                    "external_principals": [],
                    "created_at": (now - timedelta(days=21)).isoformat(),
                    "last_accessed": (now - timedelta(hours=1)).isoformat(),
                    "contains_sensitive": True,
                    "risk_score": 0.95,
                    "reasons": [
                        "Public-to-the-internet Drive folder",
                        "Contains files matching DLP rule 'Payroll PII'",
                        "Accessed 47 times in last 7d from outside org",
                    ],
                },
            ],
            "salesforce": [
                {
                    "share_id": "sf-share-0001",
                    "provider": "salesforce",
                    "resource_type": "report",
                    "resource_name": "Customer master export",
                    "resource_url": (
                        "https://login.example/lightning/r/Report/"
                        "00O1xCustomerMaster"
                    ),
                    "shared_with": "external-domain",
                    "external_principals": ["@vendor-old.example"],
                    "created_at": (now - timedelta(days=400)).isoformat(),
                    "last_accessed": (now - timedelta(days=2)).isoformat(),
                    "contains_sensitive": True,
                    "risk_score": 0.78,
                    "reasons": [
                        "Shared with vendor domain whose contract ended",
                    ],
                },
            ],
            "github": [
                {
                    "share_id": "gh-share-0001",
                    "provider": "github",
                    "resource_type": "repo",
                    "resource_name": "contoso/payroll-ingest",
                    "resource_url": (
                        "https://github.example/contoso/payroll-ingest"
                    ),
                    "shared_with": "public",
                    "external_principals": [],
                    "created_at": (now - timedelta(days=30)).isoformat(),
                    "last_accessed": (now - timedelta(minutes=15)).isoformat(),
                    "contains_sensitive": True,
                    "risk_score": 0.97,
                    "reasons": [
                        "Public repo on an internal-tooling org",
                        "Secret scanner flagged AWS_SECRET_ACCESS_KEY in "
                        "commit a1b2c3d4",
                    ],
                },
            ],
            "slack": [
                {
                    "share_id": "slack-share-0001",
                    "provider": "slack",
                    "resource_type": "channel",
                    "resource_name": "#partner-eng",
                    "resource_url": "https://contoso.slack.example/archives/CPART01",
                    "shared_with": "external-domain",
                    "external_principals": ["@vendor-old.example"],
                    "created_at": (now - timedelta(days=200)).isoformat(),
                    "last_accessed": (now - timedelta(hours=3)).isoformat(),
                    "contains_sensitive": False,
                    "risk_score": 0.60,
                    "reasons": [
                        "External guest from off-boarded vendor still in "
                        "channel",
                    ],
                },
            ],
        }
        wanted = self._filter_provider(provider)
        shares: list[dict[str, Any]] = []
        for p in wanted:
            shares.extend(catalog.get(p, []))
        return {"shares": shares[:limit], "count": len(shares)}

    async def list_third_party_integrations(
        self, *, provider: str | None = None
    ) -> dict[str, Any]:
        now = datetime.now(timezone.utc)
        catalog: dict[str, list[dict[str, Any]]] = {
            "m365": [
                {
                    "grant_id": "m365-grant-0001",
                    "provider": "m365",
                    "app_id": "m365-app-0001",
                    "app_name": "ContosoDocSign",
                    "publisher": "Unverified Publisher",
                    "publisher_verified": False,
                    "scopes": [
                        "Mail.Read",
                        "Files.Read.All",
                        "User.Read.All",
                    ],
                    "granted_by_user": "[email protected]",
                    "granted_at": (now - timedelta(days=3)).isoformat(),
                    "last_used": (now - timedelta(hours=2)).isoformat(),
                    "total_users_granted": 1,
                    "risk_score": 0.93,
                    "reasons": [
                        "Illicit-consent shape: solo install, broad scopes, "
                        "unverified publisher",
                        "Granted by user whose mailbox was flagged in "
                        "phishing case 24h earlier",
                    ],
                },
            ],
            "workspace": [
                {
                    "grant_id": "gw-grant-0001",
                    "provider": "workspace",
                    "app_id": "gw-app-0001",
                    "app_name": "DriveSyncPro",
                    "publisher": "drivesyncpro.io",
                    "publisher_verified": False,
                    "scopes": [
                        "https://www.googleapis.com/auth/drive",
                        "https://www.googleapis.com/auth/gmail.readonly",
                    ],
                    "granted_by_user": "[email protected]",
                    "granted_at": (now - timedelta(days=14)).isoformat(),
                    "last_used": (now - timedelta(hours=6)).isoformat(),
                    "total_users_granted": 38,
                    "risk_score": 0.86,
                    "reasons": [
                        "Broad Drive + Gmail scopes",
                        "Publisher domain <90d old",
                    ],
                },
            ],
            "github": [
                {
                    "grant_id": "gh-grant-0001",
                    "provider": "github",
                    "app_id": "gh-app-0001",
                    "app_name": "MarketplaceCIBot",
                    "publisher": "Unverified Publisher",
                    "publisher_verified": False,
                    "scopes": ["repo", "admin:org", "workflow"],
                    "granted_by_user": "[email protected]",
                    "granted_at": (now - timedelta(days=6)).isoformat(),
                    "last_used": (now - timedelta(hours=12)).isoformat(),
                    "total_users_granted": 1,
                    "risk_score": 0.89,
                    "reasons": [
                        "admin:org via OAuth (lateral takeover risk)",
                    ],
                },
            ],
            "slack": [
                {
                    "grant_id": "slack-grant-0001",
                    "provider": "slack",
                    "app_id": "slack-app-0001",
                    "app_name": "ExternalChatBridge",
                    "publisher": "bridgechat.app",
                    "publisher_verified": False,
                    "scopes": [
                        "channels:history",
                        "channels:read",
                        "im:history",
                        "files:read",
                        "chat:write",
                    ],
                    "granted_by_user": "[email protected]",
                    "granted_at": (now - timedelta(days=2)).isoformat(),
                    "last_used": (now - timedelta(minutes=30)).isoformat(),
                    "total_users_granted": 1,
                    "risk_score": 0.92,
                    "reasons": [
                        "Reads DM history + channel history + files",
                        "Installed by non-admin",
                    ],
                },
            ],
            "salesforce": [],
        }
        wanted = self._filter_provider(provider)
        integrations: list[dict[str, Any]] = []
        for p in wanted:
            integrations.extend(catalog.get(p, []))
        return {"integrations": integrations, "count": len(integrations)}

    async def revoke_third_party_integration(
        self,
        *,
        provider: str,
        grant_id: str,
        reason: str | None = None,
    ) -> dict[str, Any]:
        return {
            "provider": provider.lower(),
            "grant_id": grant_id,
            "revoked": True,
            "reason": reason,
            "ticket": f"SAASREVOKE-{grant_id[-6:].upper()}",
        }

    async def restrict_external_share(
        self,
        *,
        provider: str,
        share_id: str,
        reason: str | None = None,
    ) -> dict[str, Any]:
        return {
            "provider": provider.lower(),
            "share_id": share_id,
            "restricted": True,
            "new_scope": "internal-only",
            "reason": reason,
            "ticket": f"SAASSHARE-{share_id[-6:].upper()}",
        }

    async def remove_external_collaborator(
        self,
        *,
        provider: str,
        resource_id: str,
        external_principal: str,
        reason: str | None = None,
    ) -> dict[str, Any]:
        return {
            "provider": provider.lower(),
            "resource_id": resource_id,
            "external_principal": external_principal,
            "removed": True,
            "reason": reason,
            "ticket": f"SAASCOLLAB-{resource_id[-6:].upper()}",
        }


# ─── Forensics (Velociraptor / KAPE / GRR) ───────────────────────────────


class MockForensicsConnector(BaseForensicsConnector):
    """Deterministic Velociraptor-shaped fixture for the live-forensics path.

    Theme 2j. The story this mock tells matches the EDR mock's
    incident — same host (``WIN-FIN-0044``), same user (``tina.lee``),
    same suspicious PowerShell → rundll32 chain — so the Investigator
    can flow EDR-fast-path → Forensics-deep-path and find consistent
    forensic ground-truth:

      * A ``Windows.System.Pslist`` collection on the host shows the
        rundll32 PID still resident plus the parent powershell.
      * A ``Windows.Sys.AutoRuns`` collection finds a freshly-created
        Run-key persistence entry pointing at ``%TEMP%\\a.dll``.
      * A ``Windows.NetStat`` collection finds an active TCP session
        to the SIEM C2 IP (``185.220.101.42``).
      * ``run_hunt`` of ``Windows.Sys.AutoRuns`` over the
        ``label=prod-workstation`` selector finds the same persistence
        on two adjacent hosts → blast-radius is real.
      * ``fetch_file`` of ``C:\\Users\\tina.lee\\AppData\\Local\\Temp\\a.dll``
        returns the same SHA-256 that the email mock's payload had,
        so the case correlation closes.
      * ``terminate_process`` of the rundll32 PID succeeds — the
        forensics-as-containment-of-last-resort path.

    Real Velociraptor returns VQL row dicts; field names below match
    the canonical artifact column names so a real Velociraptor
    connector can be a thin shim later without rewriting the agent
    prompts.
    """

    vendor = "mock"

    async def health_check(self) -> dict[str, Any]:
        return {"ok": True, "vendor": self.vendor, "kind": self.kind.value}

    # Baked story constants. Keep these in sync with the EDR mock above
    # — the Investigator chains EDR → Forensics and the LLM-driven
    # narrative will get visibly confused if the same incident shows
    # different PIDs across the two surfaces.
    _STORY_HOST = "WIN-FIN-0044"
    _STORY_USER = "tina.lee"
    _STORY_RUNDLL32_PID = 6190
    _STORY_POWERSHELL_PID = 6014
    _STORY_DLL_PATH = (
        r"C:\Users\tina.lee\AppData\Local\Temp\a.dll"
    )
    _STORY_DLL_SHA256 = (
        "9c2a4e1a7b8d3f6e0c1b5a9d8e7f6c5b"
        "4a3d2e1f0c9b8a7d6e5f4c3b2a1d0e9f"
    )
    _STORY_C2_IP = "185.220.101.42"

    async def collect_artifact(
        self,
        *,
        host: str,
        artifact: str,
        parameters: dict[str, Any] | None = None,
        timeout_s: int = 300,
    ) -> dict[str, Any]:
        del parameters, timeout_s  # mock ignores; real connector honors
        now = datetime.now(timezone.utc)
        flow_id = f"F.{abs(hash((host, artifact))) % 10_000_000:07d}"
        started = (now - timedelta(seconds=4)).isoformat()
        completed = now.isoformat()
        base: dict[str, Any] = {
            "host": host,
            "artifact": artifact,
            "flow_id": flow_id,
            "started_at": started,
            "completed_at": completed,
            "status": "completed",
            "row_count": 0,
            "total_uploaded_bytes": 0,
            "rows": [],
            "error": None,
        }
        is_story_host = host.upper() == self._STORY_HOST
        # Velociraptor artifact names live in the dotted namespace; we
        # match by suffix so callers can pass either the full name or
        # the short tail (the LLM tends to drop the OS prefix).
        art = artifact.split(".")[-1].lower()

        if art in {"pslist", "processlist", "process_list"} and is_story_host:
            base["rows"] = [
                {
                    "Pid": self._STORY_POWERSHELL_PID,
                    "Ppid": 5240,
                    "Name": "powershell.exe",
                    "Username": self._STORY_USER,
                    "CommandLine": "powershell -EncodedCommand <REDACTED>",
                    "ExePath": (
                        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\"
                        "powershell.exe"
                    ),
                    "CreateTime": (now - timedelta(minutes=18)).isoformat(),
                    "Authenticode": "trusted",
                },
                {
                    "Pid": self._STORY_RUNDLL32_PID,
                    "Ppid": self._STORY_POWERSHELL_PID,
                    "Name": "rundll32.exe",
                    "Username": self._STORY_USER,
                    "CommandLine": (
                        f"rundll32 {self._STORY_DLL_PATH},Run"
                    ),
                    "ExePath": r"C:\Windows\System32\rundll32.exe",
                    "CreateTime": (now - timedelta(minutes=17)).isoformat(),
                    "Authenticode": "untrusted",
                    "ImageLoaded": self._STORY_DLL_PATH,
                },
            ]
        elif art in {"autoruns", "sys_autoruns", "autorun"} and is_story_host:
            base["rows"] = [
                {
                    "ProgramName": "WindowsTelemetryHelper",
                    "ImagePath": (
                        f"rundll32.exe {self._STORY_DLL_PATH},Run"
                    ),
                    "Type": "HKCU\\...\\CurrentVersion\\Run",
                    "User": self._STORY_USER,
                    "Hash.SHA256": self._STORY_DLL_SHA256,
                    "Signer": "<unsigned>",
                    "CreateTime": (now - timedelta(minutes=16)).isoformat(),
                    "Suspicious": True,
                },
            ]
        elif art in {"netstat", "netstat_enriched", "tcpstat"} and is_story_host:
            base["rows"] = [
                {
                    "Pid": self._STORY_RUNDLL32_PID,
                    "Name": "rundll32.exe",
                    "Username": self._STORY_USER,
                    "Laddr.IP": "10.0.4.118",
                    "Laddr.Port": 50211,
                    "Raddr.IP": self._STORY_C2_IP,
                    "Raddr.Port": 443,
                    "Status": "ESTAB",
                    "Direction": "outbound",
                    "FirstSeen": (now - timedelta(minutes=12)).isoformat(),
                },
            ]
        elif art in {"prefetch"} and is_story_host:
            base["rows"] = [
                {
                    "Executable": "RUNDLL32.EXE",
                    "FileSize": 73_216,
                    "Hash": self._STORY_DLL_SHA256,
                    "LastRun": (now - timedelta(minutes=17)).isoformat(),
                    "RunCount": 1,
                    "VolumeCreated": "2024-09-01T00:00:00Z",
                },
            ]
        else:
            # Unknown / non-story artifact: return an empty result with
            # status=completed so the agent can recover gracefully.
            base["rows"] = []

        base["row_count"] = len(base["rows"])
        # Crude byte estimate so dashboards can show "this much pulled"
        # without us inventing fake upload payloads.
        base["total_uploaded_bytes"] = sum(
            len(str(r).encode("utf-8")) for r in base["rows"]
        )
        return base

    async def run_hunt(
        self,
        *,
        artifact: str,
        label_selector: str | None = None,
        host_ids: list[str] | None = None,
        parameters: dict[str, Any] | None = None,
        timeout_s: int = 600,
    ) -> dict[str, Any]:
        del parameters, timeout_s
        if label_selector is None and not host_ids:
            # Match the protocol contract exactly so callers learn the
            # right shape rather than seeing a 500.
            raise ValueError(
                "run_hunt requires either label_selector or host_ids"
            )
        now = datetime.now(timezone.utc)
        hunt_id = f"H.{abs(hash((artifact, label_selector or '', tuple(host_ids or ())))) % 10_000_000:07d}"
        art = artifact.split(".")[-1].lower()
        # Story: the persistence ran on the index case AND on two
        # adjacent finance prod workstations. Other artifacts return a
        # quieter fleet-wide result so the agent can grade blast-radius.
        if art in {"autoruns", "sys_autoruns", "autorun"}:
            return {
                "hunt_id": hunt_id,
                "artifact": artifact,
                "started_at": (now - timedelta(seconds=45)).isoformat(),
                "scheduled_clients": 42,
                "completed_clients": 42,
                "error_clients": 0,
                "status": "completed",
                "results_summary": {
                    "row_count": 3,
                    "unique_hosts": 3,
                    "matched_hosts": [
                        self._STORY_HOST,
                        "WIN-FIN-0045",
                        "WIN-FIN-0061",
                    ],
                    "indicator": {
                        "field": "Hash.SHA256",
                        "value": self._STORY_DLL_SHA256,
                    },
                },
            }
        return {
            "hunt_id": hunt_id,
            "artifact": artifact,
            "started_at": (now - timedelta(seconds=20)).isoformat(),
            "scheduled_clients": 42,
            "completed_clients": 42,
            "error_clients": 0,
            "status": "completed",
            "results_summary": {
                "row_count": 0,
                "unique_hosts": 0,
                "matched_hosts": [],
                "indicator": None,
            },
        }

    async def fetch_file(
        self,
        *,
        host: str,
        path: str,
        max_size_mb: int = 100,
    ) -> dict[str, Any]:
        del max_size_mb
        now = datetime.now(timezone.utc).isoformat()
        # The one path the story knows about returns the canonical hash;
        # anything else gets a deterministic-but-distinct hash so the
        # agent can still chain to detonation.
        if host.upper() == self._STORY_HOST and path.lower() == self._STORY_DLL_PATH.lower():
            return {
                "host": host,
                "path": path,
                "size_bytes": 73_216,
                "sha256": self._STORY_DLL_SHA256,
                "vault_url": (
                    f"velociraptor://vault/{self._STORY_HOST}/"
                    f"{self._STORY_DLL_SHA256}.bin"
                ),
                "fetched_at": now,
                "truncated": False,
            }
        digest = f"{abs(hash((host, path))) % (16 ** 16):016x}" * 4
        return {
            "host": host,
            "path": path,
            "size_bytes": 1024,
            "sha256": digest,
            "vault_url": f"velociraptor://vault/{host}/{digest}.bin",
            "fetched_at": now,
            "truncated": False,
        }

    async def terminate_process(
        self,
        *,
        host: str,
        pid: int,
        reason: str | None = None,
    ) -> dict[str, Any]:
        # No paired reverse — terminating a process is destructive by
        # definition. Tickets are namespaced ``FKILL-`` so audit-log
        # review can tell forensics kills from EDR kills.
        return {
            "host": host,
            "pid": pid,
            "terminated": True,
            "reason": reason,
            "ticket": f"FKILL-{pid}",
            "error": None,
        }


# ─── factories ───────────────────────────────────────────────────────────


def make_mock_siem(config: ConnectorConfig) -> MockSiemConnector:
    return MockSiemConnector(config)


def make_mock_edr(config: ConnectorConfig) -> MockEdrConnector:
    return MockEdrConnector(config)


def make_mock_idp(config: ConnectorConfig) -> MockIdpConnector:
    return MockIdpConnector(config)


def make_mock_email(config: ConnectorConfig) -> MockEmailConnector:
    return MockEmailConnector(config)


def make_mock_cloud(config: ConnectorConfig) -> MockCloudConnector:
    return MockCloudConnector(config)


def make_mock_saas(config: ConnectorConfig) -> MockSaaSConnector:
    return MockSaaSConnector(config)


def make_mock_forensics(config: ConnectorConfig) -> MockForensicsConnector:
    return MockForensicsConnector(config)


__all__ = [
    "MockCloudConnector",
    "MockEdrConnector",
    "MockEmailConnector",
    "MockForensicsConnector",
    "MockIdpConnector",
    "MockSaaSConnector",
    "MockSiemConnector",
    "make_mock_cloud",
    "make_mock_edr",
    "make_mock_email",
    "make_mock_forensics",
    "make_mock_idp",
    "make_mock_saas",
    "make_mock_siem",
]
