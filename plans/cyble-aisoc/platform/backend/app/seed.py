"""Seed realistic alerts that exercise every code path in the demo.

Twenty alerts spanning phishing, lateral movement, data exfil, BEC,
ransomware staging, and benign-looking false positives.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlmodel import select

from app.cmdb import upsert_asset
from app.config import settings
from app.db import session_scope
from app.memory.autopop import populate_from_alert, populate_from_ioc
from app.models.alert import Alert
from app.models.case import Case, CaseStatus, Severity
from app.models.ioc import IOC, IOCType


SEED_ALERTS: list[dict] = [
    {
        "external_id": "ALR-9821",
        "source": "splunk",
        "title": "Suspicious PowerShell encoded command from Office macro",
        "description": "winword.exe spawned powershell.exe with -EncodedCommand flag",
        "severity": "high",
        "detection_rule": "T1059.001-encoded-powershell",
        "mitre_tactics": ["execution", "defense-evasion"],
        "mitre_techniques": ["T1059.001", "T1027"],
        "src_user": "tina.lee",
        "src_host": "WIN-FIN-0044",
        "src_ip": "10.4.21.118",
        "dst_ip": "185.220.101.42",
        "process_name": "powershell.exe",
        "file_hash": "9c2a4e1a7b8d3f6e0c1b5a9d8e7f6c5b4a3d2e1f0c9b8a7d6e5f4c3b2a1d0e9f",
    },
    {
        "external_id": "ALR-9844",
        "source": "splunk",
        "title": "Outbound traffic to known TOR exit node",
        "description": "Sustained 184KB outbound to TOR infrastructure",
        "severity": "high",
        "detection_rule": "T1090.003-tor-egress",
        "mitre_tactics": ["command-and-control"],
        "mitre_techniques": ["T1090.003"],
        "src_host": "WIN-FIN-0044",
        "src_user": "tina.lee",
        "dst_ip": "185.220.101.42",
    },
    {
        "external_id": "ALR-9902",
        "source": "okta",
        "title": "Impossible travel — US to Vietnam in 14 minutes",
        "description": "Successful sign-in from VN immediately after US auth",
        "severity": "high",
        "detection_rule": "ATO-impossible-travel",
        "mitre_tactics": ["initial-access"],
        "mitre_techniques": ["T1078.004"],
        "src_user": "marc.aldred",
        "src_ip": "203.0.113.55",
    },
    {
        "external_id": "ALR-9911",
        "source": "proofpoint",
        "title": "Phishing wave: invoice-themed Word doc with macros",
        "description": "47 recipients received message from m1crosoft-secure.com",
        "severity": "high",
        "detection_rule": "phish-typosquat-microsoft",
        "mitre_tactics": ["initial-access"],
        "mitre_techniques": ["T1566.001"],
        "src_user": "alex.rivera",
        "file_hash": "9c2a4e1a7b8d3f6e0c1b5a9d8e7f6c5b4a3d2e1f0c9b8a7d6e5f4c3b2a1d0e9f",
    },
    {
        "external_id": "ALR-9925",
        "source": "sentinelone",
        "title": "Mimikatz signature on dev machine",
        "description": "Hash-matched lsass dump tooling executed",
        "severity": "critical",
        "detection_rule": "T1003-credential-dump",
        "mitre_tactics": ["credential-access"],
        "mitre_techniques": ["T1003.001"],
        "src_user": "j.singh",
        "src_host": "MAC-DEV-1170",
        "process_name": "mimikatz.exe",
    },
    {
        "external_id": "ALR-9928",
        "source": "splunk",
        "title": "Anomalous SMB lateral movement from finance host",
        "description": "WIN-FIN-0044 → 12 internal hosts within 90 seconds",
        "severity": "high",
        "detection_rule": "T1021.002-lateral-smb",
        "mitre_tactics": ["lateral-movement"],
        "mitre_techniques": ["T1021.002"],
        "src_host": "WIN-FIN-0044",
        "src_user": "tina.lee",
    },
    {
        "external_id": "ALR-9933",
        "source": "wiz",
        "title": "S3 bucket made world-readable",
        "description": "cyble-prod-customer-pii bucket policy modified",
        "severity": "critical",
        "detection_rule": "cloud-S3-public-write",
        "mitre_tactics": ["exfiltration"],
        "mitre_techniques": ["T1530"],
        "src_user": "ci-bot-prod",
    },
    {
        "external_id": "ALR-9941",
        "source": "duo",
        "title": "MFA fatigue: 47 push prompts in 4 minutes",
        "description": "User accepted prompt #47",
        "severity": "high",
        "detection_rule": "ATO-mfa-bombing",
        "mitre_tactics": ["initial-access"],
        "mitre_techniques": ["T1621"],
        "src_user": "vp.engineering",
        "src_ip": "45.139.105.18",
    },
    {
        "external_id": "ALR-9952",
        "source": "splunk",
        "title": "DNS exfil pattern: high-entropy subdomains to *.evil-update.duckdns.org",
        "description": "1,840 DNS queries with base32-like subdomain in 8 minutes",
        "severity": "high",
        "detection_rule": "T1071.004-dns-tunnel",
        "mitre_tactics": ["command-and-control", "exfiltration"],
        "mitre_techniques": ["T1071.004"],
        "src_host": "WIN-ENG-0021",
        "dst_ip": "evil-update.duckdns.org",
    },
    {
        "external_id": "ALR-9961",
        "source": "github",
        "title": "Possible secret committed: AWS access key in commit dc7a91",
        "description": "Long-lived access key found in repo public-marketing",
        "severity": "high",
        "detection_rule": "secret-scan-AWSKey",
        "mitre_tactics": ["credential-access"],
        "mitre_techniques": ["T1552.001"],
        "src_user": "ci-bot-marketing",
    },
    {
        "external_id": "ALR-10004",
        "source": "splunk",
        "title": "Service account password sprayed against /api/auth",
        "description": "127 failures across 4 accounts in 2 minutes from single IP",
        "severity": "medium",
        "detection_rule": "T1110.003-password-spray",
        "mitre_tactics": ["credential-access"],
        "mitre_techniques": ["T1110.003"],
        "src_ip": "62.210.83.144",
    },
    {
        "external_id": "ALR-10018",
        "source": "okta",
        "title": "New admin role granted to ext_partner_5 by automation",
        "description": "okta-superadmin granted; not on change ticket",
        "severity": "critical",
        "detection_rule": "T1098.003-priv-esc",
        "mitre_tactics": ["privilege-escalation"],
        "mitre_techniques": ["T1098"],
        "src_user": "ext_partner_5",
    },
    {
        "external_id": "ALR-10026",
        "source": "sentinelone",
        "title": "Suspicious scheduled task created on engineering laptop",
        "description": "schtasks /create with hidden flag and 30-min interval",
        "severity": "medium",
        "detection_rule": "T1053.005-scheduled-task",
        "mitre_tactics": ["persistence"],
        "mitre_techniques": ["T1053.005"],
        "src_host": "MAC-DEV-1170",
        "src_user": "j.singh",
    },
    {
        "external_id": "ALR-10033",
        "source": "proofpoint",
        "title": "Executive impersonation: vendor wire change request",
        "description": "Sender 'cfo@cyble.co' (note .co), urgent reroute of $84K",
        "severity": "high",
        "detection_rule": "BEC-display-name-spoof",
        "mitre_tactics": ["initial-access"],
        "mitre_techniques": ["T1566.002"],
    },
    {
        "external_id": "ALR-10044",
        "source": "splunk",
        "title": "Beaconing: 60-second jitter to 185.220.101.42",
        "description": "Consistent ~60s callbacks with low payload variance",
        "severity": "high",
        "detection_rule": "C2-beacon-detection",
        "mitre_tactics": ["command-and-control"],
        "mitre_techniques": ["T1071.001"],
        "src_host": "WIN-FIN-0044",
        "dst_ip": "185.220.101.42",
    },
    {
        "external_id": "ALR-10058",
        "source": "splunk",
        "title": "Mass file rename on shared drive",
        "description": "8,400 files renamed to .ENCRYPTED in 3 minutes",
        "severity": "critical",
        "detection_rule": "ransomware-mass-rename",
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1486"],
        "src_host": "FILE-SRV-02",
        "src_user": "svc-backup",
    },
    {
        "external_id": "ALR-10071",
        "source": "wiz",
        "title": "EC2 instance launched in unusual region (eu-north-1)",
        "description": "Spot instance, no tags, by IAM user disabled 4 days ago",
        "severity": "high",
        "detection_rule": "cloud-anomalous-launch",
        "mitre_tactics": ["resource-development"],
        "mitre_techniques": ["T1583.004"],
        "src_user": "former.intern",
    },
    {
        "external_id": "ALR-10089",
        "source": "splunk",
        "title": "Crowdstrike agent stopped on 4 production servers",
        "description": "Service stopped via signed installer; matches T1562 pattern",
        "severity": "high",
        "detection_rule": "T1562.001-impair-defenses",
        "mitre_tactics": ["defense-evasion"],
        "mitre_techniques": ["T1562.001"],
        "src_host": "PROD-DB-04",
    },
    {
        "external_id": "ALR-10092",
        "source": "splunk",
        "title": "Backup job ran 40% longer than baseline (false positive candidate)",
        "description": "Nightly backup duration anomaly; bandwidth saturated",
        "severity": "low",
        "detection_rule": "ops-backup-duration",
        "mitre_tactics": [],
        "mitre_techniques": [],
        "src_host": "PROD-DB-01",
    },
    {
        "external_id": "ALR-10097",
        "source": "okta",
        "title": "Routine first-login from new corporate device",
        "description": "User on managed device, registered today",
        "severity": "info",
        "detection_rule": "ops-new-device-enroll",
        "mitre_tactics": [],
        "mitre_techniques": [],
        "src_user": "new.hire",
    },
]


SEED_IOCS: list[dict] = [
    {
        "value": "185.220.101.42",
        "type": "ip",
        "threat_score": 92,
        "confidence": 0.95,
        "sources": ["cyble-cti", "alienvault"],
        "tags": ["tor_exit_node", "c2", "fin7"],
        "cyble_native": True,
        "description": "Known FIN7 C2 infrastructure",
    },
    {
        "value": "evil-update.duckdns.org",
        "type": "domain",
        "threat_score": 88,
        "confidence": 0.92,
        "sources": ["cyble-cti"],
        "tags": ["typosquat", "phishing"],
        "cyble_native": True,
    },
    {
        "value": "9c2a4e1a7b8d3f6e0c1b5a9d8e7f6c5b4a3d2e1f0c9b8a7d6e5f4c3b2a1d0e9f",
        "type": "sha256",
        "threat_score": 96,
        "confidence": 0.98,
        "sources": ["cyble-cti", "vt"],
        "tags": ["cobalt_strike", "loader"],
        "cyble_native": True,
    },
    {
        "value": "62.210.83.144",
        "type": "ip",
        "threat_score": 71,
        "confidence": 0.81,
        "sources": ["cyble-cti"],
        "tags": ["password_spray_source"],
        "cyble_native": True,
    },
    {
        "value": "45.139.105.18",
        "type": "ip",
        "threat_score": 79,
        "confidence": 0.85,
        "sources": ["cyble-cti"],
        "tags": ["mfa_bombing", "scattered_spider"],
        "cyble_native": True,
    },
]


# CMDB seed — mirrors every host and user that appears in SEED_ALERTS,
# plus a handful of business-context records so asset.get_context returns
# something *useful* on every host the demo touches. Criticality, owner,
# and compliance scope are chosen to make the agents' decisions land
# differently per asset (e.g. crown-jewel prod DB → HITL for destructive
# actions; sandbox dev box → autonomous response is fine).
SEED_ASSETS: list[dict] = [
    # ── Hosts ────────────────────────────────────────────────────────
    {
        "asset_type": "host",
        "key": "WIN-FIN-0044",
        "name": "Finance Workstation 44",
        "aliases": ["win-fin-0044.corp.cyble.io", "10.4.21.118"],
        "criticality": "high",
        "environment": "prod",
        "owner": "tina.lee",
        "business_unit": "Finance",
        "location": "HQ-NYC",
        "compliance_scopes": ["SOX", "PCI-DSS"],
        "data_classifications": ["financial", "pii"],
        "ip_addresses": ["10.4.21.118"],
        "os": "Windows",
        "os_version": "11 Pro 23H2",
        "sources": ["cmdb", "intune"],
        "tags": ["endpoint", "finance"],
    },
    {
        "asset_type": "host",
        "key": "MAC-DEV-1170",
        "name": "Engineering MacBook 1170",
        "aliases": ["mac-dev-1170.dev.cyble.io"],
        "criticality": "medium",
        "environment": "dev",
        "owner": "j.singh",
        "business_unit": "Engineering",
        "location": "HQ-NYC",
        "compliance_scopes": [],
        "data_classifications": ["source_code"],
        "os": "macOS",
        "os_version": "14.5",
        "sources": ["cmdb", "jamf"],
        "tags": ["endpoint", "developer"],
    },
    {
        "asset_type": "host",
        "key": "WIN-ENG-0021",
        "name": "Engineering Workstation 21",
        "aliases": ["win-eng-0021.corp.cyble.io"],
        "criticality": "medium",
        "environment": "dev",
        "owner": "platform-eng",
        "business_unit": "Engineering",
        "location": "HQ-NYC",
        "compliance_scopes": [],
        "data_classifications": ["source_code"],
        "os": "Windows",
        "os_version": "11 Pro 23H2",
        "sources": ["cmdb", "intune"],
        "tags": ["endpoint", "developer"],
    },
    {
        "asset_type": "host",
        "key": "FILE-SRV-02",
        "name": "Shared File Server 02",
        "aliases": ["file-srv-02.corp.cyble.io"],
        "criticality": "high",
        "environment": "prod",
        "owner": "it-infra",
        "business_unit": "IT",
        "location": "DC-EAST",
        "compliance_scopes": ["SOX"],
        "data_classifications": ["confidential", "pii"],
        "os": "Windows Server",
        "os_version": "2022",
        "sources": ["cmdb"],
        "tags": ["server", "file_share"],
    },
    {
        "asset_type": "host",
        "key": "PROD-DB-04",
        "name": "Production Database 04",
        "aliases": ["prod-db-04.corp.cyble.io"],
        # Crown jewel: customer data lives here. Any destructive action
        # against this asset MUST be HITL'd by the responder.
        "criticality": "crown_jewel",
        "environment": "prod",
        "owner": "database-ops",
        "business_unit": "Platform",
        "location": "DC-EAST",
        "compliance_scopes": ["SOC2", "PCI-DSS", "HIPAA"],
        "data_classifications": ["pii", "phi", "payment_card"],
        "os": "Linux",
        "os_version": "Ubuntu 22.04",
        "sources": ["cmdb", "aws"],
        "tags": ["server", "database", "customer_data"],
    },
    {
        "asset_type": "host",
        "key": "PROD-DB-01",
        "name": "Production Database 01",
        "aliases": ["prod-db-01.corp.cyble.io"],
        "criticality": "crown_jewel",
        "environment": "prod",
        "owner": "database-ops",
        "business_unit": "Platform",
        "location": "DC-EAST",
        "compliance_scopes": ["SOC2", "PCI-DSS"],
        "data_classifications": ["pii", "payment_card"],
        "os": "Linux",
        "os_version": "Ubuntu 22.04",
        "sources": ["cmdb", "aws"],
        "tags": ["server", "database", "customer_data"],
    },
    # ── Users ────────────────────────────────────────────────────────
    {
        "asset_type": "user",
        "key": "tina.lee",
        "name": "Tina Lee",
        "aliases": ["tina.lee@cyble.io"],
        "criticality": "high",
        "environment": "prod",
        "owner": "tina.lee",
        "business_unit": "Finance",
        "compliance_scopes": ["SOX"],
        "data_classifications": ["financial"],
        "sources": ["okta", "hris"],
        "tags": ["employee", "finance"],
    },
    {
        "asset_type": "user",
        "key": "j.singh",
        "name": "Jaspreet Singh",
        "aliases": ["j.singh@cyble.io"],
        "criticality": "medium",
        "environment": "prod",
        "owner": "j.singh",
        "business_unit": "Engineering",
        "sources": ["okta", "hris"],
        "tags": ["employee", "developer"],
    },
    {
        "asset_type": "user",
        "key": "marc.aldred",
        "name": "Marc Aldred",
        "aliases": ["marc.aldred@cyble.io"],
        "criticality": "high",
        "environment": "prod",
        "owner": "marc.aldred",
        "business_unit": "Sales",
        "sources": ["okta", "hris"],
        "tags": ["employee", "sales", "frequent_traveller"],
    },
    {
        "asset_type": "user",
        "key": "alex.rivera",
        "name": "Alex Rivera",
        "aliases": ["alex.rivera@cyble.io"],
        "criticality": "medium",
        "environment": "prod",
        "owner": "alex.rivera",
        "business_unit": "Marketing",
        "sources": ["okta", "hris"],
        "tags": ["employee", "marketing"],
    },
    {
        "asset_type": "user",
        "key": "vp.engineering",
        "name": "VP Engineering",
        "aliases": ["vp.engineering@cyble.io"],
        # Exec identity — privileged target, MFA bombing risk lands here.
        "criticality": "crown_jewel",
        "environment": "prod",
        "owner": "vp.engineering",
        "business_unit": "Engineering",
        "compliance_scopes": ["SOC2"],
        "sources": ["okta", "hris"],
        "tags": ["employee", "executive", "privileged"],
    },
    {
        "asset_type": "user",
        "key": "ci-bot-prod",
        "name": "Prod CI Bot",
        "aliases": ["ci-bot-prod@cyble.io"],
        "criticality": "high",
        "environment": "prod",
        "owner": "platform-eng",
        "business_unit": "Platform",
        "compliance_scopes": ["SOC2"],
        "sources": ["okta", "github"],
        "tags": ["service_account", "automation"],
    },
    {
        "asset_type": "user",
        "key": "ci-bot-marketing",
        "name": "Marketing CI Bot",
        "aliases": ["ci-bot-marketing@cyble.io"],
        "criticality": "medium",
        "environment": "prod",
        "owner": "marketing-ops",
        "business_unit": "Marketing",
        "sources": ["okta", "github"],
        "tags": ["service_account", "automation"],
    },
    {
        "asset_type": "user",
        "key": "ext_partner_5",
        "name": "External Partner 5",
        "aliases": ["ext_partner_5@partner.example"],
        # External identities are dangerous-by-default in our risk model;
        # the recent unauthorised-admin grant in seed alert ALR-10018
        # is exactly the kind of thing this CMDB row should make obvious.
        "criticality": "high",
        "environment": "prod",
        "owner": "vendor-management",
        "business_unit": "External",
        "sources": ["okta"],
        "tags": ["external", "partner", "untrusted"],
    },
    {
        "asset_type": "user",
        "key": "svc-backup",
        "name": "Backup Service Account",
        "aliases": ["svc-backup@cyble.io"],
        "criticality": "high",
        "environment": "prod",
        "owner": "it-infra",
        "business_unit": "IT",
        "compliance_scopes": ["SOX"],
        "sources": ["okta", "ad"],
        "tags": ["service_account", "backup"],
    },
    {
        "asset_type": "user",
        "key": "former.intern",
        "name": "Former Intern",
        "aliases": ["former.intern@cyble.io"],
        # Decommissioned identity that just lit up cloud — classic
        # 'should-be-disabled' anomaly the demo wants to surface.
        "criticality": "medium",
        "environment": "prod",
        "owner": "hr",
        "business_unit": "Engineering",
        "sources": ["okta", "hris"],
        "tags": ["employee", "offboarded", "stale"],
    },
    {
        "asset_type": "user",
        "key": "new.hire",
        "name": "New Hire",
        "aliases": ["new.hire@cyble.io"],
        "criticality": "low",
        "environment": "prod",
        "owner": "new.hire",
        "business_unit": "Engineering",
        "sources": ["okta", "hris"],
        "tags": ["employee", "onboarding"],
    },
    # ── Cloud / SaaS assets touched by seed alerts ───────────────────
    {
        "asset_type": "cloud_resource",
        "key": "s3://cyble-prod-customer-pii",
        "name": "Customer PII Bucket",
        "criticality": "crown_jewel",
        "environment": "prod",
        "owner": "database-ops",
        "business_unit": "Platform",
        "compliance_scopes": ["SOC2", "GDPR", "CCPA", "HIPAA"],
        "data_classifications": ["pii", "phi"],
        "cloud_provider": "aws",
        "cloud_account_id": "111122223333",
        "region": "us-east-1",
        "sources": ["aws", "wiz"],
        "tags": ["s3", "customer_data"],
    },
    {
        "asset_type": "saas_app",
        "key": "github.com/cyble/public-marketing",
        "name": "Public Marketing Repo",
        "criticality": "low",
        "environment": "prod",
        "owner": "marketing-ops",
        "business_unit": "Marketing",
        "sources": ["github"],
        "tags": ["repo", "public"],
    },
]


def _seed_cmdb_for_tenant(tenant_id: str) -> None:
    """Idempotently upsert the demo CMDB for one tenant.

    Errors on a single row do not abort the whole seed — CMDB seeding
    is a *supporting* dataset for asset.get_context, not the demo's
    critical path. We log nothing here because seed.py is intentionally
    silent on success; failures bubble up via the upsert layer.
    """
    for asset in SEED_ASSETS:
        try:
            upsert_asset(tenant_id=tenant_id, **asset)
        except Exception:
            # Best-effort: keep going so the rest of the demo still seeds.
            continue


def seed_if_empty() -> None:
    with session_scope() as s:
        existing = s.exec(select(Alert)).first()
        if existing:
            return
        # Seed the demo tenant baseline plus the MSSP children so the
        # multi-tenant fan-out has data without onboarding a real customer.
        primary_tenant = settings.default_tenant
        mssp_children = list(settings.demo_mssp_children or [])
        tenants_to_seed = [primary_tenant] + mssp_children

        # IOCs are tenant-scoped even when they originate from a global feed —
        # we copy the same intel into every tenant so the demo dashboards
        # render identically across the fan-out.
        for tenant_id in tenants_to_seed:
            for r in SEED_IOCS:
                payload = {**r, "type": IOCType(r["type"]), "tenant_id": tenant_id}
                ioc = IOC(**payload)
                s.add(ioc)
                # Mirror the IOC into the threat graph so cross-IOC pivots
                # ("everything Cyble-native") work from day one. Failures are
                # swallowed inside populate_from_ioc.
                populate_from_ioc(ioc)
        # Commit IOCs before the CMDB pass — upsert_asset opens its own
        # session_scope, so anything still buffered on `s` would not be
        # visible to it (and we want hosts mirrored into the graph alongside
        # their related IOC nodes, not after a rollback).
        s.commit()

        # CMDB: every host and user the demo alerts touch gets a real asset
        # record. asset.get_context resolves against this — without it, the
        # Triager would have no business context for its decisions.
        for tenant_id in tenants_to_seed:
            _seed_cmdb_for_tenant(tenant_id)

        # Alerts ride into pending cases — leave un-orchestrated; UI will run them on demand
        for i, raw in enumerate(SEED_ALERTS):
            base_ts = datetime.now(timezone.utc) - timedelta(minutes=10 * (len(SEED_ALERTS) - i))
            # Round-robin spread across tenants so each demo tenant gets a
            # representative slice (the primary tenant still owns the bulk).
            tenant_id = primary_tenant
            if mssp_children and i % 3 != 0:
                tenant_id = mssp_children[(i // 3) % len(mssp_children)]

            case = Case(
                tenant_id=tenant_id,
                title=raw["title"],
                severity=Severity(raw["severity"]) if raw["severity"] in [sv.value for sv in Severity] else Severity.MEDIUM,
                status=CaseStatus.NEW,
                mitre_techniques=raw.get("mitre_techniques", []),
                created_at=base_ts,
                updated_at=base_ts,
            )
            s.add(case)
            s.commit()
            s.refresh(case)
            a = Alert(case_id=case.id, tenant_id=tenant_id, **raw, created_at=base_ts)
            s.add(a)
            s.commit()
            s.refresh(a)
            # Mirror the alert's entities into the threat graph (asset, user,
            # IPs, file hashes, process, MITRE techniques) so the demo case
            # neighbour query already returns its blast radius.
            populate_from_alert(a)
