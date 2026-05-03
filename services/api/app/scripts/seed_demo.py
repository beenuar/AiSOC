"""Seed the database with a realistic demo tenant, user, and SOC dataset.

Run this from the host (the API container has the package on its PYTHONPATH):

    docker compose exec api python -m app.scripts.seed_demo
    # or, from the repo root:
    pnpm seed:demo

The seed is idempotent — running it twice produces the same dataset and never
duplicates rows. Demo IDs are kept in sync with `app/api/v1/dev_auth.py` so the
auth bypass and the seeded data agree on who "demo@aisoc.local" is.
"""
from __future__ import annotations

import asyncio
import os
import random
import sys
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select

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
from app.models.tenant import Tenant, User

# Deterministic random for reproducible seeds.
_rng = random.Random(42)


# ─── Reference data ────────────────────────────────────────────────────────────

_SEVERITIES = ["critical", "high", "medium", "low"]
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
        "Brute-force spray from {ip} against {user}. Successful login established persistence "
        "via registry Run key. IoCs match APT28 TTPs.",
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
        "Compromised npm package `event-stream` installed by CI pipeline on {host}. "
        "Post-install hook executed reverse shell to {ip}.",
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
        "Forged SAML assertion detected. Attacker pivoted to Azure AD as {user}. "
        "Account enumeration across O365 tenant followed.",
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
        "Replication rights abused from workstation {host}. All domain NTLM hashes replicated. "
        "Matches skeleton key attack preparation.",
    ),
    (
        "Container escape via privileged pod on {host}",
        ["TA0004", "TA0007"],
        ["T1611", "T1082"],
        "Kubernetes privileged pod created by rogue service account. "
        "cgroup escape to host namespace. Node file system accessed from pod.",
    ),
    (
        "Firmware implant detected on {host} UEFI partition",
        ["TA0003", "TA0005"],
        ["T1542.001", "T1027.002"],
        "UEFI secure-boot violation alert. Unknown module in firmware image. "
        "Matches MosaicRegressor UEFI implant signatures.",
    ),
    (
        "Watering-hole attack: internal wiki delivering drive-by exploit",
        ["TA0001", "TA0002"],
        ["T1189", "T1203"],
        "Internal Confluence page injected with malicious JS. "
        "Visitor {user} on {host} exploited via CVE-2024-1234 browser vulnerability.",
    ),
    (
        "Malicious USB autorun on air-gapped {host}",
        ["TA0001", "TA0009"],
        ["T1091", "T1005"],
        "USB device inserted on air-gapped system {host}. "
        "AutoRun executed Python stager. Sensitive documents staged for exfiltration.",
    ),
    (
        "OAuth consent phishing targeting {user}'s Microsoft account",
        ["TA0001", "TA0006"],
        ["T1528", "T1550.001"],
        "Malicious OAuth app granted Mail.Read and Files.Read.All to {user}. "
        "Inbox rules created to forward emails silently to attacker.",
    ),
    (
        "Memory-only implant (fileless) executed in {host} process",
        ["TA0002", "TA0005"],
        ["T1055.012", "T1620"],
        "Process hollowing detected: svchost.exe replaced with Cobalt Strike beacon. "
        "No disk artefacts. IoC matches CS watermark 0x5A4D.",
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
    "WIN-FIN-DB01", "WIN-PROD-WEB02", "MAC-SARAH-LT", "LIN-K8S-NODE-03",
    "WIN-HR-DESKTOP", "DC01.corp.aisoc.dev", "WIN-DEVOPS-LT",
]

_USERS = [
    "alice@aisoc.dev", "bob@aisoc.dev", "carol@aisoc.dev", "dave@aisoc.dev",
    "svc-backup@aisoc.dev", "eve@aisoc.dev",
]


def _random_ip() -> str:
    return ".".join(str(_rng.randint(1, 254)) for _ in range(4))


def _pick_techniques(k: int = 2) -> list[dict]:
    chosen = _rng.sample(_TECHNIQUES, k=k)
    return [
        {"tactic": t[1], "tactic_id": t[0], "technique": t[3], "technique_id": t[2]}
        for t in chosen
    ]


def _make_alert(tenant_id: uuid.UUID, when: datetime) -> Alert:
    severity = _rng.choices(_SEVERITIES, weights=[15, 30, 35, 20])[0]
    status = _rng.choices(
        _STATUSES, weights=[40, 20, 15, 20, 5]
    )[0]
    src_name, src_cat = _rng.choice(_SOURCES)
    host = _rng.choice(_HOSTS)
    user = _rng.choice(_USERS)
    ip = _random_ip()
    title = _rng.choice(_TITLES).format(host=host, user=user, ip=ip)
    techniques = _pick_techniques(_rng.randint(1, 3))

    priority = {"critical": 90, "high": 75, "medium": 50, "low": 25}[severity]
    priority += _rng.randint(-10, 10)

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
        ai_score=_rng.uniform(0.3, 0.99),
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
    return Case(
        tenant_id=tenant_id,
        case_number=f"CASE-{1000 + idx:04d}",
        title=_rng.choice([
            "Coordinated brute-force campaign across SaaS apps",
            "Possible data exfiltration via cloud storage",
            "Endpoint compromise — finance workstation",
            "Suspected insider threat — HR records access",
            "Ransomware precursor — staging activity detected",
            "Phishing wave targeting engineering team",
        ]),
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
    result = await session.execute(select(User).where(User.id == DEMO_USER_ID))
    user = result.scalar_one_or_none()
    if user:
        return user
    user = User(
        id=DEMO_USER_ID,
        tenant_id=tenant.id,
        email=DEMO_USER_EMAIL,
        username="demo",
        hashed_password=get_password_hash("aisoc-demo"),
        role=DEMO_USER_ROLE,
        is_active=True,
        is_verified=True,
        preferences={"theme": "dark"},
    )
    session.add(user)
    await session.flush()
    return user


async def _seed_connectors(session, tenant: Tenant) -> int:
    result = await session.execute(
        select(Connector).where(Connector.tenant_id == tenant.id)
    )
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
    tactics = [
        {"id": t_id, "name": next((t[1] for t in _TECHNIQUES if t[0] == t_id), t_id)}
        for t_id in tactic_ids
    ]
    techniques = [
        {"id": t_id, "name": next((t[3] for t in _TECHNIQUES if t[2] == t_id), t_id)}
        for t_id in technique_ids
    ]

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
        summary=f"Synthetic incident #{idx + 1} for AI investigator evaluation.",
        event_metadata={
            "synthetic": True,
            "expected_tactics": tactic_ids,
            "expected_techniques": technique_ids,
            "host": host,
            "user": user,
            "src_ip": ip,
        },
        created_at=when,
        updated_at=when,
        closed_at=when + timedelta(days=2) if status in ("resolved", "closed") else None,
    )


async def _seed_alerts_and_cases(session, tenant: Tenant, *, alert_count: int = 120) -> tuple[int, int]:
    existing = await session.execute(select(Alert).where(Alert.tenant_id == tenant.id).limit(1))
    if existing.scalar_one_or_none() is not None:
        return 0, 0

    now = datetime.now(UTC)
    alerts: list[Alert] = []
    for i in range(alert_count):
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


async def main() -> None:
    print("[seed] connecting to database…", flush=True)
    async with AsyncSessionLocal() as session:
        try:
            tenant = await _ensure_tenant(session)
            user = await _ensure_user(session, tenant)
            new_connectors = await _seed_connectors(session, tenant)
            new_alerts, new_cases = await _seed_alerts_and_cases(session, tenant)
            await session.commit()
        except Exception:
            await session.rollback()
            raise

    print(f"[seed] tenant: {tenant.id} ({tenant.slug})")
    print(f"[seed] user: {user.email} (role={user.role})")
    print(f"[seed] connectors created: {new_connectors}")
    print(f"[seed] alerts created: {new_alerts}")
    print(f"[seed] cases created: {new_cases}")
    print("[seed] done — log into the console at http://localhost:3000")


if __name__ == "__main__":
    # Allow `python -m app.scripts.seed_demo` from the api service container.
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as exc:  # pragma: no cover - operational helper
        print(f"[seed] failed: {exc}", file=sys.stderr)
        sys.exit(1)
