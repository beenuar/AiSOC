#!/usr/bin/env python3
"""
AiSOC eval-harness incident generator.
=======================================

Produces a deterministic JSON dataset of N synthetic SOC incidents for the
Phase-1 eval harness. Each entry covers:

- title (one-line summary)
- description (multi-sentence narrative — what the keyword extractor sees)
- expected_tactics (MITRE ATT&CK tactic IDs, e.g. ["TA0006", "TA0008"])
- expected_techniques (MITRE technique IDs, e.g. ["T1110.001"])
- severity ("critical" | "high" | "medium" | "low")
- response_class (containment family — "isolate_host", "disable_account",
  "block_indicator", "rollback_change", "escalate", "monitor")
- evidence_keywords (atomic evidence items the report should cite to be
  considered "complete")

Usage
-----
    python3 scripts/generate_eval_incidents.py [--count 200] [--out PATH]

The output is fully deterministic given the same `--count` and template
data — re-running produces byte-identical JSON. Commit the JSON; the
generator is preserved for reviewability and future expansion.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Param pools — small, deterministic, evocative
# ---------------------------------------------------------------------------

HOSTNAMES = [
    "WIN-FIN-DB01", "WIN-PROD-WEB02", "WIN-HR-DESKTOP", "WIN-DEVOPS-LT",
    "LIN-K8S-NODE01", "LIN-BUILD-CI03", "LIN-EDGE-VPN02", "MAC-CFO-LAPTOP",
    "MAC-LEGAL-LAPTOP", "WIN-DC-PRIMARY", "WIN-DC-SECONDARY", "WIN-EXCHANGE-01",
    "LIN-OBS-LOGGER", "LIN-DB-REPLICA", "WIN-FILE-SHARE", "K8S-PROD-CLUSTER",
    "AWS-EC2-PROD-API", "AZURE-VM-FIN-001", "GCP-GKE-NODE-04",
]

USERS = [
    "alice@aisoc.dev", "bob@aisoc.dev", "carol@aisoc.dev", "dave@aisoc.dev",
    "eve@aisoc.dev", "frank@aisoc.dev", "grace@aisoc.dev", "heidi@aisoc.dev",
    "svc-deploy@aisoc.dev", "svc-backup@aisoc.dev", "admin@aisoc.dev",
    "cfo@aisoc.dev", "ceo@aisoc.dev", "ops-lead@aisoc.dev",
]

ATTACKER_IPS = [
    "192.168.1.100", "10.0.99.42", "172.16.50.7", "203.0.113.45",
    "198.51.100.23", "185.220.101.7", "45.142.122.111", "91.134.231.15",
]

CAMPAIGNS = [
    "LockBit 3.0", "ALPHV/BlackCat", "APT28", "APT29", "Emotet epoch 5",
    "Lazarus", "FIN7", "MagicWeb", "MosaicRegressor", "Volt Typhoon",
    "Scattered Spider", "Cobalt Strike",
]

# ---------------------------------------------------------------------------
# Template definitions — each template covers a tactic+technique pair
# Using structured templates lets us generate diverse, realistic narratives
# while keeping the dataset deterministic.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Template:
    title: str
    description: str
    tactics: tuple[str, ...]
    techniques: tuple[str, ...]
    severity: str
    response_class: str
    evidence_keywords: tuple[str, ...]
    placeholders: tuple[str, ...] = field(default_factory=tuple)


TEMPLATES: list[Template] = [
    # ─────────────────────────────────────────────────────────
    # Initial Access (TA0001)
    # ─────────────────────────────────────────────────────────
    Template(
        title="Spear-phishing email with macro-laden attachment delivered to {user}",
        description=(
            "Inbound email from {ip} delivered an Office document with a malicious VBA macro to "
            "{user}. Attachment opened on {host}; macro spawned cmd.exe and downloaded a stage-2 "
            "payload from a known {campaign} infrastructure."
        ),
        tactics=("TA0001", "TA0002"),
        techniques=("T1566.001", "T1059.005"),
        severity="high",
        response_class="block_indicator",
        evidence_keywords=("phishing email", "macro", "{ip}", "{host}", "{user}", "stage-2 payload"),
        placeholders=("user", "ip", "host", "campaign"),
    ),
    Template(
        title="Exploitation of public-facing web app on {host}",
        description=(
            "WAF logs show SQL-injection and SSRF probes from {ip} against the application on "
            "{host}. One request returned 200 with internal cloud-metadata content. Likely "
            "exploitation of CVE-2024-1234."
        ),
        tactics=("TA0001", "TA0007"),
        techniques=("T1190", "T1082"),
        severity="critical",
        response_class="isolate_host",
        evidence_keywords=("WAF", "SQL injection", "SSRF", "CVE-2024-1234", "{host}", "{ip}"),
        placeholders=("ip", "host"),
    ),
    Template(
        title="Watering-hole exploit served from internal Confluence by {ip}",
        description=(
            "Internal Confluence page injected with malicious JavaScript by {ip}. Drive-by exploit "
            "triggered browser exploitation on multiple visitors including {user}. Linked to "
            "{campaign} TTPs."
        ),
        tactics=("TA0001", "TA0002"),
        techniques=("T1189", "T1203"),
        severity="high",
        response_class="block_indicator",
        evidence_keywords=("watering hole", "drive-by", "Confluence", "{ip}", "{user}", "{campaign}"),
        placeholders=("ip", "user", "campaign"),
    ),
    Template(
        title="Supply-chain compromise: malicious npm package on {host}",
        description=(
            "CI pipeline on {host} installed compromised npm package `event-stream`. Post-install "
            "hook executed reverse shell to {ip}. Build artefacts may be tainted."
        ),
        tactics=("TA0001", "TA0002"),
        techniques=("T1195.001", "T1059.007"),
        severity="critical",
        response_class="rollback_change",
        evidence_keywords=("supply chain", "npm package", "event-stream", "post-install", "{host}", "{ip}"),
        placeholders=("host", "ip"),
    ),
    Template(
        title="Malicious USB autorun on air-gapped host {host}",
        description=(
            "USB device inserted on air-gapped {host} by {user}. AutoRun executed Python stager "
            "that collected local files. Data staged in C:\\Temp\\."
        ),
        tactics=("TA0001", "TA0009"),
        techniques=("T1091", "T1005"),
        severity="high",
        response_class="isolate_host",
        evidence_keywords=("USB", "autorun", "air-gapped", "{host}", "{user}", "Python stager"),
        placeholders=("host", "user"),
    ),
    Template(
        title="OAuth consent phishing targeting {user}",
        description=(
            "Malicious OAuth application granted Mail.Read and Files.Read.All scopes by {user}. "
            "Inbox forwarding rule created sending mail to {ip}."
        ),
        tactics=("TA0001", "TA0006"),
        techniques=("T1528", "T1550.001"),
        severity="high",
        response_class="disable_account",
        evidence_keywords=("OAuth consent", "Mail.Read", "Files.Read.All", "{user}", "{ip}", "forwarding rule"),
        placeholders=("user", "ip"),
    ),

    # ─────────────────────────────────────────────────────────
    # Execution (TA0002)
    # ─────────────────────────────────────────────────────────
    Template(
        title="Obfuscated PowerShell dropper executed on {host}",
        description=(
            "PowerShell dropper executed on {host} by {user}; payload base64-encoded and decoded "
            "in-memory. Linked to {campaign} ransomware staging."
        ),
        tactics=("TA0002", "TA0005"),
        techniques=("T1059.001", "T1027"),
        severity="critical",
        response_class="isolate_host",
        evidence_keywords=("powershell", "obfuscated", "base64", "{host}", "{user}", "{campaign}"),
        placeholders=("host", "user", "campaign"),
    ),
    Template(
        title="Living-off-the-land: certutil download cradle on {host}",
        description=(
            "certutil.exe -urlcache invoked from cmd.exe on {host}. cmd.exe was spawned by "
            "outlook.exe. Payload downloaded from {ip}."
        ),
        tactics=("TA0002", "TA0005"),
        techniques=("T1105", "T1218.009"),
        severity="high",
        response_class="isolate_host",
        evidence_keywords=("certutil", "urlcache", "outlook.exe", "{host}", "{ip}", "download cradle"),
        placeholders=("host", "ip"),
    ),
    Template(
        title="Container runtime abuse: malicious `docker run` on {host}",
        description=(
            "Unauthenticated Docker API on {host} exploited from {ip}. Container with cryptominer "
            "spawned. CPU on host saturated to 95%."
        ),
        tactics=("TA0002", "TA0001", "TA0040"),
        techniques=("T1610", "T1059.004", "T1496"),
        severity="high",
        response_class="isolate_host",
        evidence_keywords=("docker", "container", "cryptominer", "miner", "{host}", "{ip}"),
        placeholders=("host", "ip"),
    ),
    Template(
        title="Malicious WMI subscription on {host}",
        description=(
            "Permanent WMI event subscription created on {host} by {user}. Consumer runs encoded "
            "script. Persistence + execution mechanism."
        ),
        tactics=("TA0002", "TA0003"),
        techniques=("T1546.003", "T1059.001"),
        severity="high",
        response_class="isolate_host",
        evidence_keywords=("WMI", "subscription", "permanent", "{host}", "{user}", "encoded script"),
        placeholders=("host", "user"),
    ),

    # ─────────────────────────────────────────────────────────
    # Persistence (TA0003)
    # ─────────────────────────────────────────────────────────
    Template(
        title="Registry Run key persistence created by {user} on {host}",
        description=(
            "New value written to HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run on "
            "{host}. Points to roaming binary signed with revoked cert. Linked to {campaign}."
        ),
        tactics=("TA0003",),
        techniques=("T1547.001",),
        severity="medium",
        response_class="rollback_change",
        evidence_keywords=("registry run", "persistence", "revoked cert", "{host}", "{user}", "{campaign}"),
        placeholders=("user", "host", "campaign"),
    ),
    Template(
        title="Scheduled task persistence on {host}",
        description=(
            "Hidden scheduled task created on {host} by {user}: triggers every 30 minutes, runs "
            "script from %APPDATA%\\Roaming. Persistence mechanism."
        ),
        tactics=("TA0003",),
        techniques=("T1053.005",),
        severity="medium",
        response_class="rollback_change",
        evidence_keywords=("scheduled task", "persistence", "APPDATA", "{host}", "{user}"),
        placeholders=("host", "user"),
    ),
    Template(
        title="Firmware implant detected on UEFI partition of {host}",
        description=(
            "UEFI secure-boot violation on {host}. Unknown module detected in firmware. Signature "
            "matches MosaicRegressor implant."
        ),
        tactics=("TA0003", "TA0005"),
        techniques=("T1542.001", "T1027.002"),
        severity="critical",
        response_class="isolate_host",
        evidence_keywords=("UEFI", "firmware", "implant", "secure boot", "{host}", "MosaicRegressor"),
        placeholders=("host",),
    ),
    Template(
        title="Backdoor cron job installed on {host}",
        description=(
            "/etc/cron.d entry created by {user} on {host}. Reverse shell beacon to {ip} every 5 "
            "minutes."
        ),
        tactics=("TA0003", "TA0011"),
        techniques=("T1053.003", "T1071.001"),
        severity="high",
        response_class="rollback_change",
        evidence_keywords=("cron", "backdoor", "reverse shell", "{host}", "{user}", "{ip}"),
        placeholders=("host", "user", "ip"),
    ),

    # ─────────────────────────────────────────────────────────
    # Privilege Escalation (TA0004)
    # ─────────────────────────────────────────────────────────
    Template(
        title="UAC bypass observed on {host}",
        description=(
            "fodhelper.exe abuse on {host} by {user}; auto-elevation triggered without prompt. "
            "Process tree shows escalation to SYSTEM."
        ),
        tactics=("TA0004", "TA0005"),
        techniques=("T1548.002",),
        severity="high",
        response_class="isolate_host",
        evidence_keywords=("UAC", "fodhelper", "auto-elevation", "{host}", "{user}", "SYSTEM"),
        placeholders=("host", "user"),
    ),
    Template(
        title="Container escape via privileged pod on {host}",
        description=(
            "Kubernetes privileged pod created on {host} by {user}. cgroup escape to host "
            "namespace observed. Node filesystem accessed."
        ),
        tactics=("TA0004", "TA0007"),
        techniques=("T1611", "T1082"),
        severity="critical",
        response_class="isolate_host",
        evidence_keywords=("kubernetes", "privileged pod", "container escape", "cgroup", "{host}", "{user}"),
        placeholders=("host", "user"),
    ),
    Template(
        title="Linux SUID binary abuse on {host}",
        description=(
            "Custom SUID binary discovered in /tmp on {host}; allows arbitrary command execution "
            "as root. Likely escalation by {user}."
        ),
        tactics=("TA0004",),
        techniques=("T1548.001",),
        severity="high",
        response_class="isolate_host",
        evidence_keywords=("SUID", "/tmp", "root escalation", "{host}", "{user}"),
        placeholders=("host", "user"),
    ),

    # ─────────────────────────────────────────────────────────
    # Defense Evasion (TA0005)
    # ─────────────────────────────────────────────────────────
    Template(
        title="Memory-only fileless implant in svchost on {host}",
        description=(
            "Process hollowing detected on {host}: svchost.exe replaced with Cobalt Strike beacon "
            "to {ip}. No disk artefacts. Linked to {campaign}."
        ),
        tactics=("TA0002", "TA0005"),
        techniques=("T1055.012", "T1620"),
        severity="critical",
        response_class="isolate_host",
        evidence_keywords=("process hollowing", "fileless", "svchost", "Cobalt Strike", "{host}", "{ip}"),
        placeholders=("host", "ip", "campaign"),
    ),
    Template(
        title="Indicator removal: Windows event log cleared on {host}",
        description=(
            "Security event log cleared on {host} by {user}. wevtutil.exe cl Security observed in "
            "command-line telemetry."
        ),
        tactics=("TA0005",),
        techniques=("T1070.001",),
        severity="high",
        response_class="escalate",
        evidence_keywords=("wevtutil", "log cleared", "indicator removal", "{host}", "{user}"),
        placeholders=("host", "user"),
    ),
    Template(
        title="Disable security tooling on {host}",
        description=(
            "{user} attempted to stop Defender, CrowdStrike, and Sysmon on {host}. Tampering "
            "telemetry triggered alert."
        ),
        tactics=("TA0005",),
        techniques=("T1562.001",),
        severity="critical",
        response_class="isolate_host",
        evidence_keywords=("defender", "crowdstrike", "sysmon", "tampering", "{host}", "{user}"),
        placeholders=("host", "user"),
    ),

    # ─────────────────────────────────────────────────────────
    # Credential Access (TA0006)
    # ─────────────────────────────────────────────────────────
    Template(
        title="LSASS memory dump on {host} by {user}",
        description=(
            "comsvcs.dll MiniDump observed on {host}. lsass.exe memory dumped to "
            "C:\\Windows\\Temp\\. Mimikatz signatures detected."
        ),
        tactics=("TA0006",),
        techniques=("T1003.001",),
        severity="critical",
        response_class="isolate_host",
        evidence_keywords=("lsass", "minidump", "comsvcs", "mimikatz", "{host}", "{user}"),
        placeholders=("host", "user"),
    ),
    Template(
        title="Brute-force credential spray against {user} from {ip}",
        description=(
            "Credential spray from {ip} against {user}. 1500 password attempts in 30 minutes. "
            "One success followed by anomalous Azure AD sign-in."
        ),
        tactics=("TA0006",),
        techniques=("T1110.003",),
        severity="high",
        response_class="disable_account",
        evidence_keywords=("brute force", "credential spray", "{user}", "{ip}", "azure ad"),
        placeholders=("user", "ip"),
    ),
    Template(
        title="Kerberoasting from {host}",
        description=(
            "Service account TGS tickets requested en-masse from {host} by {user}. AES256 → RC4 "
            "downgrade observed. Mimikatz tooling indicators."
        ),
        tactics=("TA0006", "TA0008"),
        techniques=("T1558.003", "T1021.001"),
        severity="critical",
        response_class="disable_account",
        evidence_keywords=("kerberoast", "TGS", "RC4", "mimikatz", "{host}", "{user}"),
        placeholders=("host", "user"),
    ),
    Template(
        title="Active Directory DCSync from non-DC host {host}",
        description=(
            "Replication rights abused from {host} by {user}. All domain NTLM hashes replicated. "
            "Severe credential exposure."
        ),
        tactics=("TA0006", "TA0004"),
        techniques=("T1003.006", "T1078.002"),
        severity="critical",
        response_class="disable_account",
        evidence_keywords=("dcsync", "replication", "ntlm hash", "{host}", "{user}"),
        placeholders=("host", "user"),
    ),
    Template(
        title="SAML golden-ticket: forged assertion targeting {user}",
        description=(
            "Forged SAML assertion detected for {user}. Attacker pivoted to Azure AD; account "
            "enumeration followed from {ip}."
        ),
        tactics=("TA0006", "TA0007"),
        techniques=("T1606.002", "T1087.002"),
        severity="critical",
        response_class="disable_account",
        evidence_keywords=("saml", "golden ticket", "forged", "azure ad", "{user}", "{ip}"),
        placeholders=("user", "ip"),
    ),

    # ─────────────────────────────────────────────────────────
    # Discovery (TA0007)
    # ─────────────────────────────────────────────────────────
    Template(
        title="Domain enumeration from {host}",
        description=(
            "ldap discovery from {host} by {user}: BloodHound-style queries enumerating users, "
            "groups, ACLs."
        ),
        tactics=("TA0007",),
        techniques=("T1087.002",),
        severity="medium",
        response_class="monitor",
        evidence_keywords=("ldap", "bloodhound", "domain enumeration", "{host}", "{user}"),
        placeholders=("host", "user"),
    ),
    Template(
        title="Network share enumeration on {host}",
        description=(
            "Mass SMB share enumeration from {host} by {user}; net.exe and PowerShell Get-SmbShare "
            "invocations across /24 subnet."
        ),
        tactics=("TA0007",),
        techniques=("T1135",),
        severity="medium",
        response_class="monitor",
        evidence_keywords=("smb", "net.exe", "Get-SmbShare", "share enumeration", "{host}", "{user}"),
        placeholders=("host", "user"),
    ),

    # ─────────────────────────────────────────────────────────
    # Lateral Movement (TA0008)
    # ─────────────────────────────────────────────────────────
    Template(
        title="Pass-the-hash from {host} to {target_host}",
        description=(
            "Pass-the-hash lateral movement from {host} to {target_host} by {user}. Golden ticket "
            "indicators present. Linked to {campaign}."
        ),
        tactics=("TA0008", "TA0006"),
        techniques=("T1550.002", "T1558.001"),
        severity="critical",
        response_class="isolate_host",
        evidence_keywords=("pass-the-hash", "golden ticket", "{host}", "{target_host}", "{user}", "{campaign}"),
        placeholders=("host", "target_host", "user", "campaign"),
    ),
    Template(
        title="RDP lateral movement from {host}",
        description=(
            "Anomalous RDP session from {host} ({user}) to {target_host} outside business hours. "
            "Source admin not normal for {target_host}."
        ),
        tactics=("TA0008",),
        techniques=("T1021.001",),
        severity="high",
        response_class="isolate_host",
        evidence_keywords=("rdp", "lateral movement", "outside hours", "{host}", "{target_host}", "{user}"),
        placeholders=("host", "target_host", "user"),
    ),
    Template(
        title="WMI lateral execution from {host} to {target_host}",
        description=(
            "wmic.exe /node:{target_host} process call create observed from {host} by {user}. "
            "Remote command execution; payload from {ip}."
        ),
        tactics=("TA0008", "TA0002"),
        techniques=("T1047",),
        severity="high",
        response_class="isolate_host",
        evidence_keywords=("wmic", "lateral", "{host}", "{target_host}", "{user}", "{ip}"),
        placeholders=("host", "target_host", "user", "ip"),
    ),

    # ─────────────────────────────────────────────────────────
    # Collection (TA0009)
    # ─────────────────────────────────────────────────────────
    Template(
        title="Bulk PII download by {user}",
        description=(
            "{user} downloaded >10 GB of customer records from production database from {host}. "
            "Outside normal access pattern."
        ),
        tactics=("TA0009", "TA0010"),
        techniques=("T1005", "T1041"),
        severity="critical",
        response_class="disable_account",
        evidence_keywords=("bulk download", "pii", "customer record", "{host}", "{user}"),
        placeholders=("user", "host"),
    ),
    Template(
        title="Clipboard logging implant on {host}",
        description=(
            "Clipboard contents from {host} ({user}) being captured to %APPDATA%\\Local\\. "
            "Captures span 2 hours and include credentials and crypto addresses."
        ),
        tactics=("TA0009",),
        techniques=("T1115",),
        severity="high",
        response_class="isolate_host",
        evidence_keywords=("clipboard", "keylog", "credentials", "{host}", "{user}"),
        placeholders=("host", "user"),
    ),

    # ─────────────────────────────────────────────────────────
    # Exfiltration (TA0010)
    # ─────────────────────────────────────────────────────────
    Template(
        title="DNS tunnelling exfiltration from {host}",
        description=(
            "DNS query volume from {host} 50× baseline. TXT records contain base64-encoded "
            "payloads. Estimated exfil ~200 MB; destination {ip}."
        ),
        tactics=("TA0011", "TA0010"),
        techniques=("T1071.004", "T1048.003"),
        severity="critical",
        response_class="isolate_host",
        evidence_keywords=("dns tunnel", "txt records", "base64", "exfiltrat", "{host}", "{ip}"),
        placeholders=("host", "ip"),
    ),
    Template(
        title="Cloud storage exfil: data egress to attacker-controlled S3 from {host}",
        description=(
            "Egress from {host} to s3://atk-stage-{ip}/dump/ by {user}. 8 GB transferred over 20 "
            "minutes. CloudTrail PutObject events match."
        ),
        tactics=("TA0010",),
        techniques=("T1567.002",),
        severity="critical",
        response_class="block_indicator",
        evidence_keywords=("s3", "cloud storage", "egress", "exfiltrat", "{host}", "{ip}", "{user}"),
        placeholders=("host", "ip", "user"),
    ),
    Template(
        title="Personal Drive exfil by {user}",
        description=(
            "{user} on {host} uploaded 4 GB to personal Google Drive. Files include source code "
            "and customer PII."
        ),
        tactics=("TA0009", "TA0010"),
        techniques=("T1567.002", "T1005"),
        severity="critical",
        response_class="disable_account",
        evidence_keywords=("google drive", "personal", "exfiltrat", "source code", "pii", "{host}", "{user}"),
        placeholders=("user", "host"),
    ),

    # ─────────────────────────────────────────────────────────
    # Command and Control (TA0011)
    # ─────────────────────────────────────────────────────────
    Template(
        title="DGA-based C2 traffic from {host}",
        description=(
            "DGA traffic from {host} observed; 200+ NXDomain replies/min, IoCs match {campaign} "
            "epoch 5. Beacons to {ip}."
        ),
        tactics=("TA0011",),
        techniques=("T1568.002",),
        severity="high",
        response_class="block_indicator",
        evidence_keywords=("dga", "domain generation", "nxdomain", "beacon", "{host}", "{ip}", "{campaign}"),
        placeholders=("host", "ip", "campaign"),
    ),
    Template(
        title="HTTPS C2 beacon from {host} to {ip}",
        description=(
            "Periodic HTTPS beacon from {host} to {ip} every 60 seconds with low jitter. JA3 "
            "fingerprint matches Cobalt Strike."
        ),
        tactics=("TA0011",),
        techniques=("T1071.001",),
        severity="critical",
        response_class="block_indicator",
        evidence_keywords=("c2", "beacon", "ja3", "Cobalt Strike", "{host}", "{ip}"),
        placeholders=("host", "ip"),
    ),

    # ─────────────────────────────────────────────────────────
    # Impact (TA0040)
    # ─────────────────────────────────────────────────────────
    Template(
        title="Ransomware encryption in progress on {host}",
        description=(
            "Mass file rename observed on {host} ({user}); .{ext} extension applied to ~20 k "
            "files. Ransomware note R3ADM3-{campaign}.txt found."
        ),
        tactics=("TA0040",),
        techniques=("T1486",),
        severity="critical",
        response_class="isolate_host",
        evidence_keywords=("ransomware", "encrypt", "rename", "ransom note", "{host}", "{user}", "{campaign}"),
        placeholders=("host", "user", "ext", "campaign"),
    ),
    Template(
        title="Cryptominer execution on {host}",
        description=(
            "XMRig miner spawned on {host}; CPU saturated to 95%. Mining pool {ip}:5555. Linked "
            "to {campaign}."
        ),
        tactics=("TA0002", "TA0040"),
        techniques=("T1496",),
        severity="medium",
        response_class="isolate_host",
        evidence_keywords=("xmrig", "miner", "cryptomine", "{host}", "{ip}", "{campaign}"),
        placeholders=("host", "ip", "campaign"),
    ),
    Template(
        title="BEC: payment redirect by {user}",
        description=(
            "Spear-phishing email spoofed CFO. Wire transfer of $250 k initiated by {user} from "
            "{host} to threat-actor account. Linked to {campaign}."
        ),
        tactics=("TA0001", "TA0040"),
        techniques=("T1566.001", "T1657"),
        severity="critical",
        response_class="escalate",
        evidence_keywords=("phishing", "spoofed cfo", "wire transfer", "$250", "{user}", "{host}", "{campaign}"),
        placeholders=("user", "host", "campaign"),
    ),

    # ─────────────────────────────────────────────────────────
    # Cloud / Identity / Mobile / Misc
    # ─────────────────────────────────────────────────────────
    Template(
        title="Public S3 bucket exposing PII",
        description=(
            "S3 bucket world-readable; ~40k employee records accessible. CloudTrail shows external "
            "enumeration from {ip}."
        ),
        tactics=("TA0009", "TA0010"),
        techniques=("T1530", "T1567.002"),
        severity="critical",
        response_class="rollback_change",
        evidence_keywords=("s3", "public bucket", "pii", "cloudtrail", "{ip}"),
        placeholders=("ip",),
    ),
    Template(
        title="Identity provider compromise — anomalous Azure AD sign-in for {user}",
        description=(
            "Successful Azure AD sign-in for {user} from {ip} (impossible-travel from prior "
            "location). MFA satisfied via stolen session token."
        ),
        tactics=("TA0001", "TA0006"),
        techniques=("T1078.004", "T1550.001"),
        severity="critical",
        response_class="disable_account",
        evidence_keywords=("azure ad", "impossible travel", "session token", "mfa", "{user}", "{ip}"),
        placeholders=("user", "ip"),
    ),
    Template(
        title="DDoS volumetric flood targeting public-facing {host}",
        description=(
            "L4 SYN flood from a botnet (>1M PPS) targeting {host}. Edge mitigation engaged but "
            "service degraded for 12 minutes."
        ),
        tactics=("TA0040",),
        techniques=("T1498.001",),
        severity="high",
        response_class="block_indicator",
        evidence_keywords=("ddos", "syn flood", "botnet", "{host}", "1M PPS"),
        placeholders=("host",),
    ),
    Template(
        title="Insider preparing departure: large mailbox export by {user}",
        description=(
            "{user} exported full mailbox PST (8 GB) from {host}. HR flag: notice given last "
            "week."
        ),
        tactics=("TA0009", "TA0010"),
        techniques=("T1114.002", "T1567.002"),
        severity="high",
        response_class="disable_account",
        evidence_keywords=("mailbox export", "PST", "insider", "departure", "{user}", "{host}"),
        placeholders=("user", "host"),
    ),
    Template(
        title="Malicious Office add-in installed for {user}",
        description=(
            "Office VSTO add-in registered under HKCU for {user} on {host}; loads on every Outlook "
            "startup; beacons to {ip}."
        ),
        tactics=("TA0003", "TA0011"),
        techniques=("T1137.006", "T1071.001"),
        severity="high",
        response_class="rollback_change",
        evidence_keywords=("office add-in", "vsto", "outlook", "{user}", "{host}", "{ip}"),
        placeholders=("user", "host", "ip"),
    ),
    Template(
        title="GitHub PAT leaked and abused from {ip}",
        description=(
            "Personal access token belonging to {user} used from {ip} to clone 14 private repos. "
            "Token committed in public dotfiles repo 6 hours earlier."
        ),
        tactics=("TA0006", "TA0009"),
        techniques=("T1552.001", "T1213.003"),
        severity="critical",
        response_class="disable_account",
        evidence_keywords=("github", "pat", "token", "private repo", "{user}", "{ip}"),
        placeholders=("user", "ip"),
    ),
    Template(
        title="EC2 instance metadata service abused on {host}",
        description=(
            "IMDSv1 abused on {host}; temporary IAM credentials for role exfilled to {ip}. "
            "CloudTrail shows AssumeRole from external."
        ),
        tactics=("TA0006", "TA0004"),
        techniques=("T1552.005", "T1078.004"),
        severity="critical",
        response_class="rollback_change",
        evidence_keywords=("imds", "metadata", "iam credentials", "AssumeRole", "{host}", "{ip}"),
        placeholders=("host", "ip"),
    ),
    Template(
        title="Vendor admin password reset abuse for {user}",
        description=(
            "Password reset for {user} performed by helpdesk in response to social-engineering "
            "call from {ip}. Token claimed within 90 seconds."
        ),
        tactics=("TA0001", "TA0006"),
        techniques=("T1566.004", "T1078"),
        severity="high",
        response_class="disable_account",
        evidence_keywords=("password reset", "social engineering", "helpdesk", "{user}", "{ip}"),
        placeholders=("user", "ip"),
    ),
    Template(
        title="OAuth refresh-token theft for {user}",
        description=(
            "Refresh token for {user} replayed from {ip}. Granted access to mailbox + "
            "OneDrive without re-prompt."
        ),
        tactics=("TA0006",),
        techniques=("T1550.001",),
        severity="high",
        response_class="disable_account",
        evidence_keywords=("oauth", "refresh token", "replay", "onedrive", "mailbox", "{user}", "{ip}"),
        placeholders=("user", "ip"),
    ),
    Template(
        title="Container image with embedded backdoor pulled by {host}",
        description=(
            "Image registry/repo:malicious-backdoor pulled by {host}. Layer scan flagged "
            "embedded netcat reverse-shell binary."
        ),
        tactics=("TA0001", "TA0002"),
        techniques=("T1195.002", "T1610"),
        severity="high",
        response_class="rollback_change",
        evidence_keywords=("container image", "registry", "backdoor", "netcat", "{host}"),
        placeholders=("host",),
    ),
    Template(
        title="Outlook rule auto-forwarding mail from {user}",
        description=(
            "Outlook inbox rule created for {user} that forwards all mail to external address at "
            "{ip}. Linked to {campaign}."
        ),
        tactics=("TA0006", "TA0009"),
        techniques=("T1564.008", "T1114.003"),
        severity="high",
        response_class="disable_account",
        evidence_keywords=("outlook rule", "forward", "mail", "{user}", "{ip}", "{campaign}"),
        placeholders=("user", "ip", "campaign"),
    ),
    Template(
        title="Linux journald log tampering on {host}",
        description=(
            "journalctl --rotate --vacuum-time=1s observed on {host} by {user}; recent journal "
            "entries purged. Indicator removal."
        ),
        tactics=("TA0005",),
        techniques=("T1070.002",),
        severity="high",
        response_class="escalate",
        evidence_keywords=("journalctl", "log tampering", "vacuum", "{host}", "{user}"),
        placeholders=("host", "user"),
    ),
    Template(
        title="Compromised CI runner on {host} pushing to production",
        description=(
            "Self-hosted CI runner {host} compromised. Job triggered from PR injected secret "
            "exfil step; secrets posted to {ip}."
        ),
        tactics=("TA0001", "TA0006", "TA0010"),
        techniques=("T1195.002", "T1552.004"),
        severity="critical",
        response_class="rollback_change",
        evidence_keywords=("ci runner", "self-hosted", "secret", "exfil", "{host}", "{ip}"),
        placeholders=("host", "ip"),
    ),
    Template(
        title="Suspicious VPN login from new geography for {user}",
        description=(
            "VPN login for {user} from {ip} (new country, no prior history). Subsequent "
            "lateral SMB scan from VPN range to {host}."
        ),
        tactics=("TA0001", "TA0008"),
        techniques=("T1078.004", "T1021.002"),
        severity="high",
        response_class="disable_account",
        evidence_keywords=("vpn", "new geography", "lateral", "smb scan", "{user}", "{ip}", "{host}"),
        placeholders=("user", "ip", "host"),
    ),
    Template(
        title="Privileged command run as service account on {host}",
        description=(
            "Service account {user} (no interactive use expected) ran privileged net.exe + "
            "wevtutil cl Security on {host}. Anomalous."
        ),
        tactics=("TA0005", "TA0006"),
        techniques=("T1078.001", "T1070.001"),
        severity="high",
        response_class="disable_account",
        evidence_keywords=("service account", "wevtutil", "log clear", "{user}", "{host}"),
        placeholders=("user", "host"),
    ),
]


# ---------------------------------------------------------------------------
# Deterministic generation
# ---------------------------------------------------------------------------

def _seed_index(index: int, salt: str) -> int:
    """Stable per-(index, salt) integer derived from SHA256."""
    h = hashlib.sha256(f"{index}-{salt}".encode()).hexdigest()
    return int(h[:8], 16)


def _pick(pool: list[str], index: int, salt: str) -> str:
    """Deterministically pick one item from `pool`."""
    return pool[_seed_index(index, salt) % len(pool)]


def _resolve_placeholders(template: Template, index: int) -> dict[str, str]:
    """Build a deterministic substitution dict for one incident."""
    pool_map = {
        "host": HOSTNAMES,
        "target_host": HOSTNAMES,
        "user": USERS,
        "ip": ATTACKER_IPS,
        "campaign": CAMPAIGNS,
        "ext": [".locked", ".aisocrypt", ".pwned", ".enc", ".tooktdata"],
    }
    subs: dict[str, str] = {}
    for ph in template.placeholders:
        salt = f"{template.title}|{ph}"
        subs[ph] = _pick(pool_map[ph], index, salt)
    # If the template references {target_host} ensure it differs from {host}
    if "target_host" in subs and subs.get("host") == subs.get("target_host"):
        # bump by one for diversity (still deterministic)
        target_idx = (HOSTNAMES.index(subs["target_host"]) + 1) % len(HOSTNAMES)
        subs["target_host"] = HOSTNAMES[target_idx]
    # Fill any unreferenced placeholders that appear in title/description with empty
    return subs


def _format(text: str, subs: dict[str, str]) -> str:
    """Format `text`, leaving unresolved placeholders alone (no KeyError)."""
    out = text
    for k, v in subs.items():
        out = out.replace("{" + k + "}", v)
    return out


def _expand_evidence(keywords: tuple[str, ...], subs: dict[str, str]) -> list[str]:
    """Resolve placeholder evidence keywords against `subs`."""
    return [_format(k, subs) for k in keywords]


def generate_incidents(count: int) -> list[dict[str, Any]]:
    """Generate `count` deterministic incidents by cycling through templates.

    The cycle keeps coverage balanced across all templates: incident i uses
    `TEMPLATES[i % len(TEMPLATES)]` with a per-index parameter substitution.
    Re-running with the same `count` yields byte-identical output.
    """
    if not TEMPLATES:
        raise RuntimeError("No templates defined.")
    incidents: list[dict[str, Any]] = []
    for i in range(count):
        tpl = TEMPLATES[i % len(TEMPLATES)]
        subs = _resolve_placeholders(tpl, i)
        title = _format(tpl.title, subs)
        description = _format(tpl.description, subs)
        evidence = _expand_evidence(tpl.evidence_keywords, subs)
        incidents.append(
            {
                "id": f"INC-EVAL-{i + 1:03d}",
                "title": title,
                "description": description,
                "expected_tactics": list(tpl.tactics),
                "expected_techniques": list(tpl.techniques),
                "severity": tpl.severity,
                "response_class": tpl.response_class,
                "evidence_keywords": evidence,
            }
        )
    return incidents


def coverage_report(incidents: list[dict[str, Any]]) -> dict[str, Any]:
    """Summarize MITRE coverage of the generated set."""
    tactic_counts: dict[str, int] = {}
    technique_counts: dict[str, int] = {}
    severity_counts: dict[str, int] = {}
    response_counts: dict[str, int] = {}
    for inc in incidents:
        for t in inc["expected_tactics"]:
            tactic_counts[t] = tactic_counts.get(t, 0) + 1
        for tech in inc["expected_techniques"]:
            technique_counts[tech] = technique_counts.get(tech, 0) + 1
        severity_counts[inc["severity"]] = severity_counts.get(inc["severity"], 0) + 1
        response_counts[inc["response_class"]] = response_counts.get(inc["response_class"], 0) + 1
    return {
        "total": len(incidents),
        "unique_titles": len({inc["title"] for inc in incidents}),
        "tactics": dict(sorted(tactic_counts.items())),
        "techniques": dict(sorted(technique_counts.items())),
        "severity": dict(sorted(severity_counts.items())),
        "response_class": dict(sorted(response_counts.items())),
        "templates_used": len({inc["title"][:30] for inc in incidents}),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate deterministic eval incidents.")
    parser.add_argument("--count", type=int, default=200, help="Number of incidents (default: 200)")
    parser.add_argument(
        "--out",
        type=Path,
        default=Path(__file__).parent.parent
        / "services"
        / "agents"
        / "tests"
        / "eval_data"
        / "synthetic_incidents.json",
        help="Output JSON path",
    )
    parser.add_argument("--coverage", action="store_true", help="Print coverage report after generating")
    args = parser.parse_args()

    incidents = generate_incidents(args.count)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(incidents, indent=2) + "\n")

    print(f"Wrote {len(incidents)} incidents to {args.out}")
    if args.coverage:
        report = coverage_report(incidents)
        print("\n=== Coverage ===")
        print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
