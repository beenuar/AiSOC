#!/usr/bin/env python3
"""
inject_scenario.py — AiSOC Demo Lab scenario injector

Injects a Conti-style ransomware multi-stage alert sequence into the AiSOC
alert stream via the REST API, creating a realistic investigation scenario.

Stages:
  T1  — Initial compromise: phishing email with malicious macro
  T2  — Credential dumping: LSASS memory access (T1003.001)
  T3  — Lateral movement: SMB / PsExec propagation (T1570)
  T4  — C2 beacon: high-frequency HTTP to known Conti C2 IP (T1071.001)
  T5  — Data exfiltration: large DNS TXT transfer (T1048.003)
  T6  — Ransomware detonation: mass .encrypted extension changes (T1486)

Usage:
  python3 scripts/inject_scenario.py [--api-url http://localhost:8000] [--delay 0.5]
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone

SCENARIO: list[dict] = [
    {
        "stage": 1,
        "title": "Phishing Email — Macro Execution Detected",
        "severity": "medium",
        "mitre_tactics": ["initial-access", "execution"],
        "mitre_techniques": ["T1566.001", "T1204.002"],
        "source": "email-gateway",
        "raw": {
            "user": "john.doe@acme.com",
            "attachment": "Invoice_Q2_2024.xlsm",
            "action": "macro_executed",
            "process": "EXCEL.EXE",
            "child_process": "cmd.exe",
            "host": "ACME-WS-042",
        },
    },
    {
        "stage": 2,
        "title": "Credential Dumping — LSASS Memory Access",
        "severity": "critical",
        "mitre_tactics": ["credential-access"],
        "mitre_techniques": ["T1003.001"],
        "source": "edr",
        "raw": {
            "host": "ACME-WS-042",
            "process": "rundll32.exe",
            "target_process": "lsass.exe",
            "access_rights": "PROCESS_VM_READ",
            "bytes_read": 94208,
        },
    },
    {
        "stage": 3,
        "title": "Lateral Movement — PsExec SMB Propagation",
        "severity": "high",
        "mitre_tactics": ["lateral-movement"],
        "mitre_techniques": ["T1570", "T1021.002"],
        "source": "edr",
        "raw": {
            "source_host": "ACME-WS-042",
            "target_hosts": ["ACME-DC-001", "ACME-FS-003", "ACME-FS-007"],
            "tool": "psexec.exe",
            "smb_share": "ADMIN$",
        },
    },
    {
        "stage": 4,
        "title": "C2 Beacon — High-Frequency HTTP to Known Conti IP",
        "severity": "critical",
        "mitre_tactics": ["command-and-control"],
        "mitre_techniques": ["T1071.001", "T1573.001"],
        "source": "ndr",
        "raw": {
            "src_ip": "10.0.4.42",
            "dst_ip": "185.220.101.47",
            "dst_port": 443,
            "beacon_interval_seconds": 60,
            "jitter_pct": 10,
            "total_connections": 48,
            "threat_intel_match": "Conti C2 TI feed",
        },
    },
    {
        "stage": 5,
        "title": "Data Exfiltration — Large DNS TXT Record Transfer",
        "severity": "high",
        "mitre_tactics": ["exfiltration"],
        "mitre_techniques": ["T1048.003"],
        "source": "dns-monitor",
        "raw": {
            "src_host": "ACME-FS-003",
            "domain": "exfil.c2domain.ru",
            "record_type": "TXT",
            "total_queries": 2847,
            "estimated_bytes_exfiltrated": 2_500_000,
        },
    },
    {
        "stage": 6,
        "title": "Ransomware Detonation — Mass File Encryption (.encrypted)",
        "severity": "critical",
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1486"],
        "source": "edr",
        "raw": {
            "hosts_affected": ["ACME-FS-003", "ACME-FS-007", "ACME-DC-001"],
            "files_encrypted": 183_294,
            "extension": ".conti",
            "ransom_note": "README.txt",
            "shadow_copies_deleted": True,
            "vssadmin_cmd": "vssadmin delete shadows /all /quiet",
        },
    },
]


def _post(url: str, payload: dict, timeout: int = 10) -> dict:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def main() -> None:
    parser = argparse.ArgumentParser(description="Inject Conti ransomware scenario into AiSOC")
    parser.add_argument("--api-url", default="http://localhost:8000", help="AiSOC API base URL")
    parser.add_argument("--delay", type=float, default=0.5, help="Delay between alerts (seconds)")
    args = parser.parse_args()

    alerts_url = f"{args.api_url}/api/v1/alerts"
    print(f"Injecting Conti ransomware scenario → {alerts_url}")

    injected = 0
    for alert in SCENARIO:
        payload = {
            "title": alert["title"],
            "severity": alert["severity"],
            "source": alert["source"],
            "mitre_tactics": alert["mitre_tactics"],
            "mitre_techniques": alert["mitre_techniques"],
            "raw_data": alert["raw"],
            "ts": datetime.now(timezone.utc).isoformat(),
            "tags": ["demo-lab", "conti-scenario", f"stage-{alert['stage']}"],
        }
        try:
            resp = _post(alerts_url, payload)
            print(f"  [stage {alert['stage']}] ✓  {alert['title']} → id={resp.get('id', '?')}")
            injected += 1
        except urllib.error.HTTPError as e:
            body = e.read().decode()
            print(f"  [stage {alert['stage']}] ✗  HTTP {e.code}: {body[:200]}", file=sys.stderr)
        except Exception as exc:  # noqa: BLE001
            print(f"  [stage {alert['stage']}] ✗  {exc}", file=sys.stderr)

        if args.delay:
            time.sleep(args.delay)

    print(f"\n{injected}/{len(SCENARIO)} alerts injected.")
    if injected < len(SCENARIO):
        sys.exit(1)


if __name__ == "__main__":
    main()
