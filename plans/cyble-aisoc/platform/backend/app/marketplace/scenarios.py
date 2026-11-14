"""Benchmark scenarios — the open AI-SOC eval set.

Every scenario is a self-contained, deterministic test case grounded in
public threat intelligence (FIN7 phishing, CL0P MOVEit exploit, Okta
session theft, etc). Each scenario specifies:

- ``alert``: an OCSF-aligned alert payload identical to what
  ``POST /alerts`` ingests, so the agent mesh runs the same code path
  it does in production.
- ``expected``: the analyst-grade ground truth — verdict, severity
  ceiling, MITRE technique coverage, IOC extraction, and required
  response actions. The grader compares the produced :class:`Case`
  against this expectation and emits a 0..100 score.

Adding scenarios is intentionally append-only and version-stamped so
historical leaderboard entries remain comparable. Bump
``benchmark_version`` only when the grading rubric or canonical input
shape changes.

These scenarios are kept in a Python module (not JSON-on-disk) so they
ship with the source distribution, get type-checked, and can be lifted
verbatim into the public open-eval repo on day-1.
"""
from __future__ import annotations

from typing import Any

# Bump when the grading rubric or canonical scenario inputs change.
# Leaderboard rows record this so an apples-to-apples view is possible.
BENCHMARK_VERSION = "0.1.0"


_SCENARIOS: list[dict[str, Any]] = [
    # ─── 1. CL0P MOVEit-style mass exfiltration ──────────────────────
    {
        "id": "cl0p-moveit-exfil",
        "title": "CL0P-style MOVEit exploitation + data exfiltration",
        "description": (
            "External attacker exploits a known SQLi against an internet-"
            "exposed MOVEit Transfer instance, drops a webshell, and "
            "exfiltrates archives to a known CL0P staging IP."
        ),
        "alert": {
            "external_id": "bench-cl0p-001",
            "source": "splunk",
            "title": "Suspicious MOVEit data transfer to known CL0P staging IP",
            "description": (
                "Outbound transfer of 4.7GB to 198.51.100.42 from "
                "moveit01.corp.local; webshell file /human2.aspx written 12s "
                "earlier."
            ),
            "severity": "critical",
            "detection_rule": "cve-2023-34362-moveit-webshell-write",
            "mitre_tactics": ["initial_access", "exfiltration"],
            "mitre_techniques": ["T1190", "T1567"],
            "src_user": "iisapppool$",
            "src_host": "moveit01.corp.local",
            "src_ip": "10.0.42.18",
            "dst_ip": "198.51.100.42",
            "process_name": "w3wp.exe",
            "file_hash": "0a3e5f04e3b2c0a18a8a3a1b1c2d3e4f5a6b7c8d9e0f1a2b",
            "raw": {"bytes_out": 5033164800},
        },
        "expected": {
            "verdict": "true_positive",
            "min_severity": "high",
            "must_iocs": ["198.51.100.42"],
            "must_techniques": ["T1190"],
            "must_response_actions": ["isolate_host"],
            "max_latency_seconds": 180,
        },
        "tags": ["initial_access", "exfiltration", "cti-pivot"],
    },
    # ─── 2. Okta session theft / AitM ────────────────────────────────
    {
        "id": "okta-aitm-session-theft",
        "title": "Okta session-cookie theft (AitM phishing)",
        "description": (
            "User authenticated to Okta from a known-good IP, then 4 minutes "
            "later the same session-cookie is replayed from a different "
            "country and user-agent — classic adversary-in-the-middle "
            "session theft."
        ),
        "alert": {
            "external_id": "bench-okta-001",
            "source": "okta",
            "title": "Possible session cookie replay from anomalous geo",
            "description": (
                "User alex@acme.com session sid=okta-sess-abc123 used from "
                "203.0.113.7 (RU) 4 minutes after legit auth from 73.x (US)."
            ),
            "severity": "high",
            "detection_rule": "okta-session-replay-anomalous-geo",
            "mitre_tactics": ["credential_access", "lateral_movement"],
            "mitre_techniques": ["T1539", "T1078.004"],
            "src_user": "alex@acme.com",
            "src_ip": "203.0.113.7",
            "raw": {"session_id": "okta-sess-abc123"},
        },
        "expected": {
            "verdict": "true_positive",
            "min_severity": "high",
            "must_users": ["alex@acme.com"],
            "must_techniques": ["T1539"],
            "must_response_actions": ["revoke_sessions", "disable_user"],
            "max_latency_seconds": 120,
        },
        "tags": ["identity", "itdr"],
    },
    # ─── 3. FIN7 phishing chain → Carbanak loader ────────────────────
    {
        "id": "fin7-phishing-carbanak",
        "title": "FIN7 phishing chain dropping Carbanak loader",
        "description": (
            "User opened LNK attachment from a spoofed-but-similar domain. "
            "wscript spawns powershell which beacons to a known FIN7 C2."
        ),
        "alert": {
            "external_id": "bench-fin7-001",
            "source": "sentinelone",
            "title": "powershell.exe spawned by wscript with C2 beacon",
            "description": (
                "WScript -> powershell -> beacon to fin7-staging-c2[.]net "
                "(198.51.100.77) — Cyble actor catalogue tags this IP under "
                "FIN7 / Carbanak."
            ),
            "severity": "critical",
            "detection_rule": "wscript-spawns-powershell-c2",
            "mitre_tactics": ["execution", "command_and_control"],
            "mitre_techniques": ["T1059.001", "T1566.001"],
            "src_user": "jsmith",
            "src_host": "DESKTOP-04F7",
            "dst_ip": "198.51.100.77",
            "process_name": "powershell.exe",
            "raw": {"parent": "wscript.exe"},
        },
        "expected": {
            "verdict": "true_positive",
            "min_severity": "high",
            "must_hosts": ["DESKTOP-04F7"],
            "must_iocs": ["198.51.100.77"],
            "must_techniques": ["T1059.001"],
            "must_response_actions": ["isolate_host", "kill_process"],
            "must_actor": "FIN7",
            "max_latency_seconds": 240,
        },
        "tags": ["execution", "c2", "actor-attribution"],
    },
    # ─── 4. Benign printer noise (false-positive control) ────────────
    {
        "id": "benign-printer-noise",
        "title": "Benign: scheduled printer firmware check",
        "description": (
            "FP control. Office printer makes an outbound HTTPS call to "
            "vendor-update.example.com on a sane schedule. The triager "
            "should *not* escalate this."
        ),
        "alert": {
            "external_id": "bench-benign-001",
            "source": "splunk",
            "title": "Outbound HTTPS from printer vlan",
            "description": "PRN-3F floor printer → vendor-update.example.com 443.",
            "severity": "low",
            "detection_rule": "outbound-https-from-non-user-vlan",
            "mitre_tactics": [],
            "mitre_techniques": [],
            "src_host": "PRN-3F",
            "src_ip": "10.0.99.7",
            "raw": {"hostname_seen_yesterday": True},
        },
        "expected": {
            "verdict": "false_positive",
            "max_severity": "low",
            "must_response_actions": [],
            "max_latency_seconds": 60,
        },
        "tags": ["false-positive-control", "noise-filtering"],
    },
    # ─── 5. Lateral SMB file share (T1021.002) ───────────────────────
    {
        "id": "lateral-smb-admin-share",
        "title": "Lateral movement via SMB admin shares",
        "description": (
            "Compromised endpoint accessing C$ on three different servers "
            "in 90 seconds — classic post-foothold reconnaissance."
        ),
        "alert": {
            "external_id": "bench-lat-001",
            "source": "sentinelone",
            "title": "Burst access to ADMIN$/C$ across multiple hosts",
            "description": (
                "Host DESKTOP-12X3 mounted \\\\srv01\\C$, \\\\srv02\\C$, "
                "\\\\srv03\\C$ in 90s using svc-deploy."
            ),
            "severity": "high",
            "detection_rule": "smb-admin-share-burst-access",
            "mitre_tactics": ["lateral_movement", "discovery"],
            "mitre_techniques": ["T1021.002"],
            "src_user": "svc-deploy",
            "src_host": "DESKTOP-12X3",
            "raw": {"target_hosts": ["srv01", "srv02", "srv03"]},
        },
        "expected": {
            "verdict": "true_positive",
            "min_severity": "high",
            "must_hosts": ["DESKTOP-12X3"],
            "must_users": ["svc-deploy"],
            "must_techniques": ["T1021.002"],
            "must_response_actions": ["isolate_host", "revoke_sessions"],
            "max_latency_seconds": 240,
        },
        "tags": ["lateral_movement"],
    },
]


def builtin_scenarios_raw() -> list[dict[str, Any]]:
    """Return the raw scenario dicts (used by the public benchmark JSON)."""
    return list(_SCENARIOS)
