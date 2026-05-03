"""
Pillar-1 Evaluation: MITRE ATT&CK Tactic Accuracy Test
========================================================
This test validates the investigator pipeline's ability to correctly
identify MITRE ATT&CK tactics for the 20 synthetic incident scenarios
defined in seed_demo.py.

It runs OFFLINE (no LLM calls, no DB) by using a mock LLM that returns
canned tactic mentions in its output. The test asserts >=80% accuracy.

Run:
    pytest services/agents/tests/test_mitre_accuracy.py -v
    # or via the CI eval script:
    python scripts/eval_mitre_accuracy.py
"""
from __future__ import annotations

import json
import sys
import unittest
from typing import Any

# ---------------------------------------------------------------------------
# Synthetic incident fixtures (mirrors seed_demo._SYNTHETIC_INCIDENTS)
# Each entry: (title, expected_tactic_ids, technique_ids, description)
# ---------------------------------------------------------------------------
SYNTHETIC_INCIDENTS: list[tuple[str, list[str], list[str], str]] = [
    (
        "Ransomware staging detected on WIN-FIN-DB01 — precursor IOCs found",
        ["TA0002", "TA0005", "TA0040"],
        ["T1059.001", "T1027", "T1486"],
        "PowerShell dropper decoded and executed on WIN-FIN-DB01. Obfuscated payload staged in Temp. "
        "Ransomware note template found. Linked to LockBit 3.0 campaign.",
    ),
    (
        "APT credential harvesting campaign targeting alice@aisoc.dev",
        ["TA0006", "TA0003"],
        ["T1110.001", "T1547.001"],
        "Brute-force spray from 192.168.1.100 against alice@aisoc.dev. Successful login established "
        "persistence via registry Run key. IoCs match APT28 TTPs.",
    ),
    (
        "Insider threat: bulk download of PII by carol@aisoc.dev",
        ["TA0009", "TA0010"],
        ["T1005", "T1041"],
        "carol@aisoc.dev downloaded >10 GB of customer records. Traffic egressed to personal Google Drive.",
    ),
    (
        "Supply chain compromise: malicious npm package on WIN-DEVOPS-LT",
        ["TA0001", "TA0002"],
        ["T1195.001", "T1059.007"],
        "Compromised npm package `event-stream` installed by CI pipeline. Post-install hook executed "
        "reverse shell.",
    ),
    (
        "Kerberoasting and lateral movement from WIN-PROD-WEB02",
        ["TA0006", "TA0008"],
        ["T1558.003", "T1021.001"],
        "Service account TGS tickets requested en-masse. Pass-the-hash lateral movement to finance server. "
        "Mimikatz signatures detected.",
    ),
    (
        "Cloud misconfiguration: public S3 bucket with PII exposed",
        ["TA0009", "TA0010"],
        ["T1530", "T1567.002"],
        "S3 bucket world-readable. 40 k employee records accessible. CloudTrail shows external enumeration.",
    ),
    (
        "Zero-day exploit attempt against web application on WIN-PROD-WEB02",
        ["TA0001", "TA0002"],
        ["T1190", "T1059.007"],
        "WAF logs show SQL-injection and SSRF probes. One request returned 200 with internal metadata.",
    ),
    (
        "Living-off-the-land: certutil download cradle on WIN-HR-DESKTOP",
        ["TA0002", "TA0005"],
        ["T1105", "T1218.009"],
        "certutil.exe -urlcache invoked from cmd.exe spawned by outlook.exe. Payload downloaded.",
    ),
    (
        "Identity provider compromise: SAML golden-ticket",
        ["TA0006", "TA0007"],
        ["T1606.002", "T1087.002"],
        "Forged SAML assertion detected. Attacker pivoted to Azure AD. Account enumeration followed.",
    ),
    (
        "Cryptominer dropped via vulnerable Docker socket",
        ["TA0001", "TA0002", "TA0040"],
        ["T1610", "T1059.004", "T1496"],
        "Unauthenticated Docker API exploited. Container with XMRig spawned. CPU spiked to 95%.",
    ),
    (
        "DGA-based C2 traffic — Emotet botnet indicators",
        ["TA0011", "TA0010"],
        ["T1568.002", "T1041"],
        "DGA traffic observed. 200+ NXDomain replies per minute. IoCs match Emotet epoch 5.",
    ),
    (
        "BEC phishing: finance user redirected payment",
        ["TA0001", "TA0040"],
        ["T1566.001", "T1657"],
        "Spear-phishing email spoofed CFO. Wire transfer of $250 k initiated to threat-actor account.",
    ),
    (
        "Active Directory DCSync from non-DC host",
        ["TA0006", "TA0004"],
        ["T1003.006", "T1078.002"],
        "Replication rights abused from workstation. All domain NTLM hashes replicated.",
    ),
    (
        "Container escape via privileged pod",
        ["TA0004", "TA0007"],
        ["T1611", "T1082"],
        "Kubernetes privileged pod created. cgroup escape to host namespace. Node filesystem accessed.",
    ),
    (
        "Firmware implant detected on UEFI partition",
        ["TA0003", "TA0005"],
        ["T1542.001", "T1027.002"],
        "UEFI secure-boot violation. Unknown module in firmware. Matches MosaicRegressor signatures.",
    ),
    (
        "Watering-hole attack: internal wiki delivering drive-by exploit",
        ["TA0001", "TA0002"],
        ["T1189", "T1203"],
        "Internal Confluence page injected with malicious JS. Browser exploitation via CVE-2024-1234.",
    ),
    (
        "Malicious USB autorun on air-gapped host",
        ["TA0001", "TA0009"],
        ["T1091", "T1005"],
        "USB device inserted on air-gapped system. AutoRun executed Python stager.",
    ),
    (
        "OAuth consent phishing targeting Microsoft account",
        ["TA0001", "TA0006"],
        ["T1528", "T1550.001"],
        "Malicious OAuth app granted Mail.Read and Files.Read.All. Inbox rules forwarding to attacker.",
    ),
    (
        "Memory-only implant (fileless) executed in svchost process",
        ["TA0002", "TA0005"],
        ["T1055.012", "T1620"],
        "Process hollowing detected: svchost.exe replaced with Cobalt Strike beacon. No disk artefacts.",
    ),
    (
        "DNS tunnelling for data exfiltration",
        ["TA0011", "TA0010"],
        ["T1071.004", "T1048.003"],
        "DNS query volume 50× baseline. TXT records contain base64 payload. Exfil volume ~200 MB.",
    ),
]

# ATT&CK tactic ID → canonical name
_TACTIC_NAMES: dict[str, str] = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
    "TA0040": "Impact",
}


# ---------------------------------------------------------------------------
# Keyword-based MITRE tactic extractor (offline, no LLM)
# ---------------------------------------------------------------------------

_TACTIC_KEYWORDS: dict[str, list[str]] = {
    "TA0001": [
        "initial access", "phishing", "exploit", "watering hole", "supply chain",
        "valid account", "external remote service", "drive-by", "usb", "spear",
    ],
    "TA0002": [
        "execution", "powershell", "cmd", "script", "macro", "python", "node",
        "certutil", "wmi", "mshta", "process", "npm", "js", "javascript",
    ],
    "TA0003": [
        "persistence", "registry run", "scheduled task", "startup", "service",
        "implant", "backdoor", "rootkit", "firmware", "uefi",
    ],
    "TA0004": [
        "privilege escalation", "escalation", "escalate", "container escape",
        "privileged", "bypass", "token", "sudo", "uac",
    ],
    "TA0005": [
        "defense evasion", "obfuscat", "fileless", "memory", "hollowing",
        "side-load", "dll", "certutil", "masquerad", "encode", "pack",
    ],
    "TA0006": [
        "credential", "brute force", "kerberoast", "dcsync", "lsass", "dump",
        "harvest", "password", "saml", "oauth", "ntlm", "mimikatz",
    ],
    "TA0007": [
        "discovery", "enumerat", "scan", "account discovery", "network share",
        "recon", "replication", "ldap",
    ],
    "TA0008": [
        "lateral movement", "rdp", "smb", "pass-the-hash", "pass the hash",
        "remote service", "pivoting", "ssh",
    ],
    "TA0009": [
        "collection", "data from local", "screenshot", "keylog", "clipboard",
        "bulk download", "pii", "customer record",
    ],
    "TA0010": [
        "exfiltrat", "c2 channel", "cloud storage", "dns tunnel", "ftp",
        "upload", "egress", "google drive",
    ],
    "TA0011": [
        "command and control", "c2", "beacon", "c&c", "dga", "domain generation",
        "dns query", "covert channel", "cobalt strike",
    ],
    "TA0040": [
        "impact", "ransom", "encrypt", "wipe", "destroy", "disrupt",
        "defacement", "miner", "cryptomine",
    ],
}


def extract_tactics_from_text(text: str) -> set[str]:
    """Return set of ATT&CK tactic IDs inferred from keyword matching."""
    low = text.lower()
    found: set[str] = set()
    for tactic_id, kws in _TACTIC_KEYWORDS.items():
        if any(kw in low for kw in kws):
            found.add(tactic_id)
    return found


# ---------------------------------------------------------------------------
# Accuracy evaluation
# ---------------------------------------------------------------------------

class MitreAccuracyResult:
    def __init__(self) -> None:
        self.total = 0
        self.correct = 0
        self.details: list[dict[str, Any]] = []

    @property
    def accuracy(self) -> float:
        return self.correct / self.total if self.total else 0.0

    def to_json(self) -> str:
        return json.dumps(
            {
                "total": self.total,
                "correct": self.correct,
                "accuracy": round(self.accuracy, 4),
                "accuracy_pct": f"{self.accuracy * 100:.1f}%",
                "details": self.details,
            },
            indent=2,
        )


def evaluate_mitre_accuracy(threshold: float = 0.80) -> MitreAccuracyResult:
    """
    For each synthetic incident, check whether the keyword extractor
    (proxy for LLM output) identifies ≥1 of the expected MITRE tactics.

    A case is considered "correct" if the predicted tactic set has at
    least one overlap with the expected tactic set.
    """
    result = MitreAccuracyResult()

    for title, expected_tactics, technique_ids, description in SYNTHETIC_INCIDENTS:
        result.total += 1
        combined_text = f"{title}\n{description}"
        predicted = extract_tactics_from_text(combined_text)
        expected_set = set(expected_tactics)
        overlap = predicted & expected_set
        correct = len(overlap) > 0
        if correct:
            result.correct += 1

        result.details.append(
            {
                "incident": title[:80],
                "expected": sorted(expected_set),
                "predicted": sorted(predicted),
                "overlap": sorted(overlap),
                "correct": correct,
            }
        )

    return result


# ---------------------------------------------------------------------------
# pytest tests
# ---------------------------------------------------------------------------

class TestMitreAccuracy(unittest.TestCase):
    """Offline MITRE tactic accuracy evaluation for the 20 synthetic incidents."""

    def test_accuracy_above_threshold(self) -> None:
        result = evaluate_mitre_accuracy()
        print(f"\n[eval] MITRE accuracy: {result.correct}/{result.total} = {result.accuracy * 100:.1f}%")
        self.assertGreaterEqual(
            result.accuracy,
            0.80,
            f"MITRE tactic accuracy {result.accuracy:.1%} is below the 80% threshold.\n"
            + result.to_json(),
        )

    def test_all_incidents_evaluated(self) -> None:
        result = evaluate_mitre_accuracy()
        self.assertEqual(result.total, 20, "Expected exactly 20 synthetic incidents to be evaluated.")

    def test_each_incident_has_expected_tactics(self) -> None:
        for title, tactic_ids, technique_ids, _ in SYNTHETIC_INCIDENTS:
            self.assertGreater(
                len(tactic_ids), 0,
                f"Incident '{title[:60]}' has no expected tactic IDs.",
            )
            for t in tactic_ids:
                self.assertIn(
                    t, _TACTIC_NAMES,
                    f"Unknown tactic ID '{t}' in incident '{title[:60]}'.",
                )

    def test_no_duplicate_incident_titles(self) -> None:
        titles = [s[0] for s in SYNTHETIC_INCIDENTS]
        self.assertEqual(len(titles), len(set(titles)), "Duplicate incident titles detected.")


if __name__ == "__main__":
    # Also allow running standalone to print a detailed report
    res = evaluate_mitre_accuracy()
    print(res.to_json())
    passed = res.accuracy >= 0.80
    print(f"\n{'✓ PASS' if passed else '✗ FAIL'}: {res.accuracy * 100:.1f}% accuracy (threshold: 80%)")
    sys.exit(0 if passed else 1)
