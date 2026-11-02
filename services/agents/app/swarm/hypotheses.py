"""The competing hypotheses the swarm evaluates.

Each hypothesis carries supporting/contradicting signal keywords and the MITRE
techniques that corroborate it. A hypothesis agent scores its hypothesis against
an alert deterministically (an LLM can enrich this, but the deterministic floor
is what CI gates).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Hypothesis:
    key: str
    label: str
    supports_keywords: frozenset[str]
    contradicts_keywords: frozenset[str] = frozenset()
    techniques: frozenset[str] = frozenset()
    # Whether this hypothesis is a "benign" explanation (competes with the malicious ones).
    benign: bool = False


HYPOTHESES: list[Hypothesis] = [
    Hypothesis(
        key="ransomware_staging",
        label="Ransomware staging",
        supports_keywords=frozenset({"ransomware", "encrypt*", "shadow copy", "vssadmin", "lockbit", ".lockbit", "ransom note"}),
        contradicts_keywords=frozenset({"backup completed", "scheduled backup"}),
        techniques=frozenset({"T1486", "T1490"}),
    ),
    Hypothesis(
        key="insider_exfil",
        label="Insider exfiltration",
        supports_keywords=frozenset({"exfiltration", "large file", "usb", "personal email", "download", "staging", "off-hours"}),
        techniques=frozenset({"T1048", "T1567", "T1052"}),
    ),
    Hypothesis(
        key="lateral_movement",
        label="Lateral movement / intrusion",
        supports_keywords=frozenset({"lateral movement", "smb", "psexec", "credential dump", "mimikatz", "pass the hash", "rdp"}),
        techniques=frozenset({"T1021", "T1021.002", "T1003", "T1550"}),
    ),
    Hypothesis(
        key="c2_beacon",
        label="C2 beacon / active intrusion",
        supports_keywords=frozenset({"c2", "beacon", "cobalt strike", "command and control", "dns tunneling", "jitter"}),
        techniques=frozenset({"T1071", "T1573", "T1071.004"}),
    ),
    Hypothesis(
        key="false_positive_backup",
        label="False positive (backup / maintenance job)",
        supports_keywords=frozenset({"backup", "veeam", "maintenance window", "scheduled", "nominal", "service account", "svc-backup"}),
        contradicts_keywords=frozenset({"ransom note", "exfiltration to unknown", "mimikatz"}),
        benign=True,
    ),
]
