"""
Tool: MITRE ATT&CK framework lookups.
Provides context for tactics, techniques, and suggested mitigations.
"""

import structlog

logger = structlog.get_logger()

# Lightweight in-memory MITRE ATT&CK reference (subset of common TTPs)
_MITRE_TACTICS = {
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

_MITRE_TECHNIQUES = {
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "TA0002"},
    "T1078": {"name": "Valid Accounts", "tactic": "TA0001"},
    "T1110": {"name": "Brute Force", "tactic": "TA0006"},
    "T1566": {"name": "Phishing", "tactic": "TA0001"},
    "T1055": {"name": "Process Injection", "tactic": "TA0004"},
    "T1003": {"name": "OS Credential Dumping", "tactic": "TA0006"},
    "T1021": {"name": "Remote Services", "tactic": "TA0008"},
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "TA0010"},
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "TA0001"},
    "T1071": {"name": "Application Layer Protocol", "tactic": "TA0011"},
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "TA0040"},
    "T1082": {"name": "System Information Discovery", "tactic": "TA0007"},
    "T1057": {"name": "Process Discovery", "tactic": "TA0007"},
    "T1218": {"name": "Signed Binary Proxy Execution", "tactic": "TA0005"},
}

_MITRE_MITIGATIONS = {
    "T1059": ["M1042 - Disable or Remove Feature or Program", "M1026 - Privileged Account Management"],
    "T1078": ["M1032 - Multi-factor Authentication", "M1027 - Password Policies"],
    "T1110": ["M1032 - Multi-factor Authentication", "M1036 - Account Use Policies"],
    "T1566": ["M1049 - Antivirus/Antimalware", "M1031 - Network Intrusion Prevention"],
    "T1055": ["M1040 - Behavior Prevention on Endpoint", "M1026 - Privileged Account Management"],
}


def lookup_technique(technique_id: str) -> dict:
    """Look up a MITRE ATT&CK technique by ID."""
    tech = _MITRE_TECHNIQUES.get(technique_id)
    if not tech:
        return {"id": technique_id, "name": "Unknown", "tactic": "Unknown"}
    tactic_id = tech["tactic"]
    return {
        "id": technique_id,
        "name": tech["name"],
        "tactic_id": tactic_id,
        "tactic_name": _MITRE_TACTICS.get(tactic_id, "Unknown"),
        "mitigations": _MITRE_MITIGATIONS.get(technique_id, []),
    }


def lookup_tactic(tactic_id: str) -> dict:
    """Look up a MITRE ATT&CK tactic by ID."""
    return {
        "id": tactic_id,
        "name": _MITRE_TACTICS.get(tactic_id, "Unknown"),
    }


def map_techniques_to_kill_chain(technique_ids: list[str]) -> dict:
    """Map a list of technique IDs to kill chain phases."""
    result: dict[str, list[str]] = {}
    for tid in technique_ids:
        info = lookup_technique(tid)
        tactic = info.get("tactic_name", "Unknown")
        if tactic not in result:
            result[tactic] = []
        result[tactic].append(f"{tid}: {info['name']}")
    return result
