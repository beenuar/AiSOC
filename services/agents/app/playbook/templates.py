"""
12 Starter Playbook Templates — Pillar 2 (p2-templates)
========================================================
These are imported by PlaybookStore.seed_defaults() and can also be
referenced from the marketplace/index.json.
"""
from __future__ import annotations

STARTER_PLAYBOOKS: list[dict] = [
    # 1 ─ Phishing Triage
    {
        "id": "tpl-phishing-triage",
        "name": "Phishing Email Triage",
        "description": "Enrich sender IP and URLs, notify SOC channel, auto-close low-risk cases.",
        "version": "1.0.0",
        "tags": ["phishing", "email", "triage"],
        "trigger": {"on": "alert", "severity": ["low", "medium"]},
        "steps": [
            {
                "id": "step-enrich-ip",
                "name": "Enrich sender IP",
                "type": "enrich",
                "params": {"ioc_type": "ip"},
            },
            {
                "id": "step-notify",
                "name": "Notify SOC channel",
                "type": "notify",
                "params": {
                    "channel": "webhook",
                    "url": "{{SLACK_WEBHOOK_URL}}",
                    "message": "Phishing alert: {{title}} — sender IP enriched.",
                },
            },
        ],
        "author": "AiSOC",
        "enabled": True,
    },

    # 2 ─ Ransomware Response
    {
        "id": "tpl-ransomware-response",
        "name": "Ransomware Rapid Response",
        "description": "Isolate affected host, block C2 IP, trigger AI investigation, notify leadership.",
        "version": "1.0.0",
        "tags": ["ransomware", "containment", "critical"],
        "trigger": {"on": "alert", "severity": ["critical"]},
        "steps": [
            {
                "id": "step-isolate",
                "name": "Isolate host",
                "type": "isolate_host",
                "params": {},
            },
            {
                "id": "step-block",
                "name": "Block C2 IP",
                "type": "block_ip",
                "params": {},
            },
            {
                "id": "step-investigate",
                "name": "Trigger AI investigation",
                "type": "investigate",
                "params": {"dry_run": False},
            },
            {
                "id": "step-notify-lead",
                "name": "Notify leadership",
                "type": "notify",
                "params": {
                    "channel": "webhook",
                    "url": "{{SLACK_WEBHOOK_URL}}",
                    "message": "CRITICAL: Ransomware response initiated for {{host}}.",
                },
            },
        ],
        "author": "AiSOC",
        "enabled": True,
    },

    # 3 ─ Credential Stuffing
    {
        "id": "tpl-cred-stuffing",
        "name": "Credential Stuffing Detection",
        "description": "Enrich source IPs, block top offenders, create a ticket.",
        "version": "1.0.0",
        "tags": ["credential", "brute-force", "identity"],
        "trigger": {"on": "alert", "severity": ["high", "critical"]},
        "steps": [
            {
                "id": "step-enrich",
                "name": "Enrich source IP",
                "type": "enrich",
                "params": {"ioc_type": "ip"},
            },
            {
                "id": "step-block",
                "name": "Block IP",
                "type": "block_ip",
                "params": {},
            },
            {
                "id": "step-ticket",
                "name": "Create JIRA ticket",
                "type": "create_ticket",
                "params": {"project": "SOC", "type": "Incident"},
            },
        ],
        "author": "AiSOC",
        "enabled": True,
    },

    # 4 ─ Insider Threat Investigation
    {
        "id": "tpl-insider-threat",
        "name": "Insider Threat Investigation",
        "description": "Automatically investigate bulk-download alerts and escalate to HR/Legal.",
        "version": "1.0.0",
        "tags": ["insider", "data-loss", "dlp"],
        "trigger": {"on": "alert", "severity": ["medium", "high"]},
        "steps": [
            {
                "id": "step-investigate",
                "name": "AI investigation",
                "type": "investigate",
                "params": {},
            },
            {
                "id": "step-ticket",
                "name": "Escalate to HR",
                "type": "create_ticket",
                "params": {"project": "HR", "type": "Investigation"},
            },
            {
                "id": "step-notify",
                "name": "Notify Legal",
                "type": "notify",
                "params": {
                    "channel": "webhook",
                    "message": "Insider threat case opened: {{title}}",
                },
            },
        ],
        "author": "AiSOC",
        "enabled": True,
    },

    # 5 ─ Malware IOC Enrichment
    {
        "id": "tpl-malware-ioc-enrich",
        "name": "Malware IOC Enrichment",
        "description": "Enrich all IOCs attached to a case and update threat intel.",
        "version": "1.0.0",
        "tags": ["malware", "ioc", "enrichment"],
        "trigger": {"on": "case", "severity": ["medium", "high", "critical"]},
        "steps": [
            {
                "id": "step-enrich-ip",
                "name": "Enrich IP IOC",
                "type": "enrich",
                "params": {"ioc_type": "ip"},
            },
            {
                "id": "step-enrich-hash",
                "name": "Enrich hash IOC",
                "type": "enrich",
                "params": {"ioc_type": "hash"},
            },
            {
                "id": "step-enrich-domain",
                "name": "Enrich domain IOC",
                "type": "enrich",
                "params": {"ioc_type": "domain"},
            },
        ],
        "author": "AiSOC",
        "enabled": True,
    },

    # 6 ─ Cloud Misconfiguration Alert
    {
        "id": "tpl-cloud-misconfig",
        "name": "Cloud Misconfiguration Response",
        "description": "Enrich exposed resource, notify cloud team, create remediation ticket.",
        "version": "1.0.0",
        "tags": ["cloud", "misconfiguration", "aws", "azure"],
        "trigger": {"on": "alert", "severity": ["high", "critical"]},
        "steps": [
            {
                "id": "step-enrich",
                "name": "Enrich resource",
                "type": "enrich",
                "params": {},
            },
            {
                "id": "step-notify-cloud",
                "name": "Notify cloud-ops",
                "type": "notify",
                "params": {
                    "channel": "webhook",
                    "message": "Cloud misconfiguration: {{title}}",
                },
            },
            {
                "id": "step-ticket",
                "name": "Create remediation ticket",
                "type": "create_ticket",
                "params": {"project": "CLOUD", "type": "Remediation"},
            },
        ],
        "author": "AiSOC",
        "enabled": True,
    },

    # 7 ─ Lateral Movement Detection
    {
        "id": "tpl-lateral-movement",
        "name": "Lateral Movement Containment",
        "description": "Block pivot IPs, isolate source host, trigger investigation.",
        "version": "1.0.0",
        "tags": ["lateral-movement", "containment"],
        "trigger": {"on": "alert", "severity": ["high", "critical"]},
        "steps": [
            {
                "id": "step-block",
                "name": "Block lateral IP",
                "type": "block_ip",
                "params": {},
            },
            {
                "id": "step-isolate",
                "name": "Isolate source host",
                "type": "isolate_host",
                "params": {},
            },
            {
                "id": "step-investigate",
                "name": "AI investigation",
                "type": "investigate",
                "params": {},
            },
        ],
        "author": "AiSOC",
        "enabled": True,
    },

    # 8 ─ Data Exfiltration Alert
    {
        "id": "tpl-data-exfil",
        "name": "Data Exfiltration Response",
        "description": "Block exfil destination, isolate host, notify DLP team, create ticket.",
        "version": "1.0.0",
        "tags": ["exfiltration", "dlp", "containment"],
        "trigger": {"on": "alert", "severity": ["high", "critical"]},
        "steps": [
            {
                "id": "step-block",
                "name": "Block destination IP",
                "type": "block_ip",
                "params": {},
            },
            {
                "id": "step-isolate",
                "name": "Isolate exfil host",
                "type": "isolate_host",
                "params": {},
            },
            {
                "id": "step-notify",
                "name": "Notify DLP team",
                "type": "notify",
                "params": {
                    "channel": "webhook",
                    "message": "Data exfiltration blocked: {{title}}",
                },
            },
            {
                "id": "step-ticket",
                "name": "Create DLP ticket",
                "type": "create_ticket",
                "params": {"project": "DLP"},
            },
        ],
        "author": "AiSOC",
        "enabled": True,
    },

    # 9 ─ Zero-Day Exploit
    {
        "id": "tpl-zero-day",
        "name": "Zero-Day Exploit Response",
        "description": "Immediate isolation, war-room notification, AI investigation, executive escalation.",
        "version": "1.0.0",
        "tags": ["zero-day", "exploit", "critical"],
        "trigger": {"on": "alert", "severity": ["critical"]},
        "steps": [
            {
                "id": "step-isolate",
                "name": "Isolate affected host",
                "type": "isolate_host",
                "params": {},
            },
            {
                "id": "step-investigate",
                "name": "AI investigation",
                "type": "investigate",
                "params": {},
            },
            {
                "id": "step-notify-war-room",
                "name": "Notify war-room",
                "type": "notify",
                "params": {
                    "channel": "webhook",
                    "message": "ZERO-DAY: War-room activated for {{title}}",
                },
            },
            {
                "id": "step-ticket",
                "name": "P0 incident ticket",
                "type": "create_ticket",
                "params": {"project": "SEC", "type": "P0-Incident"},
            },
        ],
        "author": "AiSOC",
        "enabled": True,
    },

    # 10 ─ BEC (Business Email Compromise)
    {
        "id": "tpl-bec",
        "name": "Business Email Compromise Response",
        "description": "Freeze transfers, notify finance, open HR/Legal investigation.",
        "version": "1.0.0",
        "tags": ["bec", "fraud", "email"],
        "trigger": {"on": "alert", "severity": ["high", "critical"]},
        "steps": [
            {
                "id": "step-notify-finance",
                "name": "Notify finance team",
                "type": "notify",
                "params": {
                    "channel": "webhook",
                    "message": "BEC alert: Potential wire fraud — {{title}}. Freeze pending transfers.",
                },
            },
            {
                "id": "step-investigate",
                "name": "AI investigation",
                "type": "investigate",
                "params": {},
            },
            {
                "id": "step-ticket",
                "name": "Open fraud investigation ticket",
                "type": "create_ticket",
                "params": {"project": "FRAUD"},
            },
        ],
        "author": "AiSOC",
        "enabled": True,
    },

    # 11 ─ Supply Chain Alert
    {
        "id": "tpl-supply-chain",
        "name": "Supply Chain Compromise Response",
        "description": "Quarantine affected package/build, notify DevSecOps, trigger investigation.",
        "version": "1.0.0",
        "tags": ["supply-chain", "ci-cd", "sca"],
        "trigger": {"on": "alert", "severity": ["high", "critical"]},
        "steps": [
            {
                "id": "step-enrich",
                "name": "Enrich malicious package IOC",
                "type": "enrich",
                "params": {"ioc_type": "hash"},
            },
            {
                "id": "step-notify-devsec",
                "name": "Notify DevSecOps",
                "type": "notify",
                "params": {
                    "channel": "webhook",
                    "message": "Supply chain alert: {{title}}. Quarantine build pipeline.",
                },
            },
            {
                "id": "step-investigate",
                "name": "AI investigation",
                "type": "investigate",
                "params": {},
            },
        ],
        "author": "AiSOC",
        "enabled": True,
    },

    # 12 ─ Auto-close Informational
    {
        "id": "tpl-auto-close-info",
        "name": "Auto-close Informational Alerts",
        "description": "Automatically close low-risk informational alerts after enrichment.",
        "version": "1.0.0",
        "tags": ["triage", "automation", "low-risk"],
        "trigger": {"on": "alert", "severity": ["low"]},
        "steps": [
            {
                "id": "step-enrich",
                "name": "Enrich IP",
                "type": "enrich",
                "params": {"ioc_type": "ip"},
            },
            {
                "id": "step-close",
                "name": "Auto-close case",
                "type": "close_case",
                "params": {},
            },
        ],
        "author": "AiSOC",
        "enabled": True,
    },
]
