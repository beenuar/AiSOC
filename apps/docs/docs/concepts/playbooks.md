---
sidebar_position: 2
---

# Playbooks

Playbooks are visual, reusable automation workflows that orchestrate investigation
and response steps.

## Anatomy of a Playbook

```json
{
  "id": "ransomware-response",
  "name": "Ransomware Response",
  "version": "1.0.0",
  "trigger": { "type": "manual" },
  "steps": [
    {
      "id": "isolate-host",
      "type": "action",
      "action": "endpoint.isolate",
      "params": { "host": "{{ trigger.hostname }}" }
    },
    {
      "id": "enrich-iocs",
      "type": "enrichment",
      "indicators": "{{ trigger.iocs }}"
    }
  ]
}
```

## Starter Templates

AiSOC ships with 12 production-ready templates:

| Template | Description |
|----------|-------------|
| `ransomware-response` | Full ransomware triage and containment |
| `phishing-triage` | Email phishing investigation |
| `credential-stuffing` | Account takeover detection |
| `data-exfiltration` | DLP alert response |
| `malware-analysis` | Dynamic malware sandbox workflow |
| `insider-threat` | Anomalous user behaviour |
| `lateral-movement` | East-west threat hunting |
| `privilege-escalation` | PrivEsc detection and response |
| `c2-beacon` | C2 traffic containment |
| `supply-chain-alert` | Dependency compromise triage |
| `cloud-misconfiguration` | Cloud posture alert |
| `vulnerability-critical` | Critical CVE response |

## Playbook Editor

The visual React Flow editor lets you:

- Drag-and-drop nodes (trigger, enrichment, decision, action, notification)
- Connect nodes to define flow
- Configure step parameters inline
- Export to JSON or run immediately

Navigate to **Playbooks → Editor** in the UI to get started.
