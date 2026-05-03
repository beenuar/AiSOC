---
sidebar_position: 3
---

# Detection Rules

AiSOC supports multiple rule languages for broad coverage across data sources.

## Supported Rule Languages

| Language | Backend | Use Case |
|----------|---------|----------|
| Sigma (YAML) | OpenSearch / ClickHouse | General-purpose log detection |
| YARA | File / memory scanning | Malware, suspicious file content |
| KQL (Kusto) | ClickHouse | Windows event log analytics |
| EQL (Event Query) | Elastic-compatible | Sequence-based endpoint events |

## Rule Format (Sigma / AiSOC YAML)

```yaml
id: brute-force-login-001
name: Brute-Force Login Attempt
description: Detects more than 10 failed logins in 5 minutes from the same IP
severity: high
tactics:
  - credential-access
techniques:
  - T1110
tags:
  - brute-force
  - authentication
detection:
  source: auth_logs
  condition:
    field: event.type
    value: failed_login
    threshold:
      count: 10
      window_seconds: 300
    group_by:
      - source.ip
      - user.name
response:
  auto_create_case: true
  playbook_id: brute-force-response-v1
references:
  - https://attack.mitre.org/techniques/T1110/
```

### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique rule identifier (kebab-case) |
| `name` | string | Human-readable rule name |
| `severity` | enum | `critical`, `high`, `medium`, `low`, `info` |
| `tactics` | list | MITRE ATT&CK tactic names |
| `detection` | object | Detection logic |

### Optional Fields

| Field | Description |
|-------|-------------|
| `techniques` | MITRE technique IDs (e.g. `T1110`) |
| `tags` | Free-form labels |
| `response.auto_create_case` | Auto-open a case on first trigger |
| `response.playbook_id` | Auto-execute a playbook |
| `references` | External links (MITRE, CVE, blog posts) |

## Directory Structure

```
detections/
├── README.md
├── application/
│   └── sql-injection-attempt.yaml
├── cloud/
│   ├── aws-root-account-login.yaml
│   └── aws-s3-public-bucket.yaml
├── endpoint/
│   ├── credential-dumping-lsass.yaml
│   ├── lolbas-execution.yaml
│   └── ransomware-file-extension-change.yaml
├── identity/
│   ├── brute-force-login.yaml
│   └── impossible-travel.yaml
└── network/
    ├── c2-beacon-high-frequency.yaml
    ├── dns-data-exfiltration.yaml
    └── port-scan-internal.yaml
```

## CI Validation

All rules are validated on every PR via GitHub Actions:

```bash
python3 scripts/validate_detections.py detections/
```

The validator checks:
- Required fields present
- Valid severity value
- MITRE tactic names
- Detection condition syntax
- Referenced playbook IDs exist (if specified)

## One-Click Install from Marketplace

Community rules published to the marketplace can be installed from the UI (`/marketplace`) or via CLI:

```bash
curl -X POST http://localhost:8000/api/v1/marketplace/install \
  -H "Authorization: Bearer <token>" \
  -d '{"plugin_id": "community/brute-force-bundle"}'
```

## Contributing Rules

1. Create a YAML file in the appropriate sub-directory
2. Follow the schema — `id`, `name`, `severity`, `tactics`, `detection` are required
3. Run `python3 scripts/validate_detections.py detections/` locally
4. Open a PR — CI will validate and summarise your rule
5. Once merged, the rule appears in the community marketplace automatically
