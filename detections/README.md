# AiSOC Detection Rules

This directory contains AiSOC detection rules in a Sigma-inspired YAML format.

## Structure

```
detections/
├── network/          # Network-based detections (C2, scanning, exfil)
├── endpoint/         # Endpoint / host-based detections
├── cloud/            # Cloud provider (AWS, GCP, Azure) detections
├── identity/         # Authentication and identity-based detections
└── application/      # Application-layer detections (web, API, DB)
```

## Rule Format

```yaml
id: det-<unique-id>           # Stable UUID-like identifier
name: Human-readable title
description: >
  What this rule detects and why it matters.
version: "1.0.0"
severity: low | medium | high | critical
tags:
  - mitre.attack.tXXXX         # MITRE ATT&CK technique ID
  - tlp.white                   # Traffic Light Protocol
category: network | endpoint | cloud | identity | application
log_source:
  product: "syslog" | "cloudtrail" | "windows" | ...
  service: optional sub-service
detection:
  keywords:                     # Simple keyword match
    - "keyword1"
  condition: keywords           # Boolean expression over field sets
  filters:                      # Optional exclusions
    - fieldname: value
false_positives:
  - Description of known benign triggers
playbook: tpl-<playbook-id>     # Optional: auto-trigger this playbook
enabled: true
author: AiSOC
created: "YYYY-MM-DD"
modified: "YYYY-MM-DD"
```

## Adding a New Rule

1. Choose the correct category folder.
2. Copy an existing rule as a template.
3. Set a unique `id` starting with `det-`.
4. Run `pnpm detections:validate` locally before pushing.

## Validation

The CI pipeline validates all rules on every push:

```bash
pnpm detections:validate
```

This checks:
- Valid YAML syntax
- Required fields present (`id`, `name`, `severity`, `detection`)
- Severity is one of `low|medium|high|critical`
- No duplicate `id` values across all rules
