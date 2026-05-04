# AiSOC Detection Rules

This directory contains AiSOC detection rules in a Sigma-inspired YAML format.

The pack ships **200 curated, fixture-tested rules** across six categories.
Every rule has a positive fixture (a synthetic event that should fire it) and a
negative fixture (a near-miss event that should *not* fire it). CI replays
both on every PR using the canonical runtime matcher.

## Distribution

| Category      | Rules | Focus                                                           |
| ------------- | ----- | --------------------------------------------------------------- |
| `cloud/`      | 40    | AWS / GCP / Azure misconfig, IAM, key-rotation, S3, CloudTrail  |
| `identity/`   | 40    | Auth, MFA, SSO, IdP federation, session abuse, OAuth grants     |
| `endpoint/`   | 40    | Process exec, persistence, LOLBAS, credential theft, ransomware |
| `network/`    | 30    | C2, scanning, beaconing, DNS abuse, Tor, lateral movement       |
| `application/`| 30    | Web, API, DB, secrets, supply chain, dependency abuse           |
| `data-exfil/` | 20    | DLP, large transfers, archive uploads, tunneling, off-corp dest |
| **Total**     | 200   |                                                                 |

## Structure

```
detections/
├── cloud/                 # 40 rules
├── identity/              # 40 rules
├── endpoint/              # 40 rules
├── network/               # 30 rules
├── application/           # 30 rules
├── data-exfil/            # 20 rules
├── fixtures/
│   ├── positive/          # one .json per rule — should match
│   └── negative/          # one .json per rule — should NOT match
└── sigma-imports/         # optional auto-imported SigmaHQ rules with attribution
```

## Rule Format

```yaml
id: det-<unique-id>           # Stable identifier; prefix matches category
name: Human-readable title
description: >
  What this rule detects and why it matters.
version: "1.0.0"
severity: low | medium | high | critical
tags:
  - mitre.attack.tXXXX         # MITRE ATT&CK technique ID(s)
  - tlp.white                   # Traffic Light Protocol
category: network | endpoint | cloud | identity | application | data-exfil
log_source:
  product: "syslog" | "cloudtrail" | "windows" | ...
  service: optional sub-service
detection:
  fields: [list, of, expected, fields]
  condition: PATTERN_MATCH_ANY({...}) # Human-readable serialization of match_when
false_positives:
  - Description of known benign triggers
playbook: tpl-<playbook-id>     # Optional: auto-trigger this playbook
enabled: true
author: AiSOC
created: "YYYY-MM-DD"
modified: "YYYY-MM-DD"
```

## Source of Truth

The Python specs in [`scripts/detection_specs.py`](../scripts/detection_specs.py)
and [`scripts/detection_specs_part2.py`](../scripts/detection_specs_part2.py)
are the **canonical source of truth**. The on-disk YAML files are serialized
artifacts produced by [`scripts/generate_detections.py`](../scripts/generate_detections.py).
Edit specs, regenerate, then commit both.

```bash
# Regenerate all 200 rules + fixtures from specs
python3 scripts/generate_detections.py

# Validate (matches what CI runs)
python3 scripts/validate_detections.py --strict-fixtures
```

## Adding a New Rule

1. Add a new spec dict to the appropriate list in `scripts/detection_specs.py`
   or `scripts/detection_specs_part2.py`.
2. Required keys: `slug`, `name`, `severity`, `mitre`, `log_source`,
   `fields`, `match_when`, `fp`, `positive`, `negative`.
3. Run `python3 scripts/generate_detections.py` to materialize the YAML and
   fixtures.
4. Run `python3 scripts/validate_detections.py --strict-fixtures` to confirm
   the fixtures replay correctly.

## CI Validation

The [`Validate Detection Rules`](../.github/workflows/validate-detections.yml)
workflow runs on every push or PR touching `detections/**` or the spec/generator
scripts. It enforces:

- Valid YAML syntax
- Required fields present (`id`, `name`, `severity`, `detection`)
- Severity ∈ `{low, medium, high, critical}`
- Category ∈ `{network, endpoint, cloud, identity, application, data-exfil}`
- No duplicate `id` values across all rules
- `id` prefix matches the category directory
- Both positive and negative fixtures exist
- **Fixture replay**: positive fixture matches, negative does not — using the
  same `matches()` runtime function as the engine
