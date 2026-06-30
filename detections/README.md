# AiSOC Detection Rules

This directory contains AiSOC detection content in a Sigma-inspired YAML format.
Rules are organized into four **tiers** based on origin, quality bar, and what
the AiSOC engine can do with them out of the box.

| Tier      | Where it lives                            | Status when shipped | Quality bar                                       |
| --------- | ----------------------------------------- | ------------------- | ------------------------------------------------- |
| Native    | `detections/<category>/`                  | enabled             | YAML schema + fixture replay + MITRE mapping      |
| Imported  | `detections/<source>-imports/<category>/` | varies (see below)  | YAML schema + provenance block; fixtures optional |
| Quarantined | `detections/<source>-imports/_quarantine/<category>/` | disabled (`enabled: false`) | parses, but engine cannot execute upstream query |
| Community | `detections/community/<category>/`        | disabled by default | YAML schema; provenance encouraged                |

The native tier currently ships **800 fixture-tested rules** (1,200 fixtures —
positive + negative) across six categories, generated from the spec modules
under [`scripts/detection_specs*.py`](../scripts/) by
[`scripts/build_detections_from_specs.py`](../scripts/build_detections_from_specs.py).
Imported tiers are populated by the importers under
[`tools/detection_import/`](../tools/detection_import/) and remain empty in this
checkout until you run them — see [`tools/detection_import/README.md`](../tools/detection_import/README.md)
for the SigmaHQ, Splunk, Chronicle, and CAR pipelines and their pinned upstream
commits.

## Native tier (`detections/<category>/`)

The strict-quality, AiSOC-authored layer. Every rule has:

- A positive fixture under `detections/fixtures/positive/<slug>.json` (a
  synthetic event that should fire it).
- A negative fixture under `detections/fixtures/negative/<slug>.json` (a
  near-miss event that should not fire it).
- A MITRE ATT&CK mapping in its tag list.

CI replays both fixtures on every PR using the canonical runtime matcher in
[`scripts/generate_detections.py`](../scripts/generate_detections.py).

### Native distribution

| Category       | Rules | Focus                                                            |
| -------------- | ----- | ---------------------------------------------------------------- |
| `cloud/`       | 40    | AWS / GCP / Azure misconfig, IAM, key-rotation, S3, CloudTrail   |
| `identity/`    | 40    | Auth, MFA, SSO, IdP federation, session abuse, OAuth grants      |
| `endpoint/`    | 40    | Process exec, persistence, LOLBAS, credential theft, ransomware  |
| `network/`     | 30    | C2, scanning, beaconing, DNS abuse, Tor, lateral movement        |
| `application/` | 30    | Web, API, DB, secrets, supply chain, dependency abuse            |
| `data-exfil/`  | 20    | DLP, large transfers, archive uploads, tunneling, off-corp dest  |
| **Total**      | **200** |                                                                |

### Native rule format

```yaml
id: det-<unique-id>           # Stable identifier; native rules use det- prefix
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

### Native source of truth

The Python specs in [`scripts/detection_specs.py`](../scripts/detection_specs.py)
and [`scripts/detection_specs_part2.py`](../scripts/detection_specs_part2.py)
are the canonical source of truth. The on-disk YAML files are serialized
artifacts produced by [`scripts/generate_detections.py`](../scripts/generate_detections.py).
Edit specs, regenerate, then commit both.

```bash
# Regenerate all native rules + fixtures from specs (currently 800)
python3 scripts/generate_detections.py

# Validate (matches what CI runs)
python3 scripts/validate_detections.py --strict-fixtures
```

### Adding a new native rule

1. Add a new spec dict to the appropriate list in `scripts/detection_specs.py`
   or `scripts/detection_specs_part2.py`.
2. Required keys: `slug`, `name`, `severity`, `mitre`, `log_source`,
   `fields`, `match_when`, `fp`, `positive`, `negative`.
3. Run `python3 scripts/generate_detections.py` to materialize the YAML and
   fixtures.
4. Run `python3 scripts/validate_detections.py --strict-fixtures` to confirm
   the fixtures replay correctly.

## Imported tiers (`detections/<source>-imports/`)

Imported rules are normalized into the AiSOC schema by the source-specific
importers under [`tools/detection_import/`](../tools/detection_import/). Each
imported rule carries a populated `provenance` block so we can prove the
redistribution chain.

```yaml
id: <source>-<slug>-<short-sha>
name: Human-readable title (from upstream)
description: |
  Description preserved verbatim from upstream where present.
severity: low | medium | high | critical
category: network | endpoint | cloud | identity | application | data-exfil
enabled: true | false       # see "Quarantine" below
quarantine_reason: >        # required when enabled: false on import
  short reason — usually "requires manual translation to AiSOC engine"
detection:
  # tier-specific block: condition+fields for Sigma, splunk_spl for Splunk,
  # chronicle_yaral for Chronicle, native fields for CAR.
  ...
provenance:
  source: SigmaHQ/sigma | splunk/security_content | chronicle/detection-rules | mitre-attack/car
  source_id: <upstream UUID or rule key>
  source_commit: <pinned upstream sha>
  license: DRL-1.1 | Apache-2.0 | ...
  license_url: https://...
  imported_at: YYYY-MM-DD
  imported_by: tools.detection_import.<importer module>
  upstream_path: relative path to the source file in the upstream repo
```

`provenance.license` and `provenance.license_url` cover the legal redistribution
story; the canonical attribution table for every redistributed corpus lives in
[`.github/LICENSES.md`](../.github/LICENSES.md). Without that file we cannot legally redistribute
imported content.

### Quarantine

A rule lives under `detections/<source>-imports/_quarantine/<category>/` when:

- It parses cleanly into the AiSOC schema, **but**
- The engine cannot execute the upstream query as-is (Splunk SPL, Chronicle
  YARA-L, MITRE CAR pseudocode).

These rules ship with `enabled: false` and a `quarantine_reason`. They are
indexed for coverage accounting and surfaced in the UI as "imported, requires
translation" — never silently activated.

### Importing rules

Each importer is invoked through the orchestrator with a pinned upstream SHA:

```bash
# Run all four importers
python3 -m tools.detection_import.import_orchestrator

# Run a single source
python3 -m tools.detection_import.import_orchestrator --source sigmahq
```

See [`tools/detection_import/README.md`](../tools/detection_import/README.md)
for per-source notes on yield, dedup strategy, and what cannot be auto-translated.

## Community tier (`detections/community/`)

External contributions live here. Validation is permissive — `det-`/`<source>-`
prefixes are not required and the provenance block is encouraged but not
enforced. Community rules ship with `enabled: false` by default; operators
opt in per-tenant.

## Validation

The validator at [`scripts/validate_detections.py`](../scripts/validate_detections.py)
classifies every rule by tier from its on-disk path and applies the right rules:

- **Native**: `det-` ID prefix, fixture replay (positive must match, negative
  must not), category match against the directory name. CI runs with
  `--strict-fixtures`, which promotes missing-fixture warnings into hard fails.
- **Imported**: source-specific ID prefix (`sigmahq-sigma-`, `mitre-car-`,
  `splunk-security-content-`, `chronicle-detection-rules-`), required
  `provenance` block, no fixtures required.
- **Community**: schema check only.

The validator's summary line includes a per-tier count and a
quarantine count, so a green CI run looks like:

```
Validated 6913 rules — 6913 passed, 0 failed, 0 fixture warnings
  Tiers: native=800 imported=6113 (quarantined=5937)
```

Counts shift as importers refresh upstream sources; the line above is a
sample from the November 2026 pull, not a hard target.

CI integration lives in [`.github/workflows/validate-detections.yml`](../.github/workflows/validate-detections.yml).

## MITRE coverage

The marketplace builder at
[`scripts/build_marketplace.py`](../scripts/build_marketplace.py) walks every
tier and emits per-technique coverage counts to
`marketplace/index.json::mitre_coverage`. The web UI at
[`apps/web/src/app/(app)/detection/coverage/`](../apps/web/src/app/(app)/detection/coverage/)
renders this as a tactic × technique matrix so operators can see exactly which
techniques are covered today and at what tier (native vs imported vs
quarantined).

## File layout

```
detections/
├── cloud/                            # native, 40 rules
├── identity/                         # native, 40 rules
├── endpoint/                         # native, 40 rules
├── network/                          # native, 30 rules
├── application/                      # native, 30 rules
├── data-exfil/                       # native, 20 rules
├── fixtures/
│   ├── positive/                     # one .json per native rule — should match
│   └── negative/                     # one .json per native rule — should NOT match
├── sigma-imports/                    # populated by tools/detection_import/sigma_importer
│   └── _quarantine/                  # imported but not auto-translatable
├── splunk-imports/                   # populated by splunk_importer (SPL)
│   └── _quarantine/                  # always: SPL needs manual translation
├── chronicle-imports/                # populated by chronicle_importer (YARA-L)
│   └── _quarantine/                  # always: YARA-L needs manual translation
├── car-imports/                      # populated by car_importer (CAR pseudocode)
│   └── _quarantine/                  # always: pseudocode → engine syntax
└── community/                        # third-party / contributed rules
```
