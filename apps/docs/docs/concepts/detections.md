---
sidebar_position: 3
---

# Detection Rules

AiSOC ships detection content in a Sigma-inspired YAML format and arranges it
into four **tiers** based on origin, the legal redistribution chain, and what
the AiSOC engine can run as-is.

## Tiers

| Tier        | Where                                                  | Default state    | What CI enforces                                                     |
| ----------- | ------------------------------------------------------ | ---------------- | -------------------------------------------------------------------- |
| Native      | `detections/<category>/`                               | enabled          | schema + fixture replay (positive matches, negative does not)        |
| Imported    | `detections/<source>-imports/<category>/`              | source-dependent | schema + populated `provenance` block                                |
| Quarantined | `detections/<source>-imports/_quarantine/<category>/`  | `enabled: false` | schema + provenance, plus a populated `quarantine_reason`            |
| Community   | `detections/community/<category>/`                     | `enabled: false` | schema only (provenance encouraged)                                  |

The native tier is the strict-quality, AiSOC-authored layer (currently 800
fixture-tested rules with 1,200 positive/negative fixtures). Imported tiers are
normalized into the AiSOC schema by
the source-specific importers under [`tools/detection_import/`](https://github.com/beenuar/AiSOC/blob/main/tools/detection_import/README.md)
and remain empty in a fresh checkout until you run them.

## Native rule format

Native rules live in `detections/<category>/`. Every rule has a positive
fixture and a negative fixture under `detections/fixtures/`; both are replayed
on every PR using the runtime matcher.

```yaml
id: det-brute-force-login-001
name: Brute-Force Login Attempt
description: |
  Detects 10+ failed logins in 5 minutes from the same source IP.
version: "1.0.0"
severity: high
category: identity
tags:
  - mitre.attack.t1110
  - tlp.white
log_source:
  product: auth_logs
detection:
  fields: [event.type, source.ip, user.name]
  condition: PATTERN_MATCH_ANY({"event.type": "failed_login"})
false_positives:
  - Password manager retries during outages
playbook: tpl-brute-force-response-v1
enabled: true
author: AiSOC
created: "2026-04-01"
modified: "2026-05-04"
references:
  - https://attack.mitre.org/techniques/T1110/
```

### Required fields

| Field        | Type    | Description                                                |
| ------------ | ------- | ---------------------------------------------------------- |
| `id`         | string  | Stable identifier; native rules use the `det-` prefix      |
| `name`       | string  | Human-readable rule name                                   |
| `severity`   | enum    | `critical` \| `high` \| `medium` \| `low`                  |
| `category`   | enum    | `cloud` \| `identity` \| `endpoint` \| `network` \| `application` \| `data-exfil` |
| `detection`  | object  | Detection block (`condition`, `fields`, or tier-specific block) |

### Optional fields

| Field                 | Description                                               |
| --------------------- | --------------------------------------------------------- |
| `tags`                | MITRE ATT&CK technique IDs (`mitre.attack.tXXXX`) + TLP   |
| `log_source.product`  | The expected source product (`syslog`, `cloudtrail`, ...) |
| `false_positives`     | Known benign triggers operators should know about         |
| `playbook`            | Auto-trigger this playbook on first match                 |
| `references`          | External links (MITRE, CVE, vendor advisories)            |

## Imported rule format

Imported rules carry a populated `provenance` block; the validator rejects
imported rules that omit it. The `id` prefix and `provenance.source` together
identify the upstream corpus.

```yaml
id: sigmahq-sigma-aws-root-account-usage-abc123def456
name: AWS Root Account Usage
description: |
  Detects the AWS root account performing actions, which should be exceptional.
severity: high
category: cloud
enabled: true
tags:
  - mitre.attack.t1078.004
detection:
  condition: event.userIdentity.type == "Root"
provenance:
  source: SigmaHQ/sigma
  source_id: 8d486989-5bb5-4f76-8ddd-9cf2a04d0e0e
  source_commit: 5f06d76d68b2a18d99cba1a8c1a6f72f3e3aa6a8
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/sigma/blob/master/LICENSE.Detection.Rules.md
  imported_at: 2026-05-04
  imported_by: tools.detection_import.sigma_importer
  upstream_path: rules/cloud/aws/aws_root_account_usage.yml
```

The full attribution table for every redistributed corpus lives in the repo's
[`.github/LICENSES.md`](https://github.com/beenuar/AiSOC/blob/main/.github/LICENSES.md).

### Quarantine

A rule lives in `detections/<source>-imports/_quarantine/<category>/` when it
parses cleanly but the engine cannot execute the upstream query as-is. This
covers Splunk SPL, Chronicle YARA-L, and MITRE CAR pseudocode out of the box.
Quarantined rules ship with `enabled: false` and a `quarantine_reason`. They
are still indexed for coverage accounting and surfaced in the UI as
"imported, requires translation" — never silently activated.

## CI validation

The validator at [`scripts/validate_detections.py`](https://github.com/beenuar/AiSOC/blob/main/scripts/validate_detections.py)
classifies every rule by tier from its on-disk path and applies the right
checks:

- **Native** — `det-` ID prefix, fixtures must replay correctly.
- **Imported** — source-specific ID prefix (`sigmahq-sigma-`, `mitre-car-`,
  `splunk-security-content-`, `chronicle-detection-rules-`), required
  `provenance` block.
- **Community** — schema check only.

The summary line breaks the count down by tier and quarantine state so a
typical green CI run looks like:

```
Validated 6913 rules — 6913 passed, 0 failed, 0 fixture warnings
  Tiers: native=800 imported=6113 (quarantined=5937)
```

Counts move as importers refresh upstream sources; the line above is a
sample from the November 2026 pull, not a hard target.

CI integration is wired into the [`Validate Detection Rules`](https://github.com/beenuar/AiSOC/actions/workflows/validate-detections.yml)
workflow.

## MITRE coverage

The marketplace builder walks every tier and emits per-technique coverage
counts to `marketplace/index.json::mitre_coverage`. The web UI at
`/detection/coverage` renders this as a tactic × technique matrix so you can
see exactly which techniques are covered today, by which tier, and how many
rules each technique has.

## One-click install from the marketplace

Marketplace items can be installed from `/marketplace` in the UI or via the
API:

```bash
curl -X POST http://localhost:8000/api/v1/marketplace/install \
  -H "Authorization: Bearer <token>" \
  -d '{"type": "detection", "id": "det-brute-force-login-001"}'
```

## Contributing native rules

1. Add a spec dict to `scripts/detection_specs.py` or
   `scripts/detection_specs_part2.py` (the canonical source of truth — the
   on-disk YAML files are serialized artifacts).
2. Required keys: `slug`, `name`, `severity`, `mitre`, `log_source`, `fields`,
   `match_when`, `fp`, `positive`, `negative`.
3. Run `python3 scripts/generate_detections.py` to materialize the YAML and
   fixtures.
4. Run `python3 scripts/validate_detections.py --strict-fixtures` to confirm
   the fixtures replay correctly.
5. Open a PR — CI runs the validator against every tier touched.

## Importing third-party rules

The importers under [`tools/detection_import/`](https://github.com/beenuar/AiSOC/blob/main/tools/detection_import/README.md)
clone pinned upstream commits, normalize each rule into the AiSOC schema, and
emit them into the matching `detections/<source>-imports/` tree with
provenance attached.

```bash
# Run all four importers (SigmaHQ, MITRE CAR, Splunk, Chronicle)
python3 -m tools.detection_import.import_orchestrator

# Run a single source
python3 -m tools.detection_import.import_orchestrator --source sigmahq
```

Splunk SPL, Chronicle YARA-L, and MITRE CAR rules are written into the
`_quarantine/` subdirectory by default because the AiSOC engine cannot execute
those query languages as-is.
