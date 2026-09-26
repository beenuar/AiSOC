# AiSOC Detection Rules

This directory contains AiSOC detection content in a Sigma-inspired YAML format.
Rules are organized into four **tiers** based on origin, quality bar, and what
the AiSOC engine can do with them out of the box.

| Tier      | Where it lives                            | Status when shipped | Quality bar                                       |
| --------- | ----------------------------------------- | ------------------- | ------------------------------------------------- |
| Native    | `detections/<category>/`                  | enabled             | YAML schema + fixture replay + MITRE mapping      |
| Imported  | `detections/<source>-imports/<category>/` | varies (see below)  | YAML schema + provenance block; fixtures optional |
| Quarantined | `detections/<source>-imports/_quarantine/<category>/` | where the importer put it; see below | YAML schema + provenance + a populated `quarantine_reason` |
| Community | `detections/community/<category>/`        | disabled by default | YAML schema; provenance encouraged                |

The library holds **6,991 rules on disk, of which 2,603 execute** — 833 native
and 1,770 imported Sigma rules translated into the engine's `match_when` by
[`scripts/compile_sigma_ruleset.py`](../scripts/compile_sigma_ruleset.py).
Recount rather than quoting these: they move, and
[`docs/detections/truth-table.md`](../docs/detections/truth-table.md) derives
them from the ruleset the engine loads. The native tier is generated from the
spec modules under [`scripts/detection_specs*.py`](../scripts/).
Imported tiers are populated by the importers under
[`tools/detection_import/`](../tools/detection_import/) and remain empty in this
checkout until you run them — see [`tools/detection_import/README.md`](../tools/detection_import/README.md)
for the SigmaHQ, Splunk, Chronicle, and CAR pipelines and their pinned upstream
commits.

## What "executable" means

A rule is executable when the engine loads it, and it is only allowed into the
compiled ruleset after a vendor-shaped event has been replayed through the
**real** connector `normalize()` and the **real** `DetectionEngine` and that
rule was seen to produce a hit — with an empty event of the same shape
producing nothing. It is never inferred from a directory name, an `enabled:`
key, or the shape of a `detection:` block.

The proof is known to be able to fail, which is the only reason it is worth
quoting. `python3 scripts/compile_sigma_ruleset.py --prove-gate` reverts the
Windows connector to its pre-fix behaviour — `System` and `EventData` left
nested one level below the namespace the matcher reads — and requires all 1,687
Windows rules to stop firing. If any kept firing, the proof would not be
measuring the thing it claims to.

**What this does not claim.** Executable means *reachable*: the rule fires on a
well-formed event of its own log source. It is not evidence that the rule
detects an attack, that it is tuned for your estate, or that it will be quiet.
`false_positives:` is prose and is not machine-checked.

### Why 1,362 imported rules were refused

3,132 Sigma rules were considered and 1,362 refused with a recorded reason,
because a translation that is merely close changes what the rule means. Two
reasons cover three quarters of them:

- **556 — no connector emits that log source.** Nothing in the product
  produces the telemetry the rule reads, so it could only ever be silent.
- **464 — the negation would flip on a missing field.** Sigma treats
  `not filter` as *true* when the field is absent, and only `not_in` and
  `not_contains_any` do that in the AiSOC matcher. Compiling the rest would
  turn "not this value" into "fires whenever the field is missing".

The remaining 342 are mechanical: Sigma modifiers with no matcher operator
(`|cidr`, `|base64`, `|fieldref`, `|all` on a non-contains modifier),
case-sensitive regexes against a matcher that forces `IGNORECASE`, dotted
paths the matcher cannot traverse, and 133 that compiled but did not fire on
their own proof event. Full taxonomy with an example per reason, the
per-connector breakdown, and the known DRL-1.1 author-attribution gap:
[`docs/detections/sigma-compilation.md`](../docs/detections/sigma-compilation.md).

## Native tier (`detections/<category>/`)

The strict-quality, AiSOC-authored layer. Every rule has:

- A positive fixture under `detections/fixtures/positive/<slug>.json` (a
  synthetic event that should fire it).
- A negative fixture under `detections/fixtures/negative/<slug>.json` (a
  near-miss event that should not fire it).
- A MITRE ATT&CK mapping in its tag list.

CI replays both fixtures on every PR using the canonical runtime matcher in
[`scripts/generate_detections.py`](../scripts/generate_detections.py).

### Distribution by category

| Category       | Focus                                                            |
| -------------- | ---------------------------------------------------------------- |
| `cloud/`       | AWS / GCP / Azure misconfig, IAM, key-rotation, S3, CloudTrail   |
| `identity/`    | Auth, MFA, SSO, IdP federation, session abuse, OAuth grants      |
| `endpoint/`    | Process exec, persistence, LOLBAS, credential theft, ransomware  |
| `network/`     | C2, scanning, beaconing, DNS abuse, Tor, lateral movement        |
| `application/` | Web, API, DB, secrets, supply chain, dependency abuse            |
| `data-exfil/`  | DLP, large transfers, archive uploads, tunneling, off-corp dest  |

Per-category rule counts are not written here, because every hand-typed copy
of them in this tree had drifted. They are generated into
[`apps/web/src/data/corpus-stats.json`](../apps/web/src/data/corpus-stats.json)
under `categories` — executable rules only — by
`python3 scripts/generate_corpus_stats.py`, which reconciles the compiled
ruleset, the marketplace index and the truth table against each other and
fails if any two disagree. The by-tier split is in
[`docs/detections/truth-table.md`](../docs/detections/truth-table.md).

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
# Regenerate all native rules + fixtures from specs
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

The importer writes a rule into
`detections/<source>-imports/_quarantine/<category>/` when it parses cleanly
into the AiSOC schema but the importer could not execute the upstream query
as-is. That is still the whole story for Splunk SPL, Chronicle YARA-L and MITRE
CAR pseudocode: this repository has no evaluator for any of those languages, so
every one of those rules ships `enabled: false` with a `quarantine_reason`,
indexed for coverage accounting and surfaced in the UI as "imported, requires
translation" — never silently activated.

Sigma is the exception, and the reason the directory name is no longer a
verdict. `compile_sigma_ruleset.py` translates rules **in place** rather than
moving them, so 1,724 files under `_quarantine/` are compiled, proven to fire
and loaded by the engine today. The directory records where the importer put a
rule; the compiled ruleset records whether it runs. Every tool that reports on
the corpus — the truth table, the validator, the marketplace builder, the
coverage curator — reads the ruleset, which is why they agree. Anything that
classifies by path will report a figure roughly 1,700 too high.

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

The validator's summary line includes a per-tier count and how many of those
rules the engine loads, so a green CI run looks like:

```
Validated 6991 rules — 6991 passed, 0 failed, 44 fixture warnings
  Tiers: community=1, imported=6113, native=877
  Executable (loaded by the engine): 2603; not loaded: 4388
```

The executable figure is read from the compiled ruleset, the same artefact
`detection_truth_table.py` reads, so the two cannot publish different numbers
about the same tree.

Counts shift as importers refresh upstream sources; the line above is a
sample, not a hard target.

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
├── cloud/                            # native
├── identity/                         # native
├── endpoint/                         # native
├── network/                          # native
├── application/                      # native
├── data-exfil/                       # native
├── fixtures/
│   ├── positive/                     # one .json per native rule — should match
│   └── negative/                     # one .json per native rule — should NOT match
├── playbooks/                        # response playbooks, not detection rules —
│                                     # indexed in the marketplace as playbooks
├── sigma-imports/                    # populated by tools/detection_import/sigma_importer
│   └── _quarantine/                  # where the importer wrote them; the Sigma
│                                     # compiler translates in place, so many are loaded
├── splunk-imports/                   # populated by splunk_importer (SPL)
│   └── _quarantine/                  # always: no SPL evaluator in this repo
├── chronicle-imports/                # populated by chronicle_importer (YARA-L)
│   └── _quarantine/                  # always: no YARA-L evaluator in this repo
├── car-imports/                      # populated by car_importer (CAR pseudocode)
│   └── _quarantine/                  # always: pseudocode → engine syntax
└── community/                        # third-party / contributed rules
```

`detections/playbooks/` is the one directory here that holds no rules. Its 25
files are response playbooks — `trigger:` and `steps:`, no `detection:` block.
They are the entire difference between the 7,016 YAML files under this tree and
the 6,991 rules every count in this repository publishes.
