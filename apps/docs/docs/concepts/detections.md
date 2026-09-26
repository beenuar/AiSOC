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
| Quarantined | `detections/<source>-imports/_quarantine/<category>/`  | see below        | schema + provenance, plus a populated `quarantine_reason`            |
| Community   | `detections/community/<category>/`                     | `enabled: false` | schema only (provenance encouraged)                                  |

:::note `_quarantine/` is a location, not a verdict

It stopped being one when the Sigma compiler began translating rules where
they sat: 1,724 files under `_quarantine/` are compiled, proven to fire and
loaded by the engine today. Ask the compiled ruleset whether a rule runs —
that is what the truth table, the validator, the marketplace builder and the
coverage page all do now, and it is why they agree.

:::

The library holds **6,991 ATT&CK-mapped rules on disk, of which 2,603 are
executable** — the count the detection engine actually loads. Those two numbers
travel together everywhere, because a library figure presented on its own reads
as coverage and is not.

The executable set is 833 native rules, authored as Python specs and backed by
1,756 positive/negative fixtures, plus 1,770 imported Sigma rules translated
into the matcher's own language by
[`scripts/compile_sigma_ruleset.py`](https://github.com/beenuar/AiSOC/blob/main/scripts/compile_sigma_ruleset.py).
[`docs/detections/truth-table.md`](https://github.com/beenuar/AiSOC/blob/main/docs/detections/truth-table.md)
cross-checks these counts against the loaded ruleset. Imported tiers are
normalized into the AiSOC schema by
the source-specific importers under [`tools/detection_import/`](https://github.com/beenuar/AiSOC/blob/main/tools/detection_import/README.md)
and remain empty in a fresh checkout until you run them.

## What "executable" means here

It is a claim about evidence, not about a flag in a file. A rule counts as
executable when a vendor-shaped event has been pushed through the **real**
connector's `normalize()` and the **real** `DetectionEngine`, and that rule
was observed to produce a hit — while an empty event of the same shape
produced nothing. Nothing is inferred from the rule's directory, its
`enabled:` key or the shape of its `detection:` block.

That distinction matters because the static check that looks like it proves
this does not. `scripts/check_detection_fields.py` says in its own docstring
that it over-approximates, and that "a false pass is a rule this gate should
have caught" — so passing it is not evidence a rule can fire.

The proof is also known to be capable of failing, which is the part that makes
it worth anything. Running

```bash
python3 scripts/compile_sigma_ruleset.py --prove-gate
```

reverts the Windows connector to its pre-fix behaviour — where `System` and
`EventData` were left nested one level below the namespace the matcher reads —
replays every shipped rule against it, and **requires all 1,687 Windows rules
to stop firing**. If they kept firing, the proof would not be measuring what it
claims, and the gate fails.

## What it does not mean

A rule that is executable is *reachable*: it fires on a well-formed event of
its own log source. That is not a claim that it detects an attack, that it is
tuned for your estate, or that it will not be noisy. `false_positives:` is
prose and is not machine-checked, and there is no per-rule false-positive-rate
gate. Treat the figure as "these rules can fire", never as "these rules are
correct".

## Why 1,362 imported rules were refused

3,132 Sigma rules were considered, 1,770 ship, and 1,362 were refused with a
recorded reason. The refusals are as informative as the acceptances, because a
translation that is merely close changes what a rule means, and a rule that
fires on the wrong events is worse than one that does not ship.

The two largest reasons account for three quarters of them:

| Refused | Why |
| ---: | --- |
| 556 | **No connector emits that log source.** The rule is well-formed and there is nothing in the product producing the telemetry it reads, so it could only ever be silent. |
| 464 | **The negation would flip on a missing field.** Sigma treats `not filter` as *true* when the field is absent; only `not_in` and `not_contains_any` behave that way in the AiSOC matcher. Compiling the rest would have turned "not this value" into "fires whenever the field is missing", which is the opposite of the rule. |

The remaining 342 are smaller, mechanical gaps — Sigma modifiers with no
matcher operator (`|cidr`, `|base64`, `|fieldref`, `|all` on a non-contains
modifier), case-sensitive regexes where the matcher forces `IGNORECASE`,
dotted field paths the matcher cannot traverse, and 133 that compiled cleanly
but did not fire on their own proof event and so were not shipped.

The full taxonomy, with an example rule for every reason and the per-connector
breakdown of what does ship, is in
[the compilation report](https://github.com/beenuar/AiSOC/blob/main/docs/detections/sigma-compilation.md).
That report also records a known attribution gap: the importer never captured
the upstream `author:` field, so DRL-1.1 attribution travels as repository,
rule id, upstream path and licence, but not as the person who wrote it.

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

A rule is written into `detections/<source>-imports/_quarantine/<category>/`
when the importer could not execute the upstream query as-is. That is still
true of Splunk SPL, Chronicle YARA-L and MITRE CAR pseudocode, for which there
is no evaluator in this repository at all: all 2,005 Splunk, 877 Chronicle and
99 CAR rules are indexed for coverage accounting and surfaced in the UI as
"imported, requires translation" — never silently activated.

What changed is Sigma. `compile_sigma_ruleset.py` translates those rules in
place rather than moving them, so a file under `_quarantine/` may be compiled,
proven to fire and loaded. The directory records where the importer put a rule;
only the compiled ruleset records whether it runs. Anything that reports on the
corpus reads the latter.

## CI validation

The validator at [`scripts/validate_detections.py`](https://github.com/beenuar/AiSOC/blob/main/scripts/validate_detections.py)
classifies every rule by tier from its on-disk path and applies the right
checks:

- **Native** — `det-` ID prefix, fixtures must replay correctly.
- **Imported** — source-specific ID prefix (`sigmahq-sigma-`, `mitre-car-`,
  `splunk-security-content-`, `chronicle-detection-rules-`), required
  `provenance` block.
- **Community** — schema check only.

The summary line breaks the count down by tier and by whether the engine loads
the rule, so a typical green CI run looks like:

```
Validated 6991 rules — 6991 passed, 0 failed, 44 fixture warnings
  Tiers: community=1, imported=6113, native=877
  Executable (loaded by the engine): 2603; not loaded: 4388
```

The executable figure is read out of the compiled ruleset, which is the same
authority the truth table uses, so the validator and the truth table cannot
report different numbers about the same tree. It used to be derived from the
directory layout and said 5,937 quarantined where the truth table said 4,213.

Counts move as importers refresh upstream sources; the line above is a
sample, not a hard target.

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
