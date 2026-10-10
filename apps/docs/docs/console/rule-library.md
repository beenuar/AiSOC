---
sidebar_position: 3
title: Detection rule library
description: How /detection lists the 2,586 rules the detection engine runs, where they come from, and what disabling one actually does.
---

# Detection rule library

`/detection` lists every rule the fusion detection engine loads, together with
any rule this tenant has authored. On a default install that is **2,586
rules**, and the number on the page is derived from the same artefacts the
engine reads rather than from a second count.

## Where the rules come from

Four artefacts, all generated and all committed:

| Artefact | Rules | Loaded by |
| --- | --- | --- |
| `detection_ruleset.json` | 741 | `DetectionEngine` — stateless `match_when` |
| `detection_ruleset_imported.json` | 1,770 | `DetectionEngine` — translated upstream corpus |
| `windowed_ruleset.json` | 72 | `load_window_rules()` (70) and `load_sequence_rules()` (2) |
| `windowed_builtin_rules.json` | 3 | `load_window_rules()`, declared in fusion's Python |

The engine's own copies live under `services/fusion/app/data/`. The API carries
a byte-identical copy under `services/api/app/data/detections/`, because the
API image is built with `services/api` as its Docker context and cannot reach
into another service's tree. `scripts/sync_packaged_detection_rulesets.py`
writes the packaged copy and `--check` holds the two identical in both
directions, so the catalogue can never describe a corpus the engine does not
run — and the console can never go blank in a container while working in a
checkout.

## Built-in and authored rules

A rule card is marked **Built-in** when the detection engine loads it. The
distinction matters because the two are enforced in different places:

- A **built-in** is evaluated by `services/fusion` against every ingested
  event. Its logic is compiled and read-only; the body shown in the editor is
  the entry the engine loads, rendered as JSON.
- An **authored** rule lives only in `detection_rules` and is run by the rule
  IDE, hunts and backtests — not by the streaming engine.

Each built-in card shows its engine rule id (`det-cloud-063`,
`sigmahq-sigma-…`, `wd-port-scan`). That is the id an alert carries in its
`rule_id`, so it is what to search for when working back from a finding.

## What disabling a built-in does

Turning a built-in off writes a tenant-scoped row into `detection_rules`
carrying `provenance.source_id` — the engine's rule id. `services/fusion`
reloads each tenant's tuning overlay every 30 seconds
(`AISOC_TENANT_OVERLAY_RELOAD_SECONDS`), keyed on exactly that field, and
stops firing the rule for that tenant. Other tenants are unaffected: the
compiled corpus is shared and the overlay is the per-tenant difference.

The row records who made the change, so a match the engine suppressed can be
explained with the name and reason rather than silently not happening.

Enabling it again flips the same row back; the rule's id never changes, so
links and saved views keep working.

## What the library does not record

The compiled artefacts hold a rule's logic, severity, category and ATT&CK
mapping. They hold no confidence score, no false-positive rate and no trigger
history, because none of those are properties of a rule — they are properties
of how a particular deployment has experienced it.

So an untuned built-in reports no confidence, and the two panels that average
confidence say so rather than including it:

- **Confidence** excludes unscored rules from every average and reports
  `summary.unscored`.
- **Drift** cannot judge an unscored rule — all three of its heuristics read
  confidence, false-positive rate or last-trigger — and reports them under
  `summary.unscored` instead of filing the whole library as "low confidence,
  stale".

Set a confidence on a rule and it joins both panels.

## Paging and filtering

The list is paged at 50 and every filter except the language pill runs on the
server: `GET /api/v1/detection/rules` accepts `search`, `severity`,
`category`, `mitre`, `enabled`, `source`, `limit` and `offset`, and returns
`total` (matching the filters) beside `builtinTotal` and `customTotal` (the
library). `GET /api/v1/rules` takes the same filters and reports the matching
count in `X-Total-Count`.

The bound is not cosmetic — serialising the whole corpus is several megabytes.

## When the corpus cannot be read

If the packaged artefacts are missing from a deployment, the page says the
library could not be read and repeats the resolver's error. It does **not**
say there are no rules: the engine is still loading and firing them, and
telling an operator their coverage is zero when a file is merely unreachable
is worse than saying nothing.

A partial read — some artefacts present, others not — renders a banner naming
the missing files, because publishing the smaller total as though it were the
whole corpus is the same mistake more quietly.
