---
id: from-splunk
title: Migrating detections from Splunk, Sentinel and Elastic
sidebar_label: From SPL, KQL and EQL
---

# Migrating detections from Splunk, Sentinel and Elastic

Arriving with 400 Splunk searches and rewriting all of them by hand is
the cost that decides whether a migration happens at all.

```bash
python3 packages/aisoc-migrate/inbound.py --dialect spl --file my-searches.txt
python3 packages/aisoc-migrate/inbound.py --dialect kql --query 'SecurityEvent | where EventID == 4625'
python3 packages/aisoc-migrate/inbound.py --dialect eql --query 'process where process.name == "mimikatz.exe"'
```

Add `--json` for machine-readable output.

## Refusing is the feature

A translator that produces something for every input is worse than one
that refuses. An almost-right detection is harder to find than a
missing one: it sits in the catalogue, fires on the wrong thing, and
nobody checks it against the original.

So these constructs **refuse the whole translation** rather than being
dropped quietly:

| Dialect | Refused | Why |
|---|---|---|
| SPL | `transaction`, `eventstats`, `streamstats` | Windowed and session aggregation |
| SPL | `lookup`, `inputlookup` | Joins a table this deployment does not have |
| SPL | `join`, `map` | Correlates two searches — use a correlation rule |
| KQL | `join`, `externaldata`, `make-series`, `evaluate` | Same reasons |
| EQL | `sequence`, `until`, `join` | Ordered multi-event match; the engine evaluates one event at a time |

Every refusal names what stopped it. A reviewer cannot act on "could
not translate".

## What you get back

| Confidence | Meaning |
|---|---|
| `high` | Three or more field comparisons carried across |
| `good` | Two |
| `partial` | One, or an aggregation whose threshold did not carry |
| `none` | No rule produced; see `unsupported` |

## Measured on 2,005 real rules

This repository already stores 2,005 quarantined Splunk rules. Run
against all of them:

```
1,734 of 2,005 (86.5%)  produce a rule
  271                   refused, each with a stated cause
1,711 of the 1,734      are only `partial`
```

**The third line is the one that matters.** The corpus is
overwhelmingly aggregation-based, so "translated" mostly means *field
matches carried across, the threshold did not*. Reading 86.5% as a
finished migration would be wrong, and the test suite asserts that
ratio directly so the headline cannot drift away from it.

Refusal causes, counted: 1,709 aggregations, 109 lookups, 57
`eventstats`, 51 joins.

## What to do with a `partial`

Treat it as a draft with its field logic done for you.

1. Read the `unsupported` list. An aggregation note means you need a
   threshold the original had and this does not.
2. Check whether the windowed engine can express it. A simple count
   over a window usually can.
3. Author positive and negative fixtures — the approval gate replays
   them, and a rule that cannot prove itself cannot be approved.
4. Submit it as a proposal and have a **second person** approve it.

See [Detection lifecycle](../operations/detection-lifecycle.md).

## What is deliberately not attempted

Statistical and transactional constructs are refused rather than
approximated. They describe windowed aggregation, the engine's
windowed support is limited, and emitting a point-in-time rule that
*looks* like the original is exactly the almost-right failure above.

Two more details worth knowing:

**Splunk's `index` and `sourcetype` are dropped**, with a note. They
address Splunk's own storage rather than the event, and carrying them
would make every imported rule match on a field no connector emits.

**Keywords are word-bounded.** A field named `join_key` is not a
`join`. Without that the translator refuses rules it can handle, which
is the opposite failure and the harder one to notice.
