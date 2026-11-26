---
sidebar_position: 7
title: Incident timeline on a case
description: One chronology for an incident — the case's alerts interleaved with the raw lake events behind them, in event-time order and grouped by kill-chain stage, served by GET /api/v1/cases/{case_id}/incident-timeline.
---

# Incident timeline on a case

An alert is a moment. An incident is a sequence, and the question an analyst
actually asks — *what happened, in what order* — was previously answerable
only by reading several surfaces and holding the order in your head. The case
workspace's **Timeline** tab answers it in one place: every alert the case
links, interleaved with the raw events those alerts were built from, sorted by
the time the source records themselves carry.

## What it shows

Entries come from two tiers and are deliberately distinguishable:

- **Alerts** — each one the case links, ordered by `event_time` rather than
  by when it was ingested. Alerts carrying a kill-chain stage are grouped
  under it, in kill-chain order, so the shape of the intrusion is visible
  before any individual row is read.
- **Events** — the raw records behind each alert, resolved from the alert's
  `source_event_ids` against the event lake and attributed back to the alert
  that named them. Each alert expands to its own events.

## The honest states, and why they exist

Three things in this surface would be easy to fake and are not:

**No event lake configured.** The lake ships with the profile that includes
ClickHouse; a core-profile deployment has none. That case reads
`events_available: false` with a reason, not an empty timeline — *nobody
looked* and *nothing was there* are different facts and an analyst must be
able to tell them apart. A lake that is configured but does not answer is
reported the same way, naming the read failure rather than implying an empty
estate.

**A partial event set says so.** An alert records at most 200
`source_event_ids`. An alert sitting exactly on that ceiling is known to be
incomplete, so the response sets `source_event_ids_truncated` and carries a
note stating that more events contributed to the incident than are listed.

**The chronology does not claim causation.** Every response carries a
disclaimer: times are taken from the source records themselves, so this is a
chronology of what was *observed*, not a confirmed account of what caused
what. Clock skew between a cloud audit log and an endpoint agent is real, and
the surface does not pretend otherwise.

## Where the chain identity comes from

The stage and position badges are not computed in the console. Fusion's
correlator groups alerts by entity and tactic, and the attack-chain grouper
orders them across 14 MITRE kill-chain stages; both identities are persisted
on the alert row (`incident_id`, `chain_id`, `chain_position`, `chain_stage`).
An alert that belongs to no incident carries none of them rather than a
placeholder, and the timeline renders it as an ungrouped entry rather than
inventing a stage for it.

## The API

```
GET /api/v1/cases/{case_id}/incident-timeline
```

Returns the case's alerts and their lake events as one ordered list:

| Field | Meaning |
|---|---|
| `entries` | Alerts and events interleaved, ascending by source time |
| `alert_count` / `event_count` | How many of each the timeline holds |
| `events_available` | `false` when the lake could not answer |
| `events_unavailable_reason` | Why, when it could not — never an empty result standing in for a failure |
| `source_event_ids_truncated` | `true` when an alert sat on the 200-id ceiling |
| `truncation_note` | What that means, in words |
| `disclaimer` | Observed chronology, not established causation |

The route requires the same case-read permission as the rest of the case
workspace, and resolves everything within the caller's tenant.

## Related

- [Investigation Rail on `/alerts`](./investigation-rail.md) — the
  single-alert counterpart.
- [Architecture](../architecture.md) — where correlation and the attack-chain
  grouper sit in the pipeline.
