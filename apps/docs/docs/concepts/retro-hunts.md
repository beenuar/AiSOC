---
id: retro-hunts
title: Intel-driven retro-hunts
sidebar_label: Retro-hunts
---

# Intel-driven retro-hunts

A retro-hunt answers one question: **when somebody publishes an indicator, have
we ever seen it?**

It is the inverse of ordinary detection. A detection rule watches events
arriving now against knowledge you already had. A retro-hunt takes knowledge
that arrived now and points it at events you already recorded. That makes it
valuable, because intelligence about an intrusion usually lands weeks after the
intrusion, and it makes it expensive, because every published indicator asks a
question of your whole history.

AiSOC ships it **off by default**, at two levels, for that reason.

## What happens when an indicator arrives

`services/threatintel` polls the feeds you have configured, including the CISA
Known Exploited Vulnerabilities catalog, which needs no API key and is on by
default. Every indicator it has not seen before is published as a `NEW_IOC`
event.

For each tenant that has opted in, AiSOC then:

1. checks that tenant's sweep budget, and stops if it is spent;
2. sweeps the event lake over a lookback window, 30 days by default;
3. sweeps any SIEMs that tenant has connected, through the same typed
   indicator search the investigation agent uses;
4. opens **one** alert if anything matched, carrying provenance.

## Why one match is one alert

An indicator that appears in a million events and an indicator that appears in
one produce the same alert. Two mechanisms make that true, and they cover
different failures.

The sweep query is an **aggregate**. It returns how many sightings there were,
when the first and last were, and bounded sets of the hosts, users and sources
involved. There is no code path that returns a row per match, so a noisy
indicator costs the same as a quiet one.

The `retro_hunt_sightings` table has a **unique constraint** on
(tenant, indicator type, indicator value). A feed that republishes an indicator
every day updates that row and its `times_seen` counter rather than opening an
alert a day. Beneath that, the alert itself carries an idempotency key that the
`alerts` table has a per-tenant unique index on, so a duplicate cannot land even
if the logic above it is wrong.

## What an alert tells you

Three things, in order.

**Where the intelligence came from**: the feed, the indicator, and when that
feed first saw it. If the feed did not publish a first-seen date, the alert says
so rather than substituting the time it arrived.

**Where it matched**: which lake columns, how many sightings, the first and most
recent sighting **in your data**, and the hosts, users and connectors involved.
"First seen by the feed" and "first sighting in your data" are kept apart on
purpose. An indicator published this morning and last seen in your estate five
weeks ago is a different finding from one published and seen today, and a single
date could not say which you have.

**What was not checked**: an unreachable lake, a SIEM that failed to answer, a
SIEM with no field mapping for that indicator type, or a budget that ran out.
This section appears even when the sweep matched, because an indicator found in
the lake while the SIEM sweep failed is a weaker finding than one found in both.
A gap is never reported as an absence.

## What can and cannot be swept

The lake records a fixed set of columns, so a sweep can only ask about
indicators that land in one of them:

| Indicator | Searched in |
|---|---|
| IP address | `source_ip`, `dest_ip`, `iocs` |
| Domain | `dst_hostname` |
| Hostname | `src_hostname`, `dst_hostname` |
| SHA-256, SHA-1, MD5 | `hash_sha256`, `iocs` |
| Username | `user_name` |
| Process or file name | `process_name` |

Two deliberate absences are worth knowing about.

**URLs are not swept in the lake.** There is no URL column: a URL appears only
inside the compressed raw payload, which many connectors leave empty. A
substring scan there would cost a full table read and return a confident zero on
exactly the deployments that could not answer. URLs are swept through connected
SIEMs, which do carry a URL field.

**CVEs are not swept against telemetry.** A CVE identifier does not appear in
event data, so searching for one would match nothing anywhere. KEV entries are
checked against asset and vulnerability inventory instead.

All three hash types read the same column. The lake writer stores the first
fingerprint an event carries whatever algorithm produced it, so an MD5 lands in
the column named `hash_sha256`. The mapping follows the writer rather than the
column name, and `scripts/check_ioc_lake_mapping.py` fails the build if the two
ever disagree.

## Budgets

Each tenant has an hourly and a daily sweep allowance, checked **before** the
sweep runs so an exhausted budget costs one small database update rather than a
warehouse scan. Sweeps dropped for budget are counted, so an operator can tell a
quiet feed from a spent allowance.

The warehouse enforces its own ceiling: every sweep carries a bytes-to-read
limit and an execution-time limit. A sweep that exceeds either is reported as a
sweep that could not be completed, never as zero sightings.

## Turning it on

Two switches, answering different questions.

The operator's: `AISOC_RETRO_HUNT_ENABLED=true` on the API service, which lets
the deployment consume the intel topic at all.

The customer's: a row in `retro_hunt_settings` with `enabled = true`, which is
per tenant and controls the lookback window, whether connected SIEMs are swept,
and the budget.

Neither is assumed. A sweep costs warehouse time and, where it reaches a
connected SIEM, possibly money.
