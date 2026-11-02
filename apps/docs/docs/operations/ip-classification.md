---
title: Anonymizer and hosting classification
sidebar_label: IP classification
---

# Anonymizer and hosting classification

AiSOC stamps a class on the source address of every event whose address is
public, at ingest, from a dataset that ships with the product. A login from a
Tor exit relay and a login from a cloud range are different facts, and the
analyst reading the alert sees which it was and which snapshot of the dataset
said so.

Nothing in the product makes a network call to classify an address. The
dataset is embedded in the ingest binary, so this works on CORE, on an
air-gapped install, and with no enrichment service configured.

## What the shipped dataset covers

| Class | Shipped? | Where the records come from |
|---|---|---|
| `tor_exit` | Yes | The Tor Project's own bulk exit list, used under CC BY 3.0 US |
| `hosting_provider` | Yes | AWS, Google Cloud, Cloudflare, Fastly, DigitalOcean, Linode and Oracle, each from the publisher's own documented range endpoint |
| `vpn` | **No records** | No redistributable source. Tenant-supplied only |
| `public_proxy` | **No records** | No redistributable source. Tenant-supplied only |
| `residential_proxy` | **No records** | No redistributable source. Tenant-supplied only |

Read that table as it is written. **Three of the five classes are not
covered by anything AiSOC ships.** A connection from a commercial VPN exit
will carry no class at all unless you supply a list, and an alert with no
class means "the dataset had no entry", never "this address is ordinary".
Every surface renders an absent class as nothing rather than as a
reassurance, for that reason.

Why they are not covered: the widely cited community list of VPN and
datacentre ranges carries no licence file, so an MIT-licensed project cannot
redistribute it. Commercial anonymizer feeds are licensed per deployment.
The reasoning and the alternatives are recorded in
[ADR 0018](https://github.com/beenuar/AiSOC/blob/main/docs/decisions/0018-ip-class-dataset-provenance.md).

## Where the class appears

- **On the alert.** `src_ip_class` and `src_ip_class_dataset_version` on the
  alert row and in the `GET /api/v1/alerts/{id}` response.
- **On the investigation rail.** A "Source address" section naming the class
  and the dataset version, shown only when there is a class to show.
- **In the lake.** `src_ip_class`, `src_ip_class_source` and
  `src_ip_class_dataset_version` on `aisoc.raw_events`, as columns rather
  than inside the JSON blob, so a hunt for "logins from a Tor exit relay last
  quarter" is an index lookup.
- **To detection rules.** As the flat field `ip_class`, with
  `ip_class_source` and `ip_class_dataset_version` beside it.

## Why the version is stored with the class

The dataset is refreshed. An address that is a Tor exit relay in March is not
necessarily one in November, and relays churn constantly. Without the version
recorded on the event, an analyst re-reading an old alert cannot tell a
reclassification from a change in behaviour, and a comparison across two
quarters silently compares two different datasets.

## Refreshing the dataset

```bash
python3 scripts/fetch_ip_class_dataset.py
python3 scripts/check_ip_class_dataset.py
```

The first command is the only thing in the tree that reaches the upstream
endpoints. It is a maintainer action, run deliberately, and its output is
committed uncompressed so a refresh is reviewable as a diff - a security
dataset that changes opaquely is one nobody audits.

The second is the gate. It checks that the committed artefact matches its own
digest, that the downloader and the committed manifest name the same sources,
that the class vocabulary agrees across the downloader, the Python loader and
the manifest, and - the one that matters most - that the Go classifier and
the Python one return identical answers over a sample of the dataset. They
have to, because they answer in different places: Go classifies live events
at ingest, and Python classifies committed fixtures during detection replay.
If they disagreed, a rule matching `ip_class` would pass its fixtures and
never fire on real traffic.

## Writing a detection rule against the class

Match on `ip_class` as an ordinary field:

```yaml
match_when:
  event_type: "user.session.start"
  outcome: "success"
  ip_class: "tor_exit"
```

Two things to know before you do.

A rule gated on a class that ships with no records can never fire on a
deployment that supplied no list. That is honest, not broken, but it means
the rule's fixture passing tells you nothing about whether it will ever fire.

`ip_class` is a class, not a boolean. There is deliberately no `is_vpn`
field, because its `false` would have to cover both "the dataset says this is
not a VPN" and "the dataset has never heard of this address", and those are
different facts.

## What is not here yet

**Tenant-supplied lists are not implemented.** The three uncovered classes
have no path for a tenant to populate them today; the design is recorded in
`DEPTH2_PROGRESS.md`. Until that lands, those classes are unavailable rather
than empty-by-choice, and this page says so rather than implying a
configuration step exists.
