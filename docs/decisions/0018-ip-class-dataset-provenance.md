# 0018. Which anonymizer and hosting classes AiSOC ships, and which it refuses to

- **Status**: Accepted
- **Date**: 2026-11-01
- **Context**: depth plan wave 2, item 1.6

## Context

Item 1.6 asks for five classes stamped on public addresses at ingest -
`vpn`, `tor_exit`, `public_proxy`, `residential_proxy` and
`hosting_provider` - from a *pinned, redistributable local dataset*, with no
per-event network call, and says that where no redistributable source exists
for a class the product should accept a tenant-supplied list and say in the
docs that the class is otherwise not covered.

Three constraints make this a decision rather than an implementation detail.

**It has to work offline, on CORE.** The existing IP enricher reaches
`services/enrichment` for geography and ASN, and that service is in the
`full` profile only. A class available only on `full` would make every
detection reading it silently dead on the smallest deployment - the exact
failure shape this repository keeps finding. So the dataset is embedded in
the ingest binary and the lookup is local.

**This repository is MIT-licensed and redistributes what it commits.** A
dataset whose terms nobody can read is not redistributable, however widely it
is used elsewhere.

**A security classifier that is wrong is worse than one that is absent.** An
alert that says an address is "not a VPN" is a claim; the data has to support
it.

## Decision

### Shipped, with provenance recorded per source

| Class | Source | Terms |
|---|---|---|
| `tor_exit` | The Tor Project's own bulk exit list | Tor Project site content is CC BY 3.0 US; attributed in the dataset header and in the manifest |
| `hosting_provider` | AWS, Google Cloud, Cloudflare, Fastly, DigitalOcean, Linode and Oracle, each from the publisher's own documented range endpoint | Each publisher documents the endpoint for customer firewall and allow-list configuration; the manifest records the endpoint, the documentation link and the upstream digest per source |

Every source is published by the party that owns the addresses, at a
no-authentication endpoint that exists so third parties can load it into
network tooling. The manifest records that argument per source rather than
asserting it once in prose, so a reviewer can check each one.

### Refused

`vpn`, `public_proxy` and `residential_proxy` ship with **no records**.

The widely cited community list for VPN and datacentre ranges was checked
first and refused: its repository carries **no licence file at all** - a
request for `LICENSE` on its default branch answers 404 - so an MIT
repository cannot redistribute it. Commercial anonymizer feeds exist and are
licensed per deployment, which is a per-tenant credential rather than
something to commit.

Those three classes are therefore **tenant-supplied only**, which is exactly
the fallback the plan names. Until a tenant supplies a list, an address in
one of those classes carries no class at all.

## Consequences

**Absent is never false.** The column is NULL, the rail renders nothing, and
no surface says "not an anonymizer". A boolean `is_vpn` would have forced a
`false` the dataset cannot support, and on a security surface an analyst
would reasonably read that `false` as evidence.

**The version travels with every stamp.** The dataset is refreshed; an
address that is a Tor exit in March is not necessarily one in November. A
class with no version cannot be dated, and an analyst reading a six-month-old
alert could not tell a reclassification from a change in behaviour. The
version is a column on the alert and on the lake row, not an inference from
the alert's date.

**One classifier, two readers, held together by a gate.** The classifier that
runs in production is the Go one in
`services/ingest/internal/activity/ipclass`. The Python loader in
`scripts/ip_class_dataset.py` exists only so fixture replay classifies the
same way - a committed fixture carries a `src_ip` and no activity projection,
so without it a rule matching `ip_class` would pass its fixtures and never
fire live, or the reverse. `scripts/check_ip_class_dataset.py` runs both over
a sample of the dataset and requires identical answers.

**The dataset lives inside the Go package.** `go:embed` cannot reach above
its own package and the ingest image's build context is `services/ingest`,
so the committed artefact is at
`services/ingest/internal/activity/ipclass/data/`. The Python side resolves
that path by walking up from its own file. One copy plus a gate, rather than
two copies plus a sync - the same reasoning the event catalogue beside it
already uses.

**Refreshing is a maintainer action, not a background fetch.**
`scripts/fetch_ip_class_dataset.py` is the only thing in the tree that
reaches these endpoints, it is run deliberately, and its output is committed
and reviewed as a diff. Nothing in the product makes a per-event call.

**Size.** 21,726 records, about 820 KB of text in the repository and the same
in the ingest binary. Within the CORE budget, and committed uncompressed on
purpose: a refresh has to be reviewable as a diff, because a security dataset
that changes opaquely is one nobody audits.

## Alternatives considered

**An ASN-keyed hosting list instead of CIDRs.** Smaller, but ASN comes from
the enrichment service, which is `full`-profile only, so hosting
classification would have been dead on CORE. Rejected for the reason the
whole decision turns on.

**Fetching at boot rather than committing.** Removes the redistribution
question, and replaces it with an air-gapped deployment that has no classes
at all and a first run whose behaviour depends on the network. Rejected.

**Shipping the community VPN list anyway.** Rejected on the licence, not on
the data quality.
