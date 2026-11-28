---
title: NetAPI compromised-indicator feed
sidebar_label: NetAPI feed
description: Opt-in keyless IP and domain threat-intelligence lists polled by services/threatintel, with the measured cost of running them.
---

# NetAPI compromised-indicator feed

NetAPI publishes two plain-text indicator lists — one of IP addresses, one of
domains — that need no account and no API key. `services/threatintel` can poll
them like it polls the CISA KEV catalog, so the enrichment service's per-IOC
lookups match against them locally with no outbound call per indicator.

They fill a specific gap. Every enrichment provider AiSOC ships needs a key,
OTX needs a key, and the CISA KEV catalog carries CVEs only — so before this
there was no keyless source for the two IOC types alerts most often carry.

**This feed is off by default.** Turning it on has a real one-time cost, and
the numbers behind that decision are below so you can make it yourself.

## Attribution and licence

The lists are published by [NetAPI](https://netapi.com/) under
[Creative Commons Attribution 4.0 International (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/).
CC BY 4.0 requires attribution, which AiSOC satisfies in two places: every
indicator is stored with `source: "netapi"` and a `source_ref` naming the list
it came from, and this page credits the publisher. If you redistribute data
derived from these lists, the same attribution requirement passes to you.

The feed was [proposed by its operator](https://github.com/beenuar/AiSOC/issues/2079),
who disclosed that affiliation when proposing it. The characterisations of
what each list contains, below, are the publisher's own description of its
data. AiSOC has not independently audited how the lists are assembled, and
nothing in this page should be read as AiSOC vouching for their accuracy. What
AiSOC *has* verified is the mechanical behaviour — sizes, formats, headers and
cost — and those figures are labelled with how they were obtained.

## Enabling it

```bash
NETAPI_ENABLED=true
```

That is the whole configuration for the default setup. The remaining settings
have working defaults:

| Setting | Default | Notes |
| --- | --- | --- |
| `NETAPI_ENABLED` | `false` | Opt-in. See the cost section below. |
| `NETAPI_IPS_URL` | `…/netapi-compromised-ips.txt` | The IP list. |
| `NETAPI_DOMAINS_URL` | `…/netapi-compromised-domains-short.txt` | The **short** domain list. See "Which domain list". |
| `NETAPI_POLL_INTERVAL` | `3600` | One hour. An unchanged list costs a 304 with no body. |

Indicators land in the same stores as every other feed and are visible in the
console's indicator list under the source name `netapi`.

### Air-gapped deployments

The lists are on a public host, so with `AISOC_AIRGAPPED=1` the feed refuses to
register at boot, exactly like CISA KEV and OTX. The client enforces the policy
a second time at request time, so a deployment cannot reach the network through
it even if something constructs the client directly. To use an internal mirror,
point `NETAPI_IPS_URL` / `NETAPI_DOMAINS_URL` at it and add its host to
`AISOC_AIRGAP_ALLOWLIST`.

## What the lists contain

The publisher describes them as follows. These are its claims about its own
data, not AiSOC measurements:

- **Compromised IPs** — addresses that attacked the publisher's honeypot
  sensors in the preceding 48 hours.
- **Compromised domains** — phishing domains confirmed by CERT Polska, malware
  domains held by sinkholes, and domains sharing infrastructure with confirmed
  phishing. The **short** variant is the same list with the sinkholed domains
  removed.

### Sizes AiSOC measured

Counted from the live endpoints on 2026-11-28. The lists are rebuilt on the
publisher's schedule, so expect these to drift:

| List | Lines | Bytes (raw) | Bytes (gzip) |
| --- | --- | --- | --- |
| `netapi-compromised-ips.txt` | 40,078 | 567,299 | 143,787 |
| `netapi-compromised-domains.txt` (full) | 285,028 | 5,627,225 | 2,356,479 |
| `netapi-compromised-domains-short.txt` | 128,570 | 2,680,238 | 977,895 |

All three are served gzip-compressed when the client asks, which it does by
default.

## How polling stays cheap: conditional requests

The lists are large and change on someone else's schedule, so the client sends
`If-None-Match` and `If-Modified-Since` and treats a `304` as "nothing to do" —
it yields no indicators at all, so the ingest pipeline is never entered.

That matters more than the saved bandwidth. `ingest_iocs` pays a Redis
round-trip per indicator per storage sink whether or not the indicator is new,
so a poll that re-read an unchanged list would pay the full per-indicator cost
for zero new intelligence.

The three lists do not behave identically, and the difference is load-bearing.
Measured against the live endpoints on 2026-11-28:

| List | `ETag` | `Last-Modified` | Conditional result |
| --- | --- | --- | --- |
| compromised-ips | yes | yes | `304`, 0 bytes |
| compromised-domains (full) | yes | yes | `304`, 0 bytes |
| compromised-domains-short | **no** | yes | `304`, 0 bytes (via `If-Modified-Since`) |

The short list — the default — publishes no `ETag`. A client that only knew
about `If-None-Match` would re-download it on every poll, which is exactly the
cost the conditional request exists to avoid, so both validators are sent
whenever both are known.

## Cost of running it

All figures below were measured on 2026-11-28 on an Apple Silicon laptop
(CPU-only ONNX for embeddings), against the real published lists. Treat them as
the right order of magnitude for your hardware, not as a guarantee.

### Steady state — the number that matters

When a list has not changed, one poll costs **one conditional HTTP request per
list and nothing else**: no body, no indicators, no pipeline entry, no Redis
traffic, no embedding.

| List | Measured poll time, unchanged | Indicators ingested |
| --- | --- | --- |
| compromised-ips | 0.474 s | 0 |
| compromised-domains-short | 0.358 s | 0 |
| compromised-domains (full) | 0.470 s | 0 |

For the default setup that is roughly **0.8 s per hour**.

### When a list has changed

Download, parse and stream into the batched ingest, measured end to end through
the real client against the live endpoints:

| List | Indicators | Download + parse + stream | Peak Python memory |
| --- | --- | --- | --- |
| compromised-ips | 40,078 | 1.601 s | 2.13 MB |
| compromised-domains-short | 128,570 | 1.660 s | 1.07 MB |
| compromised-domains (full) | 285,028 | 1.404 s | 1.19 MB |

Memory is flat because the client streams: the 285,028-indicator list peaked
*lower* than the 40,078-indicator one. Nothing here scales with list size, so a
list that doubles does not double the client's footprint.

On top of that the pipeline charges its per-indicator cost, but only for
indicators it has not already stored — the dedup filter runs before the
storage write, so an unchanged-but-re-read list costs dedup round-trips without
re-embedding anything.

### First poll (one-time)

The first poll is the expensive one, because every indicator is new. Two costs
dominate, and neither is the download:

- **Redis dedup round-trips.** `ingest_iocs` issues 6 per indicator on a cold
  ingest (3 sinks × check + add). *Counted* by instrumenting the real pipeline;
  the seconds column is **arithmetic** (round-trips × 0.1 ms, a same-host Redis
  RTT), not a measurement of a live Redis.
- **Embedding.** Every indicator is embedded for the Qdrant vector store.
  *Measured* at 1.9–2.4 ms per indicator at the pipeline's 1,000-item batch
  size, using the model the service actually loads (`BAAI/bge-small-en-v1.5`).

| List | Indicators | Redis round-trips (counted) | ≈ seconds (arithmetic) | Embedding (measured) |
| --- | --- | --- | --- | --- |
| compromised-ips | 40,078 | 240,468 | 24 s | ≈ 96 s |
| compromised-domains-short | 128,570 | 771,420 | 77 s | ≈ 309 s |
| compromised-domains (full) | 285,028 | 1,710,168 | 171 s | ≈ 684 s |

For the default setup (IPs + short domains) that is a one-time cost of roughly
**8 minutes**, against about **16 minutes** if you switch to the full domain
list. Embedding runs in a worker thread, so it does not block the service.

### Storage growth

| List | OpenSearch documents | Qdrant vectors |
| --- | --- | --- |
| compromised-ips | 11.0 MB | 234.8 MB |
| compromised-domains-short | 37.4 MB | 753.3 MB |
| compromised-domains (full) | 82.6 MB | 1,670.1 MB |

Default setup: **≈ 48 MB of documents and ≈ 988 MB of vectors, about 1 GB
total**. With the full domain list, about 2 GB.

Vectors dominate by roughly 20× because every vector is stored at 1,536
dimensions. These are **raw document and raw vector bytes**, computed from the
documents the pipeline hands each store. On-disk index size after OpenSearch
and Qdrant overhead was **not measured** — that needs a live cluster.

### Effect on per-indicator lookups

None, by construction. The whole point of a polled feed is that enrichment
answers locally: the per-IOC lookup is a `term` query against an OpenSearch
`keyword` field, whose cost is an inverted-index lookup rather than anything
linear in corpus size, and this feed adds rows to that index without touching
any code on that path.

Live lookup latency against an index populated with these lists was **not
measured** — there is no live OpenSearch cluster in this environment. The claim
above is structural, from the query shape and the index mapping, not timed.

## Which domain list

The short list is the default. The full list is the same data plus about
156,000 sinkholed domains, and two measured facts drove the choice:

- It costs about **half** as much on both axes that matter — 771,420 dedup
  round-trips against 1,710,168, and 753 MB of vectors against 1,670 MB.
- Sinkholed domains are, by definition, no longer attacker-controlled. Traffic
  to one is evidence of a past infection rather than a live threat, which is a
  different and generally less urgent signal than the rest of the list.

If you want the sinkhole coverage, set:

```bash
NETAPI_DOMAINS_URL=https://netapi.com/api2/netapi-compromised-domains.txt
```

## Why it is off by default

Turning the feed on adds roughly a gigabyte of vector storage and about eight
minutes of one-time embedding. Those are reasonable costs for ~169,000 keyless
indicators on the two IOC types alerts carry most — but they are costs an
operator should choose, not inherit silently from an upgrade.

## How a hit affects a verdict

An indicator from this feed is treated exactly like any other single-feed
match, with no special weighting in either direction:

1. `services/threatintel` stores the indicator with `source: "netapi"`.
2. `services/enrichment` reads it back on a per-IOC lookup and reports a
   matching feed under that name.
3. `services/fusion` maps that name onto the `netapi` threat-intel key and the
   confidence scorer counts it as a positive signal in the `threat_intel`
   factor. A second feed matching the same indicator raises the contribution
   further, as it does for any other combination of sources.

## Honest failure states

- **Unreachable list** — logged at `error`, no indicators, the other list still
  polls. An empty result is never reported as a successful empty feed.
- **Unchanged list** — logged at `info` as unchanged, with zero ingested.
  Distinct from "unreachable" in both the log and the client's status.
- **A response that is not the feed** — these lists sit behind a CDN, and a CDN
  challenge or error page is served as `200` with an HTML body. The client
  checks the leading lines before ingesting anything and refuses the whole
  response if they do not parse as indicators, rather than storing markup. It
  also declines to remember that response's `ETag`, so the next poll retries
  properly instead of getting a `304` against the junk.
- **No per-indicator confidence** — the lists publish none, and the client does
  not invent one. The `confidence` field is simply absent.
