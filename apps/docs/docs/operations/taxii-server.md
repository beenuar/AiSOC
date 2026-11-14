---
id: taxii-server
title: Publishing indicators over TAXII 2.1
sidebar_label: TAXII 2.1 server
---

AiSOC can publish a tenant's indicators as TAXII 2.1 collections, so a
partner, an ISAC or another SOC can poll them with a stock client.

The server is read-only by design — see [Writes](#writes-are-refused).

## What a client walks

```
GET /api/v1/taxii2/                                                  discovery
GET /api/v1/taxii2/feeds/                                            API root
GET /api/v1/taxii2/feeds/collections/                                collections
GET /api/v1/taxii2/feeds/collections/{id}/                           one collection
GET /api/v1/taxii2/feeds/collections/{id}/objects/                   STIX indicators
GET /api/v1/taxii2/feeds/collections/{id}/manifest/                  manifest
```

`feeds` is the API root and it is a fixed string. The obvious design puts
a tenant id there — and a path segment is something any caller can retype,
on an endpoint whose whole purpose is to be pointed at by a third party.
The tenant comes from the authenticated principal instead.

Every response carries `application/taxii+json;version=2.1`. A plain
`application/json` response is a conformance failure that some clients
refuse outright.

## Authentication

A bearer credential with the `threat_intel:read` permission. An API key
scoped to that permission is the usual way to give a partner access
without giving them a user account.

## Collections

A collection is a **filtered view** over this tenant's indicator store,
never a copy of it. An indicator edited in the console does not have to be
edited twice, and the version a partner pulls cannot drift from the
version your own detections run on.

```bash
curl -sS -X POST "$AISOC_URL/api/v1/taxii/collections" \
  -H "Authorization: Bearer $AISOC_API_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
        "title": "High-confidence network indicators",
        "alias": "network-high",
        "ioc_filter": {"ioc_type": ["ip", "domain", "url"], "min_confidence": 70, "tlp": ["green", "white"]}
      }'
```

Filters understand `ioc_type`, `tlp`, `severity`, `source`, `tags`
(any-match) and `min_confidence`. **An unknown key is refused**, not
ignored: an ignored restriction publishes more than you asked to publish,
and does it silently.

A collection is addressable by its id or by its alias.

## Polling

A client records the `X-TAXII-Date-Added-Last` of what it saw and sends it
back as `added_after`. Pages are followed with the `next` value from the
envelope.

```bash
curl -sS "$AISOC_URL/api/v1/taxii2/feeds/collections/network-high/objects/?limit=200" \
  -H "Authorization: Bearer $PARTNER_TOKEN" \
  -H 'Accept: application/taxii+json;version=2.1'
```

The sort key is `(updated_at, id)` and the cursor compares both. This is
not pedantry: indicators written by one feed poll share `updated_at` to
the microsecond, and a cursor on the timestamp alone either repeats them
forever or silently loses them. An empty page omits the date-added
headers rather than setting them to "now", because a client that records a
boundary no row was ever written at skips anything that lands in between.

`limit` defaults to 100 and is capped at 1000.

## What is published, and what is not

Indicators are projected as STIX 2.1 `indicator` objects. The STIX id is
derived from the indicator's own primary key, so it is stable across polls
and a client can deduplicate on it.

These IOC types become STIX patterns: `ip`, `cidr`, `domain`, `url`,
`email`, `file_hash_md5`, `file_hash_sha1`, `file_hash_sha256`, `asn`.

`cve` is **not** published: a CVE is a vulnerability identifier rather
than an observable, and STIX models it as a vulnerability object that an
indicator collection is the wrong carrier for. `GET
/api/v1/taxii/unpublished-types` returns the current list with its
reasons, generated from the same table the projection uses, so the answer
cannot drift from the behaviour.

Inactive indicators and ones marked false-positive are never published.

TLP is carried as the marking-definition id the STIX specification fixes,
so a partner's tooling recognises it. Severity has no STIX field; it is
carried as `confidence`, as an `indicator_types` value and as a
`severity:<level>` label, because dropping it would lose the only ranking
a consumer has.

## Writes are refused

`can_write` is `false` on every collection and `POST .../objects/` answers
`403` with the reason. The field exists because the specification has it
and clients read it to decide whether to offer an upload.

An inbound TAXII write is an outside party inserting indicators that drive
this tenant's detections — a reach-out capability, and those ship off. Add
indicators through the threat-intel API instead.

## A note on the other TAXII route

`GET /api/v1/threatintel/stix/taxii/collections` is demo-gated and returns
a fixed sample list. It predates this server and is not it. It is kept
only because removing a published operation is a breaking change to the
OpenAPI document.
