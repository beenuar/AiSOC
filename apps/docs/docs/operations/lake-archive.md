# Archive tier: long-term retention in an open format

The event lake (`aisoc.raw_events`, ClickHouse) holds at most **400 days**
— the TTL is a hard ceiling nothing exempts. Everything older exists only
if it was exported first. The archive tier is that export: closed calendar
months written to an S3-compatible bucket you own, as **Parquet with a
signed manifest**, verified by read-back, rehydratable for investigation,
and portable by design.

## How it works

- **The database that owns the rows writes the files.** Exports run inside
  ClickHouse (`INSERT INTO FUNCTION s3(...) ... FORMAT Parquet`); there is
  no second data path whose row semantics could drift from the lake's own.
  One object per `(tenant, month)`, under
  `aisoc-archive/tenant=<id>/month=<YYYY-MM>/events.parquet`. Only
  **closed** months export — the current month is still receiving rows.
- **The manifest is signed** (row count, event-time bounds, schema and
  OCSF version, per-file SHA-256) with the same evidence-bundle signer the
  rest of the product uses.
- **"Exported" is a claim; "verified" means the bucket was read back and
  matched** — the row count from the Parquet object and the SHA-256 of the
  raw bytes, both computed by ClickHouse. A corrupted object fails
  verification naming what differed, including the sharp case: a valid
  Parquet with the same row count and different bytes is caught by the
  checksum alone.
- UUID and IP columns are exported as strings (ClickHouse cannot write
  UUID to Parquet, and a string id is the more portable spelling); the
  rehydration loader casts them back.

## Configuration

`PUT /api/v1/lake/archive-policy` (settings:write):

| Field | Meaning |
|---|---|
| `enabled` | Default **off**. Nothing exports until a tenant turns it on. |
| `s3_endpoint`, `s3_bucket`, `s3_region` | Your bucket. Path-style addressing. |
| `s3_access_key`, `s3_secret_key` | Vault-encrypted at rest; decrypted only at export time. ClickHouse masks `s3()` credential positions in its query log. |
| `archive_years` | What the attestation reports against. The sweep never deletes archive objects; expiry of archived data is your bucket's lifecycle policy. |
| `worm_declared` | A declaration that the bucket carries an Object Lock default retention. Reported by the attestation as *declared by operator, not verified by this service* — this service does not manage bucket properties. |

The sweep worker (`lake_archive_sweep`, hourly) exports closed months for
opted-in tenants, verifies exported partitions, and drops expired
rehydration tables. `POST /api/v1/lake/archive-partitions/run` triggers a
single month explicitly; `POST /api/v1/lake/archive-partitions/{id}/verify`
re-verifies one.

## Rehydration

`POST /api/v1/lake/rehydrations` with a time range (and optionally a
`connector_type` filter) returns an **estimate first** — bytes, files and
months from the manifests; retrieval cost **only when the deployment
configured a price** (`AISOC_ARCHIVE_RETRIEVAL_PRICE_PER_GB`), otherwise
`null` with the reason stated. `confirm=true` loads the covered months into
a scratch table (`aisoc.rehydrated_<id>`) with an expiry (default 7 days),
queryable through the lake explorer under the same tenant predicate
`raw_events` gets. Every rehydration records the requester and a required
reason. The loader never trusts the bucket as a tenancy boundary: foreign
rows are evicted after landing.

## Portability

`POST /api/v1/lake/portability-exports` writes a range to a bucket **you
name** (credentials supplied per request, used for the job, never
persisted): one Parquet object per month plus a signed manifest and schema
document. The export is readable with no AiSOC code — the CI gate opens it
with DuckDB and matches the manifest's row counts.

## Scoped legal holds and the attestation

Legal holds carry a subject (`user`, `host`, `ip`, or tenant-wide) and,
since migration 172, an optional time window. A hold on a user, host or IP
**exempts exactly its own rows** from the retention purge — both the
Postgres alert purge and the ClickHouse lake mutation — while the rest of
the tenant purges on schedule. A tenant-wide hold still freezes the whole
tenant's purge, because that is what it means. The lake TTL ceiling is
untouched and untouchable: a hold older than 400 days is only satisfiable
through the archive tier, which is one of the reasons it exists.

`GET /api/v1/lake/retention-attestation` reports what is retained per tier,
the oldest row per tier, how many archive partitions are verified, the
WORM declaration state, and every live hold with whether it narrows or
freezes — each figure from its own store, with *not measured* where a
store cannot answer.
