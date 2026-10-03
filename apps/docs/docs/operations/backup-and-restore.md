---
id: backup-and-restore
title: Backup and restore
sidebar_label: Backup and restore
---

# Backup and restore

AiSOC keeps state in six places, and they do not fail the same way or
recover the same way. This page says what each backup contains, how to
put it back, and — for the two cases where the honest answer is "do
not" — why.

:::info What changed
`backup.sh` has backed up five stores for some time. Until recently
`restore.sh` restored **two** of them. Neo4j, Qdrant and Redis each had
a backup nobody had ever proven they could use, and the first time
anyone would have found out is during the recovery.

Nothing failed, which is why it survived: both scripts ran, both
reported success, and the asymmetry was only visible by reading the two
files side by side. `scripts/check_backup_restore_parity.py` now fails
CI when a store gains a backup without a restore, which is the
direction this drifts — the backup is the part that feels urgent.
:::

## What is backed up

```bash
./scripts/backup.sh --component all
```

| Store | Holds | Format | Losing it costs |
|---|---|---|---|
| **Postgres** | Alerts, cases, users, policies, the audit chain | `pg_dump` | Everything. This is the system of record |
| **ClickHouse** | The event lake | Per-table TSV | Hunt history and retro-hunt reach |
| **Neo4j** | The entity graph | Cypher via APOC | Blast-radius queries until it is rebuilt from ingest |
| **Qdrant** | IOC and actor embeddings | Per-collection snapshot | Similarity search until re-embedded |
| **Redis** | Cache, OIDC sign-in state, rate-limit counters | RDB | Nothing durable |
| **Plugins** | Installed marketplace content | Tarball | Reinstallable from the marketplace |

Every artefact is encrypted with AES-256-GCM through
`scripts/backup_crypt.py` and recorded in a SHA-256 manifest. `openssl
enc` is not used because it **refuses AEAD ciphers** — a detail worth
knowing if you are reimplementing this.

## Restoring

```bash
./scripts/restore.sh --timestamp 20260503T120000Z \
    --component postgres|clickhouse|plugins|neo4j|qdrant|redis|all
```

`--dry-run` fetches and verifies every artefact without writing, and
treats an unreachable store as a **skip rather than a failure**, so it
works as a configuration check.

### Neo4j replays Cypher rather than loading a dump

`neo4j-admin load` needs the database stopped. A restore that requires
downtime on a store the platform degrades gracefully without is a worse
trade than a slower replay, so the backup exports Cypher and the
restore replays it.

Statements apply one at a time. A single failing `MERGE` must not
discard the whole graph, and failures are **counted and surfaced** — a
restore that reported success having skipped half the graph is exactly
the class of problem this page exists to close.

### Qdrant lets the upload recreate collections

Collections are not pre-created. A vector collection's dimension is
immutable, so creating one with the wrong dimension would make the
restore fail in a way that looks like corrupt data rather than a
configuration mismatch.

### Redis asks you to confirm, and the default is don't

```bash
REDIS_RESTORE_CONFIRM=yes ./scripts/restore.sh --timestamp … --component redis
```

Redis holds only state the platform rebuilds. Replacing a running cache
with an hours-old one serves stale answers with full confidence, which
is worse than a cold start — so the restore refuses unless you say
otherwise, and prints why.

The one real cost is sign-ins mid-flight: the OIDC state store lives
here, so a user part-way through authentication sees an error and signs
in again.

## Verifying a backup you have not restored

A backup you have never restored is a hypothesis.

```bash
./scripts/restore.sh --timestamp <ts> --component all --dry-run
```

This fetches every artefact, verifies it against the manifest, and
decrypts it, without touching a live store. It does not prove the data
is *useful* — only a real restore does that — but it does prove the
bytes are present, intact and decryptable, which is where most backup
failures actually live.

The `backup → destroy → restore` integration job runs the full cycle
against real containers in CI.

## What is not covered

- **Point-in-time recovery.** Backups are periodic snapshots. Recovery
  loses everything between the last snapshot and the failure; see
  [HA deployment](./ha-deployment.md) for reducing that window.
- **Cross-region replication.** Shipping artefacts to a second region
  is a storage configuration, not something these scripts do.
- **A measured RPO.** The window depends on your schedule and your
  object store, and publishing a figure from one laptop's timings
  would not describe your deployment.
