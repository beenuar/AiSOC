---
id: backup-and-restore
title: Backup and restore
sidebar_label: Backup and restore
---

# Backup and restore

AiSOC keeps state in six places, plus the one secret that makes a
restore of it mean anything. They do not fail the same way or recover
the same way. This page says what each backup contains, how to put it
back, and — for the two cases where the honest answer is "do not" — why.

:::tip Upgrading? Start here
The API migration runner is **forward-only**. There is no downgrade and
no `alembic downgrade`, so a backup is the only thing between an
operator and an unrecoverable schema. `make upgrade` takes a local
Postgres dump for you and refuses to continue if it comes back empty;
this page is the off-host copy and the other six components.
See [Upgrades](./upgrades.md).
:::

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
| **Credential key** | `AISOC_CREDENTIAL_KEY` (and its rotation predecessor) | JSON | Every connector credential in the deployment |

Every artefact is encrypted with AES-256-GCM through
`scripts/backup_crypt.py` and recorded in a SHA-256 manifest. `openssl
enc` is not used because it **refuses AEAD ciphers** — a detail worth
knowing if you are reimplementing this.

### The credential key, and why it is the one component that cannot be unencrypted

The Postgres dump carries a `vault:v1:` token for every connector
credential, and `AISOC_CREDENTIAL_KEY` is the only thing that opens
them. Without it a complete, verified, restorable backup brings the
deployment back with **every connector dead**: `CredentialVault` raises
`ciphertext failed integrity check (key rotated without re-encrypt?)`
and nothing short of re-entering every vendor credential by hand
recovers it. The restore reports success throughout.

Capturing the key means the key and the ciphertext it opens now live in
one bucket, so the AES-256-GCM envelope is the only thing separating
them. `BACKUP_ENCRYPTION=off` is therefore **refused for this component
and only this one** — a live run fails rather than writing the key in
the clear; a `--dry-run` reports it as a skip, because a dry run is a
configuration check and nothing was going to be uploaded either way. It
is uploaded under its own `credential-key/` prefix so a bucket policy
*can* grant read on the dumps without granting read on the key. That is
defence in depth rather than a control on its own: a reader with
blanket access still has both.

`AISOC_CREDENTIAL_KEY_ROTATION_FROM` is captured too. It is what
decrypts tokens written before the last rotation, and a restore holding
only the current key cannot read them.

On the way back in, `restore.sh` writes the key into `.env` when none is
set, **no-ops** when the one already there is identical, and **refuses**
when a *different* key is present — overwriting that would orphan
whatever the running deployment had been encrypting with.

A deployment with no connectors configured has no key and nothing to
lose; the backup says so rather than skipping silently.

## Restoring

```bash
./scripts/restore.sh --timestamp 20260503T120000Z \
    --component postgres|clickhouse|plugins|neo4j|qdrant|redis|credential_key|all
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
- **Grafana, Prometheus and Alertmanager state.** `backup.sh` does not
  touch them. They now have named volumes so a container recreate no
  longer discards them, but there is no artefact to restore from if the
  volume itself is lost. Keep dashboards as files under
  `infra/docker/grafana/dashboards/` — provisioning reloads them, and a
  file is backed up by whatever backs up your checkout. [Upgrades
  → Recovering lost Grafana dashboards](./upgrades.md#recovering-lost-grafana-dashboards)
  covers the case where a recreate already took them.
