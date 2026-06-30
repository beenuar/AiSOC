---
sidebar_position: 6
title: Upgrades & versioning
description: How AiSOC versions releases, what each digit means, the deprecation policy, and the procedure to upgrade in place.
---

# Upgrades and versioning

AiSOC follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html) on a single shared version across the monorepo. The authoritative version lives in [`VERSION`](https://github.com/beenuar/AiSOC/blob/main/VERSION); every release tag, container image, and SDK package is stamped with the same number.

This page is what you read before running `git pull` against a new release.

## Release cadence

| Channel | Frequency | What's in it |
|---|---|---|
| **Patch** (`x.y.Z`) | As needed, often weekly | Bug fixes, security patches, doc fixes. Always backwards compatible. |
| **Minor** (`x.Y.0`) | ~Every 1–3 weeks | New connectors, new agents, new endpoints. Backwards compatible — your existing config keeps working. |
| **Major** (`X.0.0`) | When breaking changes accumulate | Schema migrations that require downtime, removed endpoints, renamed env vars. |

Every release ships with a [CHANGELOG.md](https://github.com/beenuar/AiSOC/blob/main/CHANGELOG.md) entry that lists added features, behaviour changes, and any breaking notes. **Read it before upgrading across a major version.**

## What "breaking" means in AiSOC

A change is breaking — and therefore lives in a major release — if any of these apply:

1. An existing REST/GraphQL/WebSocket endpoint changes its request or response shape in a non-additive way.
2. An environment variable is renamed or its parsing semantics change.
3. A database migration cannot be rolled back without data loss.
4. A connector schema changes such that previously valid `auth_config` JSON would be rejected.
5. A built-in role's permission list is **reduced** (additions are not breaking).
6. An SDK function signature changes in a non-additive way.

Adding new endpoints, new fields, new connectors, new permissions, or new optional env vars is **not** breaking and ships in minor releases.

## Deprecation policy

When we plan to remove or change something:

1. **Announce in a minor release.** The CHANGELOG calls out the deprecation, the runtime emits a warning log, and the OpenAPI spec marks the endpoint as `deprecated: true`.
2. **Keep working for at least one full major-version cycle.** If we deprecate a behaviour in 6.3.0 and the next major is 7.0.0, the behaviour still works in every 6.x release.
3. **Remove in a major release.** The CHANGELOG's "Breaking" section names the removal explicitly and links to the replacement.

If you depend on something marked deprecated, open an issue — sometimes we extend the window.

## Before you upgrade

Run through this list every time:

1. **Read the CHANGELOG** between your current version and the target. Pay attention to anything labelled "Breaking", "Migration", or "Action required".
2. **Back up your database.** `pg_dump` of the AiSOC schema is the minimum bar. For Kafka- and ClickHouse-backed deployments, snapshot those too.
3. **Snapshot your `AISOC_CREDENTIAL_KEY`.** If you lose it during the upgrade, every encrypted connector credential in the database becomes unrecoverable. Treat the key the same way you treat your database backup.
4. **Confirm a maintenance window** for the API service. Migrations run inside a single transaction where possible; minor releases typically take seconds, major releases can take minutes on large `audit_log` tables.
5. **Stage first.** If you operate a non-production tenant on the same code as production, upgrade it first and let it run for a day before promoting.

## In-place upgrade procedure

The supported upgrade path is "stop, pull, migrate, start". Rolling upgrades across multiple API replicas are safe within a minor release; cross-major rolling upgrades are not supported because the running code may not understand the migrated schema.

```bash
# 1. Park new traffic at the ingress (return 503 to the API service).
# 2. Stop the API service replicas. Connectors and ingest can keep running —
#    they tolerate a temporary API outage and back-pressure into Kafka.

cd /opt/aisoc                 # your install path
git fetch --tags
git checkout v7.3.1           # the target tag

# 3. Pull dependencies.
pnpm install --frozen-lockfile
(cd services/api && uv sync)

# 4. Run database migrations.
#    From v7.3.1 onwards you can use the CLI directly:
aisoc db upgrade
#    (Equivalent to: cd services/api && uv run alembic upgrade head)

# 5. Start the API service back up.
docker compose -f infra/compose/docker-compose.dev.yml up -d api

# 6. Verify health and remove the maintenance gate.
curl -fsS http://localhost:8000/healthz
```

:::tip v7.3.1 migration idempotency
The v7.3.1 release made the close-to-7.x migrations (`005_compliance.sql`,
`025_connectors_click_and_connect.sql`, and the new
`042_alerts_schema_drift_fix.sql`) idempotent. If a previous upgrade left
your `alerts` table partially migrated, just re-run `aisoc db upgrade` —
the migration only adds columns that are missing instead of failing on
already-present ones. See the [CHANGELOG](https://github.com/beenuar/AiSOC/blob/main/CHANGELOG.md#731)
for the full column list.
:::

For Kubernetes deployments, the same flow applies: scale the API deployment to zero, run the migration as a `Job`, then scale back up. The Helm chart in [`infra/helm/`](https://github.com/beenuar/AiSOC/tree/main/infra/helm) exposes this as `helm upgrade --set runMigrations=true`.

## Verifying the upgrade

After a successful upgrade you should be able to:

- Hit `/healthz` and `/readyz` and get `200 OK` with no `degraded` services in the body.
- Run `aisoc-cli benchmark` (or `pnpm aisoc:benchmark`) and see the same or better numbers as before.
- Open the analyst console and see the version footer match the new tag.
- Check `/api/v1/system/version` and see the same number.

If any of those fail, see [Troubleshooting](./troubleshooting) — the upgrade can almost always be rolled back by checking out the previous tag and reverting the last migration with `alembic downgrade -1`.

## Rolling back

Patch and minor releases are designed to roll back cleanly. The procedure mirrors the upgrade:

```bash
git checkout v7.3.0           # the previous tag
pnpm install --frozen-lockfile
(cd services/api && uv sync)
(cd services/api && uv run alembic downgrade <previous_revision>)
docker compose -f infra/compose/docker-compose.dev.yml up -d api
```

Major releases occasionally ship one-way migrations (e.g. column drops). When that's the case, the CHANGELOG flags the migration as "irreversible" and the only rollback is restoring from the database snapshot you took in step 2 of the pre-upgrade checklist.

## Version skew

Within a given major version, the following components are guaranteed to be wire-compatible across one minor version of skew:

- Browser ↔ API service
- API service ↔ Connectors
- API service ↔ Agents
- SDK clients (Go, Python, TypeScript) ↔ API

That means you can upgrade the API service to `6.1.0` while connectors are still on `6.0.x`, finish their rollout over the day, and not break anything. Across a major version (`6.x` ↔ `7.x`) the contract resets — upgrade the API first, then everything else, on the same maintenance window.

## Long-Term Support

AiSOC does not currently offer formal LTS releases. The most recent major version is the supported version; security patches and CVE fixes are backported to the previous major for **90 days** after a new major lands, which is the window we expect operators to need to plan and execute their upgrade.

If your environment requires a longer support window, raise it in [Discussions](https://github.com/beenuar/AiSOC/discussions) — we're happy to discuss commercial support arrangements with the community.

## Pre-1.0 history

Versions `1.0.0` through `5.x` shipped during the original feature build-out and are documented in the [CHANGELOG](https://github.com/beenuar/AiSOC/blob/main/CHANGELOG.md). The `6.0.0` release in May 2026 was the first version we consider production-ready; new deployments should start from the latest tagged release (currently `v7.3.1`).
