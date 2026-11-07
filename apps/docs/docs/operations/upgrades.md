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
2. **Back up your database.** The API migration runner is forward-only — there is no downgrade — so the dump is the only thing standing between you and an unrecoverable schema. `make upgrade` takes one for you (step 2 of the procedure below) and refuses to continue if it comes back empty. For the off-host copy, and for the other six components, use [`scripts/backup.sh`](https://github.com/beenuar/AiSOC/blob/main/scripts/backup.sh); [Backup and restore](./backup-and-restore.md) explains what each artefact contains and how to put it back.
3. **Snapshot your `AISOC_CREDENTIAL_KEY`.** If you lose it during the upgrade, every encrypted connector credential in the database becomes unrecoverable: each `vault:v1:` token fails its integrity check against a key that never encrypted it, and nothing short of re-entering every vendor credential by hand gets them back. `scripts/backup.sh` now captures the key as its own component, and the preflight below refuses an upgrade on a deployment that has nothing to capture.
4. **Confirm a maintenance window** for the API service. Migrations run inside a single transaction where possible; minor releases typically take seconds, major releases can take minutes on large `audit_log` tables.
5. **Stage first.** If you operate a non-production tenant on the same code as production, upgrade it first and let it run for a day before promoting.

## In-place upgrade procedure

The supported upgrade path is "stop, pull, migrate, start", and on a Compose
deployment it is one command:

```bash
cd /opt/aisoc                 # your install path
git fetch --tags
git checkout v22.2.0          # the target tag — see VERSION for the current one
make upgrade
```

Rolling upgrades across multiple API replicas are safe within a minor release;
cross-major rolling upgrades are not supported because the running code may not
understand the migrated schema.

### What `make upgrade` does, in order

Each step is there because of something that went wrong without it, so it is
worth knowing what you are consenting to:

1. **Preflight** ([`scripts/preflight_upgrade.py`](https://github.com/beenuar/AiSOC/blob/main/scripts/preflight_upgrade.py)) refuses an upgrade a restore could not undo. Four conditions, each a hard stop: `.env` is absent; `AISOC_CREDENTIAL_KEY` is unset or empty; it is set but is not a readable Fernet key; or there is no non-empty backup from the last 24 hours. The first is the one that bites quietly — `scripts/ensure_env.py` is careful never to overwrite a secret that already has a value, but when `.env` is *missing* it copies the example and mints a **brand-new** Fernet key, which orphans every stored credential in one step. That is why the preflight runs before anything that could call it, and why `make upgrade` does not depend on the `env` target.
2. **A pre-upgrade dump** to `backups/pre-upgrade-<timestamp>.sql.gz`, taken with the stack still on the old code. A `pg_dump | gzip` into a full disk exits 0 and leaves a file, so the preflight runs a second time afterwards with its backup arm enabled, and an empty dump is refused rather than reported as a backup. This is a local artefact for *this* operation and is a different thing from `scripts/backup.sh`, which is the off-host disaster-recovery path for all seven components.
3. **Image pull** for the target tag.
4. **Migrations**, with `AISOC_MIGRATIONS_STRICT=1` set **inside the container**. This is the point of the step: without it `run_migrations.main()` logs each failure, rolls that statement back, continues, and returns normally — exit 0 with a partially-applied schema, which is worse than a clean failure because the upgrade then reports success and starts the stack. Setting the variable in your own shell does not reach the container, which is why the warning this document used to carry was unreachable through the command it was attached to.
5. **Start**, then wait for health.

The dump stays under `./backups/`. Keep it until you have confirmed the new
release behaves.

### `make up` will not migrate for you

`make up` reads the database before it starts anything else and **refuses to
start when the schema is behind the code**, naming `make upgrade` and listing
what is pending. Starting anyway and printing a warning would leave a running,
healthy-looking, subtly broken stack — every probe green, the first symptom a
request failing on a column that does not exist.

Three states it cannot fire on, which is what makes refusing safe: a first run
(an empty data directory applies the whole chain as it is created), a restart
with no code change, and `make up-dev`, where the API applies the chain at boot.

A database it cannot read is reported as **`unknown`** and never folded into
"fine". The two commands then make opposite calls on that same signal,
deliberately: `make up` warns and continues, because it is how you get to a
position where you can diagnose anything at all; `make upgrade` stops, because
there you are about to write DDL.

### From source, without `make`

```bash
git fetch --tags && git checkout v22.2.0
pnpm install --frozen-lockfile
(cd services/api && uv sync)

# Migrate. Strict mode is unconditional and is passed into the container with
# `-e`; there is nothing to export and no --no-strict to opt out with.
aisoc db upgrade

docker compose -f docker-compose.yml -f infra/compose/docker-compose.dev.yml up -d api
curl -fsS http://localhost:8000/readyz
```

`aisoc db upgrade` runs `docker compose exec <service> python -m
app.scripts.run_migrations`, so it needs the stack already up. Exporting
`AISOC_MIGRATIONS_STRICT` in your own shell before running it does **nothing** —
`docker compose exec` hands the new process the *container's* environment, which
is precisely why the warning this page used to carry never reached the runner.
The CLI sets it for you.

Running the runner directly, outside Compose, is the one place your own
environment is the container's:

```bash
cd services/api
AISOC_MIGRATIONS_STRICT=1 \
  DATABASE_MIGRATION_URL=postgresql+asyncpg://<owner>@<host>/aisoc \
  uv run python -m app.scripts.run_migrations
```

`DATABASE_MIGRATION_URL` must name the **owning** role; it falls back to
`DATABASE_URL`, which points at `aisoc_app` and holds DML only, so a migration
that creates or alters a table fails there.

Take the database dump yourself first. Nothing in this path does it for you.

### Kubernetes

The chart ships
[`templates/migrations-job.yaml`](https://github.com/beenuar/AiSOC/blob/main/infra/helm/aisoc/templates/migrations-job.yaml),
a `pre-install,pre-upgrade` hook that applies the chain before the Deployment is
patched:

```bash
helm upgrade aisoc infra/helm/aisoc --set runMigrations=true
```

It is **off by default**: a schema change is the one operation with no undo, so
the flag is your consent, the same role `make upgrade` plays on the Compose
side. The Job sets `AISOC_MIGRATIONS_STRICT=1`, so a failed migration fails the
hook and aborts the upgrade with the old pods still serving the schema they
match. It reads the same Secret and ConfigMap the API Deployment does, so the
Job cannot end up connecting somewhere other than where the application will.

A hook runs once, before the patch. An init container would run once per pod —
two concurrent migration runs racing on every rollout, restart and reschedule
with `replicaCount: 2`, and a schema change on a node drain, which is not a
moment anyone consented to. Details in [Kubernetes](../deployment/kubernetes.md).

## Verifying the upgrade

After a successful upgrade you should be able to:

- Hit `/livez` and `/readyz` on the API and get `200 OK`, with nothing detached or erroring in the `/readyz` body. Note the paths: the API service serves `/health`, `/livez` and `/readyz` — **not** `/healthz`, which this page used to tell you to curl. `curl -fsS .../healthz` fails on a perfectly healthy deployment, because `-f` turns the 404 into a non-zero exit (measured: exit 22). `/healthz` is real on `services/realtime`, `services/mcp` and `services/osquery-tls` — and on Qdrant — which is where the confusion came from. [Docker deployment](../deployment/docker.md#health-checks) has the full path-to-service map.
- Run `make smoke` and watch one real event go through ingest, fusion and triage and come out as an alert. That exercises the path an upgrade is most likely to have broken; a health probe does not.
- Open the analyst console and see the version in the sidebar footer match the new tag.
- Re-run `make up`. It should start without a schema complaint, which is the signal that every migration on disk is recorded as applied.

### `GET /api/v1/system/version`

This page used to tell operators to check this route while no such route
existed, so the documented way to confirm an upgrade answered 404. It is
real now, and the shape below is read off a running instance rather than
guessed.

It requires the **`settings:read`** permission — held by `admin`,
`platform_admin` and `tenant_admin`, and by no analyst role — so send a
bearer token for one of those:

```bash
curl -fsS -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/v1/system/version
```

A real response, taken from a v22.2.0 checkout against a Postgres with every
migration applied:

```json
{
  "version": "22.2.0",
  "revision": null,
  "environment": "development",
  "schema_migrations": {
    "state": "current",
    "detail": "All 157 migration(s) on disk are applied.",
    "migrations_on_disk": 157,
    "migrations_applied": 157,
    "latest_applied": "160_alert_reopen_on_recurrence.sql",
    "pending": [],
    "applied_not_on_disk": []
  }
}
```

`revision` is `null` there because a source checkout is not a stamped image;
a published image reports the commit it was built from. The two other fields
echo that deployment's configuration.

Four things to read, and the last is the one worth the request:

- **`version`** — the running release. The same value `/health` reports and
  the same one published as `info.version` in the OpenAPI document; they are
  one field, so they cannot disagree. It is the literal string `"unknown"`
  when neither the build arg nor a `VERSION` file in the tree declared one,
  never a placeholder number. See
  [Environment Variables](../deployment/env-vars.md#how-the-version-resolves).
- **`revision`** — the commit the image was built from, stamped from the
  `AISOC_REVISION` build arg, or `null` when the build was not stamped.
  There is deliberately no fallback to `git rev-parse`: a source checkout's
  working tree is not the commit an image was built from.
- **`environment`** — the deployment's configured environment name.
- **`schema_migrations`** — whether the database matches the code you just
  started. `state` is one of three values and **`unknown` is never a pass**:

  | `state` | Meaning | What to do |
  |---|---|---|
  | `current` | Every migration this build ships is applied. | Nothing. |
  | `skewed` | The two disagree. `pending` names migrations on disk and not applied — new code against an old schema, the dangerous direction. `applied_not_on_disk` names the reverse, which is what a rolled-back deploy looks like. | Run `make upgrade`, or the Helm migration Job. |
  | `unknown` | The comparison could not be made: no database reachable, no `aisoc_schema_migrations` table, or a query that failed. `detail` says which. | Fix the reason before trusting any other answer on this page. |

  `latest_applied` is the applied-migration high-water mark — the last
  applied migration in apply order, which is the value to compare against a
  release's migration list. `migrations_on_disk` and `migrations_applied`
  are the two counts behind the verdict; the second is `null` when the
  database could not be read.

  :::note The count and the highest number are not the same thing
  In the response above, 157 migrations on disk have a high-water mark of
  `160_…`. That is not a gap in the applied set. Migrations are tracked and
  compared **by filename**, never by a parsed number, because duplicate
  numeric prefixes are a real occurrence in this repository — thirteen
  pre-existing collisions are deliberately frozen, since renaming an applied
  migration would make it pending again everywhere it had already run.
  Comparing on the number would fold two distinct migrations into one and
  call a database that is missing one of them current.
  :::

The route answers **200 even when the database is unreachable** — pointed at
a dead port it still reports the version, with:

```json
"schema_migrations": {
  "state": "unknown",
  "detail": "Applied migrations could not be read (ConnectionRefusedError); 157 migration(s) on disk were not compared.",
  "migrations_applied": null,
  "latest_applied": null
}
```

That is deliberate: a build identifier is most needed exactly when something
is broken, and refusing to answer would withhold the diagnosis along with
the fault. Note that `migrations_applied` is `null` rather than `0` — a
database that answered and has applied nothing is real, actionable skew, and
a database that could not be asked is not the same fact.

A skewed schema is likewise reported rather than refused. It also surfaces
on `/readyz`, registered as a **non-required** dependency on purpose: failing
readiness would pull the console out of the load balancer, and losing your
console mid-incident because a migration is behind is worse than the skew.
`/readyz` answers `ready_degraded` with the detail and the orchestrator keeps
routing.

If any of those fail, see [Troubleshooting](./troubleshooting). Note what rollback does and does not mean here: `services/api` uses a **forward-only** SQL migration runner (`services/api/app/scripts/run_migrations.py`), not Alembic — there is no `alembic.ini`, no `alembic/` directory, and no downgrade concept. The only services with Alembic are `ueba`, `honeytokens`, `purple-team` and `osquery-tls`. Reverting the **code** to the previous tag is supported; reverting the **schema** is not, so a rollback that needs the old schema means restoring the snapshot taken in step 2 of the pre-upgrade checklist.

## Rolling back

Patch and minor releases are designed to roll back cleanly. The procedure mirrors the upgrade:

```bash
git checkout v22.1.0          # the previous tag
pnpm install --frozen-lockfile
(cd services/api && uv sync)
# No schema downgrade step: the API migration runner is forward-only.
# Additive migrations (the common case) are backward compatible, so the previous
# code runs against the newer schema. If a migration was destructive, restore the
# snapshot instead — the CHANGELOG flags those as irreversible.
docker compose -f docker-compose.yml -f infra/compose/docker-compose.dev.yml up -d api
```

Major releases occasionally ship one-way migrations (e.g. column drops). When that's the case, the CHANGELOG flags the migration as "irreversible" and the only rollback is restoring from the database snapshot you took in step 2 of the pre-upgrade checklist.

:::warning The pre-upgrade dump is a restore path, not a downgrade
`make upgrade` writing `backups/pre-upgrade-<timestamp>.sql.gz` does not make
the schema reversible, and nothing in this release changed that. There is still
no downgrade: putting that dump back means **replacing the database with its
pre-upgrade state** and losing everything written since, which is a different
and much more expensive operation than checking out the previous tag. Reverting
the code is supported; reverting the schema is not. The dump exists so that the
irreversible case has *an* answer, not a cheap one.
:::

## Upgrading across a major

Every major below changes behaviour rather than only schema, so read the row
for each one you are crossing. The authoritative list of what breaks is the
`### BREAKING` section of [`CHANGELOG.md`](https://github.com/beenuar/AiSOC/blob/main/CHANGELOG.md);
this table says what an operator has to **do**.

| From, to | What changes | What you do |
|---|---|---|
| any, **v10.0.0** | Services stop connecting to Postgres as a superuser, so the 92 row-level security policies begin to apply. The four services running their own alembic chain migrate as the owner, not as the app role. | Run the migrations with `DATABASE_MIGRATION_URL` set to the owning role. A service that still connects as a superuser bypasses every policy, so check the role before and after. |
| v10, **v11.0.0** | `POST /v1/ingest` and `/v1/ingest/batch` require a credential. CORE needs **8 GB of memory and 20 GB of disk**, up from about 6.5 GB. | Mint an ingest token and set it on every producer before upgrading, or ingestion stops. Check the host has the headroom first. |
| v11, **v12.0.0** | The actions service returns 503 on every mutating route, and the realtime edge rejects every connection, until their required secrets are set. | Set them before you start the stack. Both failures are deliberate and loud. |
| v12, **v13.0.0** | 75 state-changing routes require a permission they did not require before, and several move to `settings:write`, which `soc_analyst`, `soc_lead` and `threat_hunter` do not hold. | Expect HTTP 403 where operators previously got 200. Review who needs `settings:write` before upgrading, not after. |
| v13, **v14.0.0** | No route will confer a role, scope or organisation membership beyond the caller's own authority, and `platform_admin` and `admin` are unreachable from every API route. | The only way to mint a wildcard role is `python -m app.scripts.bootstrap_admin` against the database. Any automation that created one through the API stops working. |
| v14, **v15.0.0** | `/api/v1/shifts` is removed and `/api/v1/threatintel/stix/*` reads answer 404 outside demo mode. `make up` starts a production-class stack and `AISOC_DEV_MODE` no longer defaults to on. | Delete any caller of those routes; neither served data anyone entered. Set `ENVIRONMENT=development` explicitly if you were relying on the dev auth bypass, and expect previously silent warnings to become boot refusals. |
| v15.0.0, **v15.1.0** | Nothing breaks — two routes are added and none removed. Two behaviours change noticeably all the same: **CloudTrail deployments will see more alerts**, because every event previously collapsed onto a single one; and alert-triggered playbooks now actually run, where `find_matching()` had no production caller before. | No action required to upgrade. Expect the CloudTrail alert volume you should have been getting all along, and review which playbooks are enabled before upgrading, since a playbook that never fired will now fire — in preview by default, with three opt-ins needed before it can act. |
| v15.1.0, **v16.0.0** | **The `cases` table is gone.** Migration 083 moves its rows into `aisoc_cases`, repoints the child foreign keys, and renames the old table to `cases_pre_consolidation` so nothing is lost. The two tables never synchronised: the console wrote one and every case metric read the other, so MTTR and the case counts were blind to every case an analyst created. Separately, SAML and OIDC sign-in now works — it returned 403 on every deployment because the connection table had no writer. | **Check your own SQL.** Anything querying `cases` — a Grafana panel, a scheduled export, a report — must read `aisoc_cases`. It will fail loudly with "relation does not exist" rather than returning stale rows, which is deliberate. The archive table is readable if you need to compare. Expect case metrics to change the moment you upgrade: they were under-reporting, not over-reporting. If you use SSO, create a connection at `POST /api/v1/sso-connections` before pointing users at it. |
| v16.0.0, **v16.0.1** | **Nothing breaks.** A security release closing a high-severity privilege escalation (GHSA-4gx4-x7gm-4xq8): the check deciding whether a caller may *confer* authority read the caller's static role, while the check admitting it to the route read its database-resolved permissions. Where a tenant uses the `roles` and `user_roles` tables to narrow an account, those are different answers, and the narrowed account could grant itself anything its unnarrowed role carried. | **Upgrade if you restrict accounts through database-backed RBAC.** A deployment with no RBAC rows was never exposed — the static map was already the correct answer for it. After upgrading, a grant is refused when it exceeds what the caller actually holds, so an operator who had been relying on the wider static role to assign roles will now get HTTP 403; grant that operator the permissions through RBAC rather than widening its static role. |
| v16.0.1, **v17.0.0** | **Three routes are removed**: `POST /detection-loop/suggest` and the two `GET /detection-loop/suggestions` reads, with their three schemas. No migration is needed because none of them ever worked — they queried `aisoc_alerts`, `aisoc_detection_rules` and `alerts.evidence`, none of which any migration creates, so every caller was already receiving an error. The governed equivalent is `POST /api/v1/detection-proposals`. **One number changes meaning without erroring, which is the one to read twice:** `alerts.total` on `/api/v1/metrics/dashboard` now counts *open* work — `new`, `triaging`, `in_progress` — rather than every alert ever received, and the severity counts beside it are scoped the same way. A panel charting cumulative intake from that field will drop to the size of your queue. Closed work is reported separately as `alerts.resolved`. Migration `090` adds three nullable columns to `aisoc_cases`; it is additive and runs automatically. |
| v17, **v18.0.0** | **Three tables that had no reader now change authorization outcomes, in both directions.** Migration `087_enterprise_iam.sql` created `permission_conditions`, `privilege_grants` and `workload_identities` and shipped no reader for any of them; they now have readers. A row in `permission_conditions` **denies** where it was inert — a condition restricting `cases:write` to a CIDR the caller is not in used to return 201 Created and now returns 403. An approved row in `privilege_grants` **confers** where it was inert — a live grant of `roles:read` to a `viewer` used to return 403 and now returns 200 until `expires_at` passes; a row with `approved_by_id` NULL still confers nothing. `CurrentUser.effective_permissions()` now includes live elevation, so `services/actions` stops refusing an elevated analyst it had allowed elsewhere. A new credential type also authenticates: secrets prefixed `aisoc_wl_` resolve against `workload_identities`. | **Read those three tables before you upgrade.** If anything ever wrote rows into them directly — a migration of your own, a seeding script, an experiment — those rows were doing nothing and will start taking effect the moment you restart. Expect new 403s from `permission_conditions` and new 200s from approved `privilege_grants`. The shared `AISOC_SERVICE_TOKEN` path is unchanged and keeps working; `aisoc_wl_` sits beside it rather than replacing it, and the tenant header is mandatory and verified on both paths. |
| v18, **v19.0.0** | **`PATCH /api/v1/alerts/{id}` now refuses a field it cannot apply.** The request model set no `extra=`, so pydantic's default dropped anything outside `status`, `priority`, `tags`, `assignee` and `case_id` and still answered **200** with the unchanged row — a success response for a write that did not happen. The dropped fields were not nonsense: `disposition`, `severity`, `confidence` and `snoozed_until` are all real `alerts` columns, which is why callers sent them. The route now answers **422**, naming the field *and* the route that does apply it. The published spec gains `additionalProperties: false` on `AlertUpdateRequest`. | **Find every caller of that PATCH and check what it sends.** A caller that had been closing an alert with a disposition was getting a 200 and no disposition; it now gets a 422 and still no disposition, so the upgrade surfaces a bug it did not cause. Move those fields to the routes that own them: `POST /feedback/alert-override` for a disposition, `POST /alerts/{id}/escalate` for severity, `POST /alerts/{id}/snooze` for a snooze. The accepted surface is otherwise unchanged, including the `assignee` alias. |
| v19, **v20.0.0** | **`POST /api/v1/cases/{case_id}/comments` no longer accepts `is_system`** (GHSA-9mc5-hqgh-j6wf). The field let any `cases:write` holder author rows the case summary renders as an unattributed "System note", so a post-mortem dropped from the analyst record; it could not be preserved, because system notes are written by the server. | **Little to do, and check your generated SDKs.** A client that still sends the field is *ignored* rather than refused, so existing requests keep succeeding — only the generated SDK request types lose the property, which is a compile error in a typed client and nothing at runtime. If any automation relied on authoring system notes, it has been silently producing unattributable ones; move it to a normal comment. |
| v20, **v21.0.0** | **Correlation grouping narrows on missing identifiers.** Future alerts carrying no tactic group **per rule** instead of per entity, and alerts with no identifiers at all stop cross-rule merging entirely. There is no API change in this release. The major also marks a redefinition of published evaluation semantics — serving-model provenance, full-cohort denominators, closure contamination — that older scorecards do not carry. | **Expect more, smaller incidents, and do not read that as a regression.** Existing incidents are untouched; only new ones group differently. On a detection-shaped cohort the measured effect is alert reduction moving **42.6% to 24.5%**, because unrelated alerts stop being counted as grouped — the old figure was the flattering one. If you chart reduction or incident count, annotate the upgrade on those panels, and do not compare a scorecard produced before this release against one produced after. |
| v21, **v22.0.0** | **`GET /posture/summary` returns `null` rather than `0` for every count when nothing has collected.** All eight integer fields on `PostureSummary` — `total`, `critical`, `high`, `medium`, `low`, `open`, `resolved`, `suppressed` — become nullable, which changes the generated SDK types from `int` to `int \| None`. The old type *was* the defect: `posture_findings` had no production writer, so the endpoint counted an empty table and answered `total: 0, critical: 0` on every deployment, which reads as "your cloud estate is clean" about an estate nobody has looked at. No integer can carry that distinction. | **Read `collected` first in every client.** When it is false the counts are absent and the correct render is "not scanned", not a zero. Anything that unpacks those eight fields as integers — a dashboard, an export, a typed SDK call — needs the null case handled before you upgrade, or it will fail on a deployment that has never run a posture collection, which is most of them. |

Upgrading more than one major at a time is supported, and is now tested at one
boundary rather than none. Prefer one major at a time, running migrations
between each, so that a failure names the version that caused it.

### What upgrade testing actually covers

Be precise about this, because "there is an upgrade test" and "your upgrade is
tested" are different sentences.
[`.github/workflows/upgrade-test.yml`](https://github.com/beenuar/AiSOC/blob/main/.github/workflows/upgrade-test.yml)
runs on every pull request and every push to `main`, with no path filter, and
it carries data through the upgrade rather than migrating an empty schema —
which is the only case that can fail.

| Leg | Starting point | Required check? |
|---|---|---|
| **Previous minor to this tree, with data present** | the previous release | **Yes.** It is in [`.github/required-checks.json`](https://github.com/beenuar/AiSOC/blob/main/.github/required-checks.json), so a pull request cannot break it and merge. |
| **Cross-major upgrade (v21.0.0 → this tree)** | `v21.0.0`, one major back | No. |
| **Cross-major upgrade (v17.0.0 → this tree)** | `v17.0.0`, five majors in one step | No. |

Both cross-major legs build the starting schema with **that release's own**
migration runner, out of its published image, then seed real tables and assert
the rows survive. They are not required deliberately, and for a reason worth
repeating: a matrix job's context name contains the matrix value, so requiring
them would mean that adding or renaming a starting version orphans a required
context that can never report — a check that blocks the queue forever while
testing nothing.

So: **v21 → current and v17 → current are exercised. v18, v19, v20 and v22
boundaries are not.** The rows above are written from each release's CHANGELOG,
not from a test that crossed it.

## Version skew

Within a given major version, the following components are guaranteed to be wire-compatible across one minor version of skew:

- Browser ↔ API service
- API service ↔ Connectors
- API service ↔ Agents
- SDK clients (Go, Python, TypeScript) ↔ API

That means you can upgrade the API service to `22.2.0` while connectors are still on `22.1.x`, finish their rollout over the day, and not break anything. Across a major version (`21.x` ↔ `22.x`) the contract resets — upgrade the API first, then everything else, on the same maintenance window.

## Recovering lost Grafana dashboards

If you ran the `monitoring` profile before this was fixed and a `docker compose
pull && up -d` took your Grafana dashboards with it: **they are gone, and they
cannot be recovered.** Grafana's `/var/lib/grafana` had no volume behind it, so
dashboards you built in the UI, your users, your annotations and any alert rules
created in the browser lived only in the container's writable layer, which a
recreate discards. There is no copy anywhere — not in the image, not in a
backup, not on the host. Nothing was exported, so there is nothing to import.

The loss was also silent, which is why this needs saying out loud: Grafana comes
back with its *provisioned* dashboards intact and looking healthy, and nothing
on the screen indicates that the rest ever existed.

Three named volumes — `grafana_data`, `prometheus_data` and `alertmanager_data`
— now sit behind those paths, so the next recreate keeps them. Plugin state has
the same treatment, under `aisoc_plugins` and `aisoc_plugin_keys`: the plugin
directory and the Ed25519 public keys that make signed third-party plugins
loadable at all were in the writable layer too, so an image pull used to turn
every signed plugin into a refusal.

Rebuild once, then take the dashboards out of Grafana's database entirely:

```bash
# In Grafana: Dashboard → Share → Export → Save to file (one JSON per dashboard).
cp ~/Downloads/my-dashboard.json infra/docker/grafana/dashboards/
git add infra/docker/grafana/dashboards/my-dashboard.json && git commit
```

[`infra/docker/grafana/`](https://github.com/beenuar/AiSOC/tree/main/infra/docker/grafana)
is mounted read-only at `/etc/grafana/provisioning`, so a dashboard committed
there is reloaded from the file every 30 seconds and the next recreate is a
non-event. It is also reviewable in a diff, which a dashboard living in a
database is not.

One surprise to know about first: the provider sets `allowUiUpdates: false`, so
once a dashboard is provisioned, editing it in the browser is **silently
reverted** on the next reload. That is the correct behaviour — the file is the
source of truth — but it means the edit-in-UI workflow stops working for
provisioned dashboards. Export, commit, reload.

## Long-Term Support

AiSOC does not currently offer formal LTS releases, and the support window is
narrower than this page used to claim. The policy of record is
[`SECURITY.md`](https://github.com/beenuar/AiSOC/blob/main/SECURITY.md): the
**latest tagged release** receives critical fixes for 90 days after it ships,
and **older tagged releases are best-effort only**. There is no guaranteed
backport to the previous major; this page previously promised one, which
`SECURITY.md` has never offered. Plan your upgrade on the assumption that
staying a major behind means best-effort security coverage.

If your environment requires a longer support window, raise it in [Discussions](https://github.com/beenuar/AiSOC/discussions) — we're happy to discuss commercial support arrangements with the community.

## Pre-1.0 history

Versions `1.0.0` through `5.x` shipped during the original feature build-out and are documented in the [CHANGELOG](https://github.com/beenuar/AiSOC/blob/main/CHANGELOG.md). The `6.0.0` release in May 2026 was the first version we consider production-ready; new deployments should start from the latest tagged release — read [`VERSION`](https://github.com/beenuar/AiSOC/blob/main/VERSION) on `main` rather than any number written into a document, including this one.
