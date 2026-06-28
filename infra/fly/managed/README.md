# AiSOC Managed-Mode Deployment (Fly.io)

> **Phase 4.2 / T6.1 completion** — the paved-path provisioning surface for
> single-tenant AiSOC stacks on Fly.io. Each customer gets a dedicated set of
> Fly apps + a managed Postgres cluster; isolation lives at the infra layer,
> not just at the application's row-level-security boundary.

This directory is parallel to `infra/fly/` (which hosts the public demo at
`tryaisoc.com`). The managed-mode pattern uses the **same images and the same
fly.toml shape** as the demo — the difference is that every Fly app name and
hostname is parameterised on a per-customer slug, so we can run N customers
in the same Fly org without colliding.

## Why a separate `infra/fly/managed/` directory

The Terraform stack in `infra/terraform/environments/managed/` already
provisions long-lived infrastructure (Fly app shell, managed Postgres,
Cloudflare CNAME) but it is intentionally **not** a per-deploy workflow — it
runs once at tenant-onboarding time and is then left alone. This directory
ships the day-2 surface:

* The **per-app `fly.toml.tpl` templates** under `template/` get rendered into
  a customer-specific config every deploy.
* **`provision.sh`** is the one-shot tenant bootstrap (Fly apps + Postgres +
  Redis + secrets + first deploy + DNS cert).
* **`deprovision.sh`** is the symmetric tear-down.
* **`render.sh`** is the pure template renderer (used by both the
  provisioner and the auto-provision CI workflow).
* **`.github/workflows/managed-auto-provision.yml`** turns the
  `tenants/*.yaml` manifest set into the source of truth for which managed
  tenants exist. A new manifest landing on `main` triggers `provision.sh`
  automatically. A deleted manifest triggers `deprovision.sh`.

## Tenant manifests

A managed tenant is declared by adding a YAML file at
`infra/fly/managed/tenants/{slug}.yaml`:

```yaml
slug: acme              # required, [a-z0-9-]{2,32} — drives Fly app names
display_name: ACME Inc  # required — operator-facing name
plan: standard          # required, one of: starter | standard | enterprise
region: iad             # primary Fly region (e.g. iad, lhr, syd, sjc)
base_domain: aisoc.acme.com   # required — public hostname root for this tenant
contact_email: ops@acme.com    # required — used by Fly for cert renewal notices

# Optional knobs the templates honour:
api_vm_size: shared-cpu-1x          # default: shared-cpu-1x
agents_vm_size: shared-cpu-2x       # default: shared-cpu-2x
postgres_plan: development          # default: development; use ha for prod
realtime_min_machines: 1            # default: 1 (WS needs warmth)
```

The fly app names follow the pattern `aisoc-{slug}-{component}`:

| Component | Fly app                    | Hostname (after DNS)          |
|-----------|----------------------------|--------------------------------|
| API       | `aisoc-{slug}-api`         | `api.{base_domain}`            |
| Web       | `aisoc-{slug}-web`         | `{base_domain}`                |
| Realtime  | `aisoc-{slug}-realtime`    | `ws.{base_domain}`             |
| Agents    | `aisoc-{slug}-agents`      | (internal 6PN only)            |
| Postgres  | `aisoc-{slug}-postgres`    | (internal 6PN only)            |
| Redis     | `aisoc-{slug}-redis`       | (internal 6PN only)            |

## Manual provisioning

```bash
export FLY_API_TOKEN=fo1_xxx
export FLY_ORG=aisoc-managed
./infra/fly/managed/provision.sh infra/fly/managed/tenants/acme.yaml
```

The script is idempotent — re-running it against an already-provisioned slug
will:

1. Detect existing Fly apps and skip the `apps create` step.
2. Re-render the templates against the latest manifest and run
   `flyctl deploy` so config drift is reconciled.
3. Re-issue any missing certs.

A failed run can be safely re-attempted; nothing in `provision.sh` is
destructive.

## Auto-provision-from-main pipeline

`.github/workflows/managed-auto-provision.yml` watches for changes to
`infra/fly/managed/tenants/*.yaml` on every push to `main`:

* New or modified manifest → run `provision.sh` against that manifest.
* Deleted manifest → run `deprovision.sh` against the slug.

The workflow requires the `FLY_API_TOKEN` repo secret. Per-tenant secrets
(LLM keys, Slack webhooks, etc.) are not stored in the manifest — they're
declared at the secret-store layer and the workflow only sets the Fly
secrets it can derive from manifest knobs.

See [`docs/managed-mode.md`](../../../docs/managed-mode.md) for the customer-
visible signup -> manifest-merge -> live-stack flow.

## Operator surface

```bash
# Show every managed tenant + its rollout status
./infra/fly/managed/list.sh

# Tail logs for a single tenant
flyctl logs -a aisoc-acme-api

# Run an out-of-band SQL migration on one tenant
flyctl ssh console -a aisoc-acme-api -C "python -m app.scripts.run_migrations"

# Tear it down (destroys apps + Postgres + Redis + DNS records)
./infra/fly/managed/deprovision.sh acme
```

## Cost envelope (per managed tenant)

| Resource                              | Plan tier        | Monthly cost (est.) |
|---------------------------------------|------------------|---------------------|
| API + Web + Realtime (3× shared-cpu-1x)| starter / standard | ~$6                 |
| Agents (shared-cpu-2x)                | all              | ~$5                 |
| Fly Postgres                          | development      | ~$2                 |
| Fly Postgres                          | ha               | ~$30                |
| Outbound bandwidth (~50GB)            | all              | ~$1                 |
| **Total (starter / standard)**        |                  | **~$14/mo**          |
| **Total (enterprise w/ HA)**          |                  | **~$42/mo**          |
