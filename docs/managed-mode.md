# Managed Mode

> Phase 4.2 — the customer-visible side of the auto-provision-from-`main`
> pipeline. The infra-facing reference lives at
> [`infra/fly/managed/README.md`](../infra/fly/managed/README.md); this page
> describes what happens between **"customer signs"** and **"customer's
> on-call team can log in"**.

AiSOC ships in three deployment shapes today:

| Shape       | Where the workload runs                                       | Who owns the bits                |
|-------------|----------------------------------------------------------------|----------------------------------|
| Demo        | `tryaisoc.com` (single shared Fly stack)                       | AiSOC team                       |
| **Managed** | Per-customer Fly stack auto-provisioned from `infra/fly/managed/tenants/{slug}.yaml` | AiSOC team |
| Sovereign   | Customer cloud account (`infra/terraform/{aws,azure,gcp,byoc}/`) | Customer                       |

This document covers managed mode.

## The signup → live-stack pipeline

```
┌───────────────┐  1   ┌─────────────────────┐  2  ┌──────────────────────────┐
│ Sales / CSM   ├─────►│ Merged PR adds       ├────►│ GitHub Actions workflow │
│ closes deal   │      │ tenants/{slug}.yaml  │     │ managed-auto-provision  │
└───────────────┘      └─────────────────────┘     └────────┬─────────────────┘
                                                            │ 3
                                                            ▼
                                          ┌─────────────────────────────────┐
                                          │ flyctl apps create + postgres   │
                                          │ + redis + secrets + deploy +    │
                                          │ certs (idempotent)              │
                                          └─────────────────────────────────┘
                                                            │ 4
                                                            ▼
                                          ┌─────────────────────────────────┐
                                          │ Live at:                        │
                                          │   {base_domain}      (web)      │
                                          │   api.{base_domain}  (api)      │
                                          │   ws.{base_domain}   (realtime) │
                                          └─────────────────────────────────┘
```

1. **CSM creates a PR.** The only artifact is a new file at
   `infra/fly/managed/tenants/{slug}.yaml`. CSM gets a CI signal on the
   PR (manifest-shape audit) so misspelt slugs / bad domains / missing
   fields fail fast — see `scripts/audit_managed_tenants.py`.
2. **Merge to `main` triggers the workflow.** The
   `managed-auto-provision.yml` workflow detects the new manifest in the
   merge commit's diff and runs
   `./infra/fly/managed/provision.sh tenants/{slug}.yaml`.
3. **provision.sh runs.** This is a single shell script that talks to
   the Fly API in the order documented in
   `infra/fly/managed/provision.sh` (apps → Postgres → Redis → shared
   secrets → deploy → certs). Every step is idempotent so a partial
   failure can be retried by re-running the workflow.
4. **CSM points DNS.** Three CNAMEs to `*.fly.dev` apex targets; the
   workflow prints them at the end so the CSM can paste them into the
   customer's DNS console.

A new managed tenant is therefore exactly:

```diff
+ # infra/fly/managed/tenants/acme.yaml
+ slug: acme
+ display_name: ACME Inc
+ plan: standard
+ region: iad
+ base_domain: aisoc.acme.com
+ contact_email: ops@acme.com
```

If we ever need to walk a deal back, deleting that file in a follow-up
PR (with the `AISOC_ALLOW_DEPROVISION` repo var set to `1`) tears the
whole stack down.

## What "isolation" means in managed mode

Managed mode runs **one Fly app set per customer**. The implications:

* **Postgres** is dedicated — no row-level-security shared cluster.
* **Redis** is dedicated.
* **Network plane** is dedicated — agents only ever reach the API over
  Fly's 6PN internal DNS (`aisoc-{slug}-api.internal:8000`), so an agent
  decision cannot leak out of one tenant's stack into another.
* **Secrets** live in `flyctl secrets` of that stack only. A compromised
  manager-side LLM key on tenant A cannot decrypt tenant B's connector
  credentials.
* The **Fernet key** (`AISOC_CREDENTIAL_KEY`) is minted at provision
  time and never rotated automatically; the operator runbook covers
  rotation as a customer-initiated request because every stored
  connector credential needs to be re-encrypted.

This is intentionally a stronger isolation contract than the
single-shared-cluster + RLS pattern.

## Operator runbook (managed-mode failures)

| Symptom                                       | First place to look                              | Runbook                                  |
|-----------------------------------------------|--------------------------------------------------|------------------------------------------|
| API 5xx                                       | `flyctl logs -a aisoc-{slug}-api`                | [http-5xx-high](./runbooks/http-5xx-high.md) |
| API latency spike                             | `flyctl status -a aisoc-{slug}-api`              | [http-latency-high](./runbooks/http-latency-high.md) |
| A component is hard-down                      | `flyctl status -a aisoc-{slug}-{component}`      | [service-down](./runbooks/service-down.md) |
| Action executors failing on a managed tenant  | `flyctl logs -a aisoc-{slug}-agents`             | [action-executor-failures](./runbooks/action-executor-failures.md) |
| Postgres / database problems for one slug     | `flyctl postgres connect -a aisoc-{slug}-postgres` | [database-incident](./runbooks/database-incident.md) |
| `provision.sh` half-failed during onboarding  | The workflow run log + Fly dashboard for the slug | [managed-provision-rerun](./runbooks/managed-provision-rerun.md) |

## What customer success cannot do alone

Because the auto-provision workflow needs the `FLY_API_TOKEN` repo
secret, only engineers can merge the manifest PR. CSM raises the PR; an
engineer reviews and merges. This is on purpose — provisioning a Fly
stack costs money and the merge is the explicit commit-to-spend gate.
