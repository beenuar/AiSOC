# AiSOC — Managed Instance Terraform

> **T6.1** — bootstrap stack for the `tryaisoc.com` managed offering.

This module provisions the single-tenant managed AiSOC deployment that
sits behind the public `/waitlist` signup flow:

- **Fly.io app** — runs `services/api`, `services/agents`, the
  `apps/web` console, and the realtime stream as one Fly application
  with multiple process groups.
- **Fly.io managed Postgres** — primary + standby by default, with PITR
  on the Fly side.
- **Fly.io managed Redis** — Upstash-backed; `var.redis_url_override`
  lets an operator point at an external Redis instead.
- **Cloudflare DNS** — a proxied `CNAME` record for `tryaisoc.com` (and
  optionally `realtime.tryaisoc.com`) pointing at the Fly app.

> **This is a skeleton.** It compiles a Terraform plan and represents
> the canonical resource set, but the Fly community provider
> (`fly-apps/fly`) is still pre-v1 and its resource shapes change
> between releases. Treat the version pin in `main.tf` as a starting
> point: validate it against your operator's environment, pin to a
> known-good release, and (optionally) tighten the resource arguments
> before any production `apply`.

---

## Prerequisites

Make sure each of the following is set up **before** running `terraform
init`:

| Requirement                          | How                                                        |
| ------------------------------------ | ---------------------------------------------------------- |
| Terraform ≥ 1.7                      | `brew install terraform` or [download][tf-dl]              |
| Fly.io org + auth token              | `fly orgs create aisoc` then `fly auth token`              |
| Cloudflare zone for `tryaisoc.com`   | Already exists; grab the **Zone ID** from the dashboard    |
| Cloudflare API token (`Zone.DNS.Edit`) | [Create token][cf-tokens] scoped to the `tryaisoc.com` zone |

[tf-dl]: https://developer.hashicorp.com/terraform/install
[cf-tokens]: https://dash.cloudflare.com/profile/api-tokens

---

## Bootstrap

### 1. Export the secrets

Never commit these. Use a secrets manager (1Password, Doppler, …) or your
shell's transient env:

```bash
export TF_VAR_fly_api_token=fo1_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
export TF_VAR_cloudflare_api_token=cf_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
export TF_VAR_cloudflare_zone_id=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

### 2. (Optional) Configure remote state

By default Terraform uses local state, which is fine for a one-laptop
operator setup. For any team-shared environment, uncomment the `backend`
block at the bottom of `main.tf` (either `s3` or `remote`) and populate
the bucket / workspace name **before the first `init`**.

### 3. Init, plan, apply

```bash
cd infra/terraform/environments/managed
terraform init
terraform plan -out=managed.tfplan
terraform apply managed.tfplan
```

A successful apply prints a `bootstrap_checklist` output telling you
what to run next. The TL;DR:

```bash
APP_NAME=$(terraform output -raw fly_app_name)
PG_APP_NAME=$(terraform output -raw postgres_app_name)

# 1. Attach Postgres
fly attach -a "$APP_NAME" "$PG_APP_NAME"

# 2. Set the Fernet key used by the credential vault
fly secrets set \
  AISOC_CREDENTIAL_KEY=$(python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())') \
  -a "$APP_NAME"

# 3. Set the Slack webhook used by /v1/waitlist/signup
fly secrets set AISOC_WAITLIST_SLACK_WEBHOOK="https://hooks.slack.com/services/…" -a "$APP_NAME"

# 4. Ship the actual application
fly deploy --app "$APP_NAME"

# 5. Smoke test
curl -sSf "$(terraform output -raw public_app_url)/health"
```

---

## Inputs

All variables live in `variables.tf`. The ones that **must** be supplied
(no usable default) are:

| Name                     | Source                                       |
| ------------------------ | -------------------------------------------- |
| `fly_api_token`          | `export TF_VAR_fly_api_token=…`              |
| `cloudflare_api_token`   | `export TF_VAR_cloudflare_api_token=…`       |
| `cloudflare_zone_id`     | `export TF_VAR_cloudflare_zone_id=…`         |

Everything else has a sensible default (Postgres sized for the beta
cohort, Redis on the free Upstash plan, `iad` region, `tryaisoc.com`
hostname). See `variables.tf` for the full list and per-variable
validation rules.

---

## Outputs

After `terraform apply` succeeds:

| Output                | What it is                                              |
| --------------------- | ------------------------------------------------------- |
| `fly_app_name`        | The actual Fly app name (prefix + random suffix)        |
| `fly_app_hostname`    | `<app>.fly.dev` — target of the Cloudflare CNAME        |
| `fly_app_ipv4` / `_ipv6` | Dedicated IPs attached to the app                    |
| `postgres_app_name`   | Fly app backing Postgres (used by `fly attach`)         |
| `redis_app_name`      | Fly Redis name, or `null` if `redis_url_override` set   |
| `redis_url`           | `sensitive` — the URL to pipe into `REDIS_URL`          |
| `public_app_url`      | `https://tryaisoc.com` (or whatever `app_hostname` is) |
| `cloudflare_record_id`| The Cloudflare DNS record id (useful for automation)    |
| `bootstrap_checklist` | Plain-text operator checklist                           |

---

## What this stack does NOT do

Out of scope, on purpose:

- **Application secrets** — The `AISOC_CREDENTIAL_KEY`, LLM provider
  keys (OpenAI, Anthropic, etc.), Slack webhook, and any other runtime
  secrets are set with `fly secrets` after `apply`. We deliberately do
  not roundtrip them through Terraform state.
- **Image build / deploy** — `fly deploy` is the operator's job; this
  stack only provisions the long-lived infrastructure that hosts the
  images.
- **Per-tenant resources** — The managed instance is single-app /
  multi-tenant. Tenant onboarding happens at the application layer via
  `POST /v1/admin/tenants/provision` (see
  `services/api/app/api/v1/endpoints/tenant_provision.py`), not in
  Terraform.
- **Backups / DR strategy** — Fly's managed Postgres has PITR; the
  operator should still wire periodic logical dumps (`pg_dump`) to an
  S3-compatible bucket. That belongs in a separate stack so it can be
  rotated independently.

---

## Teardown

```bash
terraform destroy
```

This removes the Fly app, the Postgres cluster, the Redis instance, and
the Cloudflare DNS records — but **does not** delete:

- Application secrets stored in `fly secrets`.
- Persistent volumes (Fly's `pg_destroy` workflow asks for confirmation).
- Backups taken outside this stack.

Run the corresponding `fly` CLI commands manually if you also need to
purge those.
