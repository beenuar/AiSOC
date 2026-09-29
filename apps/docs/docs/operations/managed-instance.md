---
sidebar_position: 13
title: Managed instance (tryaisoc.com)
description: How the AiSOC managed beta works — what's deployed, how a customer is onboarded, SLAs, and billing.
---

# Managed instance (`tryaisoc.com`)

AiSOC is open source and self-hostable, but for teams who want a SOC up
and running today — without owning the infrastructure — we run a
**managed beta** at [`tryaisoc.com`](https://tryaisoc.com). This page
documents how it works, who it's for, and the operational shape of the
offering.

> **Status: invite-only beta.** Capacity is rationed deliberately so we
> can keep response times tight and feedback loops short with each
> customer. To join the queue, submit the form at
> [`tryaisoc.com/waitlist`](https://tryaisoc.com/waitlist).

## At a glance

| Property | Value |
|---|---|
| **Hostname** | `tryaisoc.com` (TLS terminated at Cloudflare) |
| **Hosted on** | Fly.io (single app, multi-process) |
| **Database** | Fly managed Postgres — primary + standby, PITR enabled |
| **Cache / pubsub** | Fly managed Redis (Upstash-backed) |
| **Region** | `iad` (US-East) by default; bespoke regions available on request |
| **Tenancy model** | Multi-tenant; each customer is a row in `tenants` with row-level isolation |
| **Identity** | Email + magic-link invites; SSO available on the higher tiers |
| **Source of truth** | This repository (`apps/`, `services/`, `detections/`) |
| **Bootstrap stack** | [`infra/terraform/environments/managed/`](https://github.com/beenuar/AiSOC/tree/main/infra/terraform/environments/managed) |

## Why a managed offering at all

The same code runs in three places:

1. **Self-hosted** — `docker compose up`, fully air-gappable, you own the
   keys and the data. This is the canonical AiSOC deployment.
2. **BYOC** — Terraform stack in `infra/terraform/byoc/` provisions
   AiSOC into the customer's own AWS account.
3. **Managed (`tryaisoc.com`)** — same code, hosted by the AiSOC
   community on Fly.io. This is where the waitlist points.

The managed offering exists for one reason: **letting a team try a
real SOC before they own the operational burden**. Once they've
validated the workflow they can graduate to BYOC or self-hosted
without touching any code — the migration is a `pg_dump` and a
`fly secrets export`.

## Architecture

Each managed AiSOC deployment is a single Fly.io application with five
process groups defined in `fly.toml`:

| Process group | Source                  | Role                                                       |
| ------------- | ----------------------- | ---------------------------------------------------------- |
| `web`         | `apps/web`              | Next.js console                                            |
| `api`         | `services/api`          | FastAPI control plane (auth, RBAC, REST + GraphQL surface) |
| `agents`      | `services/agents`       | Investigator orchestrator (LangGraph)                      |
| `realtime`    | `services/realtime`     | WebSocket fan-out for live dashboards                      |
| `connectors`  | `services/connectors`   | Connector polling scheduler                                |

All five processes share the same Postgres + Redis. Tenant isolation is
enforced at the application layer (every query is scoped by
`tenant_id`) and at the database layer (`ROW LEVEL SECURITY` policies
on tenant-scoped tables, set by `app.current_tenant`).

The Cloudflare edge in front of Fly.io handles:

- TLS termination (managed certificate)
- DDoS protection
- The basic WAF ruleset (we explicitly do **not** block AI-agent
  traffic — many customers integrate via the SDK)

## How a customer is onboarded

End-to-end this is a five-step flow. Every step has an audit-log entry.

1. **Customer fills the waitlist form** at
   [`tryaisoc.com/waitlist`](https://tryaisoc.com/waitlist). The POST
   hits `/v1/waitlist/signup`, rate-limited per IP, and the entry lands
   in `aisoc_waitlist_entries` with status `new`.
2. **The waitlist Slack notification** fires to the sales channel via
   `AISOC_WAITLIST_SLACK_WEBHOOK`. The Slack message links straight to
   `/admin/waitlist` for triage.
3. **An operator reviews the entry** in
   [`/admin/waitlist`](https://tryaisoc.com/admin/waitlist) and
   transitions the status from `new` → `contacted` once they've reached
   out, then `contacted` → `onboarded` (or `declined`) once the
   conversation has closed.
4. **Promote to tenant.** The operator clicks "Promote to tenant" on
   the entry, which calls `POST /v1/admin/tenants/provision`. The
   provisioner (`services/api/app/services/tenant_provision/`):
   - Allocates a unique tenant slug derived from the company name.
   - Generates a fresh Fernet `aisoc_credential_key` for that tenant
     and stores the **fingerprint** in `tenants.settings`. The
     plaintext key is never persisted; the operator copies it into
     `fly secrets set` as part of the bootstrap.
   - Seeds the default RBAC roles, starter detections, and seed
     playbooks from
     `services/api/app/services/tenant_provision/templates.py`.
   - Seeds the demo investigations from `app/scripts/seed_demo.py`
     so the first login lands on a populated dashboard.
   - Creates an admin user record for the customer's primary contact
     and returns a magic-link invite URL.
5. **Customer signs in** via the invite link and is dropped on a
   pre-populated dashboard. From there they configure connectors,
   invite teammates, and start running real investigations.

The waitlist entry stays linked to the tenant (`tenants.provisioned_from_waitlist_id`)
so support can always trace a live tenant back to the original
conversation.

## What's *not* part of the managed offering

A few capabilities are intentionally **only** available in self-hosted
or BYOC deployments:

- **Bring-your-own LLM credentials with full per-call attribution.**
  The managed beta uses a shared LLM pool, so per-tenant cost
  attribution is best-effort, not exact. Customers who need
  audit-grade attribution should graduate to BYOC where the LLM keys
  live in their account and every call is in their CloudTrail.
- **Air-gapped deployments.** The managed beta is internet-facing by
  definition. The [air-gap runbook](/docs/operations/air-gapped) applies to
  self-hosted deployments only.
- **Custom data residency.** Region selection on the managed plan is
  limited to whatever Fly.io supports; if you need data residency
  outside that list, BYOC is the answer.

## SLAs

The managed beta runs on a best-effort basis. Specifically:

| Metric                       | Beta target            |
| ---------------------------- | ---------------------- |
| Console availability         | 99.0% / 30-day window  |
| API availability             | 99.0% / 30-day window  |
| First-touch waitlist response| 5 business days        |
| Critical security incident response | < 24 hours      |

These are **targets, not contractual SLAs**. Customers who need a
written SLA should engage about BYOC or a paid managed tier — the
contact form for that lives at the bottom of
[`tryaisoc.com`](https://tryaisoc.com).

## Billing and cost transparency

The managed beta is free during the beta period. We're not running a
land-grab pricing experiment — we're trying to figure out what an
honest unit economic looks like for a SOC product, and we'd rather do
that with a small cohort of design partners than with a public price
sheet that we have to walk back later.

What we **do** care about is making cost visible from day one. The
[LLM cost dashboard](https://tryaisoc.com/costs) (rolled out as WS-H1 of
the v1.0 buyer-value plan) tracks every model call with token counts,
provider, and run cost, scoped per tenant. When the beta exits and
pricing lands, that dashboard is what we'll bill against — so
customers can see the bill being built in real-time today.

### Storage, and why its number is shaped differently

LLM spend and storage spend are both on that page and they are **not the
same kind of number**, so the console keeps them apart and never adds them
together.

LLM cost is measured: the gateway reports what a call cost, and where it
cannot, the figure is re-priced from a published list price and labelled an
estimate.

Storage cost is **projected**. There is no per-tenant storage invoice to
read, so the console measures the one thing it can — the uncompressed bytes
your events occupied in the event lake over the window — and runs the
committed storage cost model over it
([ADR-0005](https://github.com/beenuar/AiSOC/blob/main/docs/decisions/0005-storage-consolidation.md),
worked example in `docs/decisions/storage-cost-model.json`,
drift-gated by `.github/workflows/perf.yml`). At the model's reference
scenario of 1 TB/day that comes out at about **$902/month**, or **$30 per
raw TB ingested**, across a hot/warm/cold ladder at reference list prices.

Three things follow, and the panel states each of them:

- It is a model, not your provider's bill. Verify against your own region
  and negotiated rates before planning against it.
- The model's retention shape (30 days hot / 60 warm / 275 cold) is the
  sizing scenario, not necessarily what your deployment runs — the shipped
  ClickHouse tiering SQL is two tiers over 90 days, and per-tenant retention
  policies override both.
- The event lake runs in the `full` profile. On a CORE deployment there is
  no ingest volume to measure, so the panel reads **"Not measured"** with the
  reason. It does not read `$0.00`, because a confident zero for a tenant
  nobody measured is indistinguishable from free storage.

## Operator runbook (for the AiSOC community)

If you're operating the managed instance yourself, the relevant
runbooks live here:

- **Bootstrapping new infrastructure** —
  [`infra/terraform/environments/managed/README.md`](https://github.com/beenuar/AiSOC/blob/main/infra/terraform/environments/managed/README.md)
  walks through `terraform init` / `plan` / `apply`, the `fly attach`
  /`fly secrets` / `fly deploy` sequence, and the post-apply
  smoke-test commands.
- **Rotating the credential vault key** —
  [`/operations/credentials`](/docs/operations/credentials) documents the
  `MultiFernet` rotation procedure. Run this once per quarter and
  always before offboarding an operator who had access to the
  current key.
- **Air-gap parity** — the same code runs air-gapped (see
  [`/operations/air-gapped`](/docs/operations/air-gapped)). Every feature
  that ships to the managed instance is regression-tested against
  the air-gapped overlay so a customer can leave the managed
  offering at any time without re-validating the security story.
- **Audit log export for compliance** — `POST /v1/audit/export`
  generates a signed CSV + HTML bundle for any 24h window. Run this
  monthly as part of the managed-instance compliance cadence.

## When to graduate

The managed beta is a great starting point, but it's not where most
serious AiSOC deployments live in steady state. Move to BYOC or
self-hosted when **any** of the following becomes true:

- You need a contractual SLA, not a target.
- Your alerts touch PII or regulated data that can't leave your VPC.
- You want exact per-call LLM cost attribution against your own
  provider account.
- You want air-gapped deployment with the local-LLM overlay.
- You want to fork the codebase for tenant-specific detection
  content.

The migration is mechanical: `pg_dump` your tenant's data, run the
matching `pg_restore` against your BYOC Postgres, point the BYOC
control plane at the same Fernet key, and update your DNS. The
managed instance does nothing exotic that wouldn't survive the
round trip.
