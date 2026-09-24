---
title: Multi-tenancy and managed portfolios
sidebar_label: Multi-tenancy
---

# Multi-tenancy and managed portfolios

AiSOC separates two things that are easy to conflate: the **tenant**, which
is a security boundary around one estate's data, and the **organisation**,
which is the operator that manages some number of them. A managed service
provider is an organisation. A single company running its own SOC is also an
organisation, with a portfolio of one.

## Why the operator is not a tenant

An earlier model added `tenants.parent_tenant_id` — the provider was itself
a tenant, and its customers were child rows. That is enough to draw a tree
and not enough to run a managed service:

- It conflates the operator with a boundary. Every consumer of
  `current_user.tenant_id` on an MSSP route asks "who is the operator" and
  "whose data is this" with one value, and those have to be different
  questions or a cross-tenant surface has nothing to enforce.
- There is no per-analyst scoping. Every user of the parent tenant reaches
  every child. Providers assign analysts to accounts; the column cannot say
  so.
- `ON DELETE SET NULL` meant deleting the parent silently detached the whole
  portfolio, leaving no record it had existed.

`parent_tenant_id` still works and still backs `GET /api/v1/mssp/children`,
so existing deployments are unaffected. Migration `058` adds the
organisation model above it and backfills from it.

## The schema

| Table | Holds |
| --- | --- |
| `organizations` | The operator. `home_tenant_id` is the tenant its own staff sign in to. |
| `organization_members` | Who belongs to it, and with what authority. |
| `organization_tenants` | The managed portfolio. |
| `organization_member_tenants` | Which portfolio tenants one member may reach. |

Three constraints do the work that would otherwise live in application code,
and therefore hold even if that code is wrong:

- `organization_tenants` is unique on `tenant_id`, so two providers cannot
  both claim one customer and "whose portfolio is this in" has one answer.
- `organization_member_tenants` carries composite foreign keys onto both
  `organization_members` and `organization_tenants`. A grant cannot name a
  tenant the organisation does not manage, and releasing a tenant from the
  portfolio revokes every grant over it in the same statement.
- `organizations.home_tenant_id` cascades. If the provider's own tenant is
  erased under a deletion request, the organisation goes with it — and the
  customers it managed survive as unclaimed tenants, because offboarding a
  provider is not an instruction to erase its customers.

## Roles

Two axes, kept separate because they answer different questions.

| Role | Reaches | May act |
| --- | --- | --- |
| `owner` | The whole portfolio | Yes, and may administer the organisation |
| `admin` | The whole portfolio | Yes, and may administer the organisation |
| `operator` | Only tenants granted to them | Yes |
| `viewer` | Only tenants granted to them | No |

An `operator` or `viewer` with no grants reaches **nothing**. That is the
case the design is shaped around: "no scope" must never degrade into "all
scopes", or every new analyst starts with the entire book of business.

## Cross-tenant surfaces

| Endpoint | Returns |
| --- | --- |
| `GET /api/v1/mssp/portfolio` | Per-tenant posture plus derived totals |
| `GET /api/v1/mssp/portfolio/alerts` | Open alerts across the portfolio |
| `GET /api/v1/mssp/overview` | Portfolio totals only |
| `GET /api/v1/mssp/tenants` | Per-tenant posture only |
| `GET /api/v1/mssp/incidents` | Open alerts across the portfolio |

Each resolves its tenant list through `resolve_portfolio_scope` and nowhere
else, then passes it to `require_scope`, which raises rather than letting an
aggregate run with no filter. The tenant list is bound as a query parameter,
never formatted into SQL. A `?tenant_id=` filter is intersected with the
portfolio, so naming a tenant outside it narrows the result to nothing
instead of reaching outside.

A caller who belongs to no organisation gets `403`. A member whose portfolio
is genuinely empty gets zeros and an empty list, plus `scoped_tenants` and
`portfolio_wide` in the payload so the console can say *why* it is empty —
"you have no tenant grants" and "your organisation manages no tenants" are
different problems with different fixes.

### What these endpoints do not return

They previously returned five hardcoded companies — Acme Corp, Globex
Industries, Wayne Enterprises — with invented alert counts and a
`health_score` nobody could reproduce. Every figure is now counted from that
tenant's own rows, and two consequences are worth stating plainly:

- **`health_score` is gone.** It was an undefined composite. There is no
  honest way to keep the field and no honest way to compute it.
- **`mttr_minutes` is null when a tenant has closed no cases.** It is
  measured from cases that tenant actually closed in the trailing 30 days.
  Reporting `0.0` would put the account that has done nothing at the top of
  the league table.
- **Seeded demo rows are counted separately** as `synthetic_alerts` and
  excluded from the headline figures, so a demo install reads "0 real, 15
  synthetic" rather than reporting fixtures as a customer's posture.

## Limits and headroom

A provider's most expensive failure is a quiet one. A tenant that hits a cap
does not raise an error anyone sees: alerts keep arriving and stop being
triaged, and the customer reports it as "the AI doesn't work".

Every tenant row carries per-key headroom, and the portfolio summary counts
how many tenants are in `warning` or `exhausted`. Exhaustion is logged at
`warning` with the tenant and key.

AiSOC ships **uncapped**. A key with no configured ceiling reports
`"state": "unlimited"` and `"limit": null` — not a default ceiling, because
drawing a headroom bar against a number nobody set would put a fabricated
figure on every tenant row. Set ceilings either way:

- `tenants.limits` (JSONB, per tenant) overrides everything, in either
  direction. `"unlimited"` and `-1` both mean no limit.
- `AISOC_DEFAULT_TENANT_LIMITS` (JSON object) sets a deployment-wide
  default, e.g. `{"connectors": 25, "seats": 50}`.

Measured keys are `connectors`, `seats`, `alerts_per_day` and
`triages_per_month`. Each is a count over real rows; a key that cannot be
counted honestly is not offered.

## Isolation

Cross-tenant reads are the one place in the product where per-tenant
filtering is deliberately relaxed, so they carry their own gates:

- `services/api/tests/test_org_scope.py` runs on every PR. An empty scope
  refuses; a `?tenant_id=` filter can only narrow; and an AST check fails
  the build if a new cross-tenant function is added that never calls
  `require_scope`.
- `services/api/tests/test_mssp_portfolio_isolation.py` runs against live
  Postgres in `integration.yml`. It seeds two organisations plus an
  unmanaged tenant, asserts the outsiders' data really exists so a scoped
  read cannot pass vacuously, then asserts an aggregate as one operator
  never returns the others.

See [Tenant isolation](../operations/security.md) for the per-store rules
that apply to ordinary single-tenant reads.
