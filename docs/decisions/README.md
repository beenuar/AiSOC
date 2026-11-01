# Architecture Decision Records (ADRs)

This folder holds the small set of strategic decisions that shape the AiSOC product but are too high-level to live inside a code review. Each file is a single ADR following an abbreviated [MADR](https://adr.github.io/madr/) template:

- **Status** — `proposed` | `accepted` | `superseded by ADR-NNNN`
- **Context** — the situation that forced the decision
- **Decision** — what we chose
- **Consequences** — what changes in the codebase, the marketing, the roadmap
- **Alternatives considered** — what we explicitly *didn't* do, and why

ADRs are immutable once accepted. If a decision changes, write a new ADR that supersedes the old one rather than editing history.

## Index

| ADR | Title | Status | Date |
|-----|-------|--------|------|
| [ADR-0001](./0001-cyble-cti-moat.md) | Cyble CTI moat — retire the proprietary spec, design a pluggable CTI fusion layer | accepted | 2026-06-28 |
| [ADR-0002](./0002-compliance-claims.md) | Compliance claims — "controls aligned to" until a Type I audit lands | accepted | 2026-06-28 |
| [ADR-0003](./0003-mssp-pricing-shape.md) | MSSP pricing — keep three public tiers, treat MSSP as an Enterprise mode with its own narrative page | accepted | 2026-06-28 |
| [ADR-0004](./0004-live-demo-strategy.md) | Live demo — replace the Cloudflare Tunnel with an always-on Fly.io deploy via the managed-mode pipeline | accepted | 2026-06-28 |
| [ADR-0005](./0005-storage-consolidation.md) | Tiered storage consolidation + a $/TB cost model | accepted | 2026-07-12 |
| [ADR-0006](./0006-llm-gateway-in-core.md) | The LLM gateway belongs in the CORE profile | accepted | 2026-09-24 |
| [ADR-0007](./0007-connectors-and-actions-in-core.md) | `connectors` and `actions` belong in the CORE profile | accepted | 2026-09-26 |
| [ADR-0008](./0008-scim-trust-boundary.md) | SCIM is a third-party write surface into identity, and is scoped by its credential | accepted | 2026-09-27 |
| [ADR-0009](./0009-auto-close-without-an-earned-grant.md) | Whether a tenant with no closure policy may auto-close | proposed | 2026-10-04 |
| [ADR-0010](./0010-entity-and-session-context-in-core.md) | Entity and session context in CORE is a Postgres store; Neo4j stays in `full` | accepted | 2026-10-11 |
| [ADR-0011](./0011-behavioural-baselines-in-core.md) | Behavioural baselines in CORE are a fusion module; the UEBA service stays in `full` | accepted | 2026-10-11 |
| [ADR-0012](./0012-how-fusion-scales.md) | How fusion scales — required-field indexing, entity partitioning, and a scale hint the cluster acts on | accepted | 2026-10-11 |
| [ADR-0013](./0013-truncating-a-hash-chained-audit-log.md) | Truncating a hash-chained audit log without making an intact chain look tampered with | accepted | 2026-10-11 |
| [ADR-0014](./0014-tenant-erasure-crosses-the-audit-trigger.md) | Tenant erasure crosses the audit-log immutability trigger; nothing smaller does | accepted | 2026-10-12 |
| [ADR-0015](./0015-siem-replacement-scope.md) | AiSOC does not take on SIEM-replacement scope; it federates to the SIEM instead | proposed | 2026-11-01 |

## Authoring conventions

- Filename: `NNNN-kebab-case-title.md`
- Number monotonically; do not renumber when superseding.
- Land the ADR and the code that implements it in the same PR whenever possible. When the decision is too large for a single PR, the ADR lands first and the implementation PRs reference it in their description.
