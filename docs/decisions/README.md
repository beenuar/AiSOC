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

## Authoring conventions

- Filename: `NNNN-kebab-case-title.md`
- Number monotonically; do not renumber when superseding.
- Land the ADR and the code that implements it in the same PR whenever possible. When the decision is too large for a single PR, the ADR lands first and the implementation PRs reference it in their description.
