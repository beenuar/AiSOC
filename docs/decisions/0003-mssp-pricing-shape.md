# ADR-0003 — MSSP pricing: keep three public tiers, treat MSSP as an Enterprise mode with its own narrative page

- **Status:** accepted
- **Date:** 2026-06-28
- **Decision-makers:** Beenu Arora (founder), AiSOC core team
- **Plan reference:** [AiSOC missing pieces plan](../../plans/aisoc-missing-pieces/aisoc_missing_pieces_plan.md) §5.3

## Context

The original product request was a three-tier shape: **Free / Pro / MSSP**. What ships today on `apps/web/src/components/landing/sections/PricingTeaser.tsx` is **Community / Team / Enterprise**, and `README.md` plus `apps/docs/docs/operations/mssp-mode.md` refer to **MSSP** as an *operating mode* of the platform — a tenant-of-tenants multi-customer overlay enabled by a config flag, not a separate SKU.

Meanwhile, workspace-level facts on this repo (`AGENTS.md`) say:

- `tryaisoc.com/signup` redirects to `cyble.com/contact-us/`.
- Cyble runs the managed offering; the high-touch deal motion flows through Cyble sales.

So the strategic question is: **does MSSP get its own public pricing column, become a row inside Enterprise, or live as a separate narrative page**?

The three competing concerns are:

1. **Buyer signal.** MSSPs are a meaningfully different ICP from end-customers. A pricing column tells them they're being marketed to.
2. **Sales motion.** MSSP deals are always high-touch (multi-tenant onboarding, white-label, dedicated account management). They are not self-serve. Putting per-seat prices next to them confuses the conversation.
3. **Marketing surface clutter.** A four-column pricing grid is harder to scan than a three-column one. Comprehension drops with each additional axis.

## Decision

We **keep three public pricing tiers — Community / Team / Enterprise — and treat MSSP as an Enterprise mode with its own narrative page**.

Concretely:

1. The public `PricingTeaser` stays at **Community / Team / Enterprise**. No fourth column.
2. We ship a dedicated **`/mssp` narrative page** under `apps/web/src/app/(marketing)/mssp/page.tsx` that:
   - Explains what "MSSP mode" actually is in product terms (tenant-of-tenants, white-label, per-customer dashboards).
   - Lists the capability differences from Enterprise mode (multi-tenant RBAC, customer-scoped billing exports, branded reports).
   - Routes the CTA to `cyble.com/contact-us/?ref=mssp` so the high-touch motion flows through the same Cyble sales funnel as Enterprise.
3. The `Enterprise` pricing card grows a single line: **"Includes MSSP mode for partners — see `/mssp`"**. That line is a link to the new page.
4. We add MSSP to the **footer navigation** under the "Product" group so deep-link surfacing is consistent with `/sovereign`, `/customers`, etc.
5. We do **not** publish per-seat MSSP pricing. The page says "starts at $X/customer/month" with no hard number, mirroring how every other MSSP-focused platform (Coralogix, Vectra, Sumo Logic) markets the motion.

## Consequences

### Code changes that land alongside this ADR

- `apps/web/src/app/(marketing)/mssp/page.tsx` (new) — narrative page.
- `apps/web/src/components/landing/sections/PricingTeaser.tsx` — add the one-line "Includes MSSP mode" callout under Enterprise.
- `apps/web/src/components/landing/Footer.tsx` — add `/mssp` to the Product group.
- `scripts/audit_landing_pages.py` (Phase 1.4) — recognise `/mssp` as a valid footer link so the 404-gate doesn't fire.
- `apps/docs/docs/operations/mssp-mode.md` — already exists; add a top-of-page callout linking to the new marketing narrative.

### Marketing posture

- The three-column pricing scan stays clean.
- MSSP gets dedicated SEO surface (`tryaisoc.com/mssp`) which is what the partner buyer Googles for.
- The Cyble sales funnel sees a single inbound channel from both Enterprise and MSSP CTAs.

### Roadmap

- Per-customer billing exports inside MSSP mode is already in the platform; documenting it on `/mssp` is the only new work.
- A future "MSSP partner directory" page is out of scope until we have ≥3 named partners willing to be listed.

## Alternatives considered

1. **Fourth pricing column (Free / Pro / MSSP / Enterprise).**
   - Rejected: per the buyer-signal vs. sales-motion tradeoff above. The four-column grid is harder to scan; MSSP is high-touch and shouldn't be next to per-seat prices.
2. **Row inside Enterprise (a sub-bullet, no separate page).**
   - Rejected: insufficient SEO surface for the partner buyer. MSSPs Google for `mssp soc platform`, not `enterprise soc platform`.
3. **Mention only in docs, never in marketing.**
   - Rejected: leaves the partner buyer with no entry point. The narrative page is the entry point.
4. **Public per-seat MSSP pricing.**
   - Rejected: no precedent in the category, and per-customer pricing typically depends on volume tiers we don't want to publish.

## Open questions

- Should the MSSP page show a deployment-architecture diagram (managed-of-managed) or just narrative? Default: ship narrative-only in v1; add the diagram once we have a first partner reference.
- The `cyble.com/contact-us/?ref=mssp` querystring needs to be wired into Cyble's CRM intake. Cyble sales-ops owns that integration.

## Supersedes / superseded by

- Supersedes: none.
- Superseded by: none.
