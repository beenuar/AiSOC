# ADR-0002 — Compliance claims: "controls aligned to" until a Type I audit lands

- **Status:** accepted
- **Date:** 2026-06-28
- **Decision-makers:** Beenu Arora (founder), AiSOC core team
- **Plan reference:** [AiSOC missing pieces plan](../../plans/aisoc-missing-pieces/aisoc_missing_pieces_plan.md) §5.2; the Phase 1.3 fix already landed in v8.x.

## Context

The original landing surface asserted **`SOC 2 · ISO 27001 · GDPR · DPDP`** on every deployment row of the `/sovereign` matrix as if those were attested certifications. They are not. No third-party audit has ever been commissioned against the AiSOC platform; what we have is an internal `SOC2View.tsx` self-attestation surface that helps *tenants* track *their* controls — not a SOC 2 report for AiSOC.

Phase 1.3 of the missing-pieces plan already softened those claims to **"controls aligned to"** across `/sovereign`, `Features.tsx`, and the README. That's a temporary patch. The strategic question is whether the AiSOC platform should commission a real audit programme, or commit permanently to the "controls aligned to" framing.

The two paths from the plan are:

- **(a)** Commission SOC 2 Type I → Type II → ISO 27001 audits with the timelines from the original spec (Month 9 / Month 12 / Month 18).
- **(b)** Permanently reframe every compliance claim across landing / docs as "controls aligned to" instead of unqualified framework names.

## Decision

We adopt a **third path** that's the honest middle ground: **keep the "controls aligned to" framing in marketing for now, and commit to a Type I audit in the next fiscal year** as the gating event for graduating the framing.

Concretely:

1. **All current marketing surfaces stay as "controls aligned to ..."** with no audit-status assertions. This was already landed in Phase 1.3 and is non-regressing — the CI check at `scripts/audit_compliance_claims.py` (added in Phase 1.3) fails the build if anyone re-asserts unqualified framework names.
2. **We commission SOC 2 Type I** in the first fiscal quarter that has both >$500k ARR and an enterprise design partner who needs it for procurement. We do not chase the audit speculatively; the audit costs (~$25–40k + ~3 months of an engineer's time) only pencil out against a concrete revenue gate.
3. **ISO 27001 and DPDP wait** — Type II + ISO are sequenced after the first Type I report (typically 12 months apart). DPDP requires Indian establishment which we do not have today.
4. **GDPR** is a self-attestation regime, not an audited one. We document our GDPR posture (controller/processor mapping, DPA template, DSR workflow) under `docs/compliance/gdpr.md` and link it from `/sovereign`. No audit is needed; what's needed is a published policy. That doc lands in the same release as this ADR.
5. **The `/sovereign` page gets a "Roadmap" footer** that surfaces the path from "controls aligned" → "Type I attested" → "Type II attested" so prospects can see where we are.

## Consequences

### Code changes that land alongside this ADR

- `apps/web/src/app/(marketing)/sovereign/page.tsx` — add a "Compliance roadmap" callout below the deployment matrix.
- `docs/compliance/gdpr.md` (new) — GDPR posture: controller/processor mapping, DPA template, DSR workflow, sub-processor list.
- `docs/compliance/README.md` (new) — index of the compliance docs surface.
- `scripts/audit_compliance_claims.py` already exists from Phase 1.3; no change.

### Marketing posture

- We do **not** claim unqualified SOC 2 / ISO 27001 anywhere on the landing or docs.
- We **do** publish our internal control mappings against those frameworks so prospects can see what we cover, even pre-audit.
- The Cyble-managed SaaS row on `/sovereign` retains its `(target)` qualifier and inherits the same roadmap.

### Roadmap

- Type I audit: trigger event = "first enterprise design partner where audit is procurement-blocking". Estimated calendar quarter: H2 2027.
- Type II audit: 12 months after Type I report lands.
- ISO 27001: stage 1 audit aligned to Type II calendar.
- DPDP: deferred until Indian establishment.

## Alternatives considered

1. **Commission a Type I audit immediately, independent of revenue.**
   - Rejected: the $25–40k cash cost and ~3 months of engineering time are a meaningful fraction of seed-stage runway. We commission the audit when it converts a concrete deal, not on speculation.
2. **Permanently commit to "controls aligned to" framing with no audit on the roadmap.**
   - Rejected: enterprise procurement requires Type II or ISO for serious deals. Permanently disclaiming an audit closes off the upper market.
3. **Claim audit certifications now and reframe if challenged.**
   - Rejected: misleading. Every reframe of this kind during an enterprise procurement cycle becomes a deal-killer.

## Open questions

- Is GDPR's DSR endpoint (a real `POST /api/v1/dsr` surface for tenants to forward subject requests) in scope for the OSS repo or only for managed mode? Current default: OSS ships the endpoint stub, managed mode wires the operator workflow.

## Supersedes / superseded by

- Supersedes: none.
- Superseded by: none.
