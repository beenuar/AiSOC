# ADR-0001 — Cyble CTI moat: retire the proprietary spec, design a pluggable CTI fusion layer

- **Status:** accepted
- **Date:** 2026-06-28
- **Decision-makers:** Beenu Arora (founder), AiSOC core team
- **Plan reference:** [cyble-aisoc-plan.md](../../plans/cyble-aisoc/cyble-aisoc-plan.md) §3a / §3d / §5, [AiSOC missing pieces plan](../../plans/aisoc-missing-pieces/aisoc_missing_pieces_plan.md) §5.1

## Context

The original `cyble-aisoc-plan.md` anchored AiSOC's entire competitive thesis on three first-class agent tools sourced from Cyble's proprietary data: dark-web monitoring (§3a), attack-surface management (§3d), and brand intelligence (§5). When the project was open-sourced as **AiSOC** under MIT, that thesis broke in two ways:

1. **Licensing.** Cyble's CTI feeds are commercial. Shipping them as default agent tools in an MIT-licensed repo would either require every contributor to have a Cyble licence (unworkable) or amount to redistributing licensed data (not legal).
2. **Positioning.** The MIT release explicitly positions AiSOC as the **AI-native SOC platform**, vendor-agnostic about the CTI it ingests. Reintroducing a Cyble-only narrative would undo that.

At the same time, the agents themselves still need a CTI surface — `IocEnrichment`, `ActorProfiler`, `ASMSignals`, `BrandIntel` — and the architecture already has empty hooks for them (`platform/backend/app/tools/cti.py`, `platform/backend/app/agents/actor_profiler/`).

## Decision

We **retire the Cyble-only CTI moat as historical context** and replace it with a **pluggable, MIT-compatible CTI fusion layer** that any CTI vendor (including Cyble) can plug into.

Concretely:

1. The Cyble plan stays in `plans/cyble-aisoc/` as a sealed historical document. We add a one-paragraph banner at the top of that file marking it superseded by this ADR. We do **not** delete it — it remains useful as the original product vision and as honest provenance for AiSOC's design.
2. The CTI fusion layer is defined as a **plugin contract**, not a vendor wrapper. It lives at `platform/backend/app/tools/cti.py` and exposes four capability surfaces — `iocs.enrich`, `actors.profile`, `asm.signals`, `brand.intel` — each backed by a `CTIProvider` protocol. Providers register at startup via `AISOC_CTI_PROVIDERS=<comma-separated>`.
3. We ship two reference providers in the OSS repo:
   - `mock` — deterministic fixtures for tests and the air-gapped demo.
   - `pulsedive` — the largest free-tier CTI API that's MIT-compatible to call from MIT code (their public REST API has no licensing restrictions on the client).
4. We document the **adapter pattern** for commercial providers (Cyble, Recorded Future, Mandiant, Intel 471, …) under `apps/docs/docs/integrations/cti-providers.md`. The adapter ships as a separate package outside the MIT repo (e.g. `aisoc-cti-cyble` in a private registry) so commercial licensing stays out of the OSS surface.
5. The agent tools (`ActorProfilerAgent`, `IocEnrichmentTool`, …) call the registry rather than any specific provider. Swapping `mock` → `pulsedive` → a commercial adapter is a config change.

## Consequences

### Code changes that land alongside this ADR

- `platform/backend/app/tools/cti.py` — already scaffolded against this contract during the v8.x build-out; the work was effectively pre-emptive of this ADR. We will add the `CTIProvider` protocol + registry in the next PR.
- `platform/backend/app/agents/actor_profiler/agent.py` — already routes through the tool surface, no rework needed.
- New: `platform/backend/app/tools/cti/providers/{mock,pulsedive}.py`.
- New: `apps/docs/docs/integrations/cti-providers.md` documenting the adapter pattern.

### Marketing surface

- The landing-page CTI section narrates the **fusion contract**, not any specific vendor. "Bring your CTI" replaces "powered by Cyble".
- The `/sovereign` page already lists CTI as a configurable surface; no copy change needed.
- The README's CTI bullet is updated to reference the provider list.

### Roadmap

- Cyble commercial adapter — out of scope for the OSS repo. Tracked as a separate effort under Cyble's product organisation.
- Pulsedive provider — owned by AiSOC core, tracked under the next release's connectors milestone.

## Alternatives considered

1. **Keep the Cyble-only narrative and ship the integration via a runtime-licensed package.**
   - Rejected: the agent tools must work out-of-the-box in the MIT repo. Forcing a runtime licence for the headline product surface fragments the experience and contradicts the "AI-native SOC" positioning.
2. **Remove CTI from the AiSOC story entirely.**
   - Rejected: CTI is half of what an AI-native SOC actually does. Dropping it would gut the agent value proposition.
3. **Build proprietary CTI inside AiSOC.**
   - Rejected: not our circle of competence and not our value proposition. We are the orchestration + reasoning layer, not the data layer.

## Open questions

- The Pulsedive free-tier rate limit is currently 30 req/min. We need to confirm that's enough for a typical small-tenant burst (≈10 IOC enrichments per alert × p95 8 alerts/hour ≈ 80 req/hour — well under the limit).
- For tenants without any CTI provider configured, the agent tools should degrade gracefully — `iocs.enrich` returns the IOC unchanged, `actors.profile` returns `null`. This is the existing behaviour; we just need a clearer log line at agent startup.

## Supersedes / superseded by

- Supersedes: `plans/cyble-aisoc/cyble-aisoc-plan.md` §3a / §3d / §5 (the proprietary-CTI moat).
- Superseded by: none.
