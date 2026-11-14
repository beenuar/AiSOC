# Comparison dossier — AiSOC vs. closed-source AI SOC products

> **House rule:** this is a category-level comparison. We do **not** name
> specific competitors — AiSOC is an open-source project and naming vendors we
> can't fairly and verifiably characterize invites exactly the overreach we
> criticize. Every AiSOC-side claim below links to code or a CI gate. Every
> "closed-source" row is a structural statement about the proprietary,
> cloud-only category, not a claim about any one product.

## The one-line framing

Closed-source AI SOC vendors ship working products. AiSOC's contribution is
making the agent itself open, the per-step decision trail readable, and the
substrate gated by a public eval harness on every PR. If those three properties
matter to you, AiSOC is structurally different; if they don't, a managed vendor
may be a fine choice.

## Structural comparison

| Dimension | AiSOC | Closed-source AI SOC (category) |
|---|---|---|
| License | MIT (agent + substrate + console) | Proprietary |
| Deployment | Self-host anywhere; data stays in your perimeter | Vendor cloud (typically) |
| Agent decision trail | Public Investigation Ledger: prompt, tool call, evidence, rationale, per step; replayable | Not published |
| Eval transparency | Public harness gates every PR; synthetic-vs-measured labelled | Not published |
| Verdict engine | Readable, deterministic-by-default scoring you can fork | Opaque |
| Time-to-first-verdict | `npx aisoc triage --demo`, <1s, no key | Sales cycle → onboarding |
| Data egress control | No callbacks; hosted-LLM evidence pseudonymized by default; air-gapped local-model path | Vendor-defined |
| Cost | $0 self-host | Per-seat / per-GB / enterprise |

## AiSOC claims — each backed by code or a gate

| Claim | Evidence |
|---|---|
| Deterministic verdict engine, no LLM required | `services/agents/app/confidence/scoring.py`; CLI parity test `packages/aisoc-lite/src/verdict/stages.test.ts` |
| Every agent step is logged + replayable | `services/api/app/models/investigation.py`; ledger API + `/r/<slug>` public replay |
| Public eval harness gates PRs | `scripts/run_evals.py`; `.github/workflows/ci.yml` `p1-eval` job; `apps/docs/docs/benchmark.md` |
| Copilot/dry-run default for response | autonomy policy; `AISOC_MATURITY_TIER`; `docs/audit/CLAIM_TO_GATE_MATRIX.md` |
| Detection corpus honesty | `docs/detections/truth-table.md` (executable vs. quarantined counts) |
| Pseudonymized egress / air-gapped path | `services/agents/app/privacy/redactor.py`; `docs/trust/data-flows.md` |

## What AiSOC does NOT claim (say this out loud)

- It is not claiming higher live-LLM accuracy than any vendor — the live-LLM
  benchmark is a funded weekly job, not a per-PR gate; the per-PR gate is the
  deterministic tier.
- It does not auto-remediate by default — response is copilot/dry-run until an
  operator configures autonomy per action.
- The `--demo` fixture numbers are synthetic and demonstrate the mechanism, not
  measured production performance.

## How to use this dossier

For a landing-page comparison table, use the "Structural comparison" rows
verbatim — they're defensible without naming anyone. For analyst / procurement
conversations, lead with the "claims backed by a gate" table: the differentiator
isn't a feature checkbox, it's that every claim is falsifiable by running the
repo.
