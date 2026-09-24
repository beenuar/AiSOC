---
title: LLM cost — what is measured, what is estimated, what is not known
sidebar_label: LLM cost
---

# LLM cost

Every dollar figure AiSOC shows is one of three things, and every surface says
which. There is no fourth state, and in particular there is no "we don't know,
so call it zero".

| | What it means | How it looks |
|---|---|---|
| **Measured** | The LLM gateway reported what the call cost. Real money. | `$0.42` with "measured over N calls" |
| **Estimated** | Re-priced from a public list price for a concrete model. An approximation. | `~$0.42` with "list-price estimate … not billed" |
| **Not measured** | Neither was available. | `—` with the reason |

A **measured `$0.00`** is a value, not a gap. That is what a local model
genuinely costs, and it is reported as a measurement because it is one.

## Where the number comes from

AiSOC asks the gateway for a logical alias (`aisoc-triage`,
`aisoc-investigation`, …). The gateway resolves that alias to a real model, so
the gateway is the only party that knows what actually ran and what it cost.
It reports both on the response headers:

```
x-litellm-model-name:              ollama/qwen2:1.5b
x-litellm-response-cost-original:  0.0
```

```
x-litellm-model-name:              openai/gpt-4o-mini
x-litellm-response-cost:           1.35e-05
```

Those are real responses from the same alias set against one gateway — a local
model and a hosted one. The alias alone distinguishes neither, which is why
the cost is read from the gateway rather than computed from the model name.

Two consequences worth knowing:

- **The gateway has to be in the deployment for cost to be measurable.** It
  ships in the CORE profile
  ([ADR-0006](https://github.com/beenuar/AiSOC/blob/main/docs/decisions/0006-llm-gateway-in-core.md)),
  so the default install measures cost.
- **A model pinned directly at a provider is not measured.** Setting
  `AISOC_MODEL_PIN_<ROLE>` to a concrete provider model bypasses the gateway
  by design, and a provider returns no cost header. Those calls are estimated
  when the model has a published list price and reported as not measured
  otherwise.

## Why the counts are there

Every sum arrives with the number of calls it was computed over —
`measured_call_count`, `estimated_call_count`, `unpriced_call_count`. Without
them a console cannot distinguish "this tenant spent nothing" from "nobody
recorded what this tenant spent", and it will show the first. This is the same
contract the MTTR tiles use, for the same reason.

So on `/costs/dashboard`, a window with real LLM traffic and no measured cost
renders no currency amount at all — the headline says *not measured · N calls
the gateway did not price*, the daily chart says why it is flat, and the BYOK
panel says *not estimable* rather than claiming a saving.

## Why there is no default price

There used to be one. `CostTracker` looked a call's **model name** up in a
table of hosted list prices, and the name it looked up was an `aisoc-<role>`
alias — which is not a model and appears in no price table. So every call fell
through a `(0.001, 0.002)` default and was booked at a price nobody charges
for a model nobody named. A 903-token completion on an operator's own hardware
reported `total_cost_usd=0.000999`.

That figure was not confined to a dashboard. It reached the funnel metrics,
the per-run Investigation Ledger, the investigation summary export, and the
budget circuit breaker — which trips at `AISOC_BUDGET_HARD_USD` and would
eventually have degraded a working local-model install to deterministic-only
over money nobody spent.

A model with no published price now imputes **nothing**. "We know this model's
price" and "we guessed" were previously the same return type, and therefore
the same number.

## Reading it from the API

`GET /api/v1/costs/dashboard` and the `/investigations` routes carry the same
shape everywhere:

```jsonc
{
  "headline": {
    "total_cost_usd": 0.0,        // measured only — never includes the estimate
    "measured_call_count": 0,     // 0 => the figure above is not a measurement
    "estimated_cost_usd": 0.0,    // always labelled an estimate when surfaced
    "estimated_call_count": 0,
    "unpriced_call_count": 1287,  // calls nothing could price
    "avg_cost_per_run_usd": null  // null, not 0.0, when nothing was measured
  }
}
```

The rule for any client: **read the count before the money.** If
`measured_call_count` is `0`, `total_cost_usd` is not a total of anything.

Rows written before migration `063_cost_provenance.sql` have a zero
`measured_call_count` and therefore read as not measured — which is the truth
about them. Their historical values are left in place rather than deleted, and
no read path treats them as measured.

## What enforces this

`scripts/check_cost_provenance.py`, in `ci.yml :: python-lint`, with its
self-test first. Seven structural rules, each checked in both directions:
money fields and their counts, written columns and migration columns, the
absence of a fallback rate in either pricing table, the gateway headers that
carry a total versus the five that share their prefix and do not, the Python
and TypeScript sides of the wire, and whether a console surface consults a
provenance count before printing a currency amount.
