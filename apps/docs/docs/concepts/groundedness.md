---
title: Groundedness and abstention
description: What stops a confident, well-written, wrong verdict from auto-closing an alert.
---

# Groundedness and abstention

The failure mode of an LLM triaging alerts is not that it is wrong. It is
that it is wrong *fluently*. A verdict citing a specific IP address, a named
C2 domain and "twelve additional affected systems" reads as thorough
regardless of whether any of those appeared in the evidence — and the more
specific it is, the more convincing it is.

Two mechanisms address this, and they answer different questions.

## Groundedness: does the reasoning cite real evidence

`services/agents/app/confidence/groundedness.py` extracts the concrete
indicators a verdict cites — addresses, hashes, hostnames, accounts,
technique ids — and checks each against the evidence the agent was given.
The score is the fraction that appear.

Only checkable claims are scored. "The process behaved suspiciously" is not
graded, because grading it would measure phrasing. An IP address either was
in the evidence or was not.

**A verdict below the floor is demoted to human review**, not auto-closed.
That is the whole point: an ungrounded verdict is not a low-confidence
verdict, it is a verdict about something that did not happen, and the
autonomy tier must not act on it however confident the model was.

The score is persisted on the alert (`triage_groundedness`, migration 051),
so an ungrounded auto-closure is visible after the fact and not only at the
moment it happens. `mean_groundedness` and `ungrounded_demotions` are
published on [`/metrics/funnel`](../console/funnel-kpis.md).

### What it does not catch

Groundedness checks that cited indicators exist in the evidence. It does not
check that the *conclusion* follows from them. An agent can cite four real
addresses and reach the wrong verdict, and score 1.0. It is a floor against
fabrication, not a correctness measure.

## Abstention: does the agent know when it cannot tell

An agent that always answers is guessing on the cases it cannot decide, and
those are precisely the cases where a wrong answer is expensive. Abstention
is a first-class outcome: the agent may return "I cannot determine this from
the available evidence", and that routes to a human rather than counting as
a verdict.

Two properties make this work rather than become a way to avoid being
measured:

**Accuracy is computed over answered incidents only**, in the
[benchmark](../benchmark.md) and on the funnel. If abstentions counted as
neither right nor wrong but still sat in the denominator, an agent would
raise its score by abstaining more.

**The abstention rate is published beside accuracy.** They cannot be traded
off invisibly. A rate of zero means the agent never declines, which is a
finding. A rate above roughly 0.3 usually means missing context rather than
a cautious model — check whether a connector stopped polling.

## Reading the two together

| Groundedness | Abstention rate | Usually means |
|--------------|-----------------|---------------|
| High | Low | Working as intended |
| High | High | The agent is well-behaved but starved of context; check connector coverage |
| Low | Low | The agent is fabricating and not noticing; a prompt or model regression |
| Low | High | Evidence is thin enough that the agent is both guessing and declining; investigate ingest before the agent |

A persistent zero in `ungrounded_demotions` alongside a low `scored_verdicts`
does not mean nothing is ungrounded. It means the check is barely running,
and the two are easy to confuse — which is why both numbers are published
rather than the ratio alone.

## See also

- [Funnel KPIs](../console/funnel-kpis.md)
- [Benchmark](../benchmark.md)
- [Automation maturity](./automation-maturity.md)
