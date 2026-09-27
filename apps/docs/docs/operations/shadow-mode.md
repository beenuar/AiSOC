---
id: shadow-mode
title: Shadow mode and measured agreement
sidebar_label: Shadow mode
---

# Shadow mode and measured agreement

Shadow mode runs triage on your live alerts, records what the agent concluded,
and acts on none of it. When one of your analysts closes the same alert, the
two verdicts are compared. What accumulates is a track record: on your alerts,
against your analysts, how often the agent was right and how often it caught
the ones that mattered.

This page covers what shadow mode does and does not do, how agreement is
computed, and what the numbers can and cannot tell you.

## Why measure before trusting

The published benchmark scores this platform against a synthetic corpus. That
corpus is balanced by construction and yours is not: a real queue is mostly
false positives with a handful of findings that mattered. An agent that calls
everything benign scores well on a real queue and is worth nothing.

So the only measurement that answers "should I let this act on my estate" is
one taken on your own alerts and graded against your own analysts. Shadow mode
is how that measurement is taken without the agent influencing it.

## What it does, precisely

For each alert class you enable, triage runs exactly as it would in
production. Then:

| Effect | In normal operation | In shadow mode |
|---|---|---|
| Ledger run and event | written | written |
| `ai_score`, `ai_summary`, `ai_recommendations` on the alert | written | written |
| `alerts.disposition` | set to the agent's verdict | **left alone** |
| Alert auto-closed | when the verdict is confident and benign | **never** |
| Disposition written back to your SIEM | attempted | **never** |
| Approval raised for a proposed action | queued | **never** |
| Outcome prior recorded, so a repeat alert can suppress | written | **never** |
| Escalation into the full investigation graph | runs | **never** |
| Model spend | measured and billed | measured and billed |
| Deduplication through the cost governor | applies | applies |
| Row in `aisoc_shadow_decisions` | not written | **written** |

Two of those need their reasoning stated.

**`alerts.disposition` is left alone**, and this is the property the whole
measurement rests on. That column is the analyst's, and it is the column
agreement is later read from. If a shadow verdict landed there, every alert an
analyst did not explicitly re-dispose would score as perfect agreement, and the
track record would climb toward a promotion on nothing at all. The guard is in
the SQL statement rather than in the caller, so a future code path that forgets
to ask for it still cannot close an alert it was only meant to observe.

**Spend is still billed.** A shadow run places real model calls against a real
key. Replay evaluation declines to bill because a replay is a measurement you
asked for; a shadow run is the product running, and a month of it should appear
on your cost dashboard.

## Turning it on

Shadow mode is per tenant and per alert class, where a class is the
`category` on the alert (`identity`, `cloud`, `endpoint`, `network`,
`application`, and whatever else your detection content sets). `*` matches
every class, which is where most deployments start, because knowing which
classes your queue actually contains is part of what the first weeks of
measurement are for.

```bash
# every class
curl -X PUT "$AISOC/api/v1/autonomy-policy/shadow-mode/*" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"enabled": true}'

# one class
curl -X PUT "$AISOC/api/v1/autonomy-policy/shadow-mode/identity" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"enabled": true}'
```

The tenant comes from your credential. There is no request field for it.

## Where the analyst's verdict comes from

Two places, and both count.

**Closures made in AiSOC.** A sweep matches shadow decisions to alerts that
have since moved to `resolved` or `closed` and copies the disposition across.
It is a sweep rather than a hook on the disposition endpoint because an alert
can be closed from the feedback endpoint, by a case being resolved, by a bulk
action or by a playbook, and a hook on one of those would silently grade the
subset of alerts closed the way the hook was written for.

**Closures made in your SIEM.** Most analysts evaluating AiSOC keep working
where they always have. The same readers that power
[replay evaluation](../evaluation/replay.md) poll closed findings back out of
Splunk ES, Microsoft Sentinel, Elastic Security, IBM QRadar and Microsoft
Defender XDR, and each closure is matched to the decision it grades by the
vendor's own finding id. A tenant whose analysts work entirely in Splunk will
still see their scorecard fill in.

Either way, a closure carrying a disposition this platform cannot name becomes
`unlabeled`. It is counted as resolved and excluded from every rate. Splunk ES
ships two dispositions that literally mean "I do not know", and so do Sentinel
and Defender; folding those into a verdict because the finding happened to be
closed would manufacture agreement out of an analyst's uncertainty.

## How the numbers are computed

The definitions are the ones replay evaluation already uses. They are not
restated here in different words, and a CI gate compares them in both
directions so they cannot drift apart.

**Agreement** is the share of *answered* decisions where the agent's verdict is
the analyst's label. Abstentions, which are `needs_review`, `escalate`,
`unknown` and an empty verdict, are excluded from both halves of that fraction.

That exclusion is deliberate and it is worth understanding, because it is what
stops the metric being gameable. If abstentions counted as "not a
disagreement", an agent that answered a tenth of the queue confidently and
routed the rest to a human would post a near-perfect record on a population it
never attempted. Declining a decision removes it from the numerator and the
denominator together, so the agreement rate does not move; what moves is the
abstention rate, which is reported beside it.

**Recall on malicious** runs the other way. Its denominator is every alert an
analyst closed as a true positive, whether the agent answered or abstained, so
an abstention counts here as a miss. An alert routed to a human was not caught
by the agent.

**A rate with no denominator reads "not measured", never 0.** A zero in the
agreement column says the agent was wrong every time; "it has not been asked
yet" is a different fact, and on a new deployment it is always the true one.

**Every rate travels with the count behind it.** 100% agreement over four
answers is not the claim it is over four hundred, and a display that printed
only the percentage would have thrown that distinction away.

## The window, and the slice inside it

Agreement is reported over a rolling window, 30 days by default, **and** over
the most recent 50 decisions separately.

Both, always. A window average is exactly where a gradual decline hides: an
agent that agreed 99% of the time for three weeks and 70% of the time this week
still posts about 95% over the window. A surface that showed only the window
would conceal the thing it exists to reveal, so the console shows the trailing
slice beside it and the API returns both.

The trailing slice is a count rather than a date range, so it means the same
thing for a tenant seeing ten alerts a day and one seeing ten thousand.

## Where to look

* **SOC operations dashboard**: the "Agreement with analysts" panel, with the
  breakdowns by alert class and by source.
* **Settings, Autonomy guardrails**: the scorecard shows the configured posture
  and the measured track record on one card, because the question they answer
  together is the only one worth asking, which is whether the posture is
  justified.
* **`GET /api/v1/autonomy-policy/agreement`**: the same figures, with
  breakdowns by alert class, rule, source and model.

## What these numbers are not

They are a measure of **agreement with your analysts**, not of correctness.
Where your analysts were wrong, an agent that agreed with them scores well
here. That is a real limit, and it is the same limit any evaluation against
human labels carries.

They describe the **alert classes you enabled**, over the **window shown**, on
the **model that was running**. The per-model breakdown exists because a model
change makes every figure before it a description of something else.

They say nothing about **response actions**. Shadow mode measures triage
verdicts. Whether a containment action would have been correct is a different
question this does not answer.
