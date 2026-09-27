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

## Earning autonomy

Measurement exists so that autonomy can be earned rather than switched on. Once
a class has a track record, a tenant can ask for a capability and the evidence
decides.

Two capabilities can be earned:

* `auto_close` on an alert class: the agent closes alerts of that class without
  a human.
* `auto_execute` on a response verb: that verb's autonomy tier ceiling rises.

```bash
curl -X POST "$AISOC/api/v1/autonomy-policy/grants" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"scope_kind": "alert_class", "scope_key": "identity", "capability": "auto_close"}'
```

A refusal comes back as a `200` with `granted: false` and the reasons. Being
told no by a safety control is the control working, and returning it as an
error would invite a client to retry it.

### What has to be true

| Threshold | Default | Why |
|---|---|---|
| Decisions in the window | 100 | A handful of agreements is not a track record. |
| Of those, closed as malicious | 30 | A real queue reaches 100 decisions with two true positives in it. Agreement over that says the agent recognises noise, which is not the question. Same floor replay uses before printing a headline accuracy. |
| Agreement, over answered decisions | 95% | |
| Recall on malicious | 90% | An abstention counts as a miss here. |
| Abstention rate | at most 30% | Caps the share of the queue the agent may decline. |
| The trailing slice | not in decline | Checked against the demotion floors, so a grant is never issued into a decline it would immediately be revoked for. |

Every check runs and every failure comes back. An operator told one thing at a
time fixes it, re-asks, is told the next thing, and overrides out of
frustration rather than on the merits.

### Demotion is automatic

Standing grants are re-checked whenever they are read and whenever the
dispatch path refreshes. A grant is demoted when agreement falls below 90%,
malicious recall below 80%, the abstention rate rises above the cap, or the
trailing slice of recent decisions has slipped below those floors even though
the window average has not.

The demotion floors sit below the promotion thresholds on purpose. Equal values
would flip a grant on every decision that moved the rate across the line, and
the audit log would fill with churn nobody reads, which is how a real demotion
gets missed.

One asymmetry worth knowing, because it looks like an inconsistency:
**promotion refuses an unmeasured rate and demotion ignores one.** For a
promotion, nothing has been shown, so the answer is no. For a demotion, a week
in which no malicious alert arrived is not evidence the agent got worse, and
revoking a grant over an empty denominator would make quiet weeks dangerous.

### What a grant can and cannot unlock

A grant on a response verb raises the tier ceiling to **L3**, which permits
MINIMAL, LOW and MEDIUM blast radius. It stops there. No track record on triage
agreement makes `isolate_host` unattended, because agreement on triage verdicts
is evidence about the agent's judgement and is not evidence that a high-blast
containment was the right call.

The capability contract still applies on top. A verb declared `analyst` or
`mandatory_human`, or one whose impact is never autonomous, stays gated however
good the numbers are: a contract's floors may be raised and never lowered.

### Overrides

An operator can grant a capability the evidence refuses:

```bash
curl -X POST "$AISOC/api/v1/autonomy-policy/grants" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"scope_kind": "alert_class", "scope_key": "identity", "capability": "auto_close",
       "override": true, "override_reason": "Accepted for a two-week pilot"}'
```

A gate with no override is a gate that gets worked around by people who then
stop telling you. What must not happen is an override becoming
indistinguishable from earned autonomy once it is a week old, so it is a
different word in four places:

* a different audit action, `autonomy:overridden` rather than `autonomy:granted`
* a `source` of `operator_override` on the grant row
* the refusals that were waived, recorded in the evidence snapshot
* an amber "operator override" label on the autonomy scorecard, beside the
  reason the operator gave

A reason is required. An override nobody can review now is not reviewable later
either.

An override is re-checked and demoted on the same floors as an earned grant. It
means "I accept this today", not "stop measuring"; exempting it would make the
override permanent, which is the one thing that would turn it back into the
settings toggle this replaces.

### The evidence snapshot

Every promotion and demotion is written to the hash-chained audit log with the
numbers frozen at the moment it was made. Not a reference to them, and not a
flag that lets them be recomputed later.

Six months after a disputed auto-closure, "why was this tenant allowed to do
that" has to be answerable against the numbers as they stood on the day. By
then the window has moved, decisions have aged out, the thresholds may have
been retuned and the model has probably changed, so a recomputed justification
would describe a different world while looking authoritative doing it.

The snapshot holds:

* the counts and the rates derived from them, for the window and the trailing
  slice
* the thresholds **by value**, so a threshold retuned next quarter does not
  rewrite the justification for every promotion granted under the old one
* the window as absolute timestamps, because "the last 30 days" stops meaning
  anything the moment it is read on a different day
* the first and last decision id, so the rows behind the summary can still be
  found after the window has moved on
* the models that produced the verdicts, and whether the closures came from
  this console, a vendor, or both
* a digest of the rules that judged it, so a later reader can tell "the gate
  was more lenient then" from "the numbers were better"

The audit log refuses deletion by trigger and each entry chains onto the
previous one for the same tenant, so the record of a grant cannot be quietly
removed.
