---
id: case-orchestration
title: Case queues, SLAs and escalation
sidebar_label: Case orchestration
---

# Case queues, SLAs and escalation

Which analyst sees a case, how long they have, and what happens when
nobody picks it up.

## Three clocks, not one

A case picked up in four minutes and resolved in four days met its
acknowledgement target and missed its resolution one. A single due
date cannot say that, and a SOC that cannot distinguish them cannot
tell a staffing problem from a capability problem.

```http
POST /api/v1/cases/sla-policies
{
  "name": "Critical — 24/7",
  "severity": "critical",
  "ack_minutes": 15,
  "resolve_minutes": 240,
  "close_minutes": 1440
}
```

| Clock | Starts | Stops | Answers |
|---|---|---|---|
| `ack_minutes` | Case opened | Somebody takes it | Are we staffed? |
| `resolve_minutes` | Case opened | A verdict is reached | Can we actually investigate this? |
| `close_minutes` | Case opened | Case closed out | Are we finishing the paperwork? |

Targets are measured from **when the case opened**, never from now.
Re-reading a case must not silently extend its deadline, which would
make every breach disappear on the next edit.

A case with no matching policy gets **no target and a stated reason**.
An empty due date with no explanation reads as "met" on every
dashboard that counts breaches.

### Business hours

`business_hours_only` is **off by default**. A 24/7 SOC is the
assumption, and a business-hours policy applied silently would make
every out-of-hours breach vanish.

## Queues

A queue is a stored predicate, so one can be created from the console
without a deploy.

```http
POST /api/v1/cases/queues
{
  "name": "PCI — critical",
  "match_severity": ["critical"],
  "match_tags": ["pci"],
  "precedence": 10,
  "sla_policy_id": "…"
}
```

**Criteria are ANDed.** A queue declaring critical *and* `pci` means
critical PCI cases. Under OR it would also collect every critical case
in the estate, which is how a team's queue becomes everyone's queue.

### Routing is deterministic

Two queues can match one case and the case belongs in exactly one.

1. Lowest `precedence` wins.
2. If two tie, the **name** breaks it.

The second rule is not cosmetic. Without it, equally-ranked queues
resolve by row order and a case appears to move between them on each
read — which reads to an analyst as cases disappearing.

A queue with no criteria is a catch-all, which is legitimate and
usually wants a high `precedence` so it sorts last.

## Escalation

None of this existed before. A case nobody picked up stayed unpicked
and the SLA passed in silence, which is the failure an SLA exists to
prevent.

```http
POST /api/v1/cases/escalation-policies
{
  "name": "Critical unacknowledged",
  "queue_id": "…",
  "trigger_at_sla_fraction": 0.75,
  "ladder": [
    { "after_minutes": 0,  "notify": "shift-lead@example.com" },
    { "after_minutes": 15, "notify": "soc-manager@example.com" },
    { "after_minutes": 30, "notify": "duty-director@example.com" }
  ]
}
```

Two design points:

**It is keyed on the acknowledgement clock, not resolution.** A case
somebody is working on and has not finished is not the failure an
escalation ladder addresses.

**The trigger is a fraction of the SLA, not a fixed delay.**
Escalating a critical case after the same four hours as a low one
repeats the single-clock mistake the three targets exist to fix.

The ladder is ordered, and each escalation climbs it — so an
unanswered page progresses rather than repeats.

## Shift handoff

The `/shifts` route was removed in v15.0.0 and nothing replaced it, so
a handover was a conversation.

```http
POST /api/v1/cases/handoffs
{
  "to_user_id": "…",
  "queue_id": "…",
  "notes": "CASE-412 waiting on the customer; everything else is quiet."
}
```

The case ids are **snapshotted rather than recomputed** from the
queue. What was handed over is a historical fact, and the queue has
changed since.

`acknowledged_at` is explicit, because an unacknowledged handoff is
not a handoff — a shift that ended with nobody confirming receipt is
exactly the gap a handover exists to close.

## Transition history

A case used to carry its current status and four timestamps, so "who
moved this to resolved, and on what basis" was unanswerable. That is
the first question asked when a closed case turns out to have been an
incident.

Every transition is now recorded with its actor and an `actor_kind` of
`human`, `automation` or `escalation`. A status an analyst chose and
one a timer produced read identically in a status column, and they
mean very different things in a review.

## Task dependencies

`depends_on_task_id` blocks a task until its predecessor completes.
Enforced at the application layer rather than by a constraint, because
the useful behaviour is a clear refusal naming the blocker rather than
a foreign-key error.

## Related

- [Alert prioritisation](./alert-prioritisation.md)
- [Case reports](./case-reports.md)
