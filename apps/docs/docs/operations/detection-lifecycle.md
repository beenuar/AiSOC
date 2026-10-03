---
id: detection-lifecycle
title: Detection lifecycle
sidebar_label: Detection lifecycle
---

# Detection lifecycle

How a rule gets from an idea to the engine, how you watch it before it
pages anyone, and how you take it back out at two in the morning.

## Separation of duties

**The author of a rule cannot approve it.**

`POST /api/v1/detection-proposals/{id}/decide` compares the caller
against `proposed_by_id` and refuses an approval from the same person.
This is the surface that writes executable code into the detection
engine, and until recently it was the only governed surface in the
product with no second-person requirement — action approval, playbook
dispatch and MSSP overrides all had one.

Two deliberate exceptions:

- **Rejecting your own proposal is allowed.** That is withdrawing it,
  and requiring a second person would strand bad proposals.
- **A proposal with no author is not blocked.** Rules imported from the
  shipped corpus have no proposer, and refusing them would make the
  catalogue unapprovable.

On a single-analyst deployment:

```bash
AISOC_DETECTION_SOD_ENFORCED=0
```

Off by choice and recorded, rather than a control so rigid people
disable it entirely.

## The approval gate

Approving requires the candidate rule to have been replayed against its
own fixtures — it must fire on every positive and stay silent on every
negative. `/decide` answers **412** without that verdict.

Fixtures are stored on the proposal. They did not used to be, which
made the gate unreachable twice over: the console had no caller for the
evaluate route, and calling it directly meant re-deriving fixtures the
drafter had already produced and discarded. A proposal that cannot
prove itself can never be approved.

```bash
POST /api/v1/detection-proposals/{id}/evaluate-rule
```

The request body is optional. Omit it and the proposal's own fixtures
are replayed; supply fixtures to override them for one run.

## Environments

| Environment | Evaluates | Raises alerts | For |
|---|---|---|---|
| `dev` | Yes | No | A rule nobody has reviewed |
| `staging` | Yes | No | A reviewed rule earning confidence on live traffic |
| `production` | Yes | Yes | Live detection |

## Shadow mode

`shadow_until` is a timestamp, and it is **independent of
environment** — a production rule can be shadowed during a tuning
change without being demoted and losing its history.

While it is set and in the future, the rule is evaluated and its
matches recorded, and it raises nothing.

Matches land in `detection_shadow_matches`, a separate table rather
than a flag on `alerts`. That is the whole point: no query and no
person can mistake a shadow match for an alert.

```sql
SELECT rule_id, count(*) AS would_have_fired
  FROM detection_shadow_matches
 WHERE matched_at > now() - interval '24 hours'
 GROUP BY rule_id
 ORDER BY would_have_fired DESC;
```

A rule at the top of that list would have been your noisiest detection.

## Versions and rollback

Every body a rule has ever had live is kept in
`detection_rule_versions`. Promotion used to overwrite in place, so
"roll back the rule we shipped on Tuesday" had no answer other than
reconstructing it from a pull request — which is exactly the question
asked when a detection starts firing on everything overnight.

Versions are numbered with a **monotonic integer, not a timestamp**.
Two promotions in the same second are ordinary during a tuning session,
and "the version before this one" has to have exactly one answer.

A rollback writes a **new version carrying an old body** rather than
deleting rows, so the history of what was live when stays intact and
`rolled_back_from` records where the body came from.

## Ownership and expiry

| Field | Why |
|---|---|
| `owner_email`, `owner_team` | A rule written for an incident three years ago was indistinguishable from one somebody maintains |
| `expires_at` | Nullable. A rule with no expiry is permanent, which is a legitimate choice — what was missing was the ability to say otherwise |
| `review_due_at` | A prompt to re-check a rule that is still correct but no longer load-bearing |

## Related

- [Shadow mode](./shadow-mode.md) for the agent-level equivalent
- [Detection coverage](../detections/coverage.md)
