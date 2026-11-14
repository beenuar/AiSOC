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


:::warning Schema only: not yet read by anything

Everything from here to "Related" describes **columns and tables migration
087 creates and no code reads**. Verified on a fully-migrated database:
`detection_rule_versions` and `detection_shadow_matches` have zero readers in
`services/`, `shadow_until` has zero, and the only `rollback` in the detection
endpoints is a database transaction rollback.

So a rule set to `dev` still raises alerts, a `shadow_until` in the future
still pages, and there is no route that rolls a rule back. The schema is kept
because the design is settled and the migration has shipped; the behaviour is
not claimed until the PR that wires it lands, under the parity plan.

**What does work is above:** separation of duties on
`POST /api/v1/detection-proposals/{id}/decide`, which compares the caller
against `proposed_by_id` and refuses an approval from the same person.

:::

## Environments (schema only)

| Environment | Column accepts | Evaluates | Raises alerts |
|---|---|---|---|
| `dev` | yes | yes | **yes, today** |
| `staging` | yes | yes | **yes, today** |
| `production` | yes | yes | yes |

The engine does not read `environment`, so all three behave identically.

## Shadow mode (schema only)

`shadow_until` is a timestamp column. Nothing reads it, and
`detection_shadow_matches` is never written, so a rule with a future
`shadow_until` raises alerts exactly as it would without one.

## Versions and rollback (schema only)

`detection_rule_versions` exists and nothing writes to it, so a promotion
still overwrites in place and "roll back the rule we shipped on Tuesday" still
has no answer other than reconstructing it from a pull request.

## Ownership and expiry (schema only)

`owner_email`, `owner_team`, `expires_at` and `review_due_at` are columns a
caller can set. Nothing reads them, so an expiry does not expire a rule and a
review date prompts nobody.

## Related

- [Shadow mode](./shadow-mode.md) for the agent-level equivalent
- [Detection coverage](../detections/coverage.md)
