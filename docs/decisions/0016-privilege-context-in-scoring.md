# ADR-0016: privilege context enters scoring as bounded factors, and `unknown` is a value

- **Status:** accepted
- **Date:** 2026-11-01
- **Related:** [ADR-0010](./0010-entity-and-session-context-in-core.md) (entity context in CORE), [ADR-0011](./0011-behavioural-baselines-in-core.md) (the bounded-contribution precedent)
- **Implements:** depth plan wave 2, Phase 1.1 (carrying the first depth plan's 2.6)

## Context

Six effective-permission resolvers have shipped since T3.2 and migration 103
versioned the posture they read. Nothing consumed either. Phase 1.1 wires
them into the two places a privilege answer changes what a human sees — the
fusion confidence score and the console queue's priority — and into the
triage prompt and the typed-pivot tool surface.

Wiring a new signal into two existing scorers raises three questions that
are easy to answer badly and expensive to revisit, because both scorers are
surfaces an analyst learns to trust or learns to ignore.

## Decision 1 — bounded, and small

`identity_privilege` enters `ConfidenceScorer` at weight **0.06**, the same
weight `asset_criticality` carries, and the eight pre-existing weights are
scaled by **0.94** so the total stays exactly 1.0.

Scaling rather than taking the new weight out of one neighbour keeps every
existing factor's share of the model unchanged *relative to the others*. The
only thing that moved is that all of them together now account for 94%
instead of 100%, which shifts each alert's score slightly and reorders
nothing: a common positive scale factor preserves the ordering of `Σ(w·c)`.

In the queue, privilege is a **multiplier** (`alert_priority.py`'s existing
design: severity is the base, context multiplies) capped so that four tags
together reach 1.21 — less than one criticality step. Context reorders
alerts of similar severity; it cannot invert a severity gap.

The reason both are small is the same reason `asset_criticality` is: this is
context about what an alert is *about*, not evidence that it *happened*. A
scheme where context can outweigh the detection is one that gets switched
off the first time it surprises somebody, and then none of it is worth
anything.

## Decision 2 — the tier comes from the snapshot valid at event time

Not from the live posture row. An alert is fused seconds after the event and
triaged minutes to days later, and a role revoked in between is exactly the
case migration 103 is versioned for.

This is worth an ADR line because the wrong version of it is invisible. A
live-row read returns a tier that looks precisely as plausible as the right
one; there is no error, no log line and no shape in the data that would let
a reviewer notice. The only defence is that the point-in-time call is the
easy one to reach for, which is why `privilege_at` takes a mandatory `at`
and no function in the store answers "the current tier" without saying so in
its name.

## Decision 3 — `unknown` is a stored value and a rendered state

A principal with no posture covering the event time gets `tier = "unknown"`
and four `None` tags, all the way through: a `NOT NULL DEFAULT 'unknown'`
column, a `1.0` entry in the priority table, a `0.0` contribution in the
confidence scorer, a factor row that says "unknown" in words, and a priority
rationale line that says the platform could not answer.

The alternative — defaulting to `standard`, or omitting the factor — makes a
measured ordinary account and an unmeasured one identical. The second is the
one worth escalating, and a product whose job is noticing gaps cannot render
its own biggest gap as reassurance. The same reasoning makes the four tags
`boolean NULL`: `NULL` means no snapshot could answer and `false` means the
snapshot says no, and a surface that renders them the same is fabricating
one of them.

The usage overlay carries the strongest form of this. An install with no
event lake cannot measure which granted permissions were exercised, and
`UsageOverlay.measured` is `False` there rather than an empty used-set.
Collapsing the two would make every right-sizing finding recommend revoking
every permission in the estate.

## Decision 4 — the derivation is tiered on what an identity can *write*

Not on the name of the role it holds. A role called `ReadOnlyAuditor` that
can call `iam:PutUserPolicy` is an administrator, and the name is the part
an attacker controls when they create the role.

`domain_admin` is a wildcard over the whole provider; `admin` is
authorization-write without that wildcard; `elevated` is a wide action
surface with no authorization write — the "powerful but cannot grant" shape,
such as a data engineer with full BigQuery, which a two-tier scheme cannot
express and therefore rounds to one of the two wrong answers.

## What was rejected

**A separate privilege score alongside confidence.** Two numbers describing
one alert drift, and then nobody knows which one the queue used. The
repository has this exact defect on record twice.

**Letting a tag force a severity.** Severity is what the detection claimed
and is compared across deployments; privilege is local context. Conflating
them would make a tenant's posture-collection coverage silently change what
their detections appear to have found.

**Resolving permissions on the fusion hot path.** The resolver takes an
estate-sized policy document, and `services/fusion` cannot import
`services/api` in any case — both name their top-level package `app`. The
expensive resolution runs once per posture version into
`identity_privilege_facts`, and fusion reads one indexed row.

## Consequences

- Every alert's confidence score moves slightly, because the eight existing
  weights were scaled. Measured through the verdict scorecard and the
  alert-reduction suite in the PR that landed it; neither consumes
  `confidence_score`, and both were unchanged.
- A deployment that has collected no posture sees `unknown` on every alert
  and no score movement at all, which is the correct no-op.
- A later lane adding a ninth confidence factor must re-scale again rather
  than appending. `test_rationale_weights_sum_to_one` enforces it.
