---
id: data-governance
title: Data governance
sidebar_label: Data governance
---

# Data governance

Legal hold, data residency, field-level access and per-subject
deletion. Four controls that share one property: each decides whether
data may be *kept*, *moved*, *seen* or *removed*, and each fails
closed.

## Legal hold

**A hold outranks retention unconditionally.**

Any arrangement where retention can win is a system that deletes
evidence under litigation, which is the one outcome that cannot be
apologised for. Before this existed, the correct response to "preserve
everything relating to this account pending litigation" was to disable
retention for the whole tenant and remember to turn it back on.

```http
POST /api/v1/governance/legal-holds
{
  "name": "Matter 2026-01 — departing employee",
  "matter_ref": "MAT-2026-01",
  "subject_kind": "user",
  "subject_value": "j.okafor@example.com"
}
```

A hold is stored as a **predicate, not a list of row ids**. The rows a
hold covers keep arriving after it is placed, and a hold frozen to the
ids that existed when it was written would cover none of the evidence
created during the incident it was placed for.

`subject_kind` is one of `user`, `host`, `case`, `alert`, `ip` or
`tenant`. Matching is case-insensitive: `SVC-Backup` and `svc-backup`
are one account, and a hold that missed one spelling would preserve
half the evidence.

### Releasing

Releasing is an **event with an actor**, not a deletion. A hold that
vanished would leave no evidence it ever existed, which defeats the
audit it was placed for.

```http
POST /api/v1/governance/legal-holds/{id}/release
{ "reason": "Matter closed 2026-09-30" }
```

### How retention sees it

The retention worker reads live holds **before every run** rather than
caching them. A cache measured in hours is a cache that deletes
evidence placed under hold this morning.

The decision object carries the hold that refused, so a caller cannot
flatten "held" to a boolean and treat it as "not expired".

## Residency

Two fields on the tenant: `data_region`, and `residency_enforced`.

Enforcement is **off by default**, and deliberately so — turning it on
for an existing tenant whose data already spans regions would break it
silently. Adopting it is a step you take.

When it is on:

| Situation | Outcome |
|---|---|
| Operation targets the tenant's region | Allowed |
| Operation targets a different region | **Refused**, violation recorded |
| Operation declares no region | **Refused** — it cannot be shown to respect the constraint |
| Enforcement on, tenant declares no region | **Refused** — the alternative permits everything under a setting an operator believes is strict |

Violations are written to `residency_violations` **even when the
operation is refused**. A refusal nobody counted cannot answer "has
this ever happened", which is the question an auditor asks.

## Field-level access

A viewer who can read an alert used to read every field of it,
including the raw event, which carries whatever the source put there.

```http
POST /api/v1/governance/field-rules
{
  "resource": "alert",
  "field_path": "raw_event.user.email",
  "visible_to_roles": ["admin", "soc_lead"],
  "treatment": "hash"
}
```

| Treatment | Result | Use when |
|---|---|---|
| `redact` | `[redacted]` | The value should not be seen at all |
| `mask` | `••••1234` | An analyst needs to correlate without reading it |
| `hash` | `sha256:a1b2…` | Two records carrying the same value must stay recognisably the same |
| `omit` | Field absent | The field's existence is itself sensitive |

**A withheld field is named in the response.** A missing field and a
hidden one look identical to a client, and an analyst needs to know
whether the source IP is absent or withheld — those lead to opposite
next steps.

Dotted paths reach into `raw_event`, which is where a source puts
whatever it likes and the field most worth constraining. A rule naming
a field a record does not carry is **not** reported as withheld, or
the response would claim to be hiding something it never had.

## Per-subject deletion

`tenant_deletion` removes a whole tenant. "Delete everything about
this person" is a different question and the common one.

```http
POST /api/v1/governance/subject-deletions
{ "subject_kind": "user", "subject_value": "former.employee@example.com" }
```

A request lands in one of five states, and `blocked_by_hold` is its own
state rather than a failure — a deletion refused because of litigation
is a **correct outcome** that has to be reportable to the person who
asked.

Completion records `affected_counts` per table. An auditor needs the
counts, and a deletion that reports only "done" cannot be verified.

## Signed exports

Export bundles carry a detached Ed25519 signature, recorded in
`export_signatures` as well as in the bundle — so a recipient can
verify against a record the sender cannot alter after the fact.

The row also carries `row_count` and a digest of the query, so a
recipient can tell a partial export from a complete one. An export
that omits rows and does not say so is worse than no export.

## Related

- [Retention and data lifecycle](./performance.md)
- [Security model](./security.md)
