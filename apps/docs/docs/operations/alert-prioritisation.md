---
id: alert-prioritisation
title: Alert prioritisation
sidebar_label: Alert prioritisation
---

# Alert prioritisation

Two alerts of equal severity — one on a domain controller, one on a
meeting-room display — used to arrive in the queue in the order they
were raised. An analyst worked out which was which by reading the
hostname.

`assets.criticality` existed the whole time. It reached a prompt
string and a sort order, and nothing prioritised on it.

## Context multiplies severity, it never adds

This is the design decision everything else follows from.

Addition lets a stack of small contextual bumps push an informational
alert above a critical one, which is how a prioritisation scheme gets
switched off after the first time it surprises somebody. Multiplying
means context can **reorder alerts of similar severity** — which is
what it is for — and **cannot invert a severity gap**.

The product is clamped, so no single signal dominates. A domain
controller is more important than a laptop; it is not infinitely more
important.

## What moves the number

| Factor | Effect | Why it counts |
|---|---|---|
| Severity | Base, 50–900 | What the detection claimed |
| Asset criticality | ×0.7 – ×1.6 | A domain controller is not a meeting-room display |
| Known Exploited Vulnerability on the host | ×1.4 | A technique *known to work*, which is a different fact from a high CVSS score |
| Other exploitable vulnerabilities | ×1.15 | Weaker signal, same direction |
| Internet-facing | ×1.2 | Reachable without a foothold |
| Privilege tier | ×1.0 – ×1.5 | A domain admin changes the blast radius from one host to the estate |
| Break-glass account | ×1.45 | These are *expected* to be dormant, so any activity is notable |

Vulnerability context is read from the tenant's **own**
`asset_vulnerabilities` inventory, not from an enrichment response.
That table already held the answer and only the enrichment path ever
read it.

## The ordering is interrogable

Every factor that moved the score is recorded with its contribution:

```json
{
  "score": 1000,
  "base": 600,
  "rationale": [
    { "factor": 1.6,  "reason": "asset criticality is critical" },
    { "factor": 1.4,  "reason": "the host runs something on the Known Exploited Vulnerabilities catalogue" },
    { "factor": 1.35, "reason": "the principal holds admin privilege" }
  ]
}
```

An ordering a person cannot interrogate is one they stop trusting the
first time it surprises them. Nothing is recorded when nothing
moved — a rationale full of ×1.00 entries is noise that teaches people
to stop reading it.

## Priority is not severity

Severity is what the detection claimed, and it is compared across
deployments. Priority is local and says what to look at first *here*.

Conflating them would let a tenant's CMDB quality silently change what
their detections appear to have found, so prioritisation never writes
back to `severity`.

## Scored once, at claim time

`alerts.priority_score` is stored rather than computed at read time,
for two reasons. The queue sorts on it, and a computed sort over a
join is what makes a queue slow at exactly the moment it is busiest.
And an analyst asking "why was this top of my queue" needs the answer
that applied **then**, not the one today's CMDB produces.

`NULL` means not yet scored, which is distinct from `0` — scored, and
genuinely low.

## Without a CMDB

Most deployments have no asset inventory on day one, and the queue
still works: with no context the score is severity alone. An unknown
criticality leaves the score unchanged and says so in the rationale
rather than guessing.

An unknown *severity* ranks as medium and records why. A connector
emitting a tier this deployment does not know is a mapping bug, and
dropping the alert out of the queue over it would be worse than
ranking it in the middle and being explicit.

## Identity privilege

`identity_privilege` is a per-tenant table. No privileged-account
field existed anywhere before it — an alert on a service account with
domain-admin rights was indistinguishable in the schema from a
contractor's laptop login.

| Column | Meaning |
|---|---|
| `privilege_tier` | `standard`, `elevated`, `admin`, `domain_admin` |
| `is_service` | No interactive logons, predictable hours; compromise usually means a stolen key |
| `is_break_glass` | Expected to be dormant |

Principals are lowercased before write. `SVC-Backup` and `svc-backup`
are one account, and two rows would make the lookup depend on which
connector reported first.

## Related

- [Case orchestration](./case-orchestration.md)
- [Asset inventory](../console/investigation-rail.md)
