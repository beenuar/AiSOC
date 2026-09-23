# The lettered deferrals

**Last updated:** 2026-09-23 (v9.0)

Six sub-phases of the hardening program were deferred with a letter suffix —
3.5+, 5b, 7b+, 9b, 10b, 11b — and `ROADMAP.md` says each is "tracked in
`docs/audit/PROGRESS.md`".

That file is in `.gitignore`. It was never committed, the local copy is gone,
and so **the only record of what these six commitments contain was a filename
pointing at nothing.** Six named pieces of work with no scope anywhere a
contributor could read.

This file replaces it, and is committed. A tracker that is not in the
repository is a tracker that does not exist — the same lesson
`docs/roadmap/v8-progress.md` already carries about staleness, one step
further along.

The scope below is **re-derived from the phase lines in `ROADMAP.md` and from
the tree**, not recovered. Where the original intent is genuinely unknowable
that is said rather than guessed at, because inventing a commitment and
attributing it to a previous decision is worse than admitting the record was
lost.

---

## 3.5+ — heavy-demo-stack E2E and the demo-timing gate

**From the phase line:** *"heavy-demo-stack Playwright E2E + demo-timing gate
tracked as non-blocking 3.5+"*.

**Status: open.** Playwright E2E exists against the hermetic stack. What does
not exist is a run against the full demo stack, or a gate on how long the demo
takes to become usable.

**Why it is worth doing:** `packages/aisoc-sandbox` has a cold-start gate
(`aisoc-sandbox demo` in under 30 s) and the devcontainer has one. The demo
stack — the thing `make demo` starts and a first-time reader actually meets —
has neither, so it can get slower indefinitely without anyone noticing.

---

## 5b — backfill and replay-from-offset

**From the phase line:** *"backfill/replay-from-offset tracked as 5b"*.

**Status: open.** Phase 5 shipped the schema registry, the dead-letter queue
and event-time watermarking. What is missing is the operator action that
follows a DLQ: having captured a poison batch, replay it from a given Kafka
offset after fixing the cause.

**Why it is worth doing:** a dead-letter queue nobody can drain is an audit
trail, not a recovery mechanism. `GET /api/v1/health/dead-letters` reports the
backlog and nothing consumes it.

---

## 7b+ — posture collection and the fusion-time context bundle

**From the phase line:** *"7b+ (posture collection, effective-permissions
snapshot loader, bi-temporal valid_from/valid_to, fusion-time ContextBundle)"*.

**Status: partially closed, and the remaining gap is precisely named.**

v8.1's audit found all five effective-permissions resolvers already shipped
and reporting `coverage: "full"`. The gap is not the resolvers: **no connector
answers `__posture_snapshot__`, so four of the five return 412.** Bi-temporal
`valid_from`/`valid_to` landed in T1.2.

So what remains of 7b is one thing: a connector-side posture snapshot.

---

## 9b — live-router wiring and the durable approval-SLA timer

**From the phase line:** *"live-router wiring + durable approval-SLA timer
table tracked as 9b"*.

**Status: substantially closed in v9.0, and the rest is named.**

The live-router half is done: `services/api/app/api/v1/endpoints/approvals.py`
now carries a decision through to `services/actions` and records on the row
whether it executed, and `POST /actions` consults the confidence × impact
matrix rather than blast radius alone.

Durable storage arrived with `055_action_records.sql`. What is still missing
is the **timer**: nothing expires an approval that nobody answers, so a
pending containment waits forever rather than escalating or timing out to its
declared safe default. The Slack bot has an in-process
`ApprovalTimeoutScheduler`; it does not survive a restart, which is the same
class of defect the action store had.

---

## 10b — live-vendor sandbox smoke and checkpoint durability

**From the phase line:** *"Live-vendor sandbox smoke + rate-limit/checkpoint
durability tracked as 10b"*.

**Status: open, and one half is credential-blocked.**

Live-vendor smoke needs sandbox accounts with real vendors — an account
action, the same class of blocker as the npm publish and the funded eval key,
not an engineering task.

Checkpoint durability is not blocked and is worth doing: connector poll state
is module-scoped and keyed by base URL plus saved search, so it does not
survive a restart. A connector that restarts re-reads its overlap window,
which is safe but means a long outage silently loses events older than the
window.

---

## 11b — per-language generated-client contract drift

**From the phase line:** *"per-language SDK generated-client contract-drift
tracked as 11b"*, and it is one of the nine `PARTIAL` rows in
`CLAIM_TO_GATE_MATRIX.md`.

**Status: open.** `openapi-breaking.yml` catches a spec change that would
break a generated client. What it does not catch is the *hand-written* client
drifting from the spec — which is exactly what v9.0 found in `packages/sdk-ts`:
`approvals`, `push`, `onCall` and `passkeys` were all in `docs/openapi.yaml`
and none had a namespace, so the generated types were complete and the
ergonomic surface was three releases behind.

**The gate that closes this** is therefore not "does the spec still generate"
but "does every path in the spec have a client surface, or an explicit
exemption". That is the shape to build.

---

## What this file is for

Each entry names what remains rather than restating the phase title, because
the failure mode here was a pointer with nothing behind it. Anything blocked
on an account action says so, and stays open rather than being marked done —
`docs/audit/CLAIM_TO_GATE_MATRIX.md` exists for exactly the same reason.
