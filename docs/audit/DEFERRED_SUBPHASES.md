# The lettered deferrals

**Last updated:** 2026-09-28 (v12.0.0)

Eight sub-phases of the hardening program were deferred with a letter suffix
— 3.5+, 5b, 6b, 7b+, 8b, 9b, 10b, 11b. Six of them were named in `ROADMAP.md`,
which said each was "tracked in `docs/audit/PROGRESS.md`".

That file is in `.gitignore`. It was never committed, the local copy is gone,
and so **the only record of what those six commitments contained was a
filename pointing at nothing.** Six named pieces of work with no scope
anywhere a contributor could read.

This file replaced it, and is committed; `ROADMAP.md` has since been
corrected to point here, and the sentence it used to carry survives only as
the history above. A tracker that is not in the repository is a tracker that
does not exist — the same lesson `docs/roadmap/v8-progress.md` already
carries about staleness, one step further along.

**The other two were found later, and how they were missed is the point.**
The audit that wrote this file read `ROADMAP.md` and stopped there, so a
deferral written down anywhere else was invisible to it by construction. `6b`
was in an ADR and `8b` in a module docstring, both still pointing at the
tracker that was never committed, and neither appeared in any list of these.
`scripts/check_deferral_tracker.py` now derives the set from the whole
tracked tree rather than from a reader's memory: it fails when a deferral is
named anywhere and has no section here, when a section here is for a deferral
nothing references, and when any tracked file still sends a reader to the
file that does not exist.

The scope below is **re-derived from the phase lines in `ROADMAP.md`, from
the two documents that named 6b and 8b, and from the tree** — not recovered.
Where the original intent is genuinely unknowable that is said rather than
guessed at, because inventing a commitment and attributing it to a previous
decision is worse than admitting the record was lost.

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

## 6b — the storage cost model next to the LLM cost

**From the ADR:** *"Follow-up (Phase 6b). Wire the model into the
managed-mode sizing guide and the LLM-cost dashboard so a tenant's storage
$/mo shows next to its LLM $/mo"* —
[`docs/decisions/0005-storage-consolidation.md`](../decisions/0005-storage-consolidation.md).

**Status: open, and it was on no list of these until now.** Phase 6 shipped
the model and its drift gate, and both are real: `scripts/storage_cost_model.py`
computes ≈$902/mo and ≈$30/raw-TB at 1 TB/day, `docs/decisions/storage-cost-model.json`
is the committed worked example, and `.github/workflows/perf.yml` fails when
the two diverge.

Neither half of the follow-up exists. `services/api/app/services/cost_dashboard.py`
and `apps/web/src/app/(admin)/costs/page.tsx` mention storage nowhere — the
dashboard reports LLM spend only — and the "Billing and cost transparency"
section of `apps/docs/docs/operations/managed-instance.md` points at that LLM
dashboard and says nothing about storage. Outside the ADR, the CHANGELOG and
the perf workflow, the model's only readers are two ClickHouse tiering files
citing it in a comment.

**Why it is worth doing:** the ADR's stated reason for computing the number
at all was sizing and the managed-mode pricing shape (ADR-0003). A cost model
whose only consumer is the gate that checks the cost model is a well-tested
constant.

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

## 8b — the inline prompts the registry was built for

**From the module docstring:** *"Migration of the existing inline prompts is
tracked as 8b; this seeds the registry + gate with the canonical
triage/summary prompts"* — `services/agents/app/llm/prompt_registry.py`.

**Status: open, and the gap is countable.** Phase 8 shipped the registry, the
committed `prompts.lock.json` and `scripts/check_prompt_lock.py --check`,
which fails when a prompt's text changes without a version bump. That is the
mechanism making the `AGENTS.md` rule — a prompt change obliges an eval
re-grade — enforceable rather than aspirational.

It is enforceable over three prompts. One production module reads the
registry: `services/agents/app/hunt/agent.py` takes `hunt.system`.
`triage.system` and `summary.system` are registered, hash-pinned and gated,
and nothing under `services/agents/app/` asks for either — while ten modules
there still declare a module-level `_SYSTEM_PROMPT` of their own, the triage,
cloud, identity, insider-threat and phishing agents and the recon, forensic,
responder, report-writer and playbook-drafter among them.

**Why it is worth doing:** every prompt still inline can be edited without a
version bump, without a lock change, and therefore without the re-grade —
which is the exact hole the registry was written to close, left open for all
but one of them.

---

## 9b — live-router wiring and the durable approval-SLA timer

**From the phase line:** *"live-router wiring + durable approval-SLA timer
table tracked as 9b"*.

**Status: substantially closed, and what is left is narrower than this
section used to say.**

The live-router half is done: `services/api/app/api/v1/endpoints/approvals.py`
now carries a decision through to `services/actions` and records on the row
whether it executed, and `POST /actions` consults the confidence × impact
matrix rather than blast radius alone. Durable storage arrived with
`055_action_records.sql`.

**The timer table landed too, and this section was wrong about it.** It
recorded the Slack bot's `ApprovalTimeoutScheduler` as in-process only. A
Postgres-backed store had in fact existed since Phase B3
(`services/slack-bot/app/services/timer_store.py`) — and it genuinely was not
durable, for a reason worth keeping: it created `approval_timers` itself with
`CREATE TABLE IF NOT EXISTS`, outside every migration chain, so once
`061_runtime_app_role.sql` took `CREATE` on schema public away from the
runtime role that call raised at startup and `main.py` fell back to the
in-memory store. Durable approval timers silently stopped being durable.
`062_approval_timers.sql` brought the table into the chain with a `tenant_id`
and an RLS policy; the store now refuses to create it and names the migration
instead, and `recover()` re-arms surviving timers on start.

**What remains is every approval the bot never sees.** The expiry lives in
`services/slack-bot`, a `chatops`-profile service, and is armed per ChatOps
approval. The API's own `agent_approvals` row carries an `expires_at` and its
status vocabulary includes `expired`; nothing writes that status, and no
worker under `services/api/app/workers/` sweeps the column. An approval
raised in the console and never answered still waits forever rather than
timing out to its declared safe default.

---

## 10b — live-vendor sandbox smoke and checkpoint durability

**From the phase line:** *"Live-vendor sandbox smoke + rate-limit/checkpoint
durability tracked as 10b"*.

**Status: one half is credential-blocked; the other has a mechanism and one
adopter.**

Live-vendor smoke needs sandbox accounts with real vendors — an account
action, the same class of blocker as the npm publish and the funded eval key,
not an engineering task. It stays open and says so.

**Checkpoint durability is no longer absent, which this section used to say
it was.** `services/connectors/app/db/connector_repo.py::record_checkpoint`
persists a connector's ingest checkpoint into `connector_config.checkpoint`,
and `services/connectors/app/scheduler.py` seeds it back into the connector
before each poll and writes the advanced value only after the batch was
accepted, so a failed ingest never moves it forward.

What is missing is adoption. `splunk` is the only one of the 84 connectors
implementing `set_checkpoint`/`get_checkpoint`; the scheduler seeds through a
`getattr(connector, "set_checkpoint", None)` that is simply absent on the
other 83. For those, poll state still does not survive a restart — the
connector re-reads its overlap window, which is safe, and means a long outage
silently loses events older than that window.

---

## 11b — per-language generated-client contract drift

**From the phase line:** *"per-language SDK generated-client contract-drift
tracked as 11b"*.

**Status: closed by `scripts/check_sdk_surface.py`.** `openapi-breaking.yml`
catches a spec change that would break a generated client. What it did not
catch was the *hand-written* client drifting from the spec — which is exactly
what v9.0 found in `packages/sdk-ts`: `approvals`, `push`, `onCall` and
`passkeys` were all in `docs/openapi.yaml` and none had a namespace, so the
generated types were complete and the ergonomic surface was three releases
behind.

The gate this section called "the shape to build" — not "does the spec still
generate" but "does every path in the spec have a client surface, or an
explicit exemption" — is what landed. It reads the request sites out of both
hand-written clients and fails when one calls an operation
`docs/openapi.yaml` does not declare; it holds all three languages to the
namespace manifest at `packages/sdk-surface.json` in both directions, so a
recorded gap that has since been filled fails as stale rather than becoming a
permanent licence; and it fails a `package.json` declaring a codegen output
that is not on disk. Writing it found four operations both clients called
that the API does not serve, two of them with a passing test pinning them.

**What it does not prove.** That an operation *exists* — not that the
response matches it. `packages/sdk-ts/src/types.ts` and the Python client's
models are still hand-kept, so a field renamed or retyped in a response
schema breaks both clients with every SDK job green. That is the next gate,
not this one.

---

## What this file is for

Each entry names what remains rather than restating the phase title, because
the failure mode here was a pointer with nothing behind it. Anything blocked
on an account action says so, and stays open rather than being marked done —
`docs/audit/CLAIM_TO_GATE_MATRIX.md` exists for exactly the same reason.
