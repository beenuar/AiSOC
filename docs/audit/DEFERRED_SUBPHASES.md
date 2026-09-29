# The lettered deferrals

**Last updated:** 2026-09-29 (v12.2.0)

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

**Status: both halves built, in [#1040](https://github.com/beenuar/AiSOC/pull/1040).**
`apps/web/e2e/demo-stack/` asserts against the stack `pnpm aisoc:demo`
starts — kept separate from `journey`, which stubs the network, and from
`screenshots`, whose own header calls its tests recorders rather than
assertions. `docs/perf/demo-timing.json` records the runs the bound came
from and `scripts/check_demo_timing.py` enforces it, refusing a declaration
without its provenance and a ceiling below the worst run it cites.

**Two defects the gate found while being written.** `isPortFree` binds
127.0.0.1 and claimed to be "the same test Docker is going to run"; Docker's
allocator refuses a port another *container* holds, so the demo took 5432
anyway and postgres started with no network attached — postgres healthy, API
healthy, seed exited 1, console empty. And the harness polled `/v1/cases`
where the API serves `/api/v1/cases`, which is why the showcase lookup cost
exactly 60 s on every run. Fixing the first took the stack from 3m06s to
1m39s.

**What stays open, recorded beside the number rather than implicitly.**
`seed_demo.py` still fails on a fresh demo stack, so the console has no
cases in it: the ORM maps `CaseTask` to `case_tasks` while migration 027
creates `aisoc_case_tasks` with a different column set. `create_all` papered
over it until `061_runtime_app_role.sql` took `CREATE` on schema public
away, and the permission error is swallowed as "create_all skipped (likely
already applied)". Reconciling two designs for one table is a schema change,
not a timing gate.

---

## 5b — backfill and replay-from-offset

**From the phase line:** *"backfill/replay-from-offset tracked as 5b"*.

**Status: closed in [#1036](https://github.com/beenuar/AiSOC/pull/1036).**
`POST /api/v1/health/dead-letters/replay` re-reads a bounded range from a
given `(topic, partition, offset)`, re-validates it and produces what now
passes.

The row could never have been the thing replayed: `aisoc_dead_letters`
stores a 2,000-character excerpt, truncated on purpose. The faithful copy is
in Kafka, and reaching it needed the partition and offset the consumer had
in hand and discarded — now carried through `_dead_letter` and persisted,
nullable, because a fabricated offset replays somebody else's message.

The property that matters is not the bound or the permission: **a message is
re-validated by the validator that refused it, and one that still fails is
refused again rather than produced.** Replaying a poison batch into the
consumer that rejected it reproduces the outage, so a preview whose
`would_pass` is zero is the answer "your fix has not landed". Dry run is the
default at three layers, and on a dry run the producer is never constructed.
Proved against Redpanda with a negative control: deleting `consumer.seek()`
makes the live test fail, which every fake-client test in the suite would
have passed.

---

## 6b — the storage cost model next to the LLM cost

**From the ADR:** *"Follow-up (Phase 6b). Wire the model into the
managed-mode sizing guide and the LLM-cost dashboard so a tenant's storage
$/mo shows next to its LLM $/mo"* —
[`docs/decisions/0005-storage-consolidation.md`](../decisions/0005-storage-consolidation.md).

**Status: closed in [#1019](https://github.com/beenuar/AiSOC/pull/1019).**
`GET /api/v1/costs/dashboard` carries a `storage` block and the console
renders it. It rests on one measurement — the uncompressed bytes a tenant's
events occupied in the lake over the window — and runs the committed model
over it.

Three properties are asserted rather than asserted-to: it is badged a
projection and no field is named `*_cost_usd`, so the naming is itself the
label; it is a sibling of the headline and never a term in it, because one
number cannot be labelled two ways; and on a CORE deployment, where the lake
does not run, every money field is null with the reason attached rather than
a confident `$0.00`. The rate card is mirrored into the API because the
script cannot be imported there, and `storage_cost_model.py --check` now
reads the mirror back — closing "the model has no consumer" by adding one
that could silently quote different prices would have been the worse
outcome.

---

## 7b+ — posture collection and the fusion-time context bundle

**From the phase line:** *"7b+ (posture collection, effective-permissions
snapshot loader, bi-temporal valid_from/valid_to, fusion-time ContextBundle)"*.

**Status: still open, and still exactly one thing.** No connector answers
`__posture_snapshot__`, so four of the five effective-permissions resolvers
return 412. Bi-temporal `valid_from`/`valid_to` landed in T1.2 and the
resolvers themselves all ship reporting `coverage: "full"`.

**Re-derived rather than restated, because the shape of the remaining work
was not previously written down.** `__posture_snapshot__` is not a method or
an attribute — it is a sentinel `resource_id` passed to
`get_resource_config(resource_id, at_ts)`, and a connector answers it by
branching on the literal value and returning a reconciled snapshot in the
shape its resolver expects. Only five of the 84 connectors implement
`get_resource_config` at all, and of the four providers that 412
(`aws_security_hub`, `azure_entra`, `gcp_scc`, `google_workspace`), two
implement it for an unrelated id shape and two do not implement it at all.
Okta is the one that works, and it works because `posture_loader` assembles
its snapshot from several ordinary `get_resource_config` reads rather than
from the sentinel.

So closing this is four provider-specific snapshot collectors over real
vendor APIs — IAM policies and SCPs for AWS, role assignments for Azure,
IAM bindings for GCP, roles and privileges for Workspace — each returning
the shape its resolver already consumes, and each needing credentials to
verify against. That is a piece of work in its own right, not a loose end,
and it is left open rather than part-built.

`services/api/tests/test_posture_snapshot_coverage.py` already encodes the
gap as data, with a test per provider that fails the moment a connector
starts referencing the sentinel. That test is the thing to delete last.

---

## 8b — the inline prompts the registry was built for

**From the module docstring:** *"Migration of the existing inline prompts is
tracked as 8b; this seeds the registry + gate with the canonical
triage/summary prompts"* — `services/agents/app/llm/prompt_registry.py`.

**Status: closed in [#1016](https://github.com/beenuar/AiSOC/pull/1016).**
Coverage went from 3 registered / 1 read / 21 shipped-unpinned to 22
registered / 22 read / 0 shipped-unpinned.

The gate runs in both directions now. `inline-prompt` catches a module-level
string reaching a system-message sink, detected by what the constant *is*
rather than by its name — a sweep for `_SYSTEM_PROMPT` missed
`deep_investigation._SYSTEM_PREAMBLE` and the ten-prompt
`contextual._SYSTEM_PROMPTS` dict — and follows assignment to a fixed point,
because three of the twelve reached their sink through a local first.
`unread-prompt` catches the other direction: `summary.system` was hash-pinned
for a summariser this service does not have.

**`register()` no longer strips, and the measurement is the reason.** Ten of
the migrated prompts ended in a newline, and trimming it changed the
completion for six of those ten on `qwen2.5:0.5b` at temperature 0 — against
a control where the same prompt asked twice was identical 10/10. A
normalisation the author cannot see is an undeclared prompt change performed
by the registry itself. All 21 migrated prompts hash identically to the
literal they were moved from, so no model call changed; the one deliberate
text change is `triage.system` v1 → v2, a placeholder nobody read replaced
by the production prompt.

---

## 9b — live-router wiring and the durable approval-SLA timer

**From the phase line:** *"live-router wiring + durable approval-SLA timer
table tracked as 9b"*.

**Status: closed in [#1038](https://github.com/beenuar/AiSOC/pull/1038).**
The live-router half and the durable timer table had already landed; what
remained was every approval the ChatOps bot never sees.

`agent_approvals` has carried an `expires_at` and an `expired` status since
migration 009, and nothing wrote that status and no worker swept the column,
so a console-raised approval nobody answered waited forever — invisibly,
because the row stayed `pending` and nobody could tell it from one still
under consideration. `app/workers/approval_expiry.py` sweeps it.

Three decisions worth keeping. The safe default is `rejected` and is read
back from the two places that already declare it rather than restated, since
two halves timing out differently would be worse than either. Expiring is
not deciding: nothing is dispatched, and `/decide` still accepts an
`expired` row, so a human returning to a timed-out request can still act —
a test pins that guard. And an approval with no `expires_at` is *counted*,
not given one, because inventing a window would start expiring containments
on a schedule nobody chose.

---

## 10b — live-vendor sandbox smoke and checkpoint durability

**From the phase line:** *"Live-vendor sandbox smoke + rate-limit/checkpoint
durability tracked as 10b"*.

**Status: one half closed in [#1039](https://github.com/beenuar/AiSOC/pull/1039);
the other is credential-blocked and stays open.**

**Checkpoint adoption: 1 connector of 84 → 5.** The durable machinery
already worked; what was missing was adoption, and the reason it stayed
missing is the point. The scheduler reached the connector through
`getattr(connector, "set_checkpoint", None)`, absent on 83 of 84 — a
duck-typed optional protocol has no failing state, only a quiet one, and
nothing could report which connectors resumed. The contract is on
`BaseConnector` now, adopting is two class attributes, `checkpoints()`
answers the question, and a test asserts the adopter set is exactly the
recorded one so losing one fails loudly. `splunk` moved onto the shared
machinery with its eight existing tests unchanged. The remaining 79 are
recorded as not-checkpointing rather than described as done.

**Live-vendor sandbox smoke stays open.** It needs sandbox accounts with
real vendors — an account action, the same class of blocker as the npm
publish and the funded eval key, not an engineering task.

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
