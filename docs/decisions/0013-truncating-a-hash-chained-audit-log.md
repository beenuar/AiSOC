# ADR-0013: truncating a hash-chained audit log, without making an intact chain look tampered with

- **Status:** accepted
- **Date:** 2026-10-11
- **Related:** migration `043` (the hash chain), migration `101` (the one legal mutation, pinned to `actor_id`), migration `111` (this decision)
- **Implements:** depth plan 8.1, the remainder of parity 4.4

## Context

`retention_policies.audit_days` has been storable since the table existed and
was purged by nothing. The retention worker said so in its own module
docstring, and said why:

> The audit log is an append-only hash chain (migration 043) whose entire
> value is that no row was deleted, reordered, or rewritten; a retention
> purge would break the chain and make every subsequent verification fail.
> Enforcing an audit retention window needs chain-aware truncation with a
> re-anchored checkpoint, which is a different piece of work.

Saying it in one place beat a purge that silently errored every tick. It still
left an operator who configured `audit_days` with a setting the product
ignored, and an erasure request with no mechanism behind it.

The difficulty is specific and worth stating precisely, because it is what
rules out the obvious implementation. `verify_chain_breaks` replays a tenant's
rows oldest-first starting from `prev_hash = NULL`. Delete the oldest rows and
the new first row names a predecessor that no longer exists, so the replay
reports `prev_hash mismatch` at index 0. A chain that is perfectly intact then
reads as tampered with — which is the worst available outcome for a control
whose only job is to tell those two apart, because the false alarm is
indistinguishable from the real thing and the next one gets ignored.

## Decision

Removal goes through one `SECURITY DEFINER` function, `audit_retention_truncate`,
which writes a **checkpoint** and then deletes, in a single transaction. The
checkpoint records the cutoff that was applied, the window that produced it,
how many rows went, the hash of the last row removed, and the predecessor the
oldest survivor names. Verification re-anchors on that checkpoint:
`verify_chain_breaks` and `verify_chain` take an optional `anchor_prev_hash`,
defaulting to `None`, which is the genesis case every untruncated tenant
still gets.

Three consequences follow, and each is a deliberate choice rather than a
detail of the implementation.

**The removal becomes a fact rather than an absence.** A plain `DELETE` leaves
an auditor inferring that rows are missing from a gap in `chain_index`. A
checkpoint states what went, when, and under which policy — "everything before
13 July went" and "a 90-day window was in force" answer different questions,
and an auditor asks the second.

**The checkpoint can be checked against itself.** `last_removed_hash` is read
from the removed side and `first_retained_prev_hash` from the surviving side.
On an untampered chain the two are equal. Storing one would have been enough
to re-anchor the replay; storing both means a checkpoint that disagrees with
itself is evidence in its own right.

**The function is the only path, enforced by privilege and not by convention.**
The application role has no `DELETE` on `audit_log` at all. The trigger's
transaction-local `app.audit_retention_purge` setting is a second control, but
a custom GUC can be set by anybody, so on its own it would be a comment rather
than a mechanism; Postgres checks the privilege before the trigger runs, so a
caller who guesses the setting's name is refused one layer below the one they
were aiming at. `SET search_path` is pinned on the function, because a
definer-rights function whose caller controls `search_path` can be pointed at
an `audit_log` the caller owns.

## Alternatives rejected

**Delete and accept the broken verification.** Cheapest, and it destroys the
only property the chain has. A verifier that reports a break on every
truncated tenant trains its reader to ignore it.

**Re-chain the survivors — recompute hashes from a new genesis.** Rewriting
`prev_hash` and `entry_hash` on rows that were not changed is exactly the
operation the chain exists to detect, and it would need the immutability
trigger relaxed for `UPDATE` as well as `DELETE`. It also destroys the
evidence: after re-chaining, a tenant whose rows were tampered with and then
"retained" verifies clean.

**Move old rows to an archive table instead of deleting them.** This answers
retention and not erasure — the rows are still in the database, so it does not
satisfy a request to remove them, which is the half the operator was asking
for. It can be built later on top of this: the checkpoint is what makes the
remaining chain verifiable either way.

**A soft-delete flag.** Same objection, plus every reader now has to remember
the predicate, and the one that forgets reports deleted rows as present.

## What this does not do

**It does not unblock tenant deletion.** `audit_log`'s immutability trigger,
from migration `101`, refuses every `DELETE` including the cascade from
`tenants`. So `DELETE FROM tenants` raises for any tenant that has ever
written an audit row, which is every tenant, and `tenant_deletion.py` inherits
that. The behaviour predates this decision and relaxing a shipped immutability
control belongs in its own change with its own ADR; it is tracked separately.

The checkpoint table added here does **not** repeat the shape. Its foreign key
declares `ON DELETE CASCADE` and the trigger permits exactly that cascade,
told apart from a direct `DELETE` by whether the parent tenant is still
present — PostgreSQL runs a cascade as an AFTER trigger on the parent, so the
tenant row is already gone by the time the child's BEFORE trigger runs, while
a caller deleting checkpoints directly still has their tenant. The exception is
narrow and expensive on purpose: erasing the record of a truncation costs the
entire tenant, every alert, case and credential with it, which is not
selective erasure in any useful sense.

**It does not decide the window.** `audit_days` is a per-tenant policy with no
default, and absence of a policy means no truncation. A backfilled default
would silently start deleting audit history on upgrade.

## How this is kept true

`.github/workflows/audit-retention-live.yml` runs
`tests/isolation/test_audit_retention_live.py` against real Postgres, as the
DML-only `aisoc_app` role rather than the owner — as the owner the suite would
pass with the privilege half removed. The workflow reads the `DELETE`
privilege straight out of the catalogue, refuses a run that skipped its cases,
and carries a negative control that ignores the checkpoint anchor and requires
the suite to go red.
