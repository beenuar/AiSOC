# ADR-0014: tenant erasure crosses the audit-log immutability trigger; nothing smaller does

- **Status:** accepted
- **Date:** 2026-10-12
- **Related:** migration `004` (the trigger and the `ON DELETE CASCADE` it contradicts), migration `101` (the `actor_id` SET NULL exemption), migration `117` (the retention arm, and the same cascade arm on the checkpoint table), migration `119` (this decision), issue #1330
- **Implements:** the fix issue #1330 asked for, with the acceptance tests it named

## Context

`DELETE FROM tenants` raised for any tenant that had ever written an audit
row — in practice, every tenant. `audit_log.tenant_id` has declared
`REFERENCES tenants(id) ON DELETE CASCADE` since migration 004, and the same
migration put a `BEFORE DELETE` trigger on the table that refuses every
delete. A cascade is an ordinary DELETE on the child, so the foreign key's
own declared behaviour could never fire: the parent statement aborted, and
`tenant_deletion.py` — the path a GDPR erasure request goes through — could
not complete. The claim-to-gate matrix row for tenant offboarding stayed
green throughout, because its test database held no audit rows; the audit
retention row (ADR-0013) carried the honest caveat instead.

Migration 117 met the identical problem on the checkpoint table it added and
solved it there, deliberately leaving `audit_log` alone: relaxing a shipped
immutability control is a security decision that deserves its own change,
its own ADR and its own live test, rather than riding along in a retention
PR. This is that change.

## Decision

The trigger learns to tell a cascade from a direct delete, using the fact
PostgreSQL gives it for free: `ON DELETE CASCADE` executes as an AFTER
trigger on the parent, so by the time the child's BEFORE DELETE trigger
runs, the tenant row is already gone. A direct DELETE still finds its
tenant and is refused. `tenant_id` is NOT NULL, so a row whose tenant is
absent can only be mid-cascade. The identical arm has run on
`aisoc_audit_checkpoints` since 117.

## The trade, stated plainly

Erasing a tenant's audit history now has exactly one non-checkpointed path:
destroying the tenant, which takes every alert, case, connector and
credential with it. That is loud, irreversible, and useless for selective
tampering — an attacker who wants one incriminating row gone cannot get it
without deleting the customer, and the absence of a tenant is not a secret.
What stays impossible:

- **A direct `DELETE FROM audit_log` while the tenant exists**, refused
  twice over: migration 117 revoked DELETE from the runtime role, and the
  trigger refuses any role that does hold the privilege (including the
  table owner and a superuser, for whom the privilege layer does not
  apply).
- **Selective erasure.** The only row-level removal remains
  `audit_retention_truncate` (ADR-0013), which writes a checkpoint the
  chain verifier re-anchors on.
- **Editing.** The UPDATE arm is unchanged: `actor_id` value→NULL for the
  user-deletion FK, and nothing else.

One consequence worth naming: the cascade bypasses the hash chain's
bookkeeping entirely, which is correct — after erasure there is no tenant
left whose chain could verify, so there is nothing to re-anchor. A partial
failure cannot strand a half-erased chain either, because the cascade and
the parent delete are one statement in one transaction.

## How it is proven

`tests/isolation/test_audit_immutability_live.py` runs against real
Postgres as the DML-only `aisoc_app` role (wired into
`audit-forgery-live.yml`, which until now ran a different file and left
this suite attached to no workflow at all):

- deleting a tenant that holds audit rows succeeds as the runtime role, and
  the rows go with it — proving the referential action carries the owner's
  privilege past both the revoke and the trigger;
- a direct `DELETE FROM audit_log` while the tenant exists is still
  refused for the runtime role (privilege layer);
- the same direct DELETE is refused for the table owner too (trigger
  layer), via the owner DSN the workflow already has — so the control does
  not quietly become privilege-only.
