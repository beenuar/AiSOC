# 0009: Whether a tenant with no closure policy may auto-close

- **Status**: Proposed. **Awaiting a maintainer decision.**
- **Date**: 2026-10-04
- **Context**: fix-pass item 1.4 (`plans/aisoc_fix_pass_plan.plan.md`)

## The question

A tenant that has **no** `aisoc_closure_policies` row today auto-closes any
alert whose confidence clears `AISOC_AUTO_CLOSE_THRESHOLD`, a process-wide
default of 0.85, with no grant of any kind.

A tenant that **does** have a policy row is held to `require_grant`, which
migration 078 defaults to true, so it may only auto-close a class that has
earned an `auto_close` grant in shadow mode.

Configuring a policy therefore makes the product strictly more cautious than
configuring nothing. That is the wrong way round, and it contradicts the goal
gap-closure Phase 2 was written for: closure should be earned per class rather
than assumed from a number.

## Why this is being asked now and not before

The question was invisible while the grant reader was broken. It queried a
table called `autonomy_grants`, which exists in no migration -- the real one is
`aisoc_autonomy_grants` -- and filtered on `revoked_at` and `expires_at`, which
that table does not have. The exception was caught, logged at warning and
turned into `False`.

So the observable behaviour was: **no policy, auto-close at 0.85; a policy,
never auto-close at all.** Neither half was the designed behaviour, and fixing
the query is what makes the default a live choice rather than a dead one.

The query is fixed (item 1.4) and the live suite
`tests/isolation/test_closure_grant_live.py` asserts it against real Postgres.
This ADR is only about the default for a tenant that has configured nothing.

## Options

### A. Keep the current default

A tenant with no policy keeps auto-closing at 0.85.

- Nothing changes for any existing deployment.
- The inconsistency above stays: the cautious configuration is the one that
  looks like neglect.

### B. No auto-close without an earned grant (recommended)

A tenant with no policy row does not auto-close. Earning a grant in shadow
mode, or setting an explicit per-tenant opt-in, is what enables it.

- Consistent with Phase 2's goal and with what
  `apps/docs/docs/operations/shadow-mode.md` describes.
- **Breaking.** A deployment relying on the implicit 0.85 would stop
  auto-closing on upgrade. The symptom is a queue that stops draining, which
  is visible but unwelcome, so it needs a release note under `BREAKING` and a
  named opt-in for operators who want the old behaviour back.
- The opt-in should be explicit and audited rather than an environment
  variable, so that "this tenant closes alerts without earning it" is a
  recorded decision with an owner.

### C. Make the default explicit either way

Keep the behaviour but require the operator to state it, so no deployment
auto-closes by inheriting a constant nobody chose.

- Also breaking, and it asks every operator a question many will not have an
  answer to.

## Recommendation

**Option B**, with the opt-in recorded per tenant rather than per process.

## Decision

**Not taken.** This is a maintainer call: it changes what a running deployment
does to alerts without being asked, and the fix pass deliberately does not make
that choice on the maintainer's behalf. Recorded as `M4` in
`FIX_PASS_PROGRESS.md`.

Until it is taken, the behaviour is Option A with the grant reader working,
which is the first time the two halves have been consistent with each other.
