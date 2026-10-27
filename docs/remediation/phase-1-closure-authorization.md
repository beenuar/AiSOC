# Phase 1 — centralizing automatic alert-closure authorization

Automatic closure of a production alert now passes exactly one authorization
check, immediately before the row changes, whatever route the verdict took to
get there.

Before this, `alerts.status` could reach `'resolved'` down two paths and only
one of them asked permission. A verdict remembered from a previous alert was
being treated as permission remembered from a previous alert, which is not the
same thing and was never decided by anybody.

## The shape of the fix

`alerts.status` becomes `'resolved'` in exactly one statement in the whole
service: the `UPDATE alerts` at the end of
`app.investigator.ledger.persist_auto_triage`, gated on a caller-supplied
`auto_closed` flag. That makes a chokepoint possible, so the authorization now
lives inside that function, between resolving the alert's tenant and opening
the transaction:

```
caller (LLM triage / outcome memory / cached verdict / retry / resumed run)
        │  auto_closed=True
        ▼
ledger.persist_auto_triage
        │  tenant resolved to its canonical UUID
        ▼
closure.authorization.authorize_auto_closure   ← the only gate
        │  delegates per-tenant policy to closure.policy.decide
        ▼
UPDATE alerts ... CASE WHEN $7 AND NOT $10 THEN 'resolved'
```

Three properties follow from putting it there rather than in each caller:

- **A new caller is governed by default.** The previous arrangement required
  every caller to remember; one did not, for as long as it existed.
- **Recovery re-evaluates.** A retry, a resumed run or a deduplicated verdict
  persists a decision reached earlier, sometimes much earlier. Because the
  check runs at the write, the answer always comes from the policy in force
  when the row changes. An authorization carried alongside a verdict would let
  a tenant disable closure and still have in-flight work close alerts behind
  them.
- **The tenant is the row's tenant.** `persist_auto_triage` has already
  resolved `tenant_ref` to the canonical UUID, so the policy that is read
  belongs to the alert being closed and not to whatever string the caller
  passed.

It is **not** a second policy implementation. Thresholds, the enabled flag,
`require_grant` and the kill switch stay in `app/closure/policy.py` and are
reached through `closure_policy.decide`. What the chokepoint adds is the set
of preconditions that are not per-tenant policy — the verdict has to be
auto-closeable, the run has to be real rather than shadow or replay, and the
reasoning has to be grounded — plus one call site everything passes through.

`run_auto_triage` still pre-checks the policy. That call is advisory and is
what puts `Auto-close withheld: ...` in front of an operator at triage time;
the chokepoint is what decides. Both derive the alert class through
`authorization.alert_class_of`, so they cannot disagree about which policy row
applies.

## Findings

### Finding 1 — a second, ungoverned path to `resolved` (critical)

**Status: reproduced.**

**Affected production path.**
`FusedAlertTriageWorker._maybe_suppress_from_memory` →
`_record` → `TriageWriter.persist_auto_triage` →
`ledger.persist_auto_triage` → `UPDATE alerts`.

`_maybe_suppress_from_memory` set `state.status = AgentStatus.COMPLETED`
directly from a stored outcome prior, and `_record` forwarded
`auto_closed=state.status is AgentStatus.COMPLETED`. The strings
`closure_policy` and `kill_switch` appear in `fused_alert_consumer.py` only
inside comments. Consequences, all confirmed against a live database on the
pre-fix tree:

- a tenant with `enabled = false` in `aisoc_closure_policies` still got
  automatic closures;
- the kill switch — global or per tenant — did not stop this path;
- `require_grant` was not consulted, so a tenant waiting for shadow mode to
  earn an `auto_close` grant closed alerts anyway;
- the confidence recorded against the decision was read off the stored prior
  (`float(prior.get("confidence", 0.9))`) rather than measured for this alert.

It was gated only by `_memory_suppression_enabled()`, which is on by default.

**Regression tests.**
`tests/isolation/test_closure_authorization_live.py`:

- `TestEveryClosurePathIsGoverned::test_the_memory_suppression_path_is_governed`
- `TestEveryClosurePathIsGoverned::test_the_real_suppression_path_does_not_close_an_unauthorized_alert`
  — drives the real worker method with the real `LiveTriageWriter`, the real
  ledger and the real policy; only the outcome prior is supplied, because that
  is the worker's input rather than the authorization
- `TestStopControls::test_the_memory_path_obeys_the_kill_switch`
- `TestEveryClosurePathIsGoverned::test_the_cached_verdict_path_is_governed`

**Fix.** The authorization moved to `ledger.persist_auto_triage`, so the
suppression branch is governed without it having to ask. Suppression still
short-circuits re-triage — the prior is good evidence about the alert and
re-triaging it would be waste — but the closure it used to imply is now
decided separately.

**Compatibility.** A deployment with an enabled policy sees no change. A
deployment relying on suppression to close alerts while its policy said
otherwise stops doing so, which is the defect.

### Finding 10 — the policy was permissive when its pool was `None` (critical)

**Status: reproduced.**

**Affected production path.** `closure.policy._pool()` →
`memory.institutional._get_pool()`.

With `pool is None` the module reported the kill switch **not engaged** and
fell back to `allowed = confidence >= default_threshold`. `None` was far more
reachable than "no database configured": `_get_pool` returned it on any
exception from `asyncpg.create_pool` **and** when the bootstrap probe on
`aisoc_institutional_memory` failed. So a missing migration, or an ACL problem
on a table the closure policy never reads, silently disabled the closure
policy and the kill switch together — logged at `debug`.

**Regression tests.** `services/agents/tests/test_closure_authorization.py`:

- `TestAnUnavailableDatabaseRefuses::test_a_pool_that_failed_to_open_refuses`
- `TestAnUnavailableDatabaseRefuses::test_an_unconfigured_database_refuses_too`
- `TestAnUnavailableDatabaseRefuses::test_the_kill_switch_refuses_when_the_pool_is_unavailable`
- `TestTheMemoryTableDoesNotGateTheClosurePolicy::test_a_failed_memory_bootstrap_still_yields_a_pool`

**Fix.** Two parts.

1. The pool accessor returns a *reason* alongside the pool.
   `institutional.connection_pool()` answers `POOL_READY`,
   `POOL_UNCONFIGURED` (no `DATABASE_URL` anywhere) or `POOL_UNAVAILABLE`
   (configured and unusable). `POOL_UNAVAILABLE` refuses, in the kill switch
   and in the policy. `POOL_UNCONFIGURED` also refuses, because a deployment
   with no policy store has recorded no authorization — and no durable closure
   can happen there anyway, since `persist_auto_triage` returns early without
   a ledger pool.
2. The institutional-memory bootstrap no longer decides whether *other*
   readers get a connection. `_connect()` opens the pool; `_get_pool()` adds
   the table probe for the memory store's own use and no longer closes the
   shared pool when it fails. The memory store still degrades to its
   in-process dict; the closure policy keeps its database.

The `create_pool` failure also moved from `debug` to `warning`: a deployment
that configured a database and did not get one is a fault an operator has to
see, and a safety control is about to refuse because of it.

In-query failures were already correct and are unchanged.

### Finding 14 — no policy row meant permission (by design, now changed)

**Status: source-confirmed, changed deliberately.**

**Affected production path.** `closure.policy.resolve_closure_policy`, the
`row is None` branch.

A tenant with no row in `aisoc_closure_policies` auto-closed at
`confidence >= AUTO_CLOSE_THRESHOLD` (0.85). The original rationale was
additivity — "a deployment that configures nothing behaves exactly as it did"
— which was true of the code and wrong as a posture: it turned the absence of
a decision into a decision, and every tenant auto-closed from its first
confident benign verdict, including one that had never opened the screen.

**Regression tests.**

- `test_closure_authorization.py::TestTheDefaultIsRefusal::test_a_tenant_with_no_policy_row_is_not_authorized`
- `test_closure_authorization.py::TestTheDefaultIsRefusal::test_a_missing_tenant_is_not_authorized`
- `tests/isolation/...::TestClosureNeedsExplicitAuthorization::test_an_eligible_verdict_does_not_close_without_an_explicit_policy`
- the positive control beside it,
  `test_an_explicitly_authorized_tenant_still_closes`, which is what stops a
  gate that refuses everything from looking like a fix

`services/agents/tests/test_closure_policy.py::test_no_policy_row_is_not_authorization`
previously asserted the opposite and is updated in place, with the old
reasoning kept in its docstring.

**Fix.** The `row is None` branch refuses, with
`source="default_deny"` and a reason naming the alert class. Nothing is
inferred from history: a tenant that was auto-closing yesterday *because
nobody had decided anything* has still not decided anything.

**Compatibility — this is the breaking change in this phase.** A deployment
that never configured a closure policy and relied on the implicit default
stops auto-closing until somebody authorizes it. See the migration below for
how to find out whether that is you, and how to restore it deliberately.

### Already fixed before this phase — left alone, pinned

**Status: already-fixed.** Shadow and replay cannot mutate production status:
`shadow_mode.py` forces `auto_closed=False, shadow=True`, and the ledger SQL
guards with `NOT $10`. In-query policy failures already refused.

Both are now pinned by tests here —
`TestShadowAndReplay::test_a_shadow_run_leaves_production_status_untouched`
and `TestTheChokepointItself::test_a_shadow_run_is_refused` — so the
chokepoint cannot regress them. The chokepoint refuses a shadow run itself as
well, which is a third mechanism saying the same thing; that is deliberate, so
its answer is complete on its own terms rather than depending on a reader
holding all three in their head.

## The migration

`services/api/migrations/121_closure_authorization_default_deny.sql`.

**What it does.** Creates `aisoc_closure_authorization_migration` and writes
one row per existing tenant recording which side of the default change that
tenant fell on: `preserved` (an explicit policy row decides, exactly as
before) or `requires_authorization` (closure was implicit and is now
withheld). It is an audit record. Nothing reads it to make a decision.

**What it deliberately does not do.** It creates no policy rows. An `INSERT`
granting a row to every tenant that had auto-closed in the past would be the
same mistake in a different place — inferring authorization from behaviour the
old default produced. Only a human may grant this.

**Upgrade.** Forward-only and idempotent; re-running records nothing twice.
Apply it in the usual order and then ask who is affected:

```sql
SELECT t.slug, m.outcome
  FROM aisoc_closure_authorization_migration m
  JOIN tenants t ON t.id = m.tenant_id
 WHERE m.outcome = 'requires_authorization'
 ORDER BY t.slug;
```

**Restoring closure for a tenant** is a deliberate grant, per tenant, with a
reason — the same row the console writes:

```sql
INSERT INTO aisoc_closure_policies
    (tenant_id, alert_class, enabled, threshold, require_grant, updated_by, reason)
VALUES ('<tenant-uuid>'::uuid, NULL, TRUE, 0.85, FALSE,
        '<operator>', 'restoring pre-121 automatic closure, reviewed <date>');
```

`require_grant = FALSE` reproduces the old default exactly. Leaving it `TRUE`
is the safer choice: closure then additionally waits for an `auto_close` grant
that shadow mode has to earn.

**Rollback.** There is no schema change to undo beyond
`DROP TABLE IF EXISTS aisoc_closure_authorization_migration;`. Reverting the
*behaviour* means reverting the code change, not the migration — the migration
only records what happened.

## The gate

`scripts/check_closure_authorization.py` asserts the two properties the
chokepoint rests on: that only the ledger carries SQL which can set an alert
to `'resolved'`, and that the function holding it calls
`authorize_auto_closure`. It reads the AST and considers only string constants
that are not docstrings, because this document, the gate itself and
`authorization.py` all quote that SQL in prose — a gate that fires on
documentation gets switched off within a week.

`--self-test` proves the detector in both directions over five cases:
it must stay silent on a docstring and a comment, fire on both the literal
`status = 'resolved'` and the `CASE ... THEN 'resolved'` form the ledger
actually uses, and report a chokepoint call only where one exists.

## Verification performed

All commands were run from a worktree at `origin/main`, with a service
virtualenv built from `services/agents`'s own locked set
(`python3 scripts/service_requirements.py agents --locked`), and against
PostgreSQL 16 with all 136 migrations applied as the schema owner. The code
under test connects as the **runtime** role `aisoc_app`, not the owner, so RLS
is in force; a superuser would ignore every policy and let the cross-tenant
assertions pass for the wrong reason.

| Check | Result |
| --- | --- |
| Live suite, pre-fix | 12 failed, 3 passed — every failure the alert sitting at `resolved` |
| Live suite, post-fix | **15 passed** |
| Offline closure suites, post-fix | **28 passed** |
| Agents suite, baseline on `origin/main` | 2050 passed, 5 skipped |
| Agents suite, post-fix | **2066 passed, 5 skipped** |
| `ruff format --check .` | 2599 files already formatted |
| `ruff check services/ scripts/ tests/ tools/` | All checks passed |
| `scripts/check_mypy_baseline.py` | OK — no tree got worse (964 findings, 20 trees) |
| `scripts/check_closure_authorization.py` | OK, and `--self-test` OK (5 cases, both directions) |
| Migrations on a **fresh** database, 001→121 in order | applied cleanly |
| Migration 121 re-applied | idempotent, records nothing twice |

The three passing live tests on the pre-fix tree are the positive control, the
shadow guard and manual closure — all three are properties the fix had to
preserve rather than establish, so their passing before and after is the
intended reading.

### Negative controls

Each mechanism was reverted on top of the fix and the suite re-run, to show
the tests fail again for the stated reason rather than passing for some
unrelated one. Outputs are in the pull request body.

## Remaining limitations

Stated plainly, because an implied pass is worth less than a named gap.

- **The live suite is not yet in a workflow on `main`.** It is wired into
  `.github/workflows/agent-auth-live.yml`, which is the job that already
  stands up Postgres with every migration applied and runs the sibling
  closure-grant suite — but a workflow file added in a pull request has not
  been observed to pass on `main`, and until it has, "the gate exists" and "a
  pull request cannot regress it" are separate claims. The claim-to-gate
  matrix row is recorded as `PARTIAL` for that reason and returns to `GATED`
  in the change that observes it green on `main`.
- **No hosted model was exercised.** Nothing here places an LLM call; the
  tests drive the persistence and policy path with verdicts supplied directly.
  That is the correct scope for an authorization fix, but it means this work
  says nothing about model behaviour.
- **The console has no screen for this yet.** A tenant that lands on
  `requires_authorization` is restored with the SQL above. Surfacing it in the
  settings UI is follow-on work and is not in this phase.
- **`aisoc_kill_switch`'s `WITH CHECK (tenant_id = current_tenant_id())`
  makes the global row (`tenant_id IS NULL`) uninsertable by the runtime
  role.** Noticed while writing the live suite, which works around it by
  seeding as the owner. The *read* path — the one that matters for stopping
  closures — is unaffected and is covered by the tests here. Whether the
  global switch can be engaged through the product at all is outside this
  phase's scope and is not fixed here.
- **One tenant-attribution path is unverified.** `persist_auto_triage`
  resolves the `"default"` placeholder to the canonical seed tenant in a
  single-tenant install. The tests here always pass an explicit UUID, so the
  placeholder path is governed by the same chokepoint but has not been
  exercised with a live multi-tenant ambiguity.
