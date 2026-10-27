# Gate hardening: duplicate migration numbers, and a tenant credit keyed on the wrong thing

Two gates that were assumed to cover a defect class and did not. One did not
exist; the other existed, passed, and was reading the wrong property.

Both are proven three ways below — against the defect as it really shipped,
against current `main`, and with the detector reverted so it can be seen to
stop detecting. The third is the one that matters: a gate that has only ever
been run against violations its own author wrote is weak evidence, and for the
first of these there was a real one available.

---

## Gap 1 — nothing detected two migrations claiming the same number

### What happened

`services/api/migrations/NNN_*.sql` is a sequentially numbered, first-come
namespace. Two branches both took **121** on the same morning:

| File | Where it was |
| --- | --- |
| `121_fusion_alert_outbox.sql` | merged to `main` as `17fe377b` |
| `121_closure_authorization_default_deny.sql` | open in [#1525](https://github.com/beenuar/AiSOC/pull/1525) |

Git reports no conflict. Two branches each *added* a file, and the filenames
differ, so there is nothing to resolve — both could have merged.

### Why a duplicate is worse than it sounds

"Ambiguous apply order" undersells it. `run_migrations.py` does two things:

```276:320:services/api/app/scripts/run_migrations.py
    files = sorted(p for p in MIGRATIONS_DIR.iterdir() if p.suffix == ".sql")
    ...
        pending = [p for p in files if p.name not in already]
```

It orders by the **whole filename**, and `aisoc_schema_migrations` keys what it
has applied on the **filename** (`name TEXT PRIMARY KEY`). With two 121s:

- on a **fresh** deployment both are pending, and they apply in filename order
  — `121_closure…` *before* `121_fusion…`;
- on a deployment that already took `121_fusion…`, only `121_closure…` is
  pending, so it applies *after* it.

The same two migrations, in a different order on a new install than on an
upgrade. Silent, permanent once both rows exist, and invisible to everything
else in the tree.

### What the gate checks

`scripts/check_migration_numbering.py`, wired as
`.github/workflows/migration-numbering.yml`.

Chains are discovered **structurally** — any directory holding two or more
tracked files named `<digits>_…` with a `.sql`, `.py` or `.sh` suffix — rather
than from a list. A list would have missed two of the six:

```
infra/postgres/initdb: 2 file(s), 10–20, 9 gap(s) (not graded)
services/api/migrations: 136 file(s), 1–121
services/honeytokens/alembic/versions: 3 file(s), 1–3
services/osquery-tls/app/db/versions: 5 file(s), 1–5
services/purple-team/alembic/versions: 4 file(s), 1–4
services/ueba/alembic/versions: 4 file(s), 1–4
```

`services/osquery-tls` sets `script_location = app/db`, so its chain matches
neither `*/migrations/*` nor `*/alembic/versions/*`; `infra/postgres/initdb` is
numbered shell the Postgres entrypoint runs in filename order. Being structural
also makes the gate self-extending: a chain added tomorrow is checked tomorrow.

The unit is the **directory**, because that is what every runner here iterates.
No runner recurses — `lake_migrations.py` declares its chain in Python and
reads neither `.sql` file — so `services/api/clickhouse/001_init.sql` and
`clickhouse/tiering/002_tiering.sql` are two namespaces rather than a
collision. That was checked rather than assumed.

### What it deliberately does not check

**Gaps are not failures.** `118`, `120`, no `119` is the ordinary residue of a
branch that was reverted or never merged, and every runner here applies what it
finds in order rather than counting. Failing on a gap would red `main` until
somebody renumbered history. The count is reported and never graded. A
duplicate is the opposite: no workflow legitimately produces one.

**Alembic `down_revision` graphs are not walked.** For those four services the
filename prefix is a convention and the real ordering is inside the file. A
duplicate prefix is still a sign two branches raced, which is worth failing on;
a broken revision graph is a different defect and alembic raises on it itself.

**ADRs are out of scope.** `docs/decisions/0001-*.md` is also a first-come
numbered namespace, but two ADRs sharing a number is a broken cross-reference,
not two schemas applying in different orders. (It uses a dash and `.md`, so it
is excluded twice over.)

### The 13 collisions already on `main`

`main` carries 28 files across 13 duplicated numbers — including two triples,
`043` and `096` — predating this gate. They are frozen in `GRANDFATHERED`
rather than renumbered, for one reason: `aisoc_schema_migrations` is keyed on
the **filename**, so renaming `012_case_management.sql` makes it pending again
on every deployment that has already applied it, and the runner re-executes it.
The files are defensively written, so it would *probably* be harmless —
"probably harmless re-execution of 28 migrations across every installed
deployment" is not a trade worth making to tidy a number.

The table is checked in both directions: an entry that no longer collides fails
as a stale exemption, and so does one that has gained a **third** file. The
second half is the one that matters — without it, a new `121_x.sql` could join
a grandfathered pair and be absorbed in silence, which is the exact defect this
gate exists to catch.

### Proof

**1 — fails on the real defect.** A worktree at `origin/main` with PR #1525's
migration checked into the index beside the merged one. The gate under test was
copied into that tree so it resolved that tree as its own root.

```
$ git checkout probe-1525 -- services/api/migrations/121_closure_authorization_default_deny.sql
$ git ls-files 'services/api/migrations/121_*'
services/api/migrations/121_closure_authorization_default_deny.sql
services/api/migrations/121_fusion_alert_outbox.sql

$ python3 scripts/check_migration_numbering.py; echo "EXIT=$?"

FAIL: 1 migration numbering problem(s).
  - services/api/migrations: migration 121 is claimed by 2 files
      - services/api/migrations/121_closure_authorization_default_deny.sql
      - services/api/migrations/121_fusion_alert_outbox.sql
      Both will be applied. On a fresh deployment they run in filename order;
      on a deployment that already took one of them, the other runs afterwards.
      Renumber the one that has not merged yet.
check_migration_numbering: 6 numbered chain(s) under /private/tmp/aisoc-dup121
  services/api/migrations: 137 file(s), 1–121
EXIT=1
```

`git checkout <ref> -- <path>` stages the file, and the gate reads
`git ls-files`, which is the index — so this is the "verify with your changes
staged" case, not a disk-only one. A file that has *not* been `git add`ed is
invisible to the gate, which is asserted by its own self-test rather than left
implicit.

**2 — passes on current `main`.**

```
$ python3 scripts/check_migration_numbering.py; echo "EXIT=$?"
check_migration_numbering: 6 numbered chain(s) under /Users/…/AiSOC-gatehard
  …
OK: 154 migration file(s) across 6 chain(s); no two claim the same number,
    and all 13 grandfathered historical collisions still hold.
EXIT=0
```

**3 — negative control.** Same tree as proof 1 (both 121s present), one token
changed so every duplicate is treated as already-exempt:
`frozen_table.get(key)` → `frozen_table.get(key, tuple(names))`.

```
$ python3 scripts/check_migration_numbering.py
OK: 155 migration file(s) across 6 chain(s); no two claim the same number,
    and all 13 grandfathered historical collisions still hold.
EXIT=0          <-- a confident false pass

$ # restored
$ python3 scripts/check_migration_numbering.py >/dev/null 2>&1; echo $?
1
```

A first attempt at this control disabled the whole `len(names) > 1` loop, which
also stopped `seen_keys` being populated and failed with 13 *stale exemption*
reports instead — exit 1 for an unrelated reason. Recorded because it is
evidence the two arms are independent, and because a control that fails for the
wrong reason reads like a pass.

**4 — nothing existing caught it.** The three migration-adjacent gates already
in the tree, against the same both-121s worktree:

```
check_orm_migration_parity.py              exit 0
check_service_migration_bootstrap.py       exit 0
check_store_migrations.py                  exit 0
```

**5 — self-test**, 15 cases, written per *shape the filesystem can take*
rather than per instance observed:

```
PASS  the real defect: PR #1525's 121 beside the merged 121: flagged
PASS  clean: consecutive numbers: clean
PASS  a gap is not a failure: clean
PASS  padding differs, number does not: 012 and 12 collide: flagged
PASS  three files on one number: flagged
PASS  a 4-digit alembic chain is checked too: flagged
PASS  a chain at a non-conventional script_location is still found: flagged
PASS  numbered shell in initdb is a first-come namespace too: flagged
PASS  same number in two different directories is two namespaces: clean
PASS  an untracked duplicate is invisible, and the gate must not claim otherwise: clean
PASS  a grandfathered collision passes
PASS  a third file joining a grandfathered pair is not absorbed
PASS  a grandfathered entry that no longer collides is reported stale
PASS  all 13 live grandfather entries still name a real collision
PASS  refuses a tree with no content rather than reporting it clean
```

The padding case is worth calling out: `012_a.sql` and `12_b.sql` are two
filenames that sort apart and are the same migration number. No instance of it
exists on `main`, and a rule that compared the numeric prefix as a *string*
would miss it.

### One false-positive wave, caught before it shipped

Written first as `^(\d+)[_-]`, the gate's opening run reported
`docs/perf/results: migration 0000000000000000000000000000002026 is claimed by
7 files` — `2026-09-27-compose-steady.json` and six siblings. Dated filenames
open with digits and a dash.

The fix was to narrow the signature, not to add an allowlist: every real chain
uses an underscore, and migrations are files a runner *executes*
(`.sql`/`.py`/`.sh`). Both false positives disappeared and the exclusion list
stayed empty. An allowlist of "directories that are not migrations" would have
grown forever and would have silenced the gate on whatever was added to it by
mistake.

### Why the workflow has no `paths:` filter

A filter scoped to `services/api/migrations/**` looks obviously right and is
wrong twice.

The collision is a property of a **pair**, and the second half arrives from
somebody else's merge: a pull request that touches no migration at all becomes
the duplicate when `main` moves under it. Only an unconditional run sees that.
Separately, this repository has repeatedly found required checks that report
success having executed only their "nothing under test changed" step. The gate
is a sub-second, dependency-free read of `git ls-files`; there is nothing to
buy by skipping it.

---

## Gap 2 — `check_tenant_query_predicates.py` credited a bare token match

### What was wrong

The raw-SQL arm credited a statement as tenant-scoped when `tenant_id` appeared
**anywhere in the SQL text**:

```python
if _TENANT_IN_SQL.search(blob):
    continue
```

So `UPDATE … WHERE expires_at < now() RETURNING id, tenant_id` read as scoped.
The token was in the projection of returned columns; it constrained nothing.

The blind spot was already written in the module's own docstring, left open on
the grounds that one statement relied on it and that statement was legitimately
cross-tenant. **That had stopped being true.** It was 17, and one of them is
the reason the brief flagged this: `alert_outbox.py::claim` — an
`UPDATE … RETURNING id, tenant_id` worker sweep — merged in `17fe377b` and
passed the ratchet at 60 without raising it, because the `RETURNING` list
credited it.

### The defect had two code paths, not one

Fixing the line above moved 17 statements from "credited" to "judged", and only
**3** of them became findings. The other 14 were absorbed by this, 12 lines
later:

```python
if any(_TENANT_IN_SQL.search(r) for r in resolved) or (resolved & TENANT_TOKENS):
    continue
```

`resolved` is built by `_names()`, which collects **string constants** as well
as identifiers. The statement's own SQL therefore comes back round in
`resolved`, and the same bare-token test is applied to it a second time.
Fixing only the first line would have left 14 of 17 statements still falsely
credited and looked like a complete fix. Both now call the same rule.

### What counts as constraining

The clause the token sits in decides. Occurrences are attributed to the clause
keyword most recently opened before them, which handles subqueries and CTEs the
way they nest.

| Credited | Not credited |
| --- | --- |
| `WHERE` | `SELECT` projection |
| join `ON` | `RETURNING` |
| `USING (…)` | `ORDER BY`, `GROUP BY` |
| `HAVING` | `VALUES` alone |
| `INSERT INTO t (tenant_id, …)` | UPDATE `SET tenant_id = …` |
| `ON CONFLICT (tenant_id, …)` | `--` and `/* */` comments |

Two of those need a reason.

**`INSERT INTO`'s column list is credited.** For a write there is no row-filter
to look for; the column list plus a bound value is what stamps the new row with
a tenant, and it is the only form in which an INSERT can be scoped at all. 90
of the 108 statements this rule re-examines are that shape and every one is
correct — flagging them would have been 90 false positives, which is how a gate
gets switched off.

**UPDATE `SET tenant_id = …` is not credited.** It *writes* the tenant column
and constrains nothing about which rows are rewritten. It is a tenant
reassignment, the opposite of a scope.

A fragment — `" AND tenant_id = :t"` appended to a base query — carries no
clause keyword of its own, so it is credited when the token is one side of a
comparison (stepping over an optional `::cast`). An appended fragment that
merely *names* the column still fails, which has its own self-test case.

### Why not a real SQL parser

`sqlglot` is in the tree and pinned exactly. Every gate here has to run on a
bare interpreter before any `pip install` — `gate_toolkit` imports nothing
outside the standard library for that reason — and a gate that acquires a
dependency is one that gets skipped in the environment that matters. The cost
of that choice is two residuals, recorded in the module rather than discovered
later:

- a correlated subquery in a projection credits the outer statement off the
  inner predicate (the correlation makes the outer read per-tenant in practice,
  so this errs toward a credit rather than a false alarm);
- `INSERT INTO a (tenant_id, …) SELECT … FROM b` credits the stamped write
  while the read from `b` may be unscoped. One statement of that shape exists
  and it carries its own `WHERE tenant_id`.

### Finding-count delta

Measured with `_TENANT_IN_SQL` and `_tenant_predicate_in_sql` run side by side
over the same corpus, rather than inferred:

| | before | after |
| --- | --- | --- |
| raw-SQL statements on a tenant-scoped table | 462 | 462 |
| of those, credited as tenant-scoped by the text rule | 431 | 414 |
| credited by a token that constrains nothing | **17** | 0 |
| unscoped-statement findings surfaced | 0 | **17** |
| route→unscoped-statement pairs surfaced | 0 | **12** |
| `MAX_RATCHET` | 60 | 77 |
| `MAX_ROUTE_REACHABLE` | 34 | 46 |

Of the 17 that lost the credit, **3** became findings as soon as the first call
site was fixed; the other **14** were re-credited by the second bare-token path
described above and only surfaced once that was fixed too.

A larger figure appears in the module comments and is a different measurement:
**108** statements carry the token in no `WHERE`/`ON`/`USING`/`HAVING`. **90**
of those are `INSERT INTO t (tenant_id, …)`, which the new rule credits
deliberately — the column list is what stamps the written row. Flagging them
would have been 90 false positives.

**On raising the ceilings.** "Raise the ceiling until the scan passes" is the
move this repository forbids, and from the diff alone this looks identical, so
the reasoning is recorded beside the constant as well as here.

Not one line under `services/` changed. All 17 statements are byte-for-byte
what they were and every one was already unscoped; 60 was never a debt balance,
it was the balance a broken detector could see. The honest number is 77 and the
count of genuinely new exemptions is **zero**. Leaving it at 60 was rejected
because it fails every pull request for findings no author introduced and none
can fix, which is how a gate gets switched off. Giving the 17 real predicates
was rejected per statement, for the reasons below — in every case a tenant
predicate would break the thing the statement exists to do.

### Every newly-flagged statement, and why

**i. The lookup that *establishes* the tenant** — reached before a request has
one, so a tenant predicate would mean it could never resolve a tenant. Same
class as the pre-auth group already at the top of the ratchet.

| Statement | Reason |
| --- | --- |
| `auth/sso_provisioning.py::resolve_connection` | resolves which SSO connection an assertion belongs to, by `(provider, issuer)`; the row it finds is what assigns the tenant |
| `auth/saml_metadata.py::resolve_saml_connection` | SP-metadata and ACS resolve by issuer, or by none at all on the console link. `LIMIT 2` so an ambiguous config is detected rather than silently resolved to row one |
| `mfa.py::_principal_for_enrolment` | `:u` is the subject of a signed, purpose-checked sign-in challenge, not a caller-supplied id |
| `inbox_itsm.py::_fetch_token_and_connector` (`tenant_inbox_tokens`) | the ITSM webhook carries an opaque inbox token and nothing else; this is what turns it into a tenant |

**ii. Reads cross-tenant *in order to* enforce the tenant check.**

| Statement | Reason |
| --- | --- |
| `inbox_itsm.py::_fetch_token_and_connector` (`connectors`) | deliberately unscoped so the next statement can compare `connector_row.tenant_id != token_row.tenant_id`, log a cross-tenant attempt with both ids and refuse. Scoping the SELECT would collapse that into an indistinguishable 404 and lose the signal. Nothing from the row reaches the caller before the comparison |

**iii. An identity predicate, which is strictly narrower than a tenant.**

| Statement | Reason |
| --- | --- |
| `mfa.py::enrolment_row` | keyed on `user_id`, which all eight callers pass as the authenticated principal's own (`current_user.user_id`, `principal.user_id`, or an id already resolved from a verified challenge). The ORM arm of this gate already credits that; the raw-SQL arm cannot see it because the predicate is bound one function away |

**iv. A worker's working set — "which tenants", which cannot presuppose one.**
The discover-then-bind shape already recorded for `hunt_scheduler.run_once` and
`oauth_refresh._select_due_connectors`.

| Statement | Reason |
| --- | --- |
| `workers/autonomy_drift.py` | `SELECT DISTINCT tenant_id` across granted autonomy; each tenant bound individually afterwards |
| `workers/retention_purge.py::_load_policies` | every tenant's retention policy; a tenant missing from this read is one whose data is never purged |
| `workers/phishing_report_intake.py::_mailbox_connectors` | enabled mailbox connectors across tenants, ordered by tenant so the fan-out is deterministic |
| `workers/shadow_reconcile.py` | `COUNT(DISTINCT tenant_id)` — a fleet gauge for one log line; returns a number, never a tenant's rows |
| `workers/approval_expiry.py` | expires every tenant's stale approvals, bounded by `expires_at < now()`. The clearest instance of the defect: credited by `RETURNING id, tenant_id` |
| `fusion/services/sessions.py` | `SELECT DISTINCT tenant_id` of sessions due for expiry |
| `fusion/services/alert_outbox.py::claim` | the outbox dispatcher claims due rows across every tenant under a lease; one that drained a single tenant would stall delivery for all the others. **This is the statement that passed the ratchet at 60.** |
| `fusion/services/alert_outbox.py::backlog` | depth-and-age gauge, grouped by tenant precisely so one tenant's backlog is attributable. `GROUP BY` buckets rows already read — which is why the rule does not credit it |
| `fusion/memory/provider.py::refresh` | rebuilds the per-signature prior cache for every tenant in one pass, then partitions by `tenant_id` in Python and hands each tenant only its own. The projected column is the partition key |
| `connectors/app/scheduler.py::_promote_overdue_findings` | `SELECT DISTINCT tenant_id` over enabled connectors — **the one statement the module docstring already named** as relying on the bare-token credit. It now holds a reason instead of a regex match |

**v. A fragment, judged at its use sites.**

| Statement | Reason |
| --- | --- |
| `services/alert_source_link.py` (`_SELECT`) | a column list and a `FROM`, never executed as written: all four callers interpolate it into an f-string appending `WHERE tenant_id = :tenant_id`, and the gate judges each of those call sites independently — a fifth caller omitting the predicate is flagged there. Keyed on this table, so an unscoped statement on any other table in the module still fails |

This last one is the only entry keyed on `<module>` scope, and the residual is
stated rather than hidden: another unscoped statement on `alert_source_links`
at module scope in that same file would be covered by it. It was independently
confirmed as a parse artefact rather than a judgement call when a self-test
probe built the same shape and the finding landed on the module-level constant
rather than on the call site.

**The 12 route pairs** are all pre-auth routes — five SAML/OIDC callbacks, the
ITSM webhook, and six MFA handlers reading the caller's own enrolment. A
handler cannot filter on a tenant it has not been assigned, and each of these
statements is the thing that assigns it.

### Proof

**1 — fails on the real defect.** `alert_outbox.py::claim`, with its ratchet
entry removed so the statement is judged on the detector alone:

```
A. NEW detector, ratchet entry REMOVED
   exit=1   alert_outbox.py:208 flagged=YES
```

**2 — negative control.** Same tree, same entry removed, detector reverted to
`_TENANT_IN_SQL.search` on both call sites:

```
B. OLD bare-token detector
   exit=1   alert_outbox.py:208 flagged=NO
```

The exit code stays 1 in B — but for a different reason, and the distinction is
the point. With the statement credited again, its (removed) ratchet entry is
never matched, so the gate fails on the **stale-entry** arm instead. The
statement itself is not flagged, which is the thing under test.

**3 — passes on current `main`.**

```
C. RESTORED (new detector + full ratchet)
OK: every statement on a tenant-scoped table filters on a tenant, or is one of
77 ratcheted exceptions that still holds; and every one of the 46
route->unscoped-statement paths is a recorded exception.
   exit=0
```

**4 — self-test**, 16 injected drifts and 22 controls, written per SQL *clause*
rather than per instance found on `main`:

```
[PASS] drift I: tenant_id only in a RETURNING list: 1 finding(s), want 1
[PASS] drift J: tenant_id only in a SELECT projection: 1 finding(s), want 1
[PASS] drift K: tenant_id only in an ORDER BY: 1 finding(s), want 1
[PASS] drift L: tenant_id only in a GROUP BY: 1 finding(s), want 1
[PASS] drift M: tenant_id only in a -- line comment: 1 finding(s), want 1
[PASS] drift N: tenant_id only in a /* block comment */: 1 finding(s), want 1
[PASS] drift O: UPDATE SET tenant_id rewrites the column, it does not scope: 1 finding(s), want 1
[PASS] drift P: an appended fragment that names tenant_id without comparing it: 1 finding(s), want 1
[PASS] control: tenant_id in a WHERE: 0 finding(s), want 0
[PASS] control: tenant_id in a JOIN ... ON: 0 finding(s), want 0
[PASS] control: tenant_id in a USING (...): 0 finding(s), want 0
[PASS] control: tenant_id in a HAVING: 0 finding(s), want 0
[PASS] control: INSERT column list stamps the written row: 0 finding(s), want 0
[PASS] control: ON CONFLICT target selects the upserted row: 0 finding(s), want 0
[PASS] control: predicate inside a subquery, RETURNING outside it: 0 finding(s), want 0
[PASS] control: predicate inside a CTE: 0 finding(s), want 0
[PASS] control: tenant_id::uuid = $1 — a cast before the operator: 0 finding(s), want 0
[PASS] control: predicate carried in by an f-string: 0 finding(s), want 0
[PASS] control: predicate appended as a bare fragment: 0 finding(s), want 0

self-test passed: 16 injected drifts detected and 22 controls clear …
```

---

## Gate suite

Every gate `ci.yml` invokes was run against this branch: **175 pass, 6 fail.**
Three of the six are artefacts of how the list was extracted — `run_evals.py
--ci --out`, `service_requirements.py` and `upgrade_playbooks.py --dir` were
captured without their mandatory path arguments. The other three were run
against a clean `origin/main` worktree and fail there identically, so they are
pre-existing and unrelated:

| Gate | On this branch | On pristine `main` |
| --- | --- | --- |
| `check_console_route_contract.py` | exit 1 | exit 1 |
| `check_console_route_contract.py --self-test` | exit 1 | exit 1 |
| `check_mcp_client_policy.py` | exit 1 | exit 1 (`No module named 'mcp'`) |

Also run and clean: `ruff format --check .` (2,610 files),
`ruff check services/ scripts/ tests/ tools/`, `check_mypy_baseline.py` (964
findings, no tree worse), `check_gate_coverage.py`, `check_gate_contract.py`,
`check_workflow_concurrency.py`, `check_claim_gate_matrix.py` (321 rows / 317
GATED / 4 PARTIAL / 0 NO GATE), `check_attribution.py --all`,
`check_competitor_names.py`, `check_machine_paths.py`, `check_comment_paths.py`
and `check_repo_self_links.py`.

One measurement artefact worth recording, because it nearly became a false
report: the first pass of this suite read **104 failures**. The loop ran under
zsh, which does not word-split an unquoted expansion, so `python3 $inv` passed
`"scripts/x.py --self-test"` as a single filename and every gate exited 2 on
`No such file or directory`. Re-run under bash it is 6. A batch result that
disagrees this sharply with a single-gate run is the shell, not the tree.

## Not verified

- ~~Neither gate has been observed on a GitHub runner.~~ **Resolved on
  [#1530](https://github.com/beenuar/AiSOC/pull/1530):** `Migrations — No
  duplicate numbers` passed in 10 s and `Route tenant scope (no route lets its
  caller name the tenant)` — the job that runs the tenant-predicate gate and
  its self-test — passed in 3 m 12 s, both on ubuntu-latest with Python 3.11.
- **CodeQL flagged the first revision**, `py/unused-global-variable` on
  `_UNCREDITED` — a tuple written as documentation and referenced by nothing.
  Rather than delete it, the clause list became the single source the regex is
  built from and `_clause_classification_is_total()` now asserts the two
  classification tables are disjoint and together cover all 25 keywords, which
  is checked by the self-test. A keyword added to the matcher and classified
  nowhere would otherwise default to "not constraining" — the safe direction,
  but one nobody decided.
- **`security-audit` fails on this branch and the cause is not this branch.**
  `CVE-2026-114605 in dnspython==2.8.0`, a purely transitive dependency
  resolved in `services/api/poetry.lock`; `dnspython` appears nowhere in the
  diff. Every `security-audit` run before 15:33 UTC succeeded across `main`
  and four other branches, and the two runs here at 16:23 and 16:28 are the
  first anywhere after the advisory published. This is the documented
  stale-green shape, and `main` has since confirmed it: its 15:32 run
  succeeded and its 17:08 run **fails with the identical advisory**, so the
  condition is repository-wide rather than branch-specific.

  ```
  failure  2026-10-27T17:08:06Z  main                        <- same CVE
  failure  2026-10-27T16:55:12Z  remediation/gate-hardening
  success  2026-10-27T15:32:56Z  main                        <- predates the advisory
  success  2026-10-27T15:31:44Z  remediation/p1-closure-authz
  ```

  The fix is a lockfile regeneration under `services/api/`, which is outside
  this change's scope and belongs on `main` rather than being duplicated per
  branch. It has **not** been suppressed.
- **The first push went red on a gate the local suite does not include**, and
  it is worth recording as the live example of the thing this file is about.
  Adding two matrix rows made three prose copies of the count stale:
  `apps/docs/docs/compliance/evidence-pack.md` and two figures in
  `ROADMAP.md`. One of those sentences warns the reader, in the sentence
  itself, that a count copied into prose goes stale in silence. The cross-check
  lives in `scripts/readme_gates.py`, which is not invoked by `ci.yml` and so
  was not in the 181-gate sweep run before pushing — run `readme_gates.py`
  directly after touching the matrix.
- **The claim that no runner recurses into a migration subdirectory** was
  established by reading `run_migrations.py`, the four `alembic.ini`
  `script_location` values and `lake_migrations.py`. It was not established by
  running a migration against a live database.
- **The 13 grandfathered collisions are asserted to be already applied on
  existing deployments**, which is why renumbering them is unsafe. That follows
  from their being on `main` and in released tags; no deployment's
  `aisoc_schema_migrations` table was queried to confirm it.
- **`MAX_RATCHET` 60 → 77 is a judgement call**, argued above and in the
  module. If the reviewer disagrees, the alternative is to scope the statements
  rather than to lower the number back — the 17 are unscoped either way.
