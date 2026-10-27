# The platform-wide kill switch could not be engaged

The kill switch is the control an operator reaches for when the agent is
doing something they did not expect. It has two scopes: a per-tenant row and
a global one that stops autonomous closure and action dispatch across the
whole deployment.

**The per-tenant switch worked. The global one had never been engageable by
anything, on any deployment, since it shipped in migration 078.** A stop
control that cannot be reached is worse than no stop control, because people
believe it is there.

This note records what was verified, what the defect turned out to be once
investigated, the fix, and the operator procedure.

## What was reported, and what was actually wrong

A sibling lane reported one half: the row-level security policy on
`aisoc_kill_switch` carries `WITH CHECK (tenant_id = current_tenant_id())`,
which makes the global row uninsertable by the runtime role.

That is true. Investigation found it was **the smaller half**.

| | Reported | Verified |
| --- | --- | --- |
| The RLS policy refuses the global row | yes | yes, for every session the runtime role can open |
| Any endpoint, console control, CLI or script could engage it | not assessed | **no writer existed anywhere in the tree** |
| The per-tenant switch | not assessed | works, and is unaffected |

So the fix had to be two things. Repairing the policy alone would have left
a correct policy over a row nothing writes, which this repository treats as
not existing.

### 1. The policy refused the global row

`078_closure_policy_and_kill_switch.sql` creates the table with a nullable
`tenant_id`, where `NULL` is the global row, and this policy:

```sql
USING      (tenant_id IS NULL OR tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)
WITH CHECK (tenant_id = current_tenant_id())
```

`current_tenant_id()` returns `NULL` for an unset or empty setting
(`002_rls.sql`). Judged by that `WITH CHECK`, the global row is:

- `NULL = NULL` on a session with no tenant bound, which is `NULL`;
- `NULL = '<uuid>'` on a session with one bound, which is also `NULL`.

A `WITH CHECK` that does not evaluate to true refuses the row, so **both**
cases fail. The table's own comment says the global row "is written by the
platform operator through a session with no tenant set" — the one case the
check rejects.

Verified against `postgres:16` with all 136 migrations applied, connected as
the `NOSUPERUSER NOBYPASSRLS` `aisoc_app` runtime role. This matters: the
migration owner is a superuser and ignores policies even under `FORCE ROW
LEVEL SECURITY`, so seeding the row as the owner succeeds and proves
nothing. That is precisely the workaround that hid this.

```
######## PROOF 1: global INSERT as aisoc_app, NO tenant bound ########
ERROR:  new row violates row-level security policy for table "aisoc_kill_switch"

######## PROOF 2: global INSERT as aisoc_app, WITH tenant A bound ########
SET
ERROR:  new row violates row-level security policy for table "aisoc_kill_switch"

######## CONTROL: per-tenant INSERT as aisoc_app, tenant A bound ########
SET
INSERT 0 1
```

The live policy and role attributes, read from the catalogue rather than
from the migration text:

```
polname    | tenant_isolation
using_expr | ((tenant_id IS NULL) OR (tenant_id = current_tenant_id()) OR (current_tenant_id() IS NULL))
with_check | (tenant_id = current_tenant_id())

  rolname  | rolsuper | rolbypassrls | rolcanlogin
-----------+----------+--------------+-------------
 aisoc     | t        | t            | t
 aisoc_app | f        | f            | t

         relname         | relrowsecurity | relforcerowsecurity
-------------------------+----------------+---------------------
 aisoc_kill_switch       | t              | t
 aisoc_kill_switch_audit | t              | t
```

`aisoc_kill_switch_audit` carries the same strict check, so even a switch
that could be thrown would have failed on its audit row.

### 2. Nothing could write the global row

Every write to the table in the repository bound the caller's own tenant:

```
services/api/app/api/v1/endpoints/kill_switch.py:129  INSERT INTO aisoc_kill_switch           ... VALUES (:id, :t, ...)
services/api/app/api/v1/endpoints/kill_switch.py:144  INSERT INTO aisoc_kill_switch_audit     ... VALUES (:id, :t, ...)
services/api/app/api/v1/endpoints/kill_switch.py:178  UPDATE aisoc_kill_switch ... WHERE tenant_id = :t
services/api/app/api/v1/endpoints/kill_switch.py:201  INSERT INTO aisoc_kill_switch_audit     ... VALUES (:id, :t, ...)
```

`:t` is `user.tenant_id` at all four sites. There was no fifth writer: no
console control (`apps/web` contains no kill-switch component at all), no
CLI, no script. The published route table confirmed the surface was three
operations, none of them global:

```
GET    /api/v1/kill-switch
POST   /api/v1/kill-switch/engage
POST   /api/v1/kill-switch/release
```

Meanwhile **two readers consult the global row**: the `GET` above, and
`kill_switch_engaged` in `services/agents/app/closure/policy.py`, which the
closure resolver calls first and separately on every alert.

A reader over a table nothing writes is a shape `AGENTS.md` calls out by
name. Here it was wearing the label of an emergency stop.

### 3. The per-tenant switch was fine

It had already been repaired — the routes take `TenantDBSession`, so they
bind `app.current_tenant_id` and satisfy the strict check (the sibling of
GHSA-898c-wxrw-hx6c, pinned by `test_rls_write_sessions.py`). The per-tenant
assertions and all four negative properties passed **before** the fix as
well as after, which is how the fix is known not to have regressed them.

## The fix

### The policy expresses the distinction rather than dropping the check

Dropping `WITH CHECK` would make the table writable and tenant isolation
decorative. A global row is legitimately not tenant-scoped, so
`123_kill_switch_global_engageable.sql` says so:

```sql
WITH CHECK (
    tenant_id = current_tenant_id()
    OR (tenant_id IS NULL AND current_tenant_id() IS NULL)
)
```

Read over the two things a session can be, this says "you may write exactly
the row that is yours":

| session | row | decision |
| --- | --- | --- |
| unbound | global | **allowed** — the platform operator's own row |
| unbound | a tenant's | refused — `NULL OR FALSE` is `NULL` |
| tenant A | global | refused — a tenant cannot freeze everyone |
| tenant A | A's own | allowed — unchanged from 078 |
| tenant A | tenant B's | refused — unchanged from 078 |

Four of those five are unchanged. The only new capability is the first.
`aisoc_kill_switch_audit` gets the same policy for the same reason.

### The surface

`POST /api/v1/kill-switch/global/engage` and `.../global/release`.

Both take the **unbound** `DBSession`, which is the inverse of the tenant
routes and load-bearing rather than an oversight: migration 123 admits the
global row only when `current_tenant_id()` is `NULL`, so a tenant-scoped
session is precisely the one that cannot write it. Because moving a
kill-switch route onto `TenantDBSession` is the repair the *tenant* routes
needed, `test_they_run_on_an_unbound_session` asserts the resolved
dependency so a future sweep cannot silently undo this.

Authorization is a new permission, `platform_kill_switch:write`, **not**
`settings:write`. A tenant administrator holds `settings:write`, and this
switch stops every *other* tenant on the deployment. No tenant-scoped role
is granted the new one; only the wildcard roles hold it, which is the
decision `workload_identities:*` already records for the same reason.
Migration 123 seeds it into the permission catalogue, because `092` has
already run everywhere and a new permission reaches an existing deployment
only through a new file.

Reading stays available to any authenticated user: a platform-wide stop a
tenant cannot see reads to them as an unexplained outage.

## The evidence

Three steps, in order, all executed against `postgres:16` with all 136
migrations applied and the application connected as `aisoc_app`.

### Step 1 — the test fails on the unfixed tree

```
tests/isolation/test_kill_switch_global_live.py
FAILED ...::test_an_unbound_session_can_engage_the_global_switch
FAILED ...::test_the_global_switch_can_be_released_again
FAILED ...::test_the_global_audit_row_can_be_written
FAILED ...::TestBothScopesAreVisibleToTheTenant::test_a_tenant_reads_the_global_switch
4 failed, 7 passed

  asyncpg.exceptions.InsufficientPrivilegeError: new row violates row-level
  security policy for table "aisoc_kill_switch"

services/api/tests/test_kill_switch.py
9 failed, 11 passed          # the global routes answer 404
```

The 7 that pass are the per-tenant cases and the four negative properties.

### Step 2 — the fix

```
tests/isolation/test_kill_switch_global_live.py      11 passed
tests/isolation/test_kill_switch_endpoint_live.py    10 passed
tests/isolation/test_kill_switch_closure_live.py      4 passed
services/api/tests/test_kill_switch.py               20 passed
services/api tests/                                4974 passed, 164 skipped
```

The negative properties are asserted, not assumed. Engaging the global
switch does **not** widen anything:

- a tenant-bound session cannot write the global row;
- a tenant cannot write another tenant's row, or another tenant's audit row;
- an unbound session cannot write any tenant's row;
- one tenant cannot read another tenant's switch.

Through the product, a `tenant_admin` and an `infosec` analyst both receive
**403** on the global route and the global row stays absent, while the
`tenant_admin` can still stop their own tenant.

And the closure path observes it — which is what makes the control a
control. With the global switch engaged, `resolve_closure_policy` refuses a
confidence of 0.99 against a 0.50 bar with `source="kill_switch"`, for a
tenant that engaged nothing itself; releasing it resumes closure.

### Step 3 — negative controls

Three, each reverting one thing and leaving the rest in place.

**A. Policy reverted to 078, code intact.**

```
test_kill_switch_global_live.py      4 failed, 7 passed   (identical signature to step 1)
test_kill_switch_endpoint_live.py    4 failed, 6 passed   (the route 500s on the write)
```

The authorization cases still passed, which is what isolates this control to
the policy.

**B. Endpoint reverted, policy intact.**

```
services/api/tests/test_kill_switch.py           9 failed, 11 passed   (identical signature to step 1)
test_kill_switch_endpoint_live.py                8 failed,  2 passed   (404 on every global route)
```

**C. Policy reverted, closure suite.**

```
test_kill_switch_closure_live.py     4 failed
  asyncpg.exceptions.InsufficientPrivilegeError: new row violates row-level
  security policy for table "aisoc_kill_switch"
```

Restoring each returned every suite to green.

### Gates

```
scripts/check_rls_policy_shape.py   OK — 160 surviving policies over 159 tables; 159 FORCEd
scripts/check_route_authz.py        OK — 318 state-changing routes, 297 authorize,
                                         21 identity-only (ceiling 21), 0 discarded
ruff format --check .               2614 files already formatted
ruff check services/ scripts/ tests/ tools/    All checks passed
scripts/check_mypy_baseline.py      OK — no tree got worse (964 findings, 20 trees)
```

`kill-switch-live.yml` runs all three live suites on every pull request with
no `paths:` filter, and fails the job if the DSN resolves to a role holding
`SUPERUSER` or `BYPASSRLS` — a suite that cannot see a policy would
otherwise report the pre-fix tree healthy.

## Operator procedure

### Engaging the platform-wide stop

Requires `platform_kill_switch:write`, which only a wildcard role holds. The
reason is mandatory and must be at least 8 characters: the next operator has
to be able to tell a deliberate freeze from a forgotten test.

```bash
curl -sS -X POST https://<your-console>/api/v1/kill-switch/global/engage \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"reason": "triage agent closing alerts it should not have"}'
```

It takes effect within one poll of the closure cache, whose TTL is 10
seconds by default (`AISOC_CLOSURE_POLICY_TTL_SECONDS`). No restart and no
deploy.

Confirm from any authenticated account:

```bash
curl -sS https://<your-console>/api/v1/kill-switch -H "Authorization: Bearer $TOKEN"
# {"engaged": true, "scope": "global", "reason": "...", "engaged_by": "...", ...}
```

### Releasing it

```bash
curl -sS -X POST https://<your-console>/api/v1/kill-switch/global/release \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"reason": "root cause fixed, resuming"}'
```

Releasing when nothing is engaged answers **404** rather than reporting
success, because an operator who believes they released a stop that was not
there stops looking for the one that is.

A tenant that engaged its own switch keeps it: the two scopes are
independent and neither needs the other's agreement.

### The per-tenant switch

Unchanged. `POST /api/v1/kill-switch/engage` and `/release`, requiring
`settings:write`, acting on the caller's own tenant only. A tenant cannot
release a global switch; it is told so with a **409** rather than given a
success that changes nothing.

### Every change is audited

Both scopes write to `aisoc_kill_switch_audit` with the actor, the reason
and the scope (`global` or `tenant`).

## Still unreachable, and other limits

Stated rather than implied.

- **There is no console control for the kill switch, in either scope.**
  `apps/web` contains no kill-switch component; the per-tenant switch has
  been API-only since 078 and the global one now matches it. Engaging either
  means an API call or something that makes one. That is a real gap in
  first-run usability and is out of scope here.
- **`platform_kill_switch:write` is held only by the wildcard roles**
  (`platform_admin`, `admin`). There is no narrower role that can throw the
  platform switch without also holding everything else. Giving the stop its
  own grantable role is a product decision, not a defect.
- **The switch stops closure and dispatch, not ingestion.** Events keep
  arriving, detections keep firing and alerts keep being raised; what stops
  is automatic closure and action dispatch. An operator expecting silence
  will not get it.
- **`AISOC_CLOSURE_POLICY_TTL_SECONDS` is per process.** A deployment that
  raises it raises the delay before a stop takes effect, on every replica
  independently. The default of 10 seconds is what the measured behaviour
  above assumes.
- **No multi-replica test.** The suites drive one application process. The
  switch is a database row read by every replica, so there is no per-replica
  state to diverge, but that is an argument rather than a measurement.
- **Only closure honours the switch. Three of the four paths the docstring
  names do not consult it at all.** `endpoints/kill_switch.py` opens by
  saying the switch is "checked first and separately by everything that
  acts: closure in the triage worker, the actions dispatcher, playbook
  dispatch and the MCP write tools". Closure is real and is proven above:
  `auto_triage_agent.py` calls `closure_policy.decide(...)` on the
  production triage path, and that resolver checks the switch before
  anything else. The other three are not: `services/actions` contains no
  reference to `aisoc_kill_switch`, to `kill_switch_engaged` or to
  `app.closure` in any form, and neither does playbook dispatch or the MCP
  write surface.

  So **an engaged kill switch stops automatic closure and does not stop
  action dispatch.** That is a second, separate defect of the same family as
  this one, found while verifying this note rather than reported. It is not
  fixed here: the dispatcher is `services/actions`, the fix belongs with the
  governance chokepoint rather than beside an RLS policy, and the module
  that would carry the shared reader is owned by another in-flight change.
  Recorded so the docstring's claim is not read as a description of the
  current state — which is the exact trap `AGENTS.md` warns about, a
  docstring describing an intent rather than what the tree does.
