# Phase 2 — approval identity and durable action execution

`services/actions` is the only part of the platform that changes somebody
else's estate. Its approve path was a read, a status comparison in Python, the
vendor call, and a durable write afterwards:

```text
record = await action_store.get(action_id)                    # no tenant, cache first
if record["status"] != ActionStatus.AWAITING_APPROVAL: ...    # checked in Python
result = await executor.execute(request)                      # the host is contained
await action_store.save(record)                               # ... and only now recorded
```

Every guarantee an approval is supposed to carry lived in the gap between the
third line and the fourth. This document records what was reproduced, what was
changed, how it was verified, and what is still open.

All seven findings below are **reproduced** — each was observed failing on the
tree as it stood, not inferred from reading it.

| # | Finding | Status | Regression test |
| --- | --- | --- | --- |
| 8 | No atomic claim; durable write after the vendor call | reproduced | `TestExecutionIsClaimedBeforeTheVendorIsContacted` |
| 9 | No unknown state; no `try/except` on the approve dispatch | reproduced | `TestAnUnknownOutcomeIsRecordedAsUnknown` |
| 12 | Decision and read paths carry no tenant | reproduced | `test_an_approver_from_another_tenant_is_refused`, `TestReadingAnActionRecordIsTenantScoped` |
| 13 | Unconditional upsert replaces a pending action's intent | reproduced | `TestApprovalIsBoundToTheIntent` |
| 15 | `requested_by` is caller-supplied free text | source-confirmed | — (see below) |
| 16 | Separation of duties passes silently with no requester | reproduced | `test_separation_of_duties_is_not_waived_by_an_absent_requester` |
| **17** | **The console approval path refuses every approval** | **reproduced (new)** | `test_an_agent_originated_request_is_approved_by_a_human`, `test_the_real_console_dispatch_path_approves` |

Everything lives in one live suite, `tests/isolation/test_action_durability_live.py`,
graded by `.github/workflows/action-durability-live.yml`.

---

## Finding 17 — every approval raised in the console was refused upstream

Not on the brief's list. Found by running the path rather than reading it, and
it is the most consequential item here.

**Affected production path.** `POST /api/v1/approvals/{id}/decide` →
`approvals._dispatch_decision` → `actions_client.submit_action` →
`POST /api/v1/actions` → `actions_client.decide_action` →
`POST /api/v1/actions/{id}/approve`.

**What happened.** `_dispatch_decision` built one principal — the deciding
console user — and sent it as the submit's `principal`. `router.submit_action`
records `principal.user_id` as `requested_by_user_id`. The same principal was
then sent as the approver, so `authorize_approver` compared the approver
against itself and raised *"approver cannot be the requester (separation of
duties)"*. The 403 became an `ActionsServiceError`, which `_dispatch_decision`
recorded as `{"state": "failed", "stage": "decide"}`, which surfaced to the
operator as a 502 reading *"Decision recorded, but the action service refused
it"*.

The code was aware of the distinction and solved it in the wrong field: it
passed `requested_by="agent"` with a comment saying *"Sending the approver here
would make them both, and separation of duties would pass by accident."*
`requested_by` is a free-text label that nothing compares; `principal` is what
the comparison reads.

Reproduced directly against the shipped app before anything was changed:

```
submit:  200 awaiting_approval  requested_by_user_id= e84b8dfe-980c-4210-bda6-0741cea66aa8
approve: 403 {"detail":"approver cannot be the requester (separation of duties)"}
```

**Fix.** `ActionRequest` gains `requester`, the originating identity, separate
from `principal`, the invoking identity whose permissions gate the submit. The
three identities are now distinct by construction:

| Identity | Field | Used for |
| --- | --- | --- |
| who originally asked | `requester` | separation of duties, provenance |
| who relayed the call | `principal` | least-privilege check on the submit |
| who approved | `approver` on the approve call | permission tier, tenant, separation of duties |

`approvals.create_approval` stamps the authenticated principal that raised the
approval into `action["requester_principal"]` — server-written, always
overwritten, never read from the request body — and `_dispatch_decision` sends
it as `requester`. For an agent-raised approval that is the agents service's
own service principal, so the agent identity survives a human approving it;
for one a human raised it is that human, so self-approval is still refused.

**Compatibility.** `requester` is optional. When absent, `requested_by_user_id`
falls back to `principal.user_id`, which is exactly what shipped — so a caller
that submits on its own behalf is unchanged. Approvals created before this
change carry no stamp; their dispatch sends no `requester`, separation of
duties has nothing to compare, and the action records
`separation_of_duties: "unevaluated"` rather than claiming it passed.

---

## Finding 8 — two replicas could both contain the host

**Affected production path.** `POST /api/v1/actions/{id}/approve`, and the
auto-execute branch of `POST /api/v1/actions`.

**Reproduced.** Two approvals in flight against one action, from two replicas
behind one Postgres, produced **two** containment requests at the recording
vendor. On a single replica the race is invisible: `action_store.get` answered
from a module-global dict and handed both callers *the same object*, so the
status check and the mutation operated on one record. That is why a second
container is required to see it at all, and why this suite starts two.

**Fix.** `action_store.claim_for_execution` — one conditional `UPDATE` moving
`awaiting_approval → running`, scoped by id, tenant and expected status, which
writes the claim and the claiming worker into the record and returns the row:

```sql
UPDATE aisoc_action_records
   SET status = $4, record = jsonb_set(...), updated_at = now()
 WHERE id = $1 AND tenant_id = $2 AND status = $3
RETURNING record
```

Postgres takes a row lock, so a second claimant blocks until the first commits
and then re-evaluates the predicate against the committed row, finds `running`
and matches nothing. That re-evaluation is the whole mechanism; it is the same
one `scheduler_leases` (migration 115) uses, and it is why this is not a
`SELECT` followed by an `UPDATE` — that pair has no re-evaluation and elects
two executors.

The claim is also the fail-closed point. `save` still tolerates a store
failure, deliberately: losing a *pending* containment because the store blinked
is the failure the module was written to prevent, and an outcome write that
raised would discard the only record of a vendor already touched. A claim is
different — it *is* the authorization for an external effect — so it returns
`STORE_UNAVAILABLE` and the route answers 503 having contacted nobody.

Finally, the durable write now goes first and decision reads pass
`authoritative=True`, which skips the process-local cache when a DSN is
configured. That cache never expired: the submitting replica held an
`awaiting_approval` copy for the life of the process and would re-execute an
action another replica had already run.

**Compatibility.** `RUNNING` already existed in `ActionStatus` and nothing
wrote it; it is now written before every dispatch. With no DSN configured —
the single-process and unit-test configuration — the claim is an in-memory
compare-and-set under an `asyncio.Lock`, so the 1,237-case offline suite runs
unchanged.

---

## Finding 9 — a vendor that acted was recorded as having failed

**Affected production path.** The dispatch in both `approve_action` and the
auto-execute branch of `submit_action`.

**Reproduced, and the shape is not quite what the brief describes.** There was
indeed no `try/except` around `approve_action`'s `executor.execute`, and no
status meaning "unknown". But the executors catch their *own* vendor errors and
return `ActionResult(status=FAILED, error=str(exc))`, so the dominant symptom
was not a 500 — it was a record reading `failed` for a containment the EDR had
accepted. That is the dangerous direction: the obvious response to a failure is
to run it again.

**Fix, and why not exception classification.** Classifying the exception
answers "did the client raise", and the question is "did the estate change" —
for the case that matters, a vendor that accepted a containment and then
dropped the response, those two answers disagree. So a dispatch that does not
come back clean is resolved by *reading the vendor back*, using
`PostActionVerifier`, which already re-queries with the same clients the
forward action uses and already refuses to invent a `VERIFIED` it did not earn:

| Read-back | Recorded as |
| --- | --- |
| effect present | `completed` (the response was lost, not the action) |
| effect absent | `failed` |
| cannot be read | `reconciliation_required` |

`ActionStatus.RECONCILIATION_REQUIRED` is the new member. An action in it
cannot be approved again — the claim's `expected_status` does not match, and
the 409 names the reconcile route.

**One deliberate limit.** Below MEDIUM blast radius the executor's own verdict
stands and no probe runs. A reconciliation queue filled with retryable Slack
messages and tickets is one an operator learns to ignore, and a control nobody
reads is not a control. `_UNKNOWN_OUTCOME_FLOOR` in `router.py` is where that
line is drawn, and `test_a_refused_dispatch_is_still_a_failure` is the control
proving the rule does not collapse into "everything is unknown".

**The crash window in `approvals.py`** was real: `_dispatch_decision` ran at one
line and `db.commit()` at the next, so a crash in between left the approval
`pending` against an action that had run, with nothing in the row saying a
dispatch had been attempted. The decision is now committed first with
`dispatch.state = "dispatching"`, then dispatched, then committed again with
the outcome. That costs the property the old ordering protected — a window
where the row says approved and the action has not run — and makes that window
*visible*, which is the one that matters: a repeat decide re-enters on an
unresolved dispatch, and the actions service's claim is what stops a re-entry
from executing twice.

`actions_client` now distinguishes a refusal from silence: a `ConnectError`
wrote nothing to a socket, while a timeout or a dropped connection on a POST
may well have been processed. The second raises with `indeterminate=True`, and
`_dispatch_decision` records `{"state": "unknown"}` and answers **504** with
"whether the action ran is not yet known" rather than 502 "the action did not
run".

**Compatibility.** `reconciliation_required` is a new status string. Checked
against every consumer:

* `services/api`'s usage meter keys `EXECUTED_STATUS` on `"completed"`, so an
  unresolved action is correctly *not* counted as a vendor touch.
* `services/slack-bot`'s `commands.py` tests for
  `{"awaiting_approval", "pending_approval", "pending"}` to decide whether to
  post an approval card; anything else renders as a status line, which is
  right.
* `packages/types`' `AlertAction.status` union is a console-side concept that
  already does not mirror `ActionStatus` (it has no `awaiting_approval`,
  `approved` or `rejected`, and its `type` union contains verbs `ActionType`
  has never had), so it is not a consumer of this enum.
* The status column is written through `_column_text`, so the new member lands
  as `reconciliation_required` and not `ActionStatus.RECONCILIATION_REQUIRED` —
  the defect migration 095 had to repair.

---

## Finding 12 — an id was a capability across tenants

**Affected production path.** `approve_action`, `reject_action` and
`get_action`.

**Reproduced.** An approver holding `actions:execute:high` in a freshly-made
tenant approved another tenant's `isolate_host` from the second replica, and
the host was contained. `GET /api/v1/actions/{id}` returned the full record —
target, parameters and all — to any holder of the shared service token.

`action_store.get`'s docstring said a tenant "should always be supplied from a
request path"; no request path supplied one. Its claim that the table "carries
no RLS policy" is **imprecise**: migration 060 does create
`aisoc_action_records_tenant`. The consequence stated is still right, for a
different reason — the policy reads `app.current_tenant_id`, which nothing in
this service sets, and its unset arm is deliberately permissive so cross-tenant
workers are not starved. The policy is inert here, so the query predicate is
the only control.

**Fix.** Two layers on the decision paths:

1. The deciding identity is resolved **before** the record is read
   (`_resolve_identity`), and the read is narrowed by its tenant. Fetching
   globally and comparing in Python is the same defect one line later.
2. `authorize_approver` compares the approver's tenant to the action's, which
   `authorize_action` has done since it was written and only the approve side
   went without.

The claim carries `AND tenant_id = $2` as well, so the write cannot land
cross-tenant even if both reads were wrong.

On `get_action`: a caller declaring `X-Tenant-ID` gets the record when it owns
it and **404** when it does not — never 403, which would make the route an
existence oracle over every tenant's action ids. A caller declaring none keeps
working and is answered with status only (`_UNSCOPED_READ_FIELDS`), so the
route stays usable for polling without handing out the host an action was
aimed at. The header is read off `request.headers` rather than declared as a
`Header(...)` parameter, because one such parameter adds a parameter and a 422
response to the published OpenAPI document for every operation it guards.

**Compatibility.** No caller of `GET /api/v1/actions/{id}` exists anywhere in
the tree — `services/slack-bot` and `services/api` call only `/approve` and
`/reject` — so the redaction breaks nothing today and the full record remains
one header away. `docs/openapi.yaml` is byte-identical after the change
(`scripts/export_openapi.py --check`: *"docs/openapi.yaml is up to date"*).

---

## Finding 13 — a pending approval could be retargeted

**Affected production path.** `POST /api/v1/actions` with an id that already
exists.

**Reproduced.** Submitting `ws-4471`, then the same id with `target: "dc-01"`,
left the record naming `dc-01` while the approval card said `ws-4471`.

**Fix.** The upsert's `DO UPDATE` is now conditional, comparing the three
fields that define what an approver signed off:

```sql
 WHERE aisoc_action_records.status NOT IN ('awaiting_approval','running','reconciliation_required')
    OR ( record->>'action_type' IS NOT DISTINCT FROM EXCLUDED.record->>'action_type'
     AND record->>'target'      IS NOT DISTINCT FROM EXCLUDED.record->>'target'
     AND record->'parameters'   IS NOT DISTINCT FROM EXCLUDED.record->'parameters' )
RETURNING id
```

`RETURNING id` is how the refusal is detected: an `ON CONFLICT DO UPDATE` whose
`WHERE` is unsatisfied returns no row, which is the only signal Postgres gives.
`save` raises `ActionIntentConflict` and the route answers 409.

`rationale` and `confidence` are deliberately **not** part of the intent: the
first is prose shown to a human, the second is re-graded by the gate on every
submission, and neither changes what happens to the estate.

**Compatibility.** The store's standing contract — *"a replay of the same
submission is idempotent rather than a duplicate pending approval"* — is
preserved and pinned by `test_an_identical_resubmission_is_still_idempotent`.
Only a *changed* intent is refused, and only while a decision is outstanding.

---

## Finding 16 — separation of duties passed on the requests it could not evaluate

`if separation_of_duties and requester and str(requester) == str(approver.user_id)`
— the `and requester` arm meant a submission carrying no principal produced an
approval the control reported as satisfied, and the row afterwards was
indistinguishable from one where it had been checked and passed.

**Fix.** `authorize_approver` returns which state applied and the route records
it on the action as `separation_of_duties: "enforced" | "unevaluated"`.

Refusing instead was considered and rejected: `AISOC_ACTIONS_REQUIRE_PRINCIPAL`
defaults false, and a hard denial would brick every legacy system-initiated
action during an incident. The honest fix is that it must *be a fact in the
row*, not an omission.

## Finding 15 — `requested_by` is caller-supplied free text

**Source-confirmed, deliberately not "fixed" by trusting it.** It remains a
label. Separation of duties reads `requester` / `principal`, which arrive from
authenticated context, and the fix for finding 17 is what makes the originating
identity trustworthy rather than cosmetic. Using `requested_by` to *refuse* an
approval was considered and rejected: a caller controlling that string could
name an analyst and block them from approving during an incident, which trades
a non-bypass for a denial of service on the containment path.

---

## No migration

`aisoc_action_records` needs no schema change, and that is a decision rather
than an omission:

* The claim's predicates are the existing `id`, `tenant_id` and `status`
  columns, and `ix_action_records_tenant_status` already serves the operator's
  `status = 'running'` scan.
* Dispatch provenance (`dispatch.claimed_by`, `dispatch.claimed_at`,
  `verification`, `approved_at`) lives in the JSONB record, which is the
  argument migration 055 makes for storing it whole: *"mirroring it as columns
  here would make every contract change a migration"*.
* The intent comparison is a JSONB expression, so there is no second definition
  of "the intent" to drift from the Python one and no backfill to get wrong.
* Migration 061 already grants the runtime role DML on every table, and 060
  already carries the RLS policy.

## Recovery and reconciliation — what an operator runs

### 1. Find actions that were claimed and never resolved

```sql
SELECT id, tenant_id, status, updated_at,
       record->'dispatch'->>'claimed_by'  AS claimed_by,
       record->'dispatch'->>'claimed_at'  AS claimed_at,
       record->>'action_type'             AS action_type,
       record->>'target'                  AS target
  FROM aisoc_action_records
 WHERE status IN ('running', 'reconciliation_required')
   AND updated_at < now() - interval '10 minutes'
 ORDER BY updated_at;
```

`running` means a worker took the action and has not written an outcome — it
either died mid-dispatch or is still inside a vendor call.
`reconciliation_required` means it finished and could not establish what
happened. `claimed_by` is `hostname/pid`, which is how you find the container.

**A stale claim is never stolen automatically.** A timeout that reassigns a
claim is exactly the duplicate execution this work exists to prevent: the
previous holder may have reached the vendor. Resolution is always the probe
below.

### 2. Reconcile by asking the vendor

```bash
curl -sS -X POST "$ACTIONS_URL/api/v1/actions/$ACTION_ID/reconcile" \
  -H "Authorization: Bearer $AISOC_ACTIONS_SERVICE_TOKEN" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -H 'Content-Type: application/json' \
  -d '{"parameters": {"cs_client_id": "...", "cs_client_secret": "..."}}'
```

`parameters` is merged over the stored ones and is how you present a current
credential rather than depending on whatever was captured at submit time. The
route **never re-executes** — it runs the read-back probe only.

| Response `status` | Meaning | Next step |
| --- | --- | --- |
| `completed` | the effect is in force; the response was lost, not the action | nothing |
| `failed` | the vendor was read and the effect is absent | submit a **new action id** if it is still wanted |
| `reconciliation_required` | the vendor could not be read | fix the credential or vendor reachability and run it again; check by hand if it stays |

`verification.reason` on the returned record says which probe ran and what it
saw. A verb with no registered probe reports
`no read-back verifier for <verb>`, which stays `reconciliation_required` — the
honest answer, and never a guess in either direction.

### 3. Never do this

* Do not re-approve. The claim refuses it (409) and the refusal is the point.
* Do not hand-edit `status` to `completed` without a probe that said so — that
  is the fabricated-verdict shape the project disavows everywhere else.
* Do not resubmit the **same** action id with different parameters: the upsert
  refuses it (409) while a decision is outstanding, by design.

## Verification performed

Against PostgreSQL 16 with all 135 migrations applied, replicas connecting as
the runtime role `aisoc_app` (`NOBYPASSRLS`, not the owner), two actions
containers on loopback sockets, and a recording HTTP vendor.

| Check | Result |
| --- | --- |
| `tests/isolation/test_action_durability_live.py` **before** the fix | 20 failed, 7 passed |
| the same suite **after** | **27 passed** |
| `services/actions` offline suite | 1,237 passed (baseline 1,234 + 3 new) |
| `services/api` offline suite | 4,964 passed, 164 skipped |
| `ruff check services/ scripts/ tests/ tools/` | All checks passed |
| `ruff format --check .` (0.16.10, the pin) | 2,596 files already formatted |
| `scripts/check_mypy_baseline.py` | OK — no tree got worse |
| `scripts/export_openapi.py --check` | docs/openapi.yaml is up to date |
| `check_tenant_query_predicates`, `check_raw_sql_columns`, `check_route_authz`, `check_action_contract`, `check_attribution`, `check_competitor_names`, `check_machine_paths`, `check_gate_coverage`, `check_text_bind_casts`, `check_comment_paths`, `check_logger_kwargs` | all pass |

### Negative controls

Each removes one piece of the fix and requires the suite to go red. All three
were executed, not asserted, and are wired into the workflow.

| Control | Result |
| --- | --- |
| drop `AND status = $3` from the claim | 3 of 4 cases fail, including both replicas containing the host |
| make the upsert unconditional (`WHERE true`) | the pending approval is retargeted to `dc-01` — 409 becomes 200 |
| remove both tenant layers | tenant A's approver contains tenant B's host and is returned the full record |

The third removes two lines rather than one deliberately: tenant isolation here
is the narrowed read *plus* the authorization check, and removing either alone
leaves the other refusing, so a one-line control would prove nothing. Saying
which pair is load-bearing is the accurate claim.

### Two test expectations were corrected after seeing the implementation

Written against a weaker design, both now assert a stronger property, and both
were re-run against the pre-fix tree to confirm they still fail there (they are
in the 20).

* A lost vendor response was expected to produce `reconciliation_required`. The
  implementation reads the device back, finds it contained, and records
  `completed` — which is better, and the test now asserts that plus a separate
  case where the device API is down.
* "No probe available" was expressed by sending empty `parameters`, which the
  reconcile route merges over the stored ones, so the probe ran. It now makes
  the vendor's read-back route unavailable instead.

## Remaining limitations

* **No hosted vendor has been exercised.** The forward call and the read-back
  both go to a stub on a loopback socket. That proves the client constructs,
  authenticates, and that the two are distinct routes; it does not prove any
  vendor's real API behaves as modelled.
* **Vendor-side idempotency keys are not used**, because none of the clients in
  `services/actions/app/clients/` accepts one. The duplicate-execution
  guarantee is therefore entirely ours — the claim — rather than ours plus the
  vendor's. Adding `Idempotency-Key` per client is tracked work, not done here.
* **The unknown-outcome rule has a floor.** Below MEDIUM blast radius an
  unverifiable failure is still recorded as `failed`. Stated above with its
  reasoning; it is a judgement, not an oversight.
* **Reconciliation is operator-driven.** There is no worker sweeping stale
  claims, by choice: an automatic sweep that resolved an unreadable probe would
  be guessing, and one that re-dispatched would duplicate. The SQL above is the
  queue.
* **`chatops_callback` still mutates the record without saving it.** Reached
  only by the ChatOps verification link, pre-existing, and outside this phase's
  scope — but it means a user's reply updates the in-process copy and not the
  durable row on any other replica.
* **The API-side crash window is narrowed, not closed.** A crash between the
  first commit and the dispatch leaves `dispatch.state = "dispatching"`, which
  a repeat decide re-enters safely. Nothing automatically re-enters it; a
  stalled approval needs a human or a client retry.
* **`services/api`'s own route layer is exercised by its offline suite, not
  here.** The live suite drives `_dispatch_decision` with a stand-in ORM row
  and principal, because the question it answers is what crosses the wire to
  the actions service. The session, auth dependency and ORM behind
  `decide_approval` are covered by `services/api/tests/`.
