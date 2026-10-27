# Phase 3 — queue acknowledgement and checkpoint semantics

Scope: `services/connectors/**`. Two findings were handed over; a third was
found while building the live proof for them and is worse than either.

The question this phase answers is **what "accepted" means**. An HTTP 200 from
a service that only buffered, an in-memory list, or a coroutine that has been
created but not awaited are all insufficient. Acknowledgement requires
recoverable downstream acceptance.

On this tree that bar is met in exactly one place, and it genuinely is met
there: `services/ingest` awaits `PublishBatch`, whose writer is configured
`RequiredAcks: kafka.RequireAll` with a synchronous `WriteMessages`, and
answers HTTP 500 if it fails. So a 200 carrying `accepted == submitted` means
the broker acknowledged on all replicas. Its graph fan-out is explicitly
non-blocking (`_ = h.graph.WriteEvent(...)`) and is not part of the guarantee.

Everything below is about getting the connectors to wait for that answer.

---

## Finding 4 — acknowledgement preceded durable acceptance

**Status: reproduced and fixed.**

### Affected production path

`ConnectorScheduler._poll_one` → `connector.fetch_alerts()` → *returns* →
normalize → tenant filter rules → schema fingerprint →
`IngestClient.push_events` → `record_checkpoint`.

Both queue-backed connectors answered the source **inside `fetch_alerts`**,
several steps before anything durable had seen the events:

| Connector | Pre-fix behaviour |
| --- | --- |
| `gcp_pubsub` | `POST :acknowledge` once the batch was appended to a local `list` |
| `aws_cloudtrail_s3` | `sqs:DeleteMessage` once an object's records were in that same list |

The comment on the Pub/Sub site — *"Acknowledge after the batch is in `rows`,
never before: a failure between the two has to cost a duplicate, not a gap"* —
is sound reasoning that stops one layer short. Being in a Python list is not
durability, and `fetch_alerts` returns long before the push.

So on a crash, or on any ingest 5xx, the messages were gone from the source
with no second copy anywhere. Checkpoint withholding could not help: the
scheduler's existing withholding logic is well built and fires correctly, but a
cursor held back over data that has already been deleted from a queue protects
nothing.

### Regression tests

| Test | Property |
| --- | --- |
| `test_gcp_pubsub.py::TestTheAckOutlivesTheFetch::test_nothing_is_acknowledged_while_the_entries_are_only_in_a_list` | the subscription still holds them after a fetch |
| `test_aws_cloudtrail_s3.py::TestTheHandleOutlivesTheFetch::test_a_message_is_not_deleted_while_its_records_are_only_in_a_list` | the receipt survives the fetch |
| `test_aws_cloudtrail_s3.py::TestTheHandleOutlivesTheFetch::test_an_unreadable_object_still_withholds_the_whole_message` | partial acceptance at the source end: one notification, several objects |
| `test_scheduler.py::test_a_fetch_that_ingest_rejects_leaves_the_message_on_the_queue` | fetch succeeds, ingest 500, nothing acknowledged |
| `test_scheduler.py::test_the_rejected_batch_is_recovered_in_full_on_the_next_poll` | **completeness** — the events actually come back |
| `test_scheduler.py::test_a_partially_accepted_batch_is_not_acknowledged` | 200 with `rejected > 0` acknowledges nothing |
| `test_scheduler.py::test_a_child_event_that_cannot_be_normalized_withholds_the_acknowledgement` | one unusable child event of a multi-event notification |
| `test_scheduler.py::test_a_fully_accepted_batch_is_acknowledged_and_does_not_come_back` | the other direction — the queue must still drain |
| `test_scheduler.py::test_the_checkpoint_is_durable_before_the_acknowledgement_is_sent` | ordering: cursor persisted first |
| `test_scheduler.py::test_a_redelivery_after_a_lost_acknowledgement_is_not_a_duplicate` | crash, or refused handle, in that window |
| `tests/isolation/test_queue_acknowledgement_live.py::TestIngestRefusesTheBatch` | the same, through a real socket and real Postgres |

The scheduler tests drive a queue double that **really drains on ack and
really redelivers otherwise**, so "was the event lost?" is a question the test
can ask rather than assert. A mock that records an ack call cannot model the
consequence that makes this class of bug possible — the message leaving the
queue — which is why none of the existing mock-based scheduler tests saw it.

### Fix

Fetching and acknowledging are now separate operations.

- `BaseConnector` gained `stage_acknowledgement`, `pending_acknowledgements`,
  `take_pending_acknowledgements`, `discard_acknowledgements` and
  `commit_acknowledgements`, returning an `AcknowledgementResult(requested,
  confirmed, failed)`.
- Each connector's `fetch_alerts` stages its handles instead of answering.
- The scheduler commits them under **exactly the condition the checkpoint
  already used**: counts present in the response, `rejected == 0`, and
  `accepted == len(kept)`. Anything else calls `discard_acknowledgements` and
  logs `acknowledgement_withheld` with the message count and the reason.
- The commit runs **after** the checkpoint write, deliberately. A crash
  between the two leaves messages that will be redelivered and a cursor that
  recognises them. The other order leaves a source that has forgotten them and
  a cursor that never recorded them.
- `commit_acknowledgements` on the base class is a no-op only when nothing was
  staged, and raises otherwise, so a connector that stages handles without
  implementing the commit fails loudly instead of holding a queue open.
- Both connectors report what the source **confirmed**, not what they asked
  for, so a delete nobody has permission to make is visible instead of
  presenting as a queue that never drains.

This is the smallest change that establishes the guarantee: it reuses the
staging-and-commit shape the checkpoint already had, and the acceptance
predicate is the same one, so the two cannot drift apart.

### The bound, and why it is a bound rather than an extension

An SQS visibility timeout and a Pub/Sub ack deadline are both finite, so
"hold the handle until ingest confirms" needs an explicit answer.

**The bound chosen:** a poll stops taking new work once it has spent
`acknowledgement_hold_fraction` (0.5) of the source's deadline while holding
at least one handle. The remaining half is the downstream budget — normalize,
filter, fingerprint, push to ingest, persist the cursor. With the shipped
defaults that is 60 s of a 120 s Pub/Sub ack deadline and 150 s of a 300 s SQS
visibility timeout. Whatever the poll did not take stays on the source, which
is what `CollectionBudget.backlog_stays_on_the_queue` already describes.

**If it overruns anyway**, the handle expires, the source refuses it, and the
message is redelivered — a duplicate, which the identity cursor suppresses,
and never a gap. The failure mode of the bound is in the safe direction.

**Why not extend the deadline** (`ChangeMessageVisibility` /
`modifyAckDeadline`): an extension is another network call that can fail, on
exactly the path whose failure mode this phase exists to remove, and it needs
a background task holding a timer across the scheduler's own call into ingest.
Stopping early needs no call, cannot fail, and degrades to a duplicate. An
extension becomes worth reconsidering if a deployment's poll legitimately
cannot fit in half a deadline — the log line
`gcp_pubsub.ack_deadline_reserve_reached` / `cloudtrail_s3.visibility_reserve_reached`
names that situation when it happens.

The two operator-facing timeout fields now say the timeout has to cover a poll
**and the push that follows it**, which is a larger number than before. Those
help texts are the source of the generated connector pages, which were
regenerated.

### Durable quarantine for source data that can never be read

A notification naming an object that cannot be read — deleted object, a bucket
policy the task role does not satisfy, a truncated upload — is withheld on
every poll by design, because the alternative is dropping audit data on a
transient S3 error. That is correct, and unbounded.

The bound belongs to the queue rather than to a spool built here: SQS's own
**redrive policy** moves a message to a dead-letter queue after
`maxReceiveCount` receives, preserving the original payload, and Pub/Sub has
a dead-letter topic. Both are durable quarantine with an explicit record, and
neither needs code. What was missing was any way to know it was happening, so
the connector now requests `ApproximateReceiveCount` (SQS omits it unless
asked) and logs `cloudtrail_s3.message_redelivered_repeatedly` at five
receives, naming the redrive policy as the remedy. Five because SQS's default
`maxReceiveCount` is 10 and AWS advises against going below 5, so the warning
lands near where a correctly configured queue would already be quarantining.

### Compatibility

- No change for the other 85 connectors: they stage nothing, so
  `commit_acknowledgements` returns a zero result and the scheduler's new step
  is a no-op. Verified live — `test_connector_scheduler_live.py` (which drives
  Okta, a watermark connector) passes unchanged.
- A message that can never become events — an `s3:TestEvent`, an undecodable
  body, an empty Pub/Sub payload — is still consumed, but now rides along with
  its batch's acknowledgement. It contributes no rows, so a poll containing
  only such messages submits an empty batch, which `IngestClient.push_events`
  short-circuits to `{"accepted": 0, "rejected": 0}`; that satisfies the
  acceptance predicate and the queue still drains.
- In-batch duplicates are not collapsed. That is unchanged from the watermark,
  and deliberate: every record read out of one S3 object shares its object
  key, so collapsing within a batch would discard an object's tail.

---

## Finding 5 — a monotonic watermark over an unordered queue

**Status: reproduced and fixed.**

### Affected production path

`BaseConnector.apply_checkpoint`, called from both connectors' `fetch_alerts`.
It sorts rows by `(event_time, record_id)`, drops everything at or below the
incoming cursor, and advances the cursor to the batch **maximum**.

That is correct for an ordered, time-windowed API poll — which is what its
design comment describes, and the five API connectors keep it. It is wrong for
a queue:

- Pub/Sub guarantees no ordering unless the topic was created with message
  ordering **and** the publisher sets an ordering key. A Cloud Logging sink
  sets none — the connector's own module docstring says so.
- S3 event notifications over SQS are unordered by construction.

So an event whose `event_time` was older than the batch maximum was discarded
**on first sight**, with no counter and no log, and because its message had
already been acknowledged it was unrecoverable.

A second, smaller part of the same finding: the Pub/Sub module docstring
claimed the cursor "tolerates a late arrival by re-reading its own overlap —
which is why the cursor is a de-duplicator here rather than a watermark that
may skip". That described an intent the base class does not implement. It has
been corrected to describe what the code does.

### Regression tests

| Test | Property |
| --- | --- |
| `test_gcp_pubsub.py::TestAnOlderEntryArrivingLaterSurvives::test_an_entry_older_than_the_last_batch_is_still_emitted` | a previously unseen older event survives |
| `test_aws_cloudtrail_s3.py::TestAnOlderObjectAnnouncedLaterSurvives::test_an_event_older_than_the_last_batch_is_still_emitted` | the same, per object |
| `...::test_a_genuine_redelivery_of_the_same_object_is_still_suppressed` | **duplicate handling** — the other half |
| `...::test_two_distinct_events_sharing_a_timestamp_both_survive` | a shared timestamp is not a collision |
| `test_checkpoint_contract.py::TestIdentityDedupMachinery` (9 tests) | the machinery, including the bound and the scoping |
| `test_checkpoint_contract.py::TestUnorderedSourcesDoNotCarryAWatermark` | the declarations, recorded rather than assumed |
| `tests/isolation/...::TestTheCursorRoundTripsThroughPostgres` | all of it through a real database |

### Fix

The two queue connectors declare `dedup_identity_field` instead of the
watermark pair. `apply_checkpoint` dispatches on which was declared;
declaring both is refused in `__init_subclass__`, at import, because a
connector carrying both would silently use one of them.

Identity dedup keeps a bounded set of identities seen before, never reorders
rows (arrival order is the only order a queue has), and drops a row only when
that exact identity has been seen.

| Connector | Identity | Why that one |
| --- | --- | --- |
| `gcp_pubsub` | `record_id`, the vendor `messageId` | stable across redelivery; `ackId` is **not** — a fresh one is minted each time the message is handed over |
| `aws_cloudtrail_s3` | `object_key` | every record of an object shares it, and the object is this connector's atomic unit (a message is answered only when every object it names was read in full). Keying on the object keeps the set to the few hundred keys one poll can announce rather than the 20,000 records they may hold |

Properties worth stating:

- **Bound.** `max_dedup_identities` defaults to 10,000, stored as 16-hex
  (64-bit) truncated SHA-256 digests. Measured: 195.3 KiB of JSONB at the cap,
  11.7 KiB for a realistic CloudTrail poll of 600 object keys. The window that
  must stay covered is the batch in flight — accepted downstream but not yet
  acknowledged — which is at most one poll. Falling off the end re-emits an
  event; it never drops one. Truncation is logged.
- **Scope.** The digest includes the connector id, so two sources minting the
  same record id cannot suppress each other. Tenant scope is structural: the
  cursor lives on one connector *instance* row, which belongs to one tenant.
- **A row with no identity is kept**, not guessed at, and counted
  (`connector.dedup.row_without_identity`) — it cannot be proven a duplicate,
  so it is not treated as one.
- **Compatibility.** A deployment upgrading in place has a `{"time", "id"}`
  cursor in `connector_config.checkpoint`. It is ignored rather than read,
  because reading it would reinstate the behaviour being removed; the cost is
  re-emitting at most one poll's worth once, and the queue only holds
  unacknowledged messages. Pinned by
  `test_a_watermark_cursor_left_by_an_earlier_release_is_ignored`, offline and
  live. Rolling the code back is also safe: the old watermark finds no `time`
  key, treats it as no cursor, and re-reads what is on the queue — duplicates,
  not loss.

### `azure_event_hubs` — source-confirmed, deliberately not changed

It declares the same `(event_time, record_id)` watermark and shares the
out-of-order weakness: Capture files are written per partition, and
`EnqueuedTimeUtc` is not globally ordered across partitions, so a late file
can carry records below the watermark and be dropped on sight.

It is **not** converted, for a reason that matters: its blob container is
never drained, and `_list_paths` lists it from the beginning on every poll. A
bounded identity set would roll over and re-emit the oldest capture files for
ever, which is worse than the defect. Its data is also *re-readable* — nothing
is destroyed by a read, unlike an acked queue message — so a dropped record is
recoverable by resetting the cursor, where a dropped queue message is not.

It needs a different fix (a listing cursor on the capture path, which sorts
chronologically within a partition, plus per-partition rather than global
watermarks). That is recorded here and in
`test_checkpoint_contract.py::test_a_blob_store_that_is_relisted_every_poll_keeps_its_watermark`,
which states the reasoning so the next reader does not "fix" it by symmetry.

---

## Finding 6 — persisting a cursor destroyed the connector's configuration

**Status: found during this phase, reproduced against live Postgres, fixed.**
Older than findings 4 and 5, and broader: it affects every connector that
declares a cursor, not only the two queue-backed ones.

### What happened

`connector_repo.record_checkpoint` built its patch as:

```python
patch = cast(json.dumps({"checkpoint": checkpoint}), JSONB)
```

`cast` declares the bind parameter's type, so SQLAlchemy's JSONB bind
processor serialised the already-serialised string a **second** time and
Postgres received a JSON *string scalar*. `jsonb || <scalar>` coerces both
operands to arrays, so one successful checkpointed poll rewrote
`connector_config` from an object to an array.

Measured against Postgres 16 with the shipped code:

```
after ONE successful checkpointed poll:
  connector_config type : list
  value                 : [{'filter_rules': [{'field': 'x'}], 'poll_interval_seconds': 120},
                           '{"checkpoint": {"time": "2026-10-08T11:00:00Z", "id": "evt-1"}}']
  next poll             : CRASHES -> AttributeError: 'list' object has no attribute 'items'
  poll_interval_seconds : LOST
  filter_rules          : LOST
```

The next poll raises at `scheduler.py` reading `connector_config.items()`, the
poll's broad handler files that as a failure, and the instance goes unhealthy
**permanently**. Three consequences:

1. No connector has ever resumed from a persisted cursor on any deployment —
   `connector_config -> 'checkpoint'` is `NULL` on the corrupted shape, so
   `set_checkpoint` was always seeded with nothing.
2. The instance stops polling altogether after its first successful poll.
3. Its poll interval and tenant filter rules are no longer readable.

### Why nothing caught it

Every scheduler test patches `record_checkpoint` with a fake that appends the
dict it was handed, so **this statement had never been executed by a test**.
The contract suite covers the in-memory machinery and never reaches SQL. The
test double was more capable than the real thing, precisely at the boundary
the defect lived on.

### Fix

The patch is bound as a mapping with a JSONB type, serialised once, and the
`coalesce` default is a SQL literal rather than a second `cast(...)` carrying
the identical bug. Rows already corrupted are recovered on read by
`_recover_connector_config`: the configuration is the mapping element and the
cursor is inside the encoded string, so an upgraded deployment resumes without
an operator running anything and without re-reading its overlap.

### Regression tests

`tests/isolation/test_queue_acknowledgement_live.py`:
`TestPersistingACursorDoesNotCorruptTheConfig` (config stays an object, the
next poll still runs, the poll interval survives) and
`TestACorruptedConfigIsRecoveredOnRead`.

---

## Verification performed

Commands and results, in order. The connectors venv was built from the
service's own locked set (`python3 scripts/service_requirements.py connectors
--locked`) on Python 3.11.15.

| Check | Command | Result |
| --- | --- | --- |
| Connectors suite | `python -m pytest tests/ -q` (in `services/connectors`) | **1230 passed** |
| Live scheduler (pre-existing) | `pytest tests/isolation/test_connector_scheduler_live.py` | **5 passed** |
| Live queue acknowledgement (new) | `pytest tests/isolation/test_queue_acknowledgement_live.py` | **11 passed** |
| Lint | `ruff check services/ scripts/ tests/ tools/` | All checks passed |
| Format | `ruff format --check .` | 2596 files already formatted |
| Types | `python3 scripts/check_mypy_baseline.py` | OK — no tree got worse |
| Collection-path gate | `python3 scripts/check_cloud_native_collection.py` | OK — 3 paths |
| Gate self-test | `… --self-test` | 11 PASS, including "catches a collector with no resumable cursor" |
| Marketplace parity | `python3 scripts/check_marketplace_index_parity.py` | OK |
| Attribution | `python3 scripts/check_attribution.py --diff-base origin/main` | OK |
| Competitor names | `python3 scripts/check_competitor_names.py` | OK |
| Machine paths | `python3 scripts/check_machine_paths.py` | OK — 13204 files |

Live runs used Postgres 16-alpine in Docker with every migration in
`services/api/migrations/` applied in order and the `aisoc_app` runtime role,
matching `connector-scheduler-live.yml`.

### Negative controls

Each reverts one half of the fix and requires the corresponding test to fail
again. Run, not reasoned about; the tree was restored and re-verified green
(1230 passed) afterwards.

| Reverted | Test | Result |
| --- | --- | --- |
| Pub/Sub ack back inside the pull loop | `…::test_nothing_is_acknowledged_while_the_entries_are_only_in_a_list` | **1 failed** |
| Pub/Sub watermark back in place of identity | `…::test_an_entry_older_than_the_last_batch_is_still_emitted` | **1 failed** |
| CloudTrail delete back inside the receive loop | `…::test_a_message_is_not_deleted_while_its_records_are_only_in_a_list` | **1 failed** |
| CloudTrail watermark back in place of identity | `…::test_an_event_older_than_the_last_batch_is_still_emitted` | **1 failed** |
| Scheduler acknowledges regardless of acceptance | `…::test_a_partially_accepted_batch_is_not_acknowledged` | **1 failed** |
| Scheduler acknowledges before the checkpoint write | `…::test_the_checkpoint_is_durable_before_the_acknowledgement_is_sent` | **1 failed** |
| Pre-fix ack placement, against the **live** suite | `test_queue_acknowledgement_live.py` | **3 of 11 failed** |
| `record_checkpoint` double-encode, against the live suite | `test_queue_acknowledgement_live.py` | **7 of 11 failed** |

The last two are wired into `connector-scheduler-live.yml` as a step, so the
live suite cannot silently stop proving anything.

One artefact worth recording because it looked like a defect and was not:
control 6 moves a block without changing the file's byte count, so a
same-second restore let CPython reuse the patched `.pyc` — the "restored" tree
reported a failure that was not in its source. The control script purges
`__pycache__` on every restore.

---

## Bounded recovery for source data already missed

Only for deployments that ran the affected releases. What is recoverable
depends on whether the source destroys data on read.

### CloudTrail on S3 — recoverable, bounded by the bucket's lifecycle policy

The **objects still exist**; only the SQS notifications naming them were
deleted. So an event dropped by the watermark can be recovered for as long as
the bucket keeps the object.

1. Establish the window. The last-known-good point is the `event_time` in the
   old checkpoint:
   ```sql
   SELECT id, name, connector_config -> 'checkpoint'
   FROM connectors WHERE connector_type = 'aws_cloudtrail_s3';
   ```
   On a row corrupted by finding 6 the cursor is the encoded string in the
   array's second element.
2. Re-announce the objects for that window onto the queue — the same shape S3
   sends, which the connector already parses:
   ```bash
   aws s3api list-objects-v2 --bucket "$TRAIL_BUCKET" \
     --prefix "AWSLogs/$ORG_ID/$ACCOUNT/CloudTrail/$REGION/2026/10/08/" \
     --query 'Contents[].Key' --output text \
   | tr '\t' '\n' \
   | while read -r key; do
       aws sqs send-message --queue-url "$QUEUE_URL" --message-body \
         "$(jq -nc --arg b "$TRAIL_BUCKET" --arg k "$key" \
            '{Records:[{s3:{bucket:{name:$b},object:{key:$k}}}]}')"
     done
   ```
3. Re-reading an object the connector already emitted is safe — the identity
   cursor suppresses it, and anything genuinely missed is emitted once.

Bound: the trail bucket's own retention. CloudTrail objects are not deleted by
the connector, so a bucket with no expiry rule has everything.

### Pub/Sub — mostly **not** recoverable from the subscription

An acknowledged message is gone. `subscriptions.seek` can replay acknowledged
messages **only** if the subscription was created with `retainAckedMessages`
enabled, and only inside its `messageRetentionDuration`. Both are vendor
settings AiSOC does not set, and `retainAckedMessages` defaults to off, so on
a default subscription the answer is no.

Check before assuming either way:

```bash
gcloud pubsub subscriptions describe "$SUBSCRIPTION" \
  --format='value(retainAckedMessages, messageRetentionDuration)'
# If retainAckedMessages is true, and only then:
gcloud pubsub subscriptions seek "$SUBSCRIPTION" --time="$RFC3339_TIMESTAMP"
```

The **source** is the better path. A Cloud Logging sink is a copy of data that
Cloud Logging also retains in its own buckets (`_Default` keeps 30 days unless
changed), so a gap can be re-read from Logging itself for the affected window
rather than from the subscription — which is what the sibling
`gcp_cloud_audit` connector does. Verify the retention on the bucket the sink
reads before relying on it:

```bash
gcloud logging buckets describe _Default --location=global --format='value(retentionDays)'
```

### Distinguishing the two, because it decides what to tell an operator

| | CloudTrail on S3 | Pub/Sub |
| --- | --- | --- |
| What the acknowledgement destroyed | the **notification** | the **message** |
| Does the payload survive it? | yes — the object is still in the bucket | no, unless `retainAckedMessages` was on |
| Recovery | re-announce the objects (above) | seek, if retained; otherwise re-read Cloud Logging |
| Bound | the bucket's lifecycle policy | `messageRetentionDuration`, or Logging's own retention |

### Repairing a `connector_config` corrupted by finding 6

Not required — it is recovered on read, so connectors resume on upgrade with
no operator action. For anyone who wants the column itself clean:

```sql
-- Inspect first. This should return zero rows on a healthy deployment.
SELECT id, name, connector_type
FROM connectors
WHERE jsonb_typeof(connector_config) <> 'object';

-- Repair: fold the array back into the object it should have been.
UPDATE connectors SET connector_config = (
  SELECT coalesce(jsonb_object_agg(k, v), '{}'::jsonb)
  FROM jsonb_array_elements(connector_config) AS e,
       jsonb_each(CASE WHEN jsonb_typeof(e) = 'object' THEN e ELSE '{}'::jsonb END) AS kv(k, v)
) || coalesce((
  SELECT (e #>> '{}')::jsonb
  FROM jsonb_array_elements(connector_config) AS e
  WHERE jsonb_typeof(e) = 'string'
  LIMIT 1
), '{}'::jsonb)
WHERE jsonb_typeof(connector_config) = 'array';
```

Take a backup first, and re-run the `SELECT` afterwards to confirm it returns
nothing.

Executed against Postgres 16 inside a transaction, on a row written into the
exact corrupted shape, and rolled back. Measured:

```
 before | array  | [{"filter_rules": [{"field": "x"}], "poll_interval_seconds": 120},
                   "{\"checkpoint\": {\"time\": \"2026-10-08T11:00:00Z\", \"id\": \"evt-1\"}}"]
 after  | object | {"checkpoint": {"id": "evt-1", "time": "2026-10-08T11:00:00Z"},
                   "filter_rules": [{"field": "x"}], "poll_interval_seconds": 120}
 remaining corrupt rows | 0
```

Both halves come back: the configuration and the cursor that was trapped
inside the encoded string.

---

## Remaining limitations

Stated rather than implied.

1. **Duplicates are possible and bounded; loss is not.** A crash between
   ingest accepting and the checkpoint write — one database round trip — leaves
   a redelivery nothing can recognise. Moving the acknowledgement earlier would
   shrink that window and reopen the loss window, which is the wrong trade.
2. **The dedup set is bounded at 10,000 identities.** A redelivery of
   something older than that is re-emitted. It cannot drop an event.
3. **`azure_event_hubs` still carries the out-of-order watermark**, by the
   reasoning above. Its data is re-readable, so the consequence is a recoverable
   drop rather than an unrecoverable one, but it is still a silent one.
4. **In-batch duplicates are not collapsed**, unchanged from before.
5. **No vendor was contacted.** Every test here drives a local socket or a
   boto3 double. The request and response shapes come from recorded
   vendor-shaped fixtures, and the claim is that the connector handles those
   shapes — not that it has been run against a real AWS account or a real GCP
   project. **A live run against a genuine SQS queue and a genuine Pub/Sub
   subscription has not been performed and would be worth doing**; in
   particular the behaviour of a receipt handle whose visibility has lapsed,
   and of an expired `ackId`, is taken from vendor documentation rather than
   observed here.
6. **Kafka was not in the loop.** The durability claim rests on reading
   `services/ingest` — `PublishBatch` awaited, `RequiredAcks: RequireAll`, 500
   on error — and the live suite's ingest stand-in returns the same contract
   over a real socket. The Go service itself was not run, and no broker
   acknowledgement was observed end to end in this work.
7. **`AISOC_SERVICE_TOKEN` is unset in the live runs**, so the ingest client
   logs that its pushes would be refused 401. The stand-in accepts them, which
   is right for testing the acknowledgement ordering but means authentication
   to ingest is not exercised by this suite.
8. **Only the Pub/Sub half of the live suite exists.** The CloudTrail
   connector's live coverage is the boto3-double suite, because standing up a
   credible SQS and S3 pair needs either real AWS or a LocalStack dependency
   this repository does not currently take.
