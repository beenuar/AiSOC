# Fusion durability: delivery, archival and windowed detections

Remediation phases 4, 5 and 6. All three live in `services/fusion`, which is
why they are one piece of work: they are three different answers to the same
question — *what does this service promise when the process dies between two
steps?*

Each finding below carries its status, the production path it affects, the
regression test that pins it, what changed, how it was verified, and what is
still true after the fix. Where something could not be verified it says so;
an implied pass is worth less than a stated gap.

---

## Summary of guarantees

| | Before | After |
| --- | --- | --- |
| **Fused-alert delivery** | Enqueue reported as delivery. An alert could be durable in Postgres, its offset committed, and nothing ever published. | **At-least-once.** The broker acknowledgement is awaited; an alert that still owes a notification is journalled before the message can be acknowledged, and a relay delivers it. |
| **Lake archival** | Accepted meant *buffered in memory*. A hard kill lost the buffer; capacity discarded the oldest rows after their offsets were committed. | **At-least-once with a disk spool.** Accepted means on disk. Capacity is back-pressure. A batch the store refuses is quarantined, not deleted. |
| **Windowed detections** | An observation was one *delivery*; a threshold hit was suppressed by its own retry. | **Idempotent per source event**, event-time windows, and a hit is recoverable until its alert is durable. |

None of this is exactly-once and none of it is described that way. The three
places duplicates remain possible are named in [Residual
limitations](#residual-limitations).

---

## Phase 4 — Finding 3: the fused-alert delivery future was discarded

**Status: reproduced and fixed.**

### The production path

`FusionWorker._fuse_and_persist` persists the alert row, then publishes the
fused envelope to `aisoc.alerts.fused`, which is what `services/agents`
consumes to auto-triage. The publish was:

```python
await asyncio.wait_for(producer.send(topic, value=envelope), timeout=...)
```

`AIOKafkaProducer.send` is a coroutine that appends the record to the client's
in-memory batch accumulator and returns a **future** that resolves when the
broker acknowledges it. Awaiting the call awaits the *enqueue*. The delivery
outcome — including a refusal arriving milliseconds later — was in the future
that was dropped.

The consumer commits the input offset as soon as `_handle_message` returns
true, immediately after that buffered send. A kill in that window leaves the
alert row in Postgres, the envelope in process memory, and the offset past the
source event. The alert exists and auto-triage never sees it.

The repository already knew the correct shape and explained it:
`services/fusion/app/services/dlq.py` does `future = await send(...)` then
`await future`, with a comment stating this exact hazard, and `dlq_replay.py`
uses `send_and_wait`. The hot path was the one place it was not applied.

### Why it survived a 25-case durability suite

Every existing test used `AsyncMock()` as the producer. Its `send` returns an
awaitable resolving to a `MagicMock`, so `send` and `send_and_wait` are
indistinguishable under it — both read as "awaited, no exception". The one
test that looked like it covered this,
`test_publish_failure_after_a_durable_row_is_retryable`, drives a double whose
`send` *raises*, which is an enqueue-stage failure the original code caught
correctly.

The suite's producer double now lives in
`services/fusion/tests/kafka_doubles.py`, models the two-stage contract, and
says in its docstring why `AsyncMock` must not be used for anything reaching a
publish.

### Regression tests

| Test | Proves |
| --- | --- |
| `test_publish_acknowledgement.py::test_a_broker_error_delivered_after_the_enqueue_is_observed` | A refusal arriving after a successful enqueue is reported. |
| `…::test_an_unacknowledged_record_is_not_reported_as_published` | A record still in the accumulator is not a delivery. |
| `…::test_publishing_returns_only_after_the_acknowledgement` | Positive control, and the ordering claim on the happy path. |
| `…::test_the_published_envelope_carries_a_stable_dedupe_key` | Every republication of one alert carries one key. |
| `integration/test_publish_acknowledgement_live.py` (3 tests) | The same three claims against a real broker. |

### The fix

`FusionWorker._deliver` awaits the enqueue and then the delivery future, with
one `wait_for` around both so `AISOC_KAFKA_SEND_TIMEOUT_SECONDS` is an
end-to-end delivery deadline rather than a bound on a local memory append.
A timeout cancels the wait, not the record, so a timed-out publish is reported
as **unconfirmed and re-published**, never as lost.

Records are keyed by the canonical alert id. Re-publication is designed-for —
an offset commit and a broker ack cannot be made atomic — so the key is part
of the contract: every copy of an alert lands on one partition under one key,
which is what makes a downstream de-duplicator tractable.

### Compatibility

Keying changes which partition a fused alert lands on. A consumer group reads
all partitions, so consumption is unaffected; per-key ordering improves.
`services/agents`' triage worker needs no change — `alert_row_id` was already
in the envelope, and it is the dedupe key.

---

## Phase 4 — the crash window, and the recovery mechanism

**Status: source-confirmed gap, closed.** There was no outbox and no
reconciliation sweep (`grep -r outbox services/fusion` returned nothing).

Two orderings are possible between a durable alert row and its notification,
and only one recovered:

1. **The process dies between the durable row and the publish.** The input
   offset was never committed, so Kafka re-delivers, the sink answers a
   verified `DUPLICATE`, and the publish is retried. Re-delivery is the
   recovery and it already worked.
2. **The publish fails until the retry budget runs out.** The message is then
   dead-lettered — a durable capture, so the offset *commits*, correctly. From
   that moment nothing re-delivers the record. The alert row exists, the
   offset is past the source event, and no envelope will ever be published.
   A dead letter is a triage record; nothing re-drives it.

Case 2 is permanent loss of the notification for an alert sitting in Postgres,
with every surface reporting success.

### The fix: a notification journal, not a transactional outbox

Migration `121_fusion_alert_outbox.sql` adds `fusion_alert_outbox`. A row is
written when a publish has definitively failed, and always **before** the
consumer may acknowledge the message. `NotificationRelay` runs beside the
consume loop, claims rows under a lease, publishes them through the same
awaited-ack path as the inline publish, and deletes them.

This is deliberately **not** a transactional outbox, and the reasoning is
recorded in the migration: the happy path writes nothing, because case 1 is
already closed by an offset that has not moved. Making every alert pay an
extra `INSERT` and `DELETE` to cover a window re-delivery closes for free
would buy nothing — a transactional outbox would not make delivery
exactly-once either, it would only move the duplicate.

Rows are deleted on delivery rather than flagged, so the table *is* the
backlog: `count(*)`, not a filtered scan over delivery history.

A `DUPLICATE` persist outcome clears any pending row. That is the only path on
which one can exist, so the happy path pays nothing for it.

If the journal cannot be written the alert is counted
(`notifications_unrecoverable`), logged at `critical`, and the dead-letter
reason says *the notification* was lost rather than the alert — an operator
reading "transient processing failure" alone would look for a missing alert,
find one, and conclude the pipeline is healthy.

### Acceptance criteria

| Criterion | Where it is proved |
| --- | --- |
| DB commit succeeds + Kafka delivery fails | `test_a_broker_error_delivered_after_the_enqueue_is_observed`; live `test_a_refusal_that_arrives_after_the_enqueue_is_reported` |
| Process exits after DB commit before publication | Offset is not committed, so Kafka re-delivers — `test_consumer_durability.py::test_consume_loop_does_not_commit_a_failed_message` |
| Kafka publication succeeds + input-offset commit fails | Re-delivery republishes under the same key; `test_the_published_envelope_carries_a_stable_dedupe_key` |
| Restart recovers pending notifications | `test_alert_outbox.py::test_the_relay_delivers_a_journalled_notification`; `integration/test_alert_outbox_live.py::test_the_relay_drains_the_real_table` |
| A delayed broker error is observed and reported | `integration/test_publish_acknowledgement_live.py::test_a_refusal_that_arrives_after_the_enqueue_is_reported` |
| Duplicate delivery produces no duplicate downstream effect | One key per alert plus `alert_row_id`; the sink's per-tenant dedup index (migration 120) collapses a re-persist |

---

## Phase 5 — Finding 11: "accepted" meant buffered in memory

**Status: reproduced and fixed.**

### The production path

`LakeWriter.write_event` appended to `self._buffer` — a plain `list[dict]` —
and returned `True`; its own docstring admitted True meant "accepted for
archival, not that it is already durable". `consumer.py` used that return only
to bump a counter and committed the input offset regardless. So archival rode
entirely on process memory and the fusion consumer-group offset:

* a hard kill lost the buffer whole (`stop()` was honest and counted retained
  rows as dropped, but `SIGKILL` does not run `stop()`);
* `_enforce_buffer_capacity` discarded the **oldest** rows on overflow —
  loudly, but long after their offsets were committed, so nothing could replay
  them;
* there was no spool and no lake checkpoint, so "the lake is behind" and "the
  lake has a permanent hole" were indistinguishable.

The recovery machinery already existed and nothing triggered it:
`_fallback_event_id` derives a replay-stable id from the Kafka coordinates and
the table is read with `LIMIT 1 BY event_id`, so a replay *would* deduplicate.
What was missing was a reason to replay.

ClickHouse outage handling was already good — re-prepends the batch,
distinguishes connection from data errors, reconnects with capped backoff —
and is preserved.

### The fix: the queue is a disk spool

`services/fusion/app/services/lake_spool.py`. `write_event` returns `True`
only once the row is on an append-only segment file, `start()` replays
whatever ClickHouse never took, and the consumer raises a retryable failure
when archival cannot make an event durable, so the offset is held.

**Only the spool refusing an event applies back-pressure.** A ClickHouse
outage is absorbed and costs the alert path nothing — that is the distinction
between "the archive is behind" and "the archive cannot accept anything".

**Capacity is back-pressure, never discard.** At the byte cap `write_event`
returns `False`, the offset is held, and Kafka's retention becomes the
buffer — a durable log the platform already runs, orders of magnitude larger
than any in-process cap. The regression test asserts back-pressure rather than
headroom, specifically so raising a limit cannot pass as a durability fix.

**A batch the store keeps refusing is quarantined, not deleted.** A repeated
non-connection error is a schema disagreement; retrying forever blocks
everything behind it, but deleting makes the gap permanent even after someone
fixes the schema. The rows move to `<spool>/quarantine/` and the count is
exposed.

### What the spool survives, exactly

| Failure | Survives? |
| --- | --- |
| Process crash, `SIGKILL`, container **stop** | **Yes.** The bytes are in the kernel page cache; the OS writes them out whether or not this process lives. |
| Machine power loss, kernel panic | **Only with `AISOC_LAKE_SPOOL_FSYNC=1`**, which costs a disk round trip per batch. Off by default. |
| Container **destroyed** / pod rescheduled | **Only if the spool directory is a mounted volume.** Otherwise rows whose Kafka offsets were already committed are gone. |

The third row is a real limitation and is stated rather than papered over.
`AISOC_LAKE_SPOOL_DIR` defaults to `.aisoc/lake-spool`, relative so a first run
needs no provisioning; a containerised deployment must mount it.

### Exposure

`LakeWriter.metrics()` existed and **had no caller anywhere in the service** —
the backlog it computed was unreadable. `GET /metrics` now returns it:
`spool_rows`, `spool_bytes`, `capacity_refusals`, `quarantined_rows`,
`rows_recovered`, `rows_dropped`, `spool_unreadable_lines`,
`spool_write_failures` and a `degraded` flag, alongside the notification
backlog (total, age of the oldest, and a per-tenant breakdown). Anything
unreadable reports `None`, never `0`.

`rows_dropped` is now reserved for genuine unrecoverable loss. Nothing in the
normal path increments it, so a non-zero value means events are actually gone.

### Acceptance criteria

| Criterion | Test |
| --- | --- |
| Hard termination before a flush | `test_lake_durability.py::test_a_hard_kill_before_a_flush_does_not_lose_the_archive` |
| Extended ClickHouse outage | `…::test_a_clickhouse_outage_does_not_stop_the_alert_pipeline`, `…::test_an_extended_outage_drains_when_the_store_returns` |
| Capacity exhaustion | `…::test_capacity_exhaustion_applies_back_pressure_instead_of_dropping`, `…::test_a_refused_event_stops_the_offset_committing` |
| Partial / ambiguous insert outcomes | `…::test_a_batch_the_server_keeps_rejecting_is_quarantined_not_deleted`; reading the spool is non-destructive, so a crash between insert and commit replays and collapses on `event_id` |
| Restart and recovery | `…::test_a_hard_kill_before_a_flush_does_not_lose_the_archive` |
| Duplicate replay | `…::test_a_replayed_event_keeps_one_identity` |
| Graceful shutdown | `…::test_graceful_shutdown_leaves_a_recoverable_backlog_not_a_loss` |

### Three existing tests were pinning the defect

`test_stop_counts_rows_it_could_not_flush_as_dropped`,
`test_buffer_overflow_drops_oldest_rows_explicitly` and
`test_data_errors_are_bounded_and_dropped_loudly` asserted that retained rows
are dropped at shutdown, that overflow discards the oldest rows, and that a
rejected batch is deleted. Each was a correct reading of the old design and is
now wrong; each was rewritten with a comment saying what it used to assert and
why that changed.

---

## Phase 6 — Findings 2 and 6: windowed detections were not replay-safe

**Status: both reproduced and fixed.**

### Finding 6 — observation inflation

`_observe_and_check` minted a fresh `uuid.uuid4().hex` member per call for a
threshold rule with no `distinct_by`. Delivery into this engine is
at-least-once and the consumer *deliberately* re-delivers on
`RetryableProcessingError`, so one event counted N times was N members: **N
re-deliveries of a single failed login crossed a threshold of N**, producing a
brute-force alert naming a user who did nothing.

The member is now the event's stable identity — ingest id, then Kafka
coordinates, then a content hash, the same preference order and the same
documented trade-off as `lake_writer._fallback_event_id`. `ZADD` on an
existing member updates its score rather than adding a row, so a re-delivered
event refreshes its own observation.

**The dual use of one sorted set is preserved exactly.** A `distinct_by`
rule's member is the observed value; an event-count rule's member is the
event. Both mean "one row per distinct thing" and differ only in what the
thing is. `test_a_distinct_by_rule_still_counts_distinct_values` pins that a
fix making every member the event id would turn secret enumeration into a
request-rate rule.

### Finding 2 — the retry suppressed the alert it existed to recover

The fire-once marker was written *inside* `_observe_and_check`, before
`evaluate` had built the `DetectionHit` and long before the consumer persisted
anything. `_fuse_and_persist` raises when the row is not durable, so Kafka
re-delivers — and on re-delivery `SET NX` returned falsy and no hit was
produced until the window rolled.

Firing is now a **claim**, not a flag:

1. Crossing the threshold takes `SET fired_key <token> NX EX 60`.
2. The consumer persists the alert.
3. `confirm(hit)` promotes the claim to the window-long marker; `release(hit)`
   drops it if the alert never landed.

Moving the write to *after* the database would have traded this race for a
different one — two workers both crossing the threshold before either had
written anything. Taking the claim atomically up front and resolving it
afterwards avoids both.

Both resolutions are owner-checked Lua, because an unconditional `DEL` would
free the claim of the worker that took it after yours expired, and that
worker's alert would then publish twice.

**Crash recovery** is the third outcome: a worker that dies resolves nothing
and the lease ages out, so the alert is delayed by `FIRE_CLAIM_SECONDS` (60)
rather than suppressed for the window.

### Event time, late arrival, out-of-order delivery, backfill

Scores are **event time**, with arrival as the fallback for a source that
stamps nothing. Almost every connector here polls, so arrival order is the
vendor's order; scoring by wall clock made a detection a function of the poll
cadence and made replaying a week of history look like one enormous burst
happening now.

The count is two window-length spans anchored on the event — the one ending at
it and the one starting at it — via `ZCOUNT`. The trailing span catches a
burst whose last event arrives last; the leading span catches one whose first
event arrives last.

Trimming is against the event's own time, bounded by
`REORDER_TOLERANCE_SECONDS` (300): an event that arrives late is old by
construction, and trimming it against the clock would discard the observation
it just made.

The cooldown key carries the **event-time bucket**, which is what makes a
replay idempotent rather than merely unlikely: the same events replayed at any
wall-clock time land in the same bucket and meet the same confirmed marker.

### A Redis blip no longer reads as a quiet estate

A per-rule error was caught at `logger.debug`, so a Redis outage and an estate
with nothing happening were indistinguishable. Detection stays fail-soft —
Redis must not wedge the alert pipeline — but the skip is now counted
(`WindowedDetectionEngine.rule_errors`) and logged at `warning`.

### Acceptance criteria

| Criterion | Test |
| --- | --- |
| Persistence fails immediately after a threshold is crossed | `test_windowed_replay_safety.py::test_a_hit_that_was_never_persisted_fires_again_on_re_delivery` |
| The threshold event is delivered repeatedly | `…::test_one_event_delivered_five_times_does_not_cross_a_threshold_of_five`, `…::test_a_persisted_hit_does_not_fire_twice` |
| A worker restarts during the handoff | `…::test_a_crashed_worker_does_not_suppress_the_alert_forever` |
| Multiple workers process overlapping deliveries | `…::test_two_workers_on_overlapping_deliveries_produce_one_hit`; live `integration/test_windowed_detection_live.py::test_two_concurrent_workers_take_one_claim_between_them` |
| Events arrive out of order | `…::test_out_of_order_arrival_reaches_the_same_verdict_as_in_order` |
| Historical events are backfilled | `…::test_a_historical_backfill_does_not_merge_with_live_traffic` |
| No duplicate alert or duplicate response effect | live `…::test_a_worker_cannot_release_another_workers_claim`, `…::test_a_worker_cannot_confirm_another_workers_claim` |

### Six Redis doubles became one

Five test files each carried their own in-memory Redis with a different subset
of commands; none had `eval`, some lacked `zrangebyscore`. The cost is not
duplication — it is that a command the engine newly calls raises inside the
fail-soft per-rule handler, the rule silently produces no hit, and the test
fails with "the detection did not fire" when the real answer is "the double
cannot do what Redis does". There is now one double in
`services/fusion/tests/redis_doubles.py`.

The two things a Python double cannot model — that `SET NX` is atomic between
two workers, and that the owner check and the write inside each script happen
together — are proved against a real server in
`tests/integration/test_windowed_detection_live.py`.

### One existing test had its data corrected

`test_sigma_correlation_replay.py::test_event_count_fires_at_its_threshold_and_not_one_short`
placed its first five events a second apart and the sixth **996 seconds
later**, in a 600-second window, and passed — because the engine scored by
arrival time and ignored `event_time` entirely. The data is now what the rule
describes, and the out-of-window case is asserted rather than relied on by
accident.

---

## Verification performed

Everything below was run on this branch. Commands and results are literal.

**Environment.** Python 3.11.15 in a virtualenv built from the fusion
service's own locked set (`python3 scripts/service_requirements.py fusion
--locked`); `ruff 0.16.10` and `mypy 2.4.0` in a separate virtualenv at the
pinned ranges, because a service venv holds that service's lock and nothing
else.

**Containers.** Real Postgres 16, Redis 7 and Redpanda v24.2.7 were available
and used. The live suites are gated on `AISOC_TEST_POSTGRES`,
`AISOC_TEST_REDIS` and `AISOC_TEST_KAFKA` and skip cleanly without them.

```
services/fusion$ pytest tests/ -q
1049 passed, 2 skipped, 1 warning in 20.81s     # with all three containers
1035 passed, 9 skipped                          # without them, live suites skipped

$ ruff check services/ scripts/ tests/ tools/   → All checks passed!
$ ruff format --check .                         → 2605 files already formatted
$ python scripts/check_mypy_baseline.py         → OK — no tree got worse (964 findings)
$ python scripts/check_tenant_query_predicates.py → OK (ratchet unchanged at 60)
$ python scripts/check_rls_policy_shape.py      → OK (160 policies, 159 FORCEd)
$ python scripts/check_module_reachability.py   → OK (1037 of 1065 reachable)
$ python scripts/check_raw_sql_columns.py       → 566 statements parsed, no failure
$ python scripts/check_competitor_names.py      → OK
$ python scripts/check_attribution.py --diff-base origin/main → OK
```

### Negative controls

Each fix was reverted in place and the suite re-run. Results are what was
actually printed.

| Control | Result |
| --- | --- |
| `await future` removed from `_deliver` | 3 failed — the two delivery-failure cases do not raise, and the happy path returns with the future pending. |
| Same, against the **real broker** | 1 failed, and Python reports the defect itself: `Future exception was never retrieved: MessageSizeTooLargeError`. |
| Journal write removed from the publish-failure path | 3 failed — `assert 0 == 1` on the pending journal row. |
| Consumer stops gating the offset on durable archival, and `write_event` ignores the spool's answer | 2 failed — capacity and offset-hold. |
| `LakeSpool.append` made a no-op (memory-only queue again) | 23 failed across both lake suites. |
| Random member per call restored | 3 failed, including the live real-Redis inflation test. |
| Cooldown written before persistence as a window-long flag | 3 failed, including both live claim/release tests. |

**One control changed a test rather than confirming it**, and it is the most
useful result here. The first version of the live broker-refusal test used
aiokafka's default `max_request_size` with a 2 MiB record; aiokafka enforces
that limit itself inside `send`, so the rejection happened at the *enqueue* —
which the original code caught correctly — and the test **passed with the fix
reverted**. Raising the client limit past the broker's moved the rejection to
delivery. A live test exercising the wrong stage is worse than no live test: it
reports coverage of exactly the thing it does not cover.

### What was not verified

* **No full-stack `make up` run.** The pipeline was exercised component by
  component against real Postgres, Redis and Redpanda, not as a 16-service
  compose stack with a connector polling a real vendor. The end-to-end
  connector → ingest → fusion → agents journey is unverified by this work.
* **No multi-replica deployment.** Two-worker behaviour is proved by two
  engine instances against one real Redis and two outbox instances against one
  real Postgres, which exercises the server-side primitives that make it safe.
  It is not the same as two containers under a rebalance.
* **No power-loss test.** The `AISOC_LAKE_SPOOL_FSYNC` path is implemented and
  unit-covered; nobody pulled a plug.
* **No throughput measurement.** The spool adds one buffered `write()` per
  archived event and the windowed engine's count went from one `ZCARD` to two
  `ZCOUNT`s. The suite's own timing is the only number taken: 18.5 s → 20.8 s
  for ~1,000 tests, of which the lake spool's initial O(backlog) line count was
  the dominant cost until it was cached. No EPS benchmark was run.

### A gate weakness found and not exploited

`scripts/check_tenant_query_predicates.py` credits a raw statement as
tenant-scoped when the token `tenant_id` appears anywhere in the SQL text,
including a `RETURNING` list. `AlertNotificationOutbox.claim` is cross-tenant
by design and is credited on that basis rather than on a predicate — confirmed
by removing `o.tenant_id` from its `RETURNING` clause, after which the gate
flags it. `backlog` is credited the same way, and it genuinely groups by
tenant.

Rather than lean on this further, `resolve` and `record_attempt_failed` were
**given real tenant predicates** using the tenant their own claim returned, so
the ratchet is unchanged at 60 entries and no ceiling was raised. The gate's
blind spot is reported here; fixing it is outside this change's scope.

---

## Residual limitations

1. **Delivery is at-least-once, not exactly-once.** The relay can publish an
   envelope an inline retry already delivered, and a broker acknowledgement
   arriving after the publisher stopped waiting is indistinguishable from one
   that never arrived. Every record is keyed by its alert id so a consumer can
   collapse duplicates; `alert_row_id` in the envelope is the same key.
2. **The journal is only as available as Postgres.** If a publish fails *and*
   the journal cannot be written, the dead-letter capture is the only record
   of the envelope. That is a durable, triageable archive of the payload but
   it is not a delivery: it is counted as `notifications_unrecoverable` and
   logged at `critical`. The consumer does not stall the partition for it,
   because the alert row itself is durable — what is lost is the notification.
3. **The spool is only as durable as its filesystem.** See the table in Phase
   5. A container without a mounted volume loses spooled rows whose offsets
   were committed.
4. **One windowed ordering case is detected late rather than immediately.** A
   burst whose last-arriving event is strictly interior to the span is covered
   by neither anchored window; it fires on the next matching event for that
   entity. The alternative — fetching every member and sweeping in process —
   is O(backlog) per event, and the rules with the largest thresholds have the
   largest backlogs.
5. **A burst straddling an event-time bucket boundary can fire twice**, once
   per bucket. The bucket is what makes a replay idempotent, which is the more
   valuable property; the alert sink's per-tenant dedup index collapses the
   second row where the fingerprint matches.
6. **Migration 121 must be applied.** Without it the journal reports itself
   absent once at `error` and archival of undelivered notifications does not
   happen. The table is deliberately not created at runtime: a
   `CREATE TABLE IF NOT EXISTS` there would swallow a permissions failure into
   a log line and leave the service reporting a healthy journal holding
   nothing.

---

## Operator recovery procedure

### An alert exists in Postgres but auto-triage never saw it

```bash
curl -s localhost:8003/metrics | jq '.notifications'
# {"pending": 12, "oldest_seconds": 480.3, "by_tenant": {"<uuid>": 12}}
```

`pending` is the number of alerts that still owe a notification; `by_tenant`
says whose. The relay sweeps every `AISOC_OUTBOX_RELAY_INTERVAL_SECONDS`
(default 15) and only touches rows older than
`AISOC_OUTBOX_RELAY_GRACE_SECONDS` (default 120), which is the head start the
consumer's own inline retries get.

* **Pending falling** — it is draining; nothing to do.
* **Pending flat with `oldest_seconds` rising** — the broker is unreachable to
  this replica, or the relay is not running. Check `fusion.relay_publish_failed`
  and `/readyz`'s `kafka` key, which probes the broker rather than the loop.
* **`notifications_unrecoverable` non-zero** — the journal itself could not be
  written. The envelope is in the dead-letter store; search for
  `notification was neither published nor journalled`.
* **`pending: null`** — the backlog could not be read. That is *unknown*, not
  empty: check `fusion.outbox_schema_missing` (migration 121 not applied) and
  the alert sink's pool.

### The lake is missing events

```bash
curl -s localhost:8003/metrics | jq '.lake'
```

* **`spool_rows` rising, `degraded: false`** — ClickHouse is behind or down.
  The rows are on disk and will be replayed; the alert path is unaffected.
* **`capacity_refusals` non-zero** — the spool is full, so the consumer is
  holding its Kafka offset. Ingest has stopped advancing by design. Restore
  ClickHouse, or raise `AISOC_LAKE_MAX_SPOOL_BYTES` *as headroom while the
  backlog drains*, not as a fix.
* **`quarantined_rows` non-zero** — ClickHouse refused these rows repeatedly
  as data. They are in `<AISOC_LAKE_SPOOL_DIR>/quarantine/*.jsonl`, one JSON
  row per line, and are **not** in the lake. Fix the schema disagreement, then
  replay them by moving the files back into the spool directory and restarting
  the service, which replays on start.
* **`rows_dropped` non-zero** — a genuine unrecoverable gap. Nothing in the
  normal path increments it.
* **`degraded: true`** — the spool directory is unusable (missing, read-only,
  full). Archival is refusing events and the consumer is holding offsets.

After a restart, `lake_writer.spool_recovery_started` and
`lake_writer.spool_recovery_finished` report what was carried over and what is
still pending. Replayed rows carry the same deterministic `event_id`, so
`LIMIT 1 BY event_id` collapses them; a hunt, a usage figure or an aggregate
over the lake is not inflated by a recovery.

### A windowed detection did not fire when it should have

* `windowed_detection.rule_error` at `warning`, or a rising `rule_errors`,
  means Redis was unreachable and rules were skipped. The detections are not
  queued — those events are gone from the window.
* A hit that was claimed and never confirmed holds its slot for
  `FIRE_CLAIM_SECONDS` (60) and then becomes claimable again. If a worker was
  killed mid-handoff, the alert reappears within that window on the next
  matching event.
* A replay of the same events produces no second alert: the cooldown key is
  bucketed on event time, so the replay lands in the same bucket.
