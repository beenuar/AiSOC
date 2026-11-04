# Lake flush and cached triage reliability fixes

This patch fixes two independent failures in the event archival and automatic
triage paths. It changes the fusion lake writer and the agents fused-alert
consumer. It requires no schema migration, additional service, or model.

## Symptoms and causes

### Concurrent lake flushes

The timer and consumer can both call `LakeWriter.flush()`. Previously, they
could read the same spool batch and enter the same synchronous ClickHouse
connection concurrently. This can duplicate inserts and produce transport
errors. Repeated socket errors could also be classified as rejected data and
move valid events to quarantine.

An asynchronous lock now covers client selection, spool reads, inserts and
spool commits. Cancelling a flush waits for its in-flight driver thread before
releasing that lock, because cancelling an asyncio await cannot stop the
synchronous insert. `EBADF`, `ENOTCONN` and `EPIPE` are treated as transport
failures, so their records remain queued for reconnect and replay.

This remains at-least-once archival. Cancellation after a server accepts an
insert can still leave an uncommitted spool batch that is replayed. Stable
event IDs allow readers to collapse those physical duplicates. The patch does
not provide cross-process coordination or remove historical duplicate rows.

### Cached triage with an empty explanation

The cached-verdict branch assigned local verdict and confidence variables but
did not populate the investigation state used for the persisted explanation
and source writeback. An alert could therefore have a real disposition while
its summary said `Auto-triage verdict=None confidence=0.00`.

The branch now normalizes the verdict, bounds confidence to 0–1, and copies
both into that state. The explanation records that the evidence fingerprint
matched a previous assessment and that no new model call was made. State stays
in the running/escalation path: a cached classification does not authorize
closure or prove remediation. Existing closure and response controls remain
in force. Historical summaries are not rewritten by this patch.

## Reproducing the checks

Use Python 3.11 and separate environments built from each service's lock:

```sh
python3 scripts/service_requirements.py fusion --locked > /tmp/fusion-requirements.txt
python3 -m venv /tmp/aisoc-fusion-tests
/tmp/aisoc-fusion-tests/bin/pip install --no-deps -r /tmp/fusion-requirements.txt

python3 scripts/service_requirements.py agents --locked > /tmp/agents-requirements.txt
python3 -m venv /tmp/aisoc-agents-tests
/tmp/aisoc-agents-tests/bin/pip install --no-deps -r /tmp/agents-requirements.txt
```

Configure a migrated test ClickHouse using the service's `CLICKHOUSE_HOST`,
`CLICKHOUSE_PORT`, `CLICKHOUSE_DATABASE`, `CLICKHOUSE_USER` and
`CLICKHOUSE_PASSWORD` settings. Set `AISOC_TEST_CLICKHOUSE=1` explicitly. The
native-transport tests create a connection-local temporary table from
`aisoc.raw_events`; they never insert into the actual lake. Each spool is a
pytest temporary directory.

Set `AISOC_TEST_POSTGRES_DSN` through your test environment's secret handling,
pointing to a migrated test Postgres. The ledger test creates a random synthetic
tenant and alert inside one outer transaction. The real consumer persists
through the real ledger, and the test reads back the alert before rolling the
whole transaction back, including immutable ledger entries. Other persistence
effects use the existing shadow writer; no model request or response action
runs. Both live tests skip without their explicit opt-in environment settings.

```sh
(cd services/fusion && PYTHONPATH=. /tmp/aisoc-fusion-tests/bin/python -m pytest \
  tests/test_lake_writer.py tests/test_lake_durability.py \
  tests/test_lake_flush_concurrency_live.py -q)

(cd services/agents && PYTHONPATH=. /tmp/aisoc-agents-tests/bin/python -m pytest \
  tests/test_cached_triage_ledger_live.py tests/test_fused_alert_worker.py \
  tests/test_auto_triage_dispositions.py tests/test_auto_triage_injection.py \
  tests/test_auto_triage_ledger_records_the_prompt.py -q)

PYTHONHASHSEED=0 python3 scripts/run_evals.py --json --out /tmp/eval-report.json
```

Run the evaluation command in the agents environment. Repository lint and
type checks use the separate, dependency-free environment specified in
`AGENTS.md`; do not merge service dependency locks.

## Verification record

Validated against upstream base `6af28064` with Python 3.11, ClickHouse 23.8
and Postgres 16. Tests use synthetic fixtures, not customer event payloads.

| Check | Result |
| --- | --- |
| Concurrent and cancelled flushes, real native ClickHouse transport | Both failed before the patch; both passed after |
| Three socket errno recovery cases, real disk spool | All failed before the patch; all passed after |
| Cached consumer through real Postgres ledger and alert readback | Failed before the patch; passed after |
| Focused fusion tests, including the live transport checks | 38 passed |
| Focused agents tests, including the live ledger check | 64 passed |
| Evaluation harness, fixed `PYTHONHASHSEED=0` | All 11 suites passed before and after; scores unchanged |
| Repository lint, formatting, type-baseline and attribution/name gates | Passed; no type-baseline increase |

The required negative control removes only the two production fixes, keeps
the regression tests, and reproduces the same failures. Restore the fixes
before deployment. The evaluation harness measures its checked-in corpus;
these results are not a claim about production detection accuracy or model
quality.

## Deployment and rollback

Build and deploy the fusion and agents services using your normal deployment
process. Preserve the lake spool volume across replacement. No retention,
detection rule, notification routing, tenant permission, or firewall setting
is changed. The regression tests are opt-in and are not startup tasks.

Observe lake spool depth, successful archive writes, quarantine growth and
consumer lag after deployment. For a new cache hit, check that the stored
summary identifies the prior assessment and carries its verdict and confidence.

To roll back, revert the patch commit and rebuild/redeploy those two services,
keeping all database and spool volumes. Rolling back code does not erase
archived events or revert summaries already written. Existing quarantine rows
need a separate, evidence-preserving recovery decision; this patch does not
automatically replay or delete them.

## Separate follow-ups

Conversational access to all alert sources, resumable backlog review, entity
graph coverage for inbox ingestion, and FIM backend/enrollment setup are
separate integration work. They are not delivered by these two fixes.

The deployment review also identified useful product follow-ups. These are
observations from the reviewed installation, not additional verified fixes
against the current upstream tree:

- Provide bounded tenant-scoped alert, case, rule and health reads in chat,
  with durable, paginated backlog review. Grouping repeated configuration
  checks should preserve every affected host and failed result. An assessment
  must remain distinct from resolution.
- Explain missing optional backends in the UI. An entity graph needs both
  Neo4j and a populated projection; enabling the database alone does not
  backfill historical alerts. Check graph coverage for inbox ingestion as
  well as the HTTP ingest route.
- Distinguish osquery FIM enrollment and its backend from other vendors' FIM
  alerts. A working generic alert feed does not imply the osquery FIM page
  has enrolled nodes or file events. Verify the web service's configured
  backend address instead of assuming a loopback address reaches another
  container.

This patch adds no management tool, approval bypass, endpoint response, or
bulk alert closure. Deployment-specific configuration and previously
upstreamed security fixes are intentionally excluded from the contribution.
