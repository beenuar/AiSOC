# Negative controls — patch-window promotion

Two independent halves were reverted one at a time.

## 1. The cast

Reverted in `app/vuln_promotion_sql.py`:

```sql
-        CAST(:affected_hosts AS jsonb), CAST(:tags AS jsonb), 2001, :idempotency_key,
-        :connector_id, CAST(:raw_event AS jsonb)
+        :affected_hosts::jsonb, :tags::jsonb, 2001, :idempotency_key,
+        :connector_id, :raw_event::jsonb
```

Against real Postgres 16 and asyncpg under the connectors service's own
locked interpreter (SQLAlchemy 2.1.6):

```
E  asyncpg.exceptions.PostgresSyntaxError: syntax error at or near ":"
E  sqlalchemy.dialects.postgresql.asyncpg...ProgrammingError: syntax error at or near ":"
```

`test_no_statement_uses_the_colon_cast_spelling` goes red in the same run.

The **sibling control is the proof**: in `test_the_cast_spelling_is_the_fault_
not_the_connection`, `MARK_PROMOTED_SQL` — same module, same connection, same
transaction, same tenant-scoped shape, written `CAST(:tenant_id AS uuid)` —
reports `rowcount == 1` immediately before the upsert raises. The connection,
the parameters, the role and the schema are therefore all working and the
`::` spelling is the whole fault.

Under SQLAlchemy 2.1.6 the `.bindparams()` route fails differently and
louder — `ArgumentError: This text() construct doesn't define a bound
parameter named 'affected_hosts'` — which is why the proof had to run under
the service's own interpreter rather than a system Python.

## 2. The operator-visible failure

Reverted: the two lines in `_promote_overdue_findings` that record the
per-tenant failure, and the two that record an enumeration failure.

```
>  assert response.json()["status"] == "ready_degraded"
E  AssertionError: assert 'ready' == 'ready_degraded'

ERROR aisoc.connectors.scheduler: connector.scheduler.vuln_promotion_failed tenant=1111...
ERROR aisoc.connectors.scheduler: connector.scheduler.promotion_tenant_enum_failed
```

Readiness answering `ready` while the log carries
`vuln_promotion_failed` in the same run is the original defect's shape
exactly: the sweep is broken, the service says it is fine, and the only
difference between "no overdue CVEs" and "the only path to the alert queue
has never worked" is a log line.

The positive control (`test_a_clean_sweep_keeps_readiness_green`) and the
recovery case (`test_a_recovered_tenant_clears_its_own_failure`) are there
because a probe stuck closed reads as working caution, and a sticky failure
reports a fault that is over.
