# AiSOC — known gaps & follow-ups

State as of 2026-10-03, after the fix session (see fix-log-2026-10.md).

## Data / ingestion

1. **ClickHouse lake empty (`aisoc.raw_events` = 0 rows).** Lake query chain
   is fixed end-to-end (`available: true`), but nothing has indexed events
   into the lake yet. Until ingestion backfills, agent investigations run with
   thin evidence and the reports will be model-generated rather than
   evidence-grounded. Next step (needs a decision): verify
   `aisoc-ingest` → kafka → lake sink path and trigger a backfill window.
2. **`aisoc-ingest` reports `subscriptions: {}`** at /readyz — consumer
   detached or not configured on this build. Confirm intended consumption
   topology before forcing a restart.
3. **OpenSearch vs ClickHouse ambiguity.** Both defined; API lake routes
   point at ClickHouse (`CLICKHOUSE_HOST: clickhouse`). OpenSearch runs but
   holds no event indices. Decide whether it stays (retire it if unused).

## Upstream sync obligation

All fixes are on the fork working tree. The upstream repo
(`beenuar/AiSOC`) must receive these via PR or they regress on the next
image pull. Priority upstream candidates:
- proxy auth fixes (cases/playbooks/graphql → agents)
- `_normalize_status` + forward-monotonic ladder
- investigations list fallback to the postgres ledger
- React #31 responder-card coercion + overview timeline fetch
- ledger `new→triaged` status lift + approvals principal permission fix
- alerts assignee alias + model_fields_set patch

## GPU / model

- T4 16 GB: `qwen3:8b` thinking chains are unusable (60 s+ per call).
  Current: `qwen2.5:7b-instruct` (sub-second to ~6 s). Revisit only with a
  bigger GPU or litellm timeout raise + streaming.
- `ollama n_slots=1`: single request at a time; concurrent investigations
  queue. Fine for this footprint, known ceiling.

## UI follow-ups (not blocking)

- Report tab auto-refresh after a live run completes (currently fetched once
  on completion; a late report.md write isn't picked up).
- Audit log entries render `kind/agent/summary` strings only — any future
  object-valued summary field must be coerced (React #31 class bug).

## Deliberately NOT fixed (by design — do not "fix" again)

- Backwards case status transitions → 422 (ladder guard).
- `escalate` verdict leaving alert `status='new'` (human queue stays open).
- Wazuh SIEM writeback: no disposition-write arm exists for wazuh; the
  execute flag changing nothing is correct.
- Approvals 502 when approver truly lacks `actions:execute:high` — the gate
  working; the fixed bug was only the empty-permission forwarding.
