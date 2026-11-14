# Runbook: `AisocActionExecutorFailureRateHigh`

> **Severity:** critical (pages)
> **Alert source:** [`aisoc-pipeline-kpis` group](../../infra/docker/alerts/aisoc.rules.yml)

## What the alert means

More than **20% of `{{ $labels.executor }}` dispatches failed**
over the last 10 minutes. This blocks the "respond" loop
end-to-end — analysts will see actions timing out in the UI, and
the playbook executor will treat the action as unresolved
indefinitely. The executor label maps to a real downstream
integration (`endpoint`, `network`, `siem`, `identity`,
`ticket`); the failure cause is almost always upstream:

1. **Credentials rotated.** EDR / firewall / IAM creds expired or
   the operator rotated them and didn't update the vault.
2. **Upstream API rate-limited us.** CrowdStrike / Splunk /
   SentinelOne / Azure AD have per-tenant ceilings; a sudden
   bulk-response campaign hits the cap.
3. **Upstream is down.** Vendor incident.
4. **Network split.** Egress from the AiSOC pod blocked by a
   newly-introduced firewall rule on the operator's side.

## First five minutes

```bash
# 1. Per-executor failure breakdown.
docker compose --profile monitoring exec prometheus \
  wget -qO- 'http://localhost:9090/api/v1/query?query=sum%20by%20(executor,reason)(rate(aisoc_action_executor_failures_total[10m]))'

# 2. Last-20 executor errors.
docker compose logs actions --tail 200 \
  | grep -E '"event":"executor\..*\.failed"' \
  | tail -20

# 3. Is the vault healthy? (CredentialVault decrypt errors are
#    indistinguishable from "creds wrong" at the executor layer.)
docker compose logs api --tail 200 \
  | grep -E '"name":"credentials"' \
  | tail -20

# 4. Direct vendor health check from the actions container.
docker compose exec actions \
  python -c "import httpx; r = httpx.get('https://api.crowdstrike.com'); print(r.status_code)"
```

## Mitigation

- **Credentials wrong:** rotate via the API
  (`POST /api/v1/connectors/{id}/credentials`). Don't update the
  env var directly — the per-tenant vault is the source of
  truth.
- **Rate-limited:** the action executors retry with exponential
  back-off, but if 20% are failing terminally, the back-off is
  losing the race against new dispatch rate. Temporarily slow
  the dispatcher in `services/actions/app/dispatcher/config.py`
  (`max_concurrent_per_executor`) and restart actions service.
- **Vendor incident:** flip the affected executor to dry-run
  (`POST /api/v1/executors/{name}/dry-run` — admin-only).
  Outstanding actions resolve as "would have done" with the
  intended payload captured for replay once the vendor is back.
  Don't drop the action queue — analyst playbooks depend on
  durable side-effect promises.
- **Network split:** check egress allowlist with operator. Until
  fixed, set the executor to dry-run same as the vendor-down
  case.

## Root cause

The post-mortem MUST distinguish:

- Was this our bug or theirs? (Vendor status pages + the
  executor's full response body, captured automatically into
  `audit_events.payload`.)
- Did the playbook executor handle the burst correctly?
  (Phase 3.5 wires retry semantics; this alert is the first
  signal that those semantics need tuning.)

## References

- Source rule: [`infra/docker/alerts/aisoc.rules.yml`](../../infra/docker/alerts/aisoc.rules.yml)
- Executor classes: `services/actions/app/executors/`
- Vault: `services/api/app/services/credentials.py`

Updated: **2026-06-28** (Phase 2.5).
