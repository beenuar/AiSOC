# Depth wave 2: baseline artefacts

The "before" for every delta this plan claims. Captured at kickoff so that a
later measurement has something to be compared against that was recorded
before any of the work started, rather than reconstructed afterwards.

- **Commit:** `152c6d5f` (`origin/main`, v21.0.0)
- **Date:** 2026-11-01
- **Hardware:** Apple M-series, arm64, macOS; Docker Desktop with the
  documented 8 GB / 20 GB VM budget. Single host, no cloud hardware — the
  cloud-hardware and managed-cluster runs are Phase 8.4 and stay open.
- **Host condition worth recording:** nine unrelated containers from other
  projects were already running, one of them a Postgres published on 5432.
  That is not a clean host, and it is the condition the port resolver exists
  for; see D2 in `DEPTH2_PROGRESS.md`.

Every figure here is reproduced by the command beside it. Nothing in this
directory is hand-typed from memory.

## Counted from the tree

| Figure | Value | Command |
|---|---|---|
| Executable detections | 2,530 | `python3 scripts/project_stats.py` |
| Detection rules on disk | 7,015 | same |
| Threat-and-anomaly family | 24 | same |
| Windowed rules / longest window | 76 / 86,400 s | `services/fusion/app/data/windowed_ruleset.json` |
| Registered connectors | 87 | `python3 scripts/generate_connector_count.py --check` |
| Connector type ids | 98 | `packages/types/src/generated/connector-types.json` (`members`) |
| Executor arms (strict) / distinct verbs | 89 / 39 | `capability = "..."` declarations under `services/actions/app/live_actions/` |
| Executor arms (loose grep) | 111 | the same pattern unanchored; counts `reverse_capability`, and is not the figure |
| Claim-to-gate matrix | 334 rows, 329 GATED, 5 PARTIAL, 0 NO GATE | `python3 scripts/check_claim_gate_matrix.py` |
| Cloud/identity/SaaS/code conditions | 344 (native only; windowed carry no product field) | method recorded in `DEPTH2_PROGRESS.md` D1 |
| Highest migration / ADR | 123 / 0014 | `services/api/migrations/`, `docs/decisions/` |

## Measured by running it

### Alert reduction — `services/fusion/tests/test_alert_reduction_real.py`

```
7 passed
[eval] alert reduction (real correlation_key): 1000 alerts -> 667 incidents = 33.3%
[eval] detection-shaped reduction (real correlation_key): 1000 alerts -> 755 incidents = 24.5%
```

Both figures reproduce the published ones exactly. This suite is the
before-and-after instrument for Phase 3.2 (stories) and Phase 3.3 (root-cause
dedup), and the plan requires it re-run on any change to what correlation
sees.

### `make up` + `make smoke` — the golden pipeline

`make up` brought CORE up and created an administrator. `make smoke` then
reported **PASS: 10/10 stages**, including the four that prove the spine
rather than the surface:

```
[PASS] an unauthenticated push is refused — HTTP 401
[PASS] raw telemetry accepted by ingest — HTTP 200 {"accepted":1,"rejected":0}
[PASS] event traversed the spine and became an alert
[PASS] alert is retrievable by id from the API
[PASS] severity survived normalization — severity='high'
[PASS] source attribution is not duplicated — connector_type='CrowdStrike Falcon'
[PASS] description is prose, not a serialized payload
```

### `make up-full` — the baseline the first depth plan never captured

This closes `DEPTH_PROGRESS.md` D2, which recorded that `make up-full` had
not been captured on any host available to that plan.

**22 AiSOC containers** running on the `full` profile, matching the README's
published figure. The lake, graph and search tiers all started:

```
aisoc-postgres     0.0.0.0:15432->5432/tcp      (moved by the port resolver)
aisoc-clickhouse   127.0.0.1:8123, 127.0.0.1:9000
aisoc-neo4j        127.0.0.1:7474, 127.0.0.1:7687
```

It took two attempts. The first failed on a port bind; see D2 in
`DEPTH2_PROGRESS.md` for exactly what happened and what has not been isolated
about it.

## Not captured here, and why

- **Verdict scorecard re-run.** The published matrix in
  `apps/docs/docs/benchmark.md` is the baseline and reproduces from the tree:
  best balanced accuracy **0.357** (`llama3.1:8b-instruct-q4_K_M`) against a
  **0.250** constant-answer floor, auto-close precision **0.091–0.571**,
  hosted rows **not measured**. Re-running the matrix locally would measure a
  different model on different hardware and publish a figure no contributor
  could reproduce; the plan's Phase 4.1 keeps hosted rows *not measured*
  until a funded key exists.
- **Cloud-hardware and managed-cluster runs.** Phase 8.4, maintainer-blocked.
