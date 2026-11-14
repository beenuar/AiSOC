# Vendored: `aisoc_benchmark`

This directory is an **automatically maintained mirror** of
`packages/aisoc-benchmark/aisoc_benchmark/`. Do not hand-edit files here.

## Why it exists

The replay evaluation job (gap-closure Phase 1.4) is orchestrated by
`services/api`, because that service holds the credential vault and the tenant
session and already proxies to `services/agents` and `services/actions`.
Scoring is the one link in that chain with no round trip, since
`aisoc-benchmark` is a distribution rather than a service.

It still cannot be imported directly: the `aisoc-core-api` image is built with
`./services/api` as its build context, so nothing under `packages/` is present
at runtime. Same constraint that produced `_vendor/narrative.py`,
`_vendor/llm_contract_rules.py` and `_vendor/nl_query/`.

The alternative was a second scorer living in the API. `replay.py` opens by
explaining why there is exactly one grader in this repository: a second one
would eventually disagree with the first about what "hallucination rate"
means, and both would keep calling themselves the same number.

## How it stays in sync

Run `python scripts/sync_vendored_benchmark.py` after changing anything under
`packages/aisoc-benchmark/aisoc_benchmark/`. CI runs the same script in
`--check` mode and fails the build when the two trees drift. The check runs in
**both directions**: a module in the mirror with no source counterpart fails
as well as a stale copy.

## Files

Every `*.py` file in the source package is mirrored byte for byte. At the time
of writing that is `__init__.py`, `adapter.py`, `cli.py`, `metrics.py`,
`replay.py` and `runner.py`. The list is derived from the source directory
rather than recorded here, so a seventh module is picked up by existing rather
than by being added to a list.

The API imports `score_replay`, `format_replay_report` and `ReplayScore` from
this mirror. `cli.py` and `runner.py` are mirrored for completeness and have
no caller inside the API.
