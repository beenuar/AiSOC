# Vendored: `narrative.py`

This file is an **automatically maintained mirror** of
`services/fusion/app/services/narrative.py`. Do not hand-edit it.

## Why it exists

The API service ships in a Docker image whose build context is
`./services/api`. That means modules under `services/fusion/` are not present
in the running container. The deterministic correlation-narrative builder is
consumed by both:

- **Fusion** (`services/fusion`), at fusion time, to populate
  `FusedAlert.narrative` before the alert is published to Kafka.
- **API** (`services/api`), lazily, when `GET /alerts/{id}` is asked for an
  alert whose `narrative` column is still `NULL` (e.g. legacy rows fused
  before the column existed). The API computes the narrative on first read
  and persists it on the row so subsequent reads are free.

We keep an in-tree copy here so the API container is fully self-contained.

## How it stays in sync

Run `python scripts/sync_vendored_narrative.py` whenever you change
`services/fusion/app/services/narrative.py`. CI runs the same script in
`--check` mode in `.github/workflows/ci.yml` and fails the build if the two
copies drift.

## Files

| Vendored file       | Source of truth                                       |
| ------------------- | ----------------------------------------------------- |
| `narrative.py`      | `services/fusion/app/services/narrative.py`           |

## Loader

The dynamic loader at
`services/api/app/services/narrative_loader.py::_load_narrative_module`
checks this directory **first**, then falls back to the source-of-truth file
at `services/fusion/app/services/narrative.py` for local development outside
Docker.

## Determinism contract

`build_narrative(inputs)` is a **pure, deterministic** function — same
inputs always produce the same byte-for-byte string. No timestamps, no
random ordering, no LLM. Callers may safely cache the result on the alert
row. See the module docstring in `narrative.py` for the full contract.

For the streaming **LLM** explanation surfaced by the "Deep Explain" action
in the UI, see `/api/v1/alerts/{id}/explain` — that is a separate, on-demand
endpoint that does **not** use this builder.
