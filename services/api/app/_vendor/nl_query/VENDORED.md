# Vendored: `nl_query`

This directory is an **automatically maintained mirror** of
`services/agents/app/nl_query/`. Do not hand-edit files here.

## Why it exists

The API service ships in a Docker image whose build context is
`./services/api`. That means modules under `services/agents/` are not present
in the running container. The natural-language query translator is consumed by
both the agent runtime and the API's `/nl-query/*` endpoints, so we keep an
in-tree copy here.

## How it stays in sync

Run `python scripts/sync_vendored_nl_query.py` whenever you change anything in
`services/agents/app/nl_query/`. CI runs the same script in `--check` mode in
`.github/workflows/ci.yml` and fails the build if the trees drift.

## Files

| Vendored file        | Source of truth                                   |
| -------------------- | ------------------------------------------------- |
| `__init__.py`        | `services/agents/app/nl_query/__init__.py`        |
| `translator.py`      | `services/agents/app/nl_query/translator.py`      |
| `grammar.py`         | `services/agents/app/nl_query/grammar.py`         |

## Loader

The dynamic loader at
`services/api/app/api/v1/endpoints/nl_query.py::_load_nl_query_module` checks
this directory **first**, then falls back to the source tree at
`services/agents/app/nl_query/` for local development outside Docker.
