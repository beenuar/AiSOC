# Vendored: action contracts

This directory is an **automatically maintained mirror** of three modules from
`services/actions/app/live_actions/`. Do not hand-edit the `.py` files here.

## Why it exists

`services/actions` decides whether a response verb may run without a human.
`services/api` serves the console's autonomy page, which has to tell an
operator whether a verb would actually auto-execute on their deployment.

Neither service can import the other: both package their code as top-level
`app`, and each Docker image is built with only its own service directory as
the build context. So the grading has to exist twice.

It is byte-compared rather than spot-checked because this page is the worked
example of what happens otherwise. The console answered "does this
auto-execute" from a per-action confidence threshold in a table no dispatch
path reads, concluded that seven high-blast verbs ran unattended, and showed
an **Autopilot** badge on a stock install whose dispatcher queues every one of
them for human approval. A safety claim two services compute differently is
wrong in whichever one is more generous, and a settings page is the worse
place to be wrong — nothing executes there, so nothing contradicts it.

## How it stays in sync

Run `python scripts/sync_vendored_action_contracts.py` whenever you change any
of the source modules. CI runs the same script in `--check` mode in
`.github/workflows/ci.yml` and fails the build if the trees drift.

## Files

| Vendored file             | Source of truth                                                    |
| ------------------------- | ------------------------------------------------------------------ |
| `contract.py`             | `services/actions/app/live_actions/contract.py`                     |
| `capability_contracts.py` | `services/actions/app/live_actions/capability_contracts.py`         |
| `approval_rules.py`       | `services/actions/app/live_actions/approval_rules.py`               |
| `__init__.py`             | vendored only — the source package's `__init__` imports the dispatcher |
| `VENDORED.md`             | vendored only                                                       |

## Consumer

`services/api/app/services/autonomy_effective.py`, behind
`GET /api/v1/autonomy-policy`.
