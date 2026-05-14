---
sidebar_position: 2
title: Secrets & CI tokens
description: Where every CI-managed secret comes from, what reads it, and how to rotate it without breaking automation.
---

# Secrets and CI tokens

AiSOC has two kinds of secrets:

1. **Tenant-data secrets** — connector credentials, tenant LLM keys, IDP
   tokens. Those live in the application-layer credential vault
   ([Credential vault and secret management](./credentials.md)) and never
   appear in CI.
2. **CI-managed secrets** — keys the GitHub-hosted automation needs to
   *do its job* (push to the eval-results branch, open the weekly
   benchmark PR, call the LLM provider for the wet-eval run). Those
   live in `Settings → Secrets and variables → Actions` and are
   documented on this page.

This page covers (2). Tenant-data secrets are deliberately out of scope
— they belong to the runtime path, not to CI.

## At a glance

| Secret name              | Used by                                         | Owner / who configures                   | Rotation cadence  |
|--------------------------|-------------------------------------------------|------------------------------------------|-------------------|
| `WET_EVAL_OPENAI_KEY`    | `.github/workflows/wet-eval.yml` (live LLM run) | Maintainer team — project-funded billing | 90 days           |
| `AISOC_BENCH_BOT_TOKEN`  | `.github/workflows/wet-eval.yml` (PR opener)    | Maintainer team — bench-bot account      | 180 days          |
| `GITHUB_TOKEN`           | every workflow (default, scoped per-job)        | GitHub-managed (automatic)               | per-run           |

> Workspace rule: **CI secrets are never committed to the repo, never
> echoed in workflow logs, and never restored from a backup**. They
> are issued in the GitHub UI, written into the secret store once, and
> rotated by replacement (issue new → update secret → revoke old).

## `WET_EVAL_OPENAI_KEY`

The LLM provider key the weekly wet-eval CI job uses to dispatch the
200-incident corpus through the live LangGraph agent.

| Property            | Value                                                                                   |
|---------------------|-----------------------------------------------------------------------------------------|
| **Type**            | OpenAI API key (project-scoped, `sk-...`).                                              |
| **Scope**           | A dedicated OpenAI project that contains *only* the wet-eval workload.                  |
| **Spend cap**       | $25 / month hard cap on the project (≈10× a normal weekly run; tripwire if it spikes). |
| **Read by**         | `.github/workflows/wet-eval.yml`, step "Run wet eval", and only that step.              |
| **Why not `OPENAI_API_KEY`?** | Naming the key `WET_EVAL_*` makes the secret hygiene explicit: this key only gets injected into one workflow. A compromised CI runner can't use it to call any other endpoint. The agent's resolver still reads `OPENAI_API_KEY`, so the workflow mirrors the wet-eval key into that env var **for the duration of the run step only**. |

### How to configure

1. Create a dedicated OpenAI project named `aisoc-wet-eval`.
2. Set a $25/month spending limit on it (Settings → Limits).
3. Generate a project API key. Copy it once.
4. In the AiSOC GitHub repo, go to
   `Settings → Secrets and variables → Actions → New repository secret`.
5. Name: `WET_EVAL_OPENAI_KEY`. Value: paste the key.

If the secret is **not** set, the weekly workflow short-circuits via
`scripts/wet_eval_check.py` and exits cleanly with a "skipping live
run" notice. That's the expected state on forks and on first-run
clones.

### Rotation procedure

Every 90 days (or immediately if a leak is suspected):

1. Issue a new key in the OpenAI project console.
2. Update `WET_EVAL_OPENAI_KEY` in GitHub Actions secrets.
3. Trigger a manual `workflow_dispatch` run with `dry_run=false` to
   confirm the new key works.
4. Revoke the old key in the OpenAI project console.

Rotation is replacement, never overlap-then-revoke; the workflow only
ever uses the current value, so a 30-second gap during rotation is
fine.

### What the key cannot do

The wet-eval workflow runs in `ubuntu-latest`, not in production. It
never has DB credentials, never sees tenant data, and the OpenAI
project this key belongs to has no access to any other resource. A
compromised key buys the attacker the ability to spend up to $25 of
LLM credits — annoying, but bounded.

## `AISOC_BENCH_BOT_TOKEN`

A fine-grained GitHub PAT belonging to the `aisoc-bench-bot` machine
account. The weekly workflow uses it to push the
`bench/wet-eval-YYYY-MM-DD` branch and open the PR.

| Property            | Value                                                                                                       |
|---------------------|-------------------------------------------------------------------------------------------------------------|
| **Type**            | Fine-grained personal access token.                                                                         |
| **Account**         | `aisoc-bench-bot` (machine user). Email: `aisoc-bench-bot@users.noreply.github.com`. No commit-signing key. |
| **Repository access** | This repo only. **Not** organization-wide.                                                                |
| **Permissions**     | Contents: read+write (for the PR branch). Pull requests: read+write. Metadata: read. **Nothing else.**       |
| **Read by**         | `.github/workflows/wet-eval.yml`, step "Open PR with refreshed wet-eval numbers".                           |
| **Default `GITHUB_TOKEN` won't work** | The default token can push, but PRs it opens cannot trigger downstream `pull_request` workflows (e.g. the existing CI gate would not run on the wet-eval PR). A dedicated PAT bypasses that recursion limit; the trade-off is documented on the [GitHub Actions page about `GITHUB_TOKEN`](https://docs.github.com/en/actions/security-guides/automatic-token-authentication#using-the-github_token-in-a-workflow). |

### Why a separate bot account

A maintainer's personal PAT *would* work, but the resulting commits
would have a human author and be visually indistinguishable from a
real engineering change. Routing weekly automation through a dedicated
machine account keeps the contributor graph honest:

- Every commit by `aisoc-bench-bot` is automation.
- The PRs are clearly auto-generated and labelled `automated`.
- If the bot account is ever compromised, revoking its PAT stops all
  automated PRs without affecting any human committer.

### How to configure

1. Sign in to GitHub as `aisoc-bench-bot` (the maintainer team owns
   the credentials in 1Password).
2. Generate a fine-grained PAT under
   `Settings → Developer settings → Personal access tokens → Fine-grained`.
3. Resource owner: the `beenuar` org (or your fork's owner).
4. Repository access: `Only select repositories` → AiSOC.
5. Repository permissions:
   - Contents: **Read and write**.
   - Pull requests: **Read and write**.
   - Metadata: **Read**.
   - Everything else: **No access**.
6. Expiration: 180 days from issuance.
7. Copy the token once. In the AiSOC repo, set
   `Settings → Secrets and variables → Actions → New repository secret`,
   name `AISOC_BENCH_BOT_TOKEN`, paste the value.

### Rotation procedure

Every 180 days (or immediately on compromise):

1. Generate a new fine-grained PAT under the bench-bot account, same
   permission set.
2. Update `AISOC_BENCH_BOT_TOKEN` in the AiSOC repo's Actions secrets.
3. Trigger a `workflow_dispatch` of `wet-eval.yml` with
   `dry_run=true` to confirm the new token can push the dry-run docs
   update PR. Close that PR without merging.
4. Revoke the old PAT under the bench-bot account.

The workflow consumes the secret in only one step (`Open PR with
refreshed wet-eval numbers`); rotation is therefore a single env-var
swap and never requires a code change.

### What the token cannot do

- **Cannot read tenant data.** The bot account has no access to any
  service running in production.
- **Cannot merge PRs.** The PAT only has read+write on Contents and
  Pull Requests; it can open and update PRs, but the merge button
  remains a human gate.
- **Cannot affect any other repo.** Fine-grained PATs are scoped to a
  specific repository; the bench bot's PAT only ever sees AiSOC.
- **Cannot escalate.** Fine-grained PATs cannot create new tokens or
  change account-level settings.

## `GITHUB_TOKEN`

Auto-issued by GitHub at the start of every workflow run. We do not
configure or rotate it manually. The only thing worth documenting is
the **scopes we explicitly request per-job**:

| Workflow                       | `permissions` block                                |
|--------------------------------|----------------------------------------------------|
| `ci.yml` → `p1-eval`           | `contents: write` (publishes to `eval-results`)    |
| `wet-eval.yml` → `wet-eval`    | `contents: write`, `pull-requests: write`          |
| Most other workflows           | (default — read-only)                              |

Workflows always declare `permissions:` explicitly so a workflow file
cannot silently inherit broader scopes from the org default.

## Operating procedures

### When `WET_EVAL_OPENAI_KEY` is missing

`scripts/wet_eval_check.py` is the single point of truth: if the key
isn't set, the workflow exits cleanly. There is no "fail loudly on
fork" code path — silently skipping is the right behaviour because
forks legitimately don't carry project-funded billing.

### When the weekly PR doesn't open

Most likely causes, in order:

1. **PAT expired.** Check
   `Settings → Secrets and variables → Actions → AISOC_BENCH_BOT_TOKEN`
   for the configured-on date. Fine-grained PATs expire 180 days after
   issuance; rotate per the procedure above.
2. **Numbers unchanged week-over-week.** The workflow exits cleanly
   with `Nothing to commit — wet-eval numbers unchanged.` Look at the
   workflow run logs; this is expected when the agent and rate card
   haven't moved.
3. **Pre-existing branch conflict.** A `bench/wet-eval-YYYY-MM-DD`
   branch already exists from a manual run. Delete the stale branch
   and re-run.

### When the eval cells in `benchmark.md` are blank

The substrate placeholder cells (`<!-- T2.4 populates -->`) only get
filled by `scripts/wet_eval_update_benchmark.py`, which only runs from
inside `wet-eval.yml`. If a cell is blank in production:

1. Check the most recent successful wet-eval run on the `Actions` tab.
2. If it succeeded, look at `apps/docs/static/wet-eval/<date>.json`
   for the wet-eval block — the docs writer reads from there.
3. If the writer hit a `--check` failure (the markdown scaffold drifted
   from the wet-eval JSON shape), open an issue: the family list in
   `scripts/wet_eval.py` and the table layout in `benchmark.md` need to
   be re-aligned.

### Auditing what each secret has read

Every workflow run is logged in the `Actions` tab; the step "Open PR
with refreshed wet-eval numbers" shows the bench bot's commit and the
URL of the PR it created. The workflow logs themselves are scrubbed of
secret values (GitHub does this automatically); the timestamps and the
secret *name* references are auditable from the run's `?check_suite_id`
payload via the GraphQL API.

## See also

- [Credential vault and secret management](./credentials.md) — where
  *tenant-side* connector secrets live (Azure client secrets, GCP
  service accounts, GitHub tokens, ...).
- [Public Eval Harness](../benchmark.md) — what the wet-eval job
  actually measures and how to reproduce it locally.
- The workflow source: `.github/workflows/wet-eval.yml`.
