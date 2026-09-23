---
title: GitHub Action — aisoc-action
sidebar_label: GitHub Action
---

# `aisoc-action` — triage your repo's security signals in CI

`aisoc-action` runs the AiSOC **deterministic verdict engine** over your
repository's own security alerts — Dependabot, CodeQL (code scanning), and
secret scanning — and posts verdicts, suppression rationale, and prioritization
as a PR comment or job summary. No LLM, no data leaves your CI runner.

:::warning Use the subdirectory form
`beenuar/aisoc-action` **does not exist as a repository** — that reference
404s, and every example on this page used to carry it. The form that resolves
today points at the action's directory inside the monorepo:

```yaml
- uses: beenuar/AiSOC/packages/aisoc-action@v8.1.1
```

Pin a tag rather than a branch, so a workflow cannot change underneath you.

The short `beenuar/aisoc-action@v1` alias needs a GitHub Marketplace listing,
which is an account action rather than an engineering one, and is named
against v8.2 alongside the npm and PyPI publishes. The Action itself is
complete and dogfooded on this repo via `uses: ./packages/aisoc-action`.
:::

## PR triage (comment on every pull request)

```yaml
name: security-triage
on:
  pull_request:
permissions:
  contents: read
  security-events: read
  pull-requests: write
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: beenuar/AiSOC/packages/aisoc-action@v8.1.1
        with:
          mode: pr-comment
          min-severity: low
```

You'll get a comment like:

> 🛡️ **AiSOC security triage** — 3 of 41 findings are prioritized as
> exploitable / act-now; 34 are low-signal noise.

with a table of the findings that need attention (verdict, confidence, source,
recommended action), and an idempotent update-in-place on subsequent pushes.

## Weekly posture digest (issue)

```yaml
name: security-posture
on:
  schedule:
    - cron: '17 13 * * 1' # Mondays
permissions:
  contents: read
  security-events: read
  issues: write
jobs:
  digest:
    runs-on: ubuntu-latest
    steps:
      - uses: beenuar/AiSOC/packages/aisoc-action@v8.1.1
        with:
          mode: digest
```

Refreshes a single `aisoc-digest`-labelled issue each week with an A–F posture
grade and the week-over-week change in act-now findings.

## Inputs

| Input | Default | Description |
|---|---|---|
| `github-token` | `${{ github.token }}` | Needs `security-events: read`; `pull-requests: write` for comments; `issues: write` for the digest. |
| `mode` | `job-summary` | `job-summary` \| `pr-comment` \| `digest` |
| `min-severity` | `low` | Lowest severity to include (`info`→`critical`). |
| `fail-on` | `none` | Fail the job on `needs_review` or `true_positive` findings (gate mode). |
| `sources` | `dependabot,code-scanning,secret-scanning` | Which signals to pull. |

## Outputs

`total`, `escalate`, `review`, `suppress`, `headline` — wire them into
downstream steps.

## How it works

Each alert is normalized into the same `Alert` shape the CLI uses and scored by
the vendored, byte-for-byte copy of the CLI verdict engine (kept in sync by
`scripts/sync_vendored_verdict.py`). Runtime-scope Dependabot vulnerabilities
are prioritized as exploitable-in-your-dependency-graph. Sources that are
disabled or that the token can't read are skipped gracefully with a note — the
Action never hard-fails on a missing feature.
