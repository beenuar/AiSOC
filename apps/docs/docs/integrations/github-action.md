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
  security-events: read       # code scanning
  vulnerability-alerts: read  # Dependabot — a separate permission, see below
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
  security-events: read       # code scanning
  vulnerability-alerts: read  # Dependabot — a separate permission, see below
  issues: write
jobs:
  digest:
    runs-on: ubuntu-latest
    steps:
      - uses: beenuar/AiSOC/packages/aisoc-action@v8.1.1
        with:
          mode: digest
```

Refreshes a single `aisoc-digest`-labelled issue each week with the run's UTC
timestamp, the sources it managed to read, and an A–F posture grade over those
sources.

The digest carries a week-over-week delta field, and **it does not render
today**: the action's only call site passes no previous result, so the
comparison has nothing to compare against. It is left in place because the
renderer is shared, but nothing in the published body will show a change
figure until a caller supplies last week's result.

## Inputs

| Input | Default | Description |
|---|---|---|
| `github-token` | `${{ github.token }}` | Needs `security-events: read` for code scanning **and** `vulnerability-alerts: read` for Dependabot; `pull-requests: write` for comments; `issues: write` for the digest. See [Permissions](#permissions). |
| `mode` | `job-summary` | `job-summary` \| `pr-comment` \| `digest` |
| `min-severity` | `low` | Lowest severity to include (`info`→`critical`). |
| `fail-on` | `none` | Fail the job on `needs_review` or `true_positive` findings (gate mode). |
| `sources` | `dependabot,code-scanning,secret-scanning` | Which signals to pull. |

## Permissions

The three sources need three different grants, and only two of them are
reachable by `GITHUB_TOKEN` at all.

| Source | Permission | Reachable by `GITHUB_TOKEN`? |
|---|---|---|
| Code scanning | `security-events: read` | yes |
| Dependabot | `vulnerability-alerts: read` | yes |
| Secret scanning | — | **no**, needs a GitHub App or a PAT |

Two traps are worth stating outright, because the digest on this repository
fell into both and reported `grade A (100/100)` for weeks while blind to two of
its three sources.

**`security-events` does not cover Dependabot.** GitHub's workflow syntax
reference is explicit: "For Dependabot alerts, use the `vulnerability-alerts`
permission. Secret scanning alerts cannot be read with this permission and
require a GitHub App or a personal access token."

**Naming any permission denies every unnamed one.** "If you specify the access
for any of these permissions, all of those that are not specified are set to
`none`." So a `permissions:` block that lists `security-events` and omits
`vulnerability-alerts` is not taking a default — it is denying Dependabot.

A source the action cannot read is reported as skipped, and a digest with any
skipped source refuses to publish a headline grade: it reads `incomplete (N of
M sources readable)` and scopes the grade to what answered. Zero findings from
a source nobody could read is not zero findings.

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
