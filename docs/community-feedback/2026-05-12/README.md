# AiSOC — Community-Feedback-Driven Roadmap (2026-05-12)

> **Status: a dated snapshot, not the current plan.** These artefacts were
> produced by a community-feedback synthesis pass on **2026-05-12**, against
> the v7.1 line. The tree has since moved several majors past that. They are
> kept as received — `scripts/check_deferral_tracker.py` excludes this
> directory for exactly that reason — so the `F`-ID trail from feedback to
> shipped work survives. For what is planned now, read
> [`/ROADMAP.md`](../../../ROADMAP.md); for what actually works, read
> [`/docs/audit/REPOSITORY_REALITY.md`](../../audit/REPOSITORY_REALITY.md).

This directory captures the planning artifacts derived from that synthesis
pass. No second pass has been run, so there is no later dated directory
beside it.

## Contents

| File | Purpose |
| --- | --- |
| [`AiSOC_ROADMAP.md`](./AiSOC_ROADMAP.md) | Now / Next / Later strategic narrative — 30-day, 30–90-day, and 90+-day buckets. |
| [`AiSOC_Community_Feedback_Synthesis.md`](./AiSOC_Community_Feedback_Synthesis.md) | Themed feedback log with stable IDs (`F001`–`Fxxx`) for traceability. |
| [`AiSOC_Proposed_Issues.md`](./AiSOC_Proposed_Issues.md) | 23 implementation tickets, each tagged with `Feedback Item: Fxxx`. |

## How these docs are used

- **`F-IDs` are stable.** Every issue, PR, and commit that addresses a feedback
  theme should reference the matching `F` ID in its body so the trail back to
  the originating feedback survives refactors.
- **The "Now" bucket was the work-in-flight queue as of 2026-05-12**, scoped
  to the 30 days after that date on the v7.1 line. It is history now. This
  README previously pointed at a root `PROGRESS.md` for its status; that file
  is gitignored and has never been committed, so the pointer resolved to
  nothing. Release-by-release status lives in
  [`/CHANGELOG.md`](../../../CHANGELOG.md).
- **"Next" and "Later" are intent, not commitment.** They get re-prioritized
  on the next synthesis pass.
- **Path & module references in the issue drafts are *not* authoritative.**
  They were path-corrected against the v7.1.0 baseline and nothing since.
  Where a draft conflicts with `main`, **`main` wins** — this README used to
  say the opposite, which on a v12 tree would send a contributor to rename
  working code to match a snapshot from eight majors ago.

## Reconciliation notes (carried forward)

The 2026-05-12 synthesis revealed some drift between `CHANGELOG.md` and the
state of `main`. The relevant correction lives in
[`/CHANGELOG.md`](../../../CHANGELOG.md) under the `[7.0.x]` heading: the
PR1–PR6 endpoint-telemetry wave was developed on
`feat/pr6-osquery-extensions` and **not** merged into `main`. The generic
`live_action` interface ([Issue #8](./AiSOC_Proposed_Issues.md#issue-8)) is
therefore built fresh on `main`, not on top of those primitives.

## Workflow

1. Pick an issue from `AiSOC_Proposed_Issues.md`.
2. Open a GitHub issue using the draft body (or reference the file if the
   draft is faithful enough to skip re-typing). Apply the `area:subarea`
   labels listed in the draft.
3. Re-verify every path the draft names against `main` before you start.
4. Branch off `main`, implement against the acceptance criteria, satisfy the
   eval gates listed in [`/AGENTS.md`](../../../AGENTS.md) when relevant.
5. PR title format: `[F<id>] <area>: <change>` so the feedback trail is
   visible in `git log`.

## Next synthesis pass

The 2026-05-12 pass planned a 30-day cadence. It was not repeated, and
`2026-05-12/` remains the only dated directory here. A future pass would land
beside it under its own date.
