# AiSOC — Community-Feedback-Driven Roadmap (2026-05-12)

This directory captures the **active** planning artifacts for AiSOC, derived
from a community-feedback synthesis pass on 2026-05-12. It supersedes the
"deferred beyond v7" sections of [`/ROADMAP.md`](../../../ROADMAP.md) for
day-to-day prioritization while leaving the major-version history intact for
traceability.

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
- **The "Now" bucket is the work-in-flight queue.** Items here are expected to
  ship within 30 days of the doc's date and are tracked in
  [`/PROGRESS.md`](../../../PROGRESS.md) under the active version line
  (currently v7.1.x).
- **"Next" and "Later" are intent, not commitment.** They get re-prioritized
  on the next synthesis pass.
- **Path & module references in the issue drafts are authoritative.** Where
  the draft conflicts with reality on `main`, the draft wins (file the
  reconciliation as a Stage-0 task before starting the work). The drafts in
  this directory have already been path-corrected against the v7.1.0
  baseline.

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
3. Branch off `main`, implement against the acceptance criteria, satisfy the
   eval gates listed in [`/AGENTS.md`](../../../AGENTS.md) when relevant.
4. PR title format: `[F<id>] <area>: <change>` so the feedback trail is
   visible in `git log`.
5. Update `PROGRESS.md` checkboxes as items land.

## Next synthesis pass

Plan: re-run the synthesis on a 30-day cadence. The next dated directory will
live alongside this one (e.g. `docs/community-feedback/2026-06-12/`).
