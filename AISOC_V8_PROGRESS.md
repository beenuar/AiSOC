# AiSOC v8.0 — North-Star Plan Progress

**Last updated:** 2026-06-27 (Saturday, Asia/Bangkok)
**Authored by:** AI assistant; verify by cross-referencing
[`plans/aisoc_v8.0_north_star_plan_1dee8c63.plan.md`](./plans/aisoc_v8.0_north_star_plan_1dee8c63.plan.md).

This tracker exists so the remaining v8.0 work is visible at a glance,
including which acceptance criteria have been verified and which are
still outstanding. It is intentionally short and dated — when in
doubt, treat the linked v8.0 plan file as the source of truth and
update this tracker after each landed task.

> **History note.** A previous tracker existed at this path but was
> deleted prematurely in PR #232. This re-creation captures the
> current verified state of the four T-IDs the user re-prioritised on
> 2026-06-27.

---

## Status snapshot

| T-ID | Title | Priority | Effort | Status | Notes |
|------|-------|---------:|-------:|--------|-------|
| T3.7 | NL → playbook generator | P1 | M | ✅ **Done** (2026-06-27) | Substrate + LLM paths, 47 backend tests, 8 frontend tests, dialog wired into `/playbooks`. |
| T3.8 | Design system v2 + Storybook | P1 | M | ✅ **Done** (2026-06-27) | Storybook 9 + Vite + Tailwind v4, 14 story files / 65 named stories, 4 new primitives, 33 visual-regression snapshots, CI gate. |
| T5.3 | AIT-LDS + MITRE Engenuity loaders | P1 | M | ✅ **Done** (2026-06-27) | Two new fidelity loaders + 16 tests + date-stamped `benchmark.md` section (29/29 fidelity tests). |
| T4 wave-3 | Last 5–6 connectors (Abnormal Security, Box, Datadog, Dropbox, Lacework, OCI, Sublime Security) | P1 each | S–M each | ✅ **Done** (2026-06-27) | 6 new plugin manifests + 6 new docs pages + 39 new tests + 6 connector resilience fixes. Full connector suite 633/633. |

All four T-IDs landed via dedicated PRs (merged 2026-06-27):

| T-ID | PR | Branch | Merged at (UTC) |
|------|----|--------|-----------------|
| T3.7 | [#330](https://github.com/beenuar/AiSOC/pull/330) | `feat/v8-t37-nl-playbook-drafter` | 08:55:22 |
| T3.8 | [#331](https://github.com/beenuar/AiSOC/pull/331) | `feat/v8-t38-storybook-design-system` | 08:57:36 |
| T5.3 | [#332](https://github.com/beenuar/AiSOC/pull/332) | `feat/v8-t53-aitlds-mitre-engenuity` | 08:53:48 |
| T4 wave-3 | [#333](https://github.com/beenuar/AiSOC/pull/333) | `feat/v8-t4-wave3-connector-scaffolding` | 08:55:17 |
| Tracker | [#334](https://github.com/beenuar/AiSOC/pull/334) | `docs/v8-progress-tracker` | 08:57:39 |

Follow-up after merge: [`feat/v8-storybook-draftdialog-story`](https://github.com/beenuar/AiSOC/tree/feat/v8-storybook-draftdialog-story) re-introduces the
`DraftFromPromptDialog` Storybook story that was split out of #331
because it imported a component that only existed on #330.

---

## What's verified per T-ID

### T3.7 — NL → playbook generator

- Backend module `services/agents/app/playbook/nl_drafter.py` implements
  both the deterministic substrate path AND the LLM-assisted path
  (with a clean fall-back when the LLM is unreachable, returns a
  malformed payload, or fails Pydantic validation).
- Validates every draft against `schemas/playbook.schema.json`
  (the file `scripts/lint_playbooks.py` consumes), with a step-type
  collapse pass for Pydantic-only types so drafts never fail CI.
- HTTP surface: `POST /api/v1/playbooks/draft-from-nl` with 200 /
  400 / 422 covered by 9 integration tests.
- Frontend: `DraftFromPromptDialog` on `/playbooks` posts to the
  endpoint, parks the draft in `sessionStorage["aisoc:nl-draft"]`,
  routes to `/playbooks/new?nl=true`; the existing `PlaybookEditor`
  hydrates from the seed via a one-shot effect.
- Test counts: 30 unit + 9 API + 8 frontend = **47 new tests**.
- Regressions: none — `237/237` playbook backend tests, `390/390`
  apps/web tests green after the change.

### T3.8 — Design system v2 + Storybook

- Storybook 9.1 with the `@storybook/react-vite` framework wired up
  in `apps/web/.storybook/{main.ts,preview.tsx}`. Tailwind v4 plugs in
  via `@tailwindcss/vite` so utility classes work identically inside
  Storybook and the running app.
- Four new canonical UI primitives in `apps/web/src/components/ui/`:
  `Button` (5 × 4 variants/sizes), `Badge` (10 tones), `Card`
  (+ header / body / footer), `StatusPill` (6 statuses).
- 14 story files × 65 named stories under `apps/web/stories/`,
  grouped Foundations / Primitives / Composite.
- Visual-regression: 33 jsdom-DOM snapshots committed at
  `apps/web/src/test/__snapshots__/storybook-snapshots.test.tsx.snap`
  via Vitest.
- CI gate: new `storybook-build` job in `.github/workflows/ci.yml`
  builds the static bundle and uploads as artifact (7-day retention).
- Pre-existing checks all green: type-check, lint (0 errors,
  pre-existing warnings only), tests `390/390`.

### T5.3 — AIT-LDS + MITRE Engenuity loaders

- `services/agents/tests/fidelity/ait_lds_loader.py` parses Apache
  CLF, joins labels from a sidecar CSV, normalises to OCSF Web
  Resources Activity (class_uid 6002).
- `services/agents/tests/fidelity/mitre_engenuity_loader.py` parses
  Round-7 procedure JSON, extracts techniques + tactics, normalises
  to OCSF Detection Finding (class_uid 2004).
- Substrate runner extended (`runner.py`) with `_classify_ait_lds`
  and `_classify_mitre_engenuity`; `_iter_dataset` + `_to_ocsf`
  dispatch updated.
- Micro fixtures committed under `services/agents/tests/eval_data/`
  (`access.log` force-added; `.gitignore` updated to unignore).
- 16 new tests in `test_fidelity_harness.py`; full suite **29/29**
  fidelity tests green.
- `apps/docs/docs/benchmark.md` carries a new date-stamped
  "Public-dataset fidelity (substrate)" section.

### T4 wave-3 — last 5–6 connectors

- Connector classes already existed; the gap was scaffolding around
  them. Landed:
  - 6 new `plugins/<connector>/plugin.yaml` (Abnormal Security, Box,
    Datadog, Dropbox, OCI, Sublime Security; Lacework already
    shipped).
  - 6 new `apps/docs/docs/connectors/<connector>.md` pages.
  - Comprehensive `services/connectors/tests/test_wave3_connectors.py`
    with **39 new tests** covering schema, capabilities,
    normalisation, connection probes, and error handling.
- 6 connector resilience fixes: every `fetch_alerts` (and Datadog's
  `_fetch_logs` / `_fetch_events`) now wraps the `httpx` call in
  `try / except (httpx.HTTPError, httpx.InvalidURL)` so network
  errors log + break the pagination loop instead of crashing the
  polling worker.
- Full connectors suite **633/633** tests green.

---

## What's still open

- **All five PRs are merged.** Follow-up to re-add the
  `DraftFromPromptDialog` Storybook story (was split out of #331
  because of cross-branch dependency on #330) is the only loose
  end and is staged on `feat/v8-storybook-draftdialog-story`.
- This tracker should be updated on every merge with the PR URL and
  the merge timestamp.

## Out of scope for this pass

- T1–T2 fidelity work beyond the AIT-LDS + MITRE Engenuity micro
  fixtures (the full-corpus runs are still local-only with floors
  committed in `expected_results.yaml`).
- Storybook visual-regression in a real browser (pixel-diff) — the
  current gate is jsdom DOM snapshots, which catch structural
  regressions at sub-second cost. Real-browser regression is in the
  Track-7 roadmap.

