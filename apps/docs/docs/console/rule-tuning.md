---
sidebar_position: 2
title: Detection Tuning workbench
description: The /detection/tuning workbench — an opinionated, single-page console for triaging noisy detection rules with API-driven suggestions, scored mechanical actions, and per-rule auto-tune opt-in.
---

# Detection Tuning workbench

`/detection/tuning` is the page a detection engineer or SOC lead opens when alert volume is climbing and they need to know *which rules are spending the queue's attention*. It replaces the old static `/noise-tuning` prototype with a live, API-backed workbench: every row is projected from real `DetectionRule` state (false-positive rate, total hits, confidence, last-triggered time, status), classified into one of six suggestion lanes, and surfaced with a one-click mechanical action that mutates the rule and writes an audit log entry.

This page documents the projection heuristics, the action set, the API surface, and the pieces that make the workbench cheap enough to run on every page load.

## Where the workbench sits

```
┌──────────────────────────────────────────────────────────────────────────┐
│  Detection Tuning                              Updated 10:14:02  [Refresh]│
│  ──────────────────────────────────────────────────────────────────────  │
│  [Total 87]  [Actionable 14]  [Healthy 73]  [Auto-tune 6]                │
│  [Disable 3] [Add suppression 5] [Raise threshold 4] [Tune confidence 2] │
│  ──────────────────────────────────────────────────────────────────────  │
│  [All severities ▾] [All suggestions ▾] [Search…]  ☑ Enabled only        │
│  ──────────────────────────────────────────────────────────────────────  │
│  ● HIGH  Okta — failed MFA flood    Disable        FP 72%  1.2k hits  ⓘ │
│         FP 72% ≥ 50% with confidence 30 < 40       [Disable rule] [⋮]    │
│         Auto-tune ◯                                                       │
│  ● MED   Defender — script block    Add suppression FP 28%  340 hits  ⓘ │
│         FP 28% ≥ 20% — add a suppression for the noisy entity            │
│         Auto-tune ●                                                       │
│  ──────────────────────────────────────────────────────────────────────  │
│         Disable first ─► Suppress ─► Threshold ─► Confidence ─► Stale    │
└──────────────────────────────────────────────────────────────────────────┘
```

The workbench is intentionally narrow — one row per rule, one suggestion per row, one primary mechanical action surfaced as a button. Drilling into rule semantics still happens on `/detection/{id}`; this page is where you decide *which* rule to tune next.

## The six suggestion lanes

The projection is a pure function: given a `DetectionRule`, the classifier walks a fixed precedence ladder and returns the **first** matching lane. Heavier interventions (`disable`, `add_suppression`) win over softer hints (`review_stale`), so the workbench never recommends a confidence bump for a rule that should clearly be turned off.

| Lane | Trigger | Default action | Reason text |
|---|---|---|---|
| **Disable** | Rule is active, `fp_rate ≥ 0.50`, `confidence < 40`. | `disable` | "FP rate X% ≥ 50% with confidence Y < 40" |
| **Add suppression** | Rule is active and `fp_rate ≥ 0.20`. | `add_suppression` | "FP rate X% ≥ 20% — add a suppression for the noisy entity" |
| **Raise threshold** | Rule is active, `fp_rate ≥ 0.10`, `total_hits ≥ 20`. | `raise_threshold` | "FP rate X% with N hits — bumping the threshold trims volume without losing the signal" |
| **Tune confidence** | `confidence < 40` and `total_hits ≥ 20` (regardless of status). | `acknowledge` | "Confidence Y < 40 despite N hits — re-evaluate the rule body" |
| **Review stale** | Rule is active and either last fired more than 30 days ago, or has never fired but is older than 30 days. | `acknowledge` | "Last hit was N days ago (stale threshold is 30d)" |
| **Healthy** | Nothing above matched. | — | Empty reasons; the row is included in the population so the summary tile counts remain meaningful. |

All thresholds are exported from [`app/services/rule_tuning.py`](https://github.com/beenuar/AiSOC/blob/main/services/api/app/services/rule_tuning.py) as module constants — `TUNING_FP_RATE_NOISY`, `TUNING_FP_RATE_BUMPABLE`, `TUNING_FP_RATE_DISABLE`, `TUNING_LOW_CONFIDENCE`, `TUNING_MIN_HITS_FOR_THRESHOLD`, `TUNING_STALE_DAYS` — so the docs page, the tests, and the production classifier share the same numbers. If product tuning changes one, every consumer updates with it.

### Why we do not recompute live FP rates

The classifier reads `fp_rate`, `total_hits`, `confidence`, and `last_triggered` directly off the `DetectionRule` row. Those fields are maintained by the alert ingestion and feedback pipelines — every confirmed false-positive bumps the count, every fired alert updates the timestamp. The workbench never joins the alerts table at projection time. That keeps the page fast enough to scan hundreds of rules per request without putting any load on the hot path, and it means the suggestions stay stable across page polls (the picture only changes when the underlying rule metrics move).

### Scoring and ordering

After classification, every entry gets a single integer score:

```
score = SUGGESTION_WEIGHT[lane]            # 500 disable → 0 healthy
      + round(fp_rate * 100)               # 0..100
      + min(total_hits, 1000) // 10        # 0..100
```

The lane weight dominates so the list is grouped sensibly (`disable` rows are always above `add_suppression` rows are always above `raise_threshold`, and so on), but inside a lane the *noisiest* and *highest-volume* rules float to the top. The frontend then breaks ties by `fp_rate desc`, `total_hits desc`, and finally name (case-insensitive) for stable rendering across polls.

### Scan budget

Each projection caps at `TUNING_MAX_RULES_SCANNED = 1000` — the heaviest rules by `fp_rate` and `total_hits` are pulled from PostgreSQL first, and the Python classifier walks at most that many. A tenant that has imported 50 000 Sigma rules will see the worst 1 000 surface; a tenant with 87 rules sees all of them. This bound exists so the workbench cannot accidentally DoS itself.

## The actions

Each row exposes one primary mechanical action (driven by the suggestion lane), one secondary affordance (Dismiss), and one persistent toggle (Auto-tune). All three are flat: no modals, no confirmation dialogs. Toast feedback comes from the response payload.

| Action | What it does | Backend |
|---|---|---|
| **Disable rule** | Sets `DetectionRule.status = 'disabled'`. | `POST /api/v1/detection/tuning/{id}/apply` with `action='disable'`. |
| **Add suppression** | Appends a `{kind: 'tune_placeholder', reason, added_by}` entry to `suppression_config.rules` and stamps `last_tuned_at`. The real suppression engine consumes `suppression_config.rules` — this just seeds it with an entry analysts can refine. | `POST /api/v1/detection/tuning/{id}/apply` with `action='add_suppression'`. |
| **Raise threshold** | Increments `threshold_config.event_threshold` by +1 (or sets the explicit `threshold` from the payload, clamped `[1, 1_000_000]`) and stamps `threshold_config.last_raised_at`. | `POST /api/v1/detection/tuning/{id}/apply` with `action='raise_threshold'`. |
| **Acknowledge** | No-op on rule semantics — only stamps `suppression_config.tuning_last_action*` and emits an audit event. Used by `tune_confidence` and `review_stale` rows to clear them without mutation. | `POST /api/v1/detection/tuning/{id}/apply` with `action='acknowledge'`. |
| **Dismiss** | Sets `suppression_config.tuning_dismissed_at` (+ `tuning_dismissed_by`, optional `tuning_dismissed_reason`). The row drops out of the default workbench view. Toggling `include_dismissed=true` brings it back so dismissals stay auditable. | `POST /api/v1/detection/tuning/{id}/dismiss`. |
| **Auto-tune toggle** | Flips `suppression_config.auto_tune` (with `auto_tune_updated_at` + `auto_tune_updated_by`). The flag is an opt-in marker for future automated tuners — flipping it does **not** trigger any immediate rule change. | `POST /api/v1/detection/tuning/{id}/auto_tune`. |

### Apply also un-dismisses

Every `apply_tuning` call clears `suppression_config.tuning_dismissed_at` and `tuning_dismissed_reason` on its way out. The reasoning: if an analyst engages with a previously dismissed rule, they have implicitly decided to bring it back into the queue. The audit event still records the prior dismissal in the `before` block, so nothing is lost.

### Version + audit on every mutation

`apply_tuning` always bumps `DetectionRule.version` and emits a `detection.tuning.apply` audit event with the pre/post values of `status`, `confidence`, `threshold_config`, and `suppression_config`, plus a `payload` block describing the requested action. `dismiss_tuning` and `set_auto_tune` emit `detection.tuning.dismiss` and `detection.tuning.auto_tune` respectively. Every change is reversible by inspecting the audit log; nothing is mutated silently.

### Platform vs tenant rules

Built-in / platform rules (rows with `tenant_id IS NULL`) appear in projections so analysts can see them, but every mutator (`apply`, `dismiss`, `auto_tune`) refuses to touch them with a `403 Forbidden`. Tuning a global rule from one tenant's workbench would leak the change to every other tenant; the guard is in `_load_rule_for_tenant`.

## The API surface

The workbench is served by four endpoints under a single router prefix:

```
GET  /api/v1/detection/tuning
     ?severity=info|low|medium|high|critical    (default: any)
     &suggestion=disable|add_suppression|raise_threshold|tune_confidence|review_stale|healthy
     &search=<substring, max 200 chars>         (matches name/description/category)
     &enabled_only=true|false                   (default: false)
     &include_dismissed=true|false              (default: false)
     &page=1                                    (default: 1)
     &page_size=50                              (default: 50, max: 100)

GET  /api/v1/detection/tuning/summary
POST /api/v1/detection/tuning/{rule_id}/apply
POST /api/v1/detection/tuning/{rule_id}/dismiss
POST /api/v1/detection/tuning/{rule_id}/auto_tune
```

`GET` endpoints require `rules:read`; all three `POST` endpoints require `rules:write`. Every endpoint runs under a tenant-scoped DB session, and the build query filters `DetectionRule.tenant_id = current_user.tenant_id OR DetectionRule.tenant_id IS NULL` — analysts see their own tenant's rules plus platform rules, but cannot mutate platform rules.

### Response shape

The `TuningResponse` envelope:

```jsonc
{
  "entries": [
    {
      "rule_id": "8b2e…",
      "name": "Okta — failed MFA flood",
      "description": "…",
      "category": "identity",
      "severity": "high",
      "status": "active",
      "enabled": true,
      "confidence": 30,
      "fp_rate": 0.72,
      "total_hits": 1247,
      "last_triggered_at": "2026-05-12T18:42:11Z",
      "tags": ["okta", "mfa"],
      "mitre_tactics": ["TA0006"],
      "mitre_techniques": ["T1110"],
      "version": 7,
      "updated_at": "2026-05-13T09:01:33Z",

      "suggestion": "disable",
      "score": 572,
      "reasons": [
        "FP rate 72% ≥ 50% with confidence 30 < 40",
        "1247 total hits — disable will reduce queue pressure immediately"
      ],
      "auto_tune": false,
      "dismissed_at": null,
      "last_action": null,
      "last_action_at": null
    }
  ],
  "summary": {
    "total_rules": 87,
    "actionable": 14,
    "healthy": 73,
    "disable_count": 3,
    "add_suppression_count": 5,
    "raise_threshold_count": 4,
    "tune_confidence_count": 2,
    "review_stale_count": 0,
    "auto_tune_enabled": 6,
    "average_fp_rate": 0.0834,
    "high_fp_count": 8
  },
  "filters": {
    "severity": null,
    "suggestion": null,
    "search": null,
    "enabled_only": false,
    "include_dismissed": false,
    "page": 1,
    "page_size": 50
  },
  "total": 87,
  "generated_at": "2026-05-13T10:14:02Z"
}
```

Notes on the contract:

- `summary` is computed across the **entire classified population** for the tenant, not just the current page. The header tiles stay stable as analysts page through filtered results.
- `total` is the count *after* the `suggestion` filter is applied (but before pagination), so it matches the size of the filtered result set.
- Dismissed rules are excluded from `entries` *and* `summary` by default. Pass `include_dismissed=true` to bring them back when auditing what's been hidden.
- `generated_at` is the server's `now()` at projection time — the frontend renders it in the header so analysts can confirm the data is fresh.

### `POST /apply` payload

```jsonc
{
  "action": "disable" | "add_suppression" | "raise_threshold" | "acknowledge",
  "note": "optional free-text reason, recorded in suppression_config",
  "threshold": 5,            // only for raise_threshold; clamped [1, 1_000_000]
  "suppression_reason": "…"  // only for add_suppression; max 255 chars
}
```

The response is the **re-projected entry** for the freshly-mutated rule, so the UI can refresh in place without a second round-trip. Frontend usage: `handleApply` issues the POST, awaits the response, then `mutate()`s the SWR cache to redraw the row with its new suggestion and reasons.

### `POST /dismiss` and `POST /auto_tune`

Both endpoints accept minimal bodies (`{reason?: string}` and `{enabled: bool}` respectively) and return the re-projected entry. Auto-tune is the only mutator that doesn't write to the audit `changes.before/after` triplet — it only stamps the boolean transition because that's the only thing analysts and auditors care about for that flag.

## Polling and freshness

The workbench uses SWR with `keepPreviousData: true` and `revalidateOnFocus: false`. There is no automatic refresh interval — the data is cheap to fetch but does not move minute-to-minute, so we trade auto-polling for an explicit **Refresh** button in the header. Every successful mutation (`apply`, `dismiss`, `auto_tune`) calls `mutate()` to revalidate immediately, so the row updates in place without waiting for an interval.

Tests cover the same flow: render → click action → assert SWR cache was invalidated and the new entry rendered.

## Permissions and tenancy

| Endpoint | Permission |
|---|---|
| `GET /detection/tuning`, `GET /detection/tuning/summary` | `rules:read` |
| `POST /detection/tuning/{id}/apply`, `/dismiss`, `/auto_tune` | `rules:write` |

The tenant filter is baked in at the SQLAlchemy layer — `_load_rule_for_tenant` re-asserts it on every mutation and 404s if the rule belongs to a different tenant. Platform rules (`tenant_id IS NULL`) are visible everywhere but mutable nowhere from inside a tenant workbench.

## What this replaces

| Before (v1.4) | After (v1.5) |
|---|---|
| `/noise-tuning` was a hand-coded prototype that read from fixture data and surfaced cosmetic "auto-tune" toggles with no backing semantics. | `/detection/tuning` runs against live `DetectionRule` state, classifies every rule into one of six lanes, and persists every action with a version bump and an audit event. |
| Tuning was a manual JSON edit in the rule editor, with no projection or scoring. | A single-page workbench groups rules by suggestion lane, scores them so the worst surface first, and exposes one-click mechanical actions. |
| Auto-tune was UI-only — flipping the toggle had no server-side effect. | `auto_tune` is stored on `suppression_config.auto_tune` with a server-recorded actor and timestamp, ready to gate future automated tuners. |
| Dismissing a rule meant filtering it out client-side; the next page load brought it back. | Dismissals persist on `suppression_config.tuning_dismissed_at`, are auditable, and can be inspected by passing `include_dismissed=true`. |
| The legacy `/noise-tuning` route still existed in the sidebar. | `/noise-tuning` now redirects to `/detection/tuning` so bookmarks and external links land on the live workbench automatically. |

## Source layout

| Concern | File |
|---|---|
| Workbench page route | [`apps/web/src/app/(app)/detection/tuning/page.tsx`](https://github.com/beenuar/AiSOC/blob/main/apps/web/src/app/(app)/detection/tuning/page.tsx) |
| Workbench component | [`apps/web/src/components/detections/RuleTuningView.tsx`](https://github.com/beenuar/AiSOC/blob/main/apps/web/src/components/detections/RuleTuningView.tsx) |
| Back-compat redirect | [`apps/web/src/app/(app)/noise-tuning/page.tsx`](https://github.com/beenuar/AiSOC/blob/main/apps/web/src/app/(app)/noise-tuning/page.tsx) |
| Sidebar entry | [`apps/web/src/components/layout/Sidebar.tsx`](https://github.com/beenuar/AiSOC/blob/main/apps/web/src/components/layout/Sidebar.tsx) (search for `Detection Tuning`) |
| API client | [`apps/web/src/lib/api.ts`](https://github.com/beenuar/AiSOC/blob/main/apps/web/src/lib/api.ts) (search for `tuningApi`) |
| Tuning endpoints | [`services/api/app/api/v1/endpoints/rule_tuning.py`](https://github.com/beenuar/AiSOC/blob/main/services/api/app/api/v1/endpoints/rule_tuning.py) |
| Projection + classifier + mutators | [`services/api/app/services/rule_tuning.py`](https://github.com/beenuar/AiSOC/blob/main/services/api/app/services/rule_tuning.py) |
| Backend tests | [`services/api/tests/test_rule_tuning.py`](https://github.com/beenuar/AiSOC/blob/main/services/api/tests/test_rule_tuning.py) |
| Frontend tests | [`apps/web/src/components/detections/RuleTuningView.test.tsx`](https://github.com/beenuar/AiSOC/blob/main/apps/web/src/components/detections/RuleTuningView.test.tsx) |

## Author

Beenu Arora · `beenu@cyble.com`
