---
sidebar_position: 1
title: Investigation Queue workbench
description: The /queue workbench — an opinionated, single-page feed answering "what should I work on next?" with atomic claim semantics, server-anchored SLA countdowns, and one-click triage actions.
---

# Investigation Queue workbench

`/queue` is the page a Tier-1 analyst lives on. It exists to answer one question — *"what should I work on next?"* — and it answers it the same way an experienced shift-lead would: alerts already assigned to you first, then critical and high alerts no one has claimed, all of it ordered by SLA due time so the closest-to-breach work surfaces first. Low-priority unassigned alerts are deliberately excluded; those are triaged in bulk on `/alerts`.

This page documents the bucket model, the SLA timer, the action set, and the API surface that powers the workbench.

## Where the workbench sits

```
┌──────────────────────────────────────────────────────────────────────────┐
│  Investigation Queue                          [Mine 3] [Unassigned 12] [All 15] │
│  ──────────────────────────────────────────────────────────────────────  │
│  ● CRIT  Impossible travel · analyst@aisoc.dev    SLA -2m 04s  [Open]    │
│  ● HIGH  Defender — credential dump · web-01      SLA  3m 41s  [Open]    │
│  ● HIGH  GitHub PAT exfil · svc-deploy            SLA  9m 12s  [Open]    │
│  ● MED   New OAuth grant · helpdesk@…             SLA  1h 22m  [Open]    │
│  ──────────────────────────────────────────────────────────────────────  │
│  ● HIGH  AWS S3 mass-download · prod-data-lake    SLA 12m 03s  [Claim]   │
│  ● HIGH  Suspicious lateral SMB · fin-pc-19       SLA 14m 47s  [Claim]   │
│                                                                          │
│       Mine first ─────► Unassigned (critical / high) ─────► oldest SLA   │
└──────────────────────────────────────────────────────────────────────────┘
```

The queue is intentionally narrow — one row per alert, one anchor entity per row, one suggested next action. The Investigation Rail (W6) and `/alerts` are where the deep dive happens; the queue is where you decide *which* deep dive to take next.

## The three buckets

The owner toggle drives both the filter and the count badges. Counts are returned for every bucket on every fetch so the workbench can switch tabs without re-fetching.

| Bucket | What it shows | Why |
|---|---|---|
| **Mine** | Every open alert assigned to the current user, any severity. | Once you own a row you finish it — severity is no longer the gating factor. |
| **Unassigned** | Open `critical` and `high` alerts with no `assigned_to_id`. | The "up for grabs" queue. Low-priority unassigned alerts are deliberately omitted: paging through them one at a time is a documented anti-pattern of legacy SOC consoles. |
| **All** | Mine first, then Unassigned, ordered as above. | The default landing view. Tier-1 sees their own work without losing sight of the unowned high-severity queue. |

Each bucket is filtered against the same `closed` exit set (`resolved`, `closed`, `false_positive`, `fp`) and the same snooze mask (`snoozed_until <= now`), so claiming, resolving, or snoozing a row makes it disappear deterministically across all three views.

## The SLA timer

Every queue row carries a server-computed `sla_due_at` and `sla_remaining_seconds`. The frontend then ticks the timer down once per second against the server's authoritative `generated_at` timestamp, so:

- The number two analysts on two laptops see for the *same row at the same wall-clock moment* is identical.
- A 30-second polling gap does not produce a 30-second jump in the countdown — the next page payload arrives with a fresh `generated_at` and the local clock simply re-anchors.
- Once `sla_remaining_seconds` goes negative, the pill flips to **breached** and the row sorts to the top of its bucket (because `sla_due_at ASC` is the primary sort).

### SLA target resolution

`sla_due_at` is a *virtual* column computed at query time as `first_seen + mttd_target`, where `mttd_target` is severity-keyed and tenant-configurable:

```
critical  →  configurable, defaults to DEFAULT_SLA_TARGETS["critical"]["mttd_target"] minutes
high      →  ...
medium    →  ...
low       →  ...
info      →  ...
```

The query merges `DEFAULT_SLA_TARGETS` with any rows in `tenant_sla_config`, so per-tenant overrides win without rewriting the alerts schema when the targets are re-tuned. The SQL is a plain `CASE` on severity, so PostgreSQL can index-walk on `alerts.first_seen` and apply the offset cheaply — there is no per-row Python pass.

### The 10-minute amber threshold

The SLA pill has three colour states:

| State | Trigger | Meaning |
|---|---|---|
| `ok` | `sla_remaining_seconds >= 600` | Plenty of runway. |
| `warn` | `0 <= sla_remaining_seconds < 600` | Inside the last 10 minutes — act now. |
| `breached` | `sla_remaining_seconds < 0` | Past the deadline — bump the case, escalate, or document why it slipped. |

10 minutes is the operations-spec threshold and is independent of severity — anything in the last ten minutes of an SLA is treated as "act now" territory.

## The actions

Each queue row exposes four single-click actions. They are intentionally flat — no modals, no confirmation dialogs — so an SOC can sweep through a backlog without breaking flow:

| Action | What it does | Backend |
|---|---|---|
| **Open** | Navigates to `/alerts/{id}` to load the Investigation Rail. | Read-only. |
| **Claim** | Atomically assigns the unassigned alert to the current user. | `POST /api/v1/alerts/{id}/claim` |
| **Release** | (Only on rows you own.) Sets `assigned_to_id = NULL`, returning the row to the Unassigned bucket. | `PATCH /api/v1/alerts/{id}` |
| **Snooze** | Defers the row from the queue for a fixed window. The four presets are **15m / 1h / 4h / 24h**. Anything longer should go through a suppression rule, not a per-alert snooze. | `POST /api/v1/alerts/{id}/snooze` |

### Atomic claim semantics

Claim is the only action with race semantics, because two analysts looking at the same Unassigned bucket can both reach for the same row. The backend handles this with a compare-and-set:

```sql
UPDATE alerts
   SET assigned_to_id = :user, assigned_at = now(), updated_at = now()
 WHERE id = :alert_id
   AND assigned_to_id IS NULL
RETURNING assigned_to_id;
```

- If the `RETURNING` row matches the caller → claim succeeded, response is `200 AlertResponse`.
- If it does not return a row → someone else got there first; the endpoint re-reads `assigned_to_id` and responds with `409 Conflict` carrying the actual owner's UUID.
- If the alert is already assigned to *the caller* → no-op `200`. Re-clicking Claim after a stale page refresh must never produce a 409, and it does not.

The frontend surfaces a `toast` on `409` so the analyst sees who beat them to the row and can move on without reloading.

## The API envelope

The workbench is served by a single endpoint:

```
GET /api/v1/alerts/queue
    ?owner=me|unassigned|all       (default: all)
    &period=24h|7d|30d|all         (default: all)
    &page=1                        (default: 1)
    &page_size=50                  (default: 50, max: 200)
```

### Route ordering

`/alerts/queue` is registered **before** `/alerts/{alert_id}` in the FastAPI router. This is intentional and load-bearing: FastAPI matches top-down, and a parametric path that lands first would happily route `GET /alerts/queue` into `get_alert(alert_id="queue")` and 422. The endpoint definition is explicit about the ordering so future contributors do not accidentally swap them.

### Response shape

The `QueueResponse` envelope:

```jsonc
{
  "items": [
    {
      "id": "8b2e…",
      "tenant_id": "…",
      "title": "Impossible travel — Okta",
      "severity": "high",
      "status": "new",
      "priority": 3,
      "category": "identity",
      "connector_type": "okta",

      "assigned_to_id": "11a3…",     // null if unclaimed
      "case_id": null,

      "first_seen": "2026-05-13T08:31:00Z",
      "sla_due_at": "2026-05-13T09:01:00Z",
      "sla_remaining_seconds": -124,  // negative → breached
      "sla_breached": true,
      "age_seconds": 1864,

      "asset": { "kind": "host", "value": "web-01" },
      "suggested_action": {
        "priority": 1,
        "action": "Isolate the host via EDR",
        "risk": "high"
      },
      "bucket": "mine"
    }
  ],
  "total": 15,
  "counts": { "mine": 3, "unassigned": 12, "all": 15 },
  "period": "all",
  "owner": "all",
  "page": 1,
  "page_size": 50,
  "pages": 1,
  "generated_at": "2026-05-13T09:03:04Z"
}
```

Notes on the contract:

- `counts` is **always** populated for all three buckets regardless of the `owner` filter — that is what lets the tab badges and the sidebar live badge render without an extra round-trip.
- `generated_at` is the server-side `now()` used to compute `sla_remaining_seconds`. The frontend drifts all per-row countdowns from this value, so two analysts on different boxes see the same numbers.
- `asset` surfaces one representative pivot per alert (host → user → asset → ip, in that order). The full pivotable list lives on the Investigation Rail; this is the *anchor*, not the inventory.
- `suggested_action` is the lowest-priority entry from `Alert.ai_recommendations`, normalised across modern (`{priority, action, risk}`) and legacy (bare string) payloads. Older rows that wrote strings get `risk="low"` and a priority derived from their array index.

## Polling and freshness

The workbench polls `GET /alerts/queue` on a **15-second cadence** (`refreshInterval: 15000`, `keepPreviousData: true`). Between polls, every row's SLA countdown ticks down once per second on the client, anchored to `generated_at`. The combination means:

- The page is never more than 15 seconds stale.
- The numbers never visibly stutter — the client never re-renders the countdown from a stale anchor, it always re-anchors from the latest server response.
- Action responses (claim / release / snooze) re-validate the SWR cache immediately, so a successful action is reflected in the queue without waiting for the next 15-second tick.

## Sidebar live badge

The sidebar `Investigation Queue` nav item carries a live pill showing the **count of items in your personal Mine bucket**. The badge is rendered by a small `LiveQueueBadge` component that polls `GET /alerts/queue?owner=me&page_size=1` on a **30-second cadence** (the metadata-only request is much cheaper than the full workbench fetch).

- The badge is hidden entirely when `counts.mine === 0` — we don't draw attention to an empty queue.
- Counts > 99 render as `99+` while the exact number is preserved in the `aria-label` and `title` attributes for screen readers and tooltip hover.
- The badge revalidates on focus and on reconnect, so coming back from a sleeping laptop refreshes the number immediately rather than waiting for the next 30-second tick.

## Permissions and tenancy

All queue endpoints run under the existing `alerts:read` and `alerts:write` permissions and a tenant-scoped DB session. The build query has `Alert.tenant_id == current_user.tenant_id` baked in at the SQLAlchemy layer, and `claim_alert` re-asserts the tenant filter on every row read. Analysts only ever see queue rows for alerts they are authorised to see on `/alerts` in the first place.

## What this replaces

| Before (v1.4) | After (v1.5) |
|---|---|
| Analysts paged through `/alerts` filtered by `assigned_to_me=true` and severity. | One opinionated `/queue` page with three buckets and a single ordering rule. |
| SLA countdowns were derived client-side from `first_seen` and a hard-coded default. | SLA target resolved server-side from `tenant_sla_config`, anchored to `generated_at` for cross-analyst consistency. |
| Claim was a PATCH that any client could send — no race protection. | Atomic compare-and-set on `assigned_to_id IS NULL`. Two analysts racing for the same alert is now a deterministic single-winner. |
| Snooze did not exist as a queue affordance; alerts had to be acknowledged or assigned away. | Four preset snooze windows (15m / 1h / 4h / 24h) on every row, server-validated against a 30-day ceiling. |
| Sidebar showed a static "Alerts" label. | Sidebar `Investigation Queue` link carries a live pill anchored to the same backend the workbench uses. |

## Source layout

| Concern | File |
|---|---|
| Workbench page route | [`apps/web/src/app/(app)/queue/page.tsx`](https://github.com/beenuar/AiSOC/blob/main/apps/web/src/app/(app)/queue/page.tsx) |
| Workbench component | [`apps/web/src/components/queue/QueueView.tsx`](https://github.com/beenuar/AiSOC/blob/main/apps/web/src/components/queue/QueueView.tsx) |
| Sidebar live badge | [`apps/web/src/components/layout/LiveQueueBadge.tsx`](https://github.com/beenuar/AiSOC/blob/main/apps/web/src/components/layout/LiveQueueBadge.tsx) |
| API client | [`apps/web/src/lib/api.ts`](https://github.com/beenuar/AiSOC/blob/main/apps/web/src/lib/api.ts) (search for `queueApi`) |
| Queue endpoint + claim/snooze | [`services/api/app/api/v1/endpoints/alerts.py`](https://github.com/beenuar/AiSOC/blob/main/services/api/app/api/v1/endpoints/alerts.py) |
| Queue builder, claim logic, SLA expression | [`services/api/app/services/alert_queue.py`](https://github.com/beenuar/AiSOC/blob/main/services/api/app/services/alert_queue.py) |
| SLA targets (default + per-tenant resolution) | [`services/api/app/services/sla.py`](https://github.com/beenuar/AiSOC/blob/main/services/api/app/services/sla.py) |
| Backend tests | [`services/api/tests/test_alert_queue.py`](https://github.com/beenuar/AiSOC/blob/main/services/api/tests/test_alert_queue.py) |
| Frontend tests | [`apps/web/src/components/queue/QueueView.test.tsx`](https://github.com/beenuar/AiSOC/blob/main/apps/web/src/components/queue/QueueView.test.tsx) · [`apps/web/src/components/layout/LiveQueueBadge.test.tsx`](https://github.com/beenuar/AiSOC/blob/main/apps/web/src/components/layout/LiveQueueBadge.test.tsx) |

## Author

Beenu Arora · `beenu@cyble.com`
