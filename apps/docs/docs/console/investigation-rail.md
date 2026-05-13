---
sidebar_position: 2
title: Investigation Rail on /alerts
description: How AiSOC turns the legacy alert detail drawer into a structured triage rail — narrative, related entities, mini-timeline, and recommended actions — served by GET /api/v1/alerts/{id} and rendered to the right of the queue.
---

# Investigation Rail on `/alerts`

Tier-1 analysts spend most of their day on the alert queue. The thing they reach for first is not a chart; it is *context*. v1.5 reshapes `/alerts` into a two-pane workbench: the queue on the left, an **Investigation Rail** on the right. Selecting a row hydrates the rail in place — no drawer, no page hop — and the same row's "Deep Explain" button still opens the existing LLM walkthrough on demand.

This page documents the rail, the four sections it renders, and the API envelope it consumes.

## Where the rail sits

```
┌────────────────────────────────────────────┬──────────────────────────────┐
│  Alerts queue                              │  Investigation Rail          │
│  ───────────────────────────────────────── │  ─────────────────────────── │
│  ● ALERT-7341  Impossible travel          │  Impossible travel — Okta   │
│  ● ALERT-7340  Suspicious OAuth grant    →│  Severity: high · Risk 87   │
│  ● ALERT-7339  AWS S3 mass-download        │                              │
│  ● ALERT-7338  Defender — credential dump  │  Narrative                   │
│  ● ALERT-7337  GitHub PAT exfil            │  Related entities            │
│                                            │  Mini-timeline               │
│                                            │  Recommended actions         │
└────────────────────────────────────────────┴──────────────────────────────┘
```

The queue is unchanged for analysts who already memorised v1.4 muscle memory: column order, filters, saved views, and the bulk-acknowledge bar still behave the way they always did. The right pane appears the first time you click a row and stays in place until you press **Close investigation rail** or unmount the page.

## The four rail sections

### 1. Narrative — *why* this alert was promoted

Every alert that comes through fusion now carries a short, deterministic narrative explaining the correlation that promoted it. The narrative is generated once at fusion time, cached on the alert row, and rendered verbatim in the rail. There is no LLM call on the read path — the same text is identical for every analyst who opens the alert.

For alerts created before v1.5, the API lazily back-fills the narrative on the first read: `GET /api/v1/alerts/{id}` projects the row into `NarrativeInputs`, generates the text via the shared narrative builder, and persists the result so subsequent reads are cheap. Analysts never see a blank panel.

The narrative is the *first* thing the analyst reads. It answers four questions a Tier-1 needs in under five seconds:

- *Which detection or detections fired?*
- *What did fusion match on?* (principal, host, indicator, MITRE technique)
- *How much weight did each factor carry?*
- *What does fusion say the next move is?*

### 2. Related entities — pivots, not paragraphs

The rail groups related entities into four buckets so the analyst can scan them at a glance:

| Group | Examples |
|---|---|
| Principal | user accounts, service principals, IAM roles |
| Network | source IPs, destination IPs, hostnames, ASNs |
| Workflow | case ID, playbook run ID, ticket key |
| Tenant | tenant slug, business unit, environment tag |

Each entry has a `kind`, a `value`, an optional `displayLabel` (for example `analyst@aisoc.dev (Okta)`), and — most importantly — an optional `pivotPath`. When present, the rail renders the row as a `next/link`: clicking it sends the analyst straight to `AttackGraphView` or the corresponding workbench, with the entity prefocused. The whole point of this section is to make the queue a launchpad: every entity is a *verb*, not a label.

The grouping is computed server-side in `services/api/app/services/alert_rail.py` so the frontend never has to re-sort the list, and so two analysts looking at the same alert see exactly the same buckets in the same order.

### 3. Mini-timeline — the last six things that happened

The rail surfaces the six most recent events for the alert's case, drawn from two sources that already exist in the platform:

- **`CaseTimeline`** — analyst comments, status transitions, playbook checkpoints, attached evidence.
- **`AuditLog`** — auth events, RBAC changes, and system actions that touched the alert or its case.

The two streams are merged, deduplicated, ordered newest-first, and capped at six. Each event renders with a kind badge (`comment`, `status`, `evidence`, `auth`, `playbook`, `system`), a title, an actor if one is recorded, and a relative timestamp. Malformed timestamps fall through gracefully — the badge still renders so the analyst sees the event count is right even if a single event lost its clock.

The point of the mini-timeline is to answer "what did someone else already do here?" without forcing the analyst to open the full case page. If something interesting happened in the last hour, it shows up on the rail.

### 4. Recommended actions — the responder's structured guidance

ResponderAgent already emits structured `recommended_actions` for v1.4 cases. The rail surfaces them verbatim:

```json
{
  "priority": "critical",
  "action": "Isolate the host via EDR",
  "rationale": "Defender flagged credential-dump tooling and the same host appears in a GitHub PAT exfil alert from 11 minutes ago.",
  "risk": "Isolation will sever active RDP sessions on this host."
}
```

The rail normalises both modern (`{priority, action, rationale, risk}`) and legacy (list-of-strings) payloads so older alerts still render uniformly. Each card carries a priority chip (`critical | high | medium | low | info`), the action title, the rationale, and the risk callout. If a payload omits `priority`, the rail falls back to `medium` so the chip is always rendered — there is no empty state inside a populated card.

The rail does *not* execute actions. The "Run this action" affordance lives on the case page; the rail's job is to make sure the analyst sees the recommendation *before* they spend ten minutes investigating a dead end.

## The API envelope

The rail is served by a single endpoint:

```
GET /api/v1/alerts/{alert_id}
```

The response is the `AlertDetailResponse` Pydantic contract:

```jsonc
{
  // ─── existing AlertResponse fields ──────────────────────────────
  "id": "ALERT-7341",
  "title": "Impossible travel — Okta",
  "severity": "high",
  "status": "new",
  "risk_score": 87,
  "source": "okta",
  "ai_confidence": 0.82,
  "ai_recommendations": [ /* ... */ ],

  // ─── rail envelope (added in v1.5) ─────────────────────────────
  "narrative": "Fusion linked an Okta impossible-travel signal …",
  "related_entities": [
    { "kind": "principal", "value": "analyst@aisoc.dev",
      "display_label": "analyst@aisoc.dev (Okta)",
      "pivot_path": "/graph?focus=user:analyst%40aisoc.dev" },
    { "kind": "network",   "value": "203.0.113.42",
      "pivot_path": "/graph?focus=ip:203.0.113.42" }
  ],
  "mini_timeline": [
    { "id": "evt-1", "kind": "comment", "title": "Initial triage",
      "actor": "tier1@aisoc.dev", "occurred_at": "2026-05-13T08:31:00Z" }
  ],
  "recommended_actions": [
    { "priority": "critical",
      "action": "Isolate the host via EDR",
      "rationale": "Credential-dump tooling on the same host.",
      "risk": "Active RDP sessions will be severed." }
  ]
}
```

Older clients (the v1.4 detail drawer, third-party MCP integrations) keep working because every rail field is optional. If the rail receives an envelope without a `narrative` or with an empty `related_entities`, the corresponding section is omitted from the panel entirely — the rail never shows an empty "Mini-timeline" header above zero events.

### Lazy back-fill

For pre-v1.5 alerts, `narrative` is `null` on disk. The endpoint:

1. Projects the alert into `NarrativeInputs` (`services/api/app/services/narrative_projection.py`).
2. Calls the vendored narrative builder (`services/api/app/_vendor/narrative.py`).
3. Persists the resulting text on the alert row.
4. Returns the populated `AlertDetailResponse`.

This back-fill is best-effort and idempotent. If projection fails (for example, the alert was written by a connector that does not populate `correlated_indicators`), the response simply omits `narrative` and the rail hides the section. The endpoint never raises a 5xx because the narrative could not be generated.

## Permissions and tenancy

The endpoint is gated by the existing `alerts:read` permission and runs under a tenant-scoped DB session, so the rail respects every RLS policy that already applies to the queue. Analysts only ever see related entities, timeline events, and recommended actions for alerts they are authorised to read in the first place.

## Deep Explain is still one click away

The rail is deterministic and cheap by design — there is no LLM call on the read path. For the rich, LLM-driven walkthrough analysts already know from v1.4, every rail header carries a **Deep Explain** button. It opens the same `ExplainDrawer` the queue used to open inline, with the same prompt and the same model contract. The rail does not replace Deep Explain; it makes it opt-in.

## What this replaces

| Before (v1.4) | After (v1.5) |
|---|---|
| Click a row → drawer slides over the queue, hides the next ten alerts | Click a row → rail hydrates beside the queue, queue stays visible |
| Drawer shows free-form LLM narrative as the *primary* affordance | Rail shows deterministic narrative + structured entities; LLM is one click away |
| Mini-timeline lived in a separate `/cases/{id}` page | Last six events render inline on the rail |
| Recommended actions were a `<ul>` of strings on the drawer footer | Cards with priority chip, action, rationale, and risk callout |
| `GET /api/v1/alerts/{id}` returned `AlertResponse` | `GET /api/v1/alerts/{id}` returns `AlertDetailResponse` (superset; fully backwards-compatible) |

## Source layout

- **Frontend rail** — `apps/web/src/components/alerts/InvestigationRail.tsx`
- **Two-pane queue** — `apps/web/src/components/alerts/AlertsView.tsx`
- **API envelope** — `services/api/app/api/v1/endpoints/alerts.py`
- **Rail builder** — `services/api/app/services/alert_rail.py`
- **Narrative projection** — `services/api/app/services/narrative_projection.py`
- **Vendored narrative** — `services/api/app/_vendor/narrative.py`

## Author

Beenu Arora · `beenu@cyble.com`
