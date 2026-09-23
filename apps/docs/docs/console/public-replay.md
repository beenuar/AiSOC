---
title: Public investigation replays
sidebar_label: Public replays
---

# Public investigation replays

Turn any investigation ledger into an **immutable, redacted, public share link**
at `<your-console>/r/<slug>` so you can show how the agent reasoned through a
case — in a blog post, an incident write-up, or a talk — without exposing your
environment.

Replays are served by your own deployment, so the host is whatever
`CONSOLE_PUBLIC_BASE_URL` points at. On a local stack that is
`http://localhost:3000/r/<slug>`. The seeded LockBit 3.0 case ships with the
demo data as slug `demo-lockbit`; there is no hosted public instance to link
to right now, so run the demo seed locally to see it.

## What a viewer sees

A read-only animated playback:

- a **timeline scrubber** over the LangGraph traversal (play / pause / seek),
- **evidence cards** appearing per step,
- the **attack graph** growing as techniques are discovered,
- a **verdict stamp** with the elapsed time, step count, tool-call count, and
  evidence-source count ("Investigated in 94s, 14 tool calls, 3 evidence
  sources").

Links unfurl on X / LinkedIn / Slack via a dynamically-generated Open Graph
image.

## Publishing (with a redaction review)

Publishing is a two-step, opt-in flow — nothing is ever published automatically.

1. **Preview the redaction.**
   `POST /api/v1/ledger/{run_id}/publish/preview` returns the redacted snapshot
   **plus the alias map** (`{ "HOST_1": "WIN-FIN-DB01", ... }`) so you can review
   exactly what will be hidden before anything is stored.
2. **Confirm.**
   `POST /api/v1/ledger/{run_id}/publish` with `{ "confirm": true }` re-builds
   the snapshot server-side (the client preview is never trusted), stores an
   **immutable** row, and returns the public slug + URL.

Unpublish at any time with `DELETE /api/v1/ledger/publish/{slug}`.

## What is redacted

Redaction reuses the same reversible pseudonymizer the LLM egress path uses
(`services/agents/app/privacy/redactor.py`, vendored into the API):

| Redacted → alias | Preserved |
|---|---|
| Internal IPs, emails, file paths, secrets, internal hostnames, usernames | Public IOCs (external domains / IPs), MITRE technique IDs |

Public IOCs and ATT&CK techniques are intentionally preserved — they are the
shareable threat-intelligence value of a replay, not customer PII. Only the
redacted snapshot is persisted; the alias map is returned in the preview and is
**never stored**.

## Guarantees

- **Immutable.** A published snapshot never changes (a DB trigger blocks
  UPDATEs to every field except the view counter). Re-publishing mints a new
  slug.
- **Public-by-design.** The `/r/<slug>` read is unauthenticated and served from
  a non-RLS session because the stored data is post-redaction and
  non-identifying. Writes remain tenant-scoped.
- **CDN-cacheable.** The replay page and OG image are static-friendly and do not
  depend on the demo box being up.

## Badges

shields.io-compatible endpoint badges live at `<your-console>/api/badge/<kind>`
(`triaged`, `noise-suppressed`, `benchmark`, `verified-detection`, `self-play`).
The endpoint must be publicly reachable for shields.io to render it. Embed one
in a README:

```markdown
![AiSOC](https://img.shields.io/endpoint?url=https://your-console.example.com/api/badge/triaged)
```

Callers can override the message/label/color via query params (e.g. the GitHub
Action passes its per-run triaged count).
