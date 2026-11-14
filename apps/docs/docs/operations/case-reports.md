# Case Reports: Auto-Summary & Blameless Post-mortem

Every case in AiSOC ships with two deterministic, on-demand reports:

| Endpoint | Audience | Question it answers |
|---|---|---|
| `GET /api/v1/cases/{id}/summary` | Analyst, on-call, exec | _What does this case look like **right now**?_ |
| `GET /api/v1/cases/{id}/postmortem` | Whole team, in retro | _What happened, when did we find out, what did we do, and what should we change?_ |

Both endpoints are **pure functions of case state** — same case, same data, same
output, every time. There is no LLM in the rendering path, so they are safe
for runbook archives, audit packages, and air-gapped deployments.

## When to use which

The summary is a **status snapshot**. It surfaces the current severity, MITRE
techniques, observables, evidence, comments, tasks, and a short list of
recommendations. Reach for it when you join a case mid-investigation, when an
exec asks "what is this case?", or when you need to hand a case off at
shift change.

The post-mortem is a **retrospective**. It reconstructs the timeline of the
incident, classifies the response actions taken, scores detection timing
against the SLA, calls out what went well and what fell short, and emits
concrete action items framed at systems and processes — not people. Reach
for it the moment a case is resolved or closed and you are about to schedule
the team retro.

## Output formats

Both endpoints accept a `format` query parameter:

- `format=json` (default) — the full structured payload (Pydantic model).
  Use this from the SDKs, MCP server, ChatOps bot, or any downstream
  automation.
- `format=html` — a self-contained HTML document with inline CSS, a
  print stylesheet, and a `Content-Disposition: inline; filename="…"` header.
  Open it in a browser and hit Ctrl/Cmd-P → Save as PDF for the runbook
  archive. No server-side PDF rendering, no headless browser, no fonts to
  ship.

```bash
# Structured payload — feed into a wider pipeline
curl -H "Authorization: Bearer $AISOC_TOKEN" \
  "$AISOC_API/api/v1/cases/CASE-1234/postmortem"

# Print-ready HTML — drop into the runbook archive
curl -H "Authorization: Bearer $AISOC_TOKEN" \
  "$AISOC_API/api/v1/cases/CASE-1234/postmortem?format=html" \
  -o case-1234-postmortem.html
```

The case identifier accepts either the human case number (`CASE-1234`) or
the underlying UUID — same resolution rules as every other `/cases/{id}`
endpoint.

## What the post-mortem includes

Each `CasePostmortem` payload is composed of seven sections, all derived
deterministically from the case row, comments, and tasks:

1. **Headline** — one-line summary keyed off severity, technique label, and
   resolution status.
2. **Incident overview** — case label, opened/triaged/resolved/closed
   timestamps, severity, status, MITRE ATT&CK techniques bucketed by
   tactic, and total time-to-resolution.
3. **Detection** — when the alert fired, when an analyst first touched it,
   first-touch latency, and whether the SLA was breached. Paired with a
   `detection_gaps` list for any structural problems we should fix
   (e.g. "first analyst touch arrived after 4h — extend on-call alerting").
4. **Response** — every analyst action bucketed into a small, stable set
   (`triage`, `containment`, `eradication`, `recovery`, `comms`,
   `evidence`, `escalation`, `other`), plus a numeric effectiveness score
   (`actions_taken`, `actions_overdue`, `automated_count`,
   `effectiveness_score` 0–100).
5. **Timeline** — chronological lifecycle events (opened, triaged,
   resolved, closed) merged with system + analyst comments. The narrative
   strips author names so the timeline is **about the incident**, not
   about people.
6. **What went well / What fell short** — short bullet lists derived from
   measurable signals: SLA met vs missed, first-touch latency, action
   throughput, technique coverage, etc.
7. **Action items** — concrete, system-focused follow-ups
   (`detection`, `process`, `automation`, `tooling`, `documentation`,
   `training`) with priority (`now`, `next`, `later`) and an optional
   `target` system. When a case is genuinely clean, the list contains a
   single neutral marker so consumers always have at least one row to
   render.

## Blameless by design

The post-mortem is **explicitly blameless**:

- Analyst names are stored in the underlying comments so we can audit who
  did what, but the rendered narrative — "What went well", "What fell
  short", and the timeline — never surfaces individual handles.
- Action items are framed at the system layer ("extend on-call alerting",
  "add auto-containment for technique T1078") rather than at people
  ("X should respond faster").
- Both signals "first analyst touch was slow" and "no analyst touched
  this high-severity case" route into structural detection-gap items, not
  into individual feedback.

This is the same property the testsuite enforces: see
[`tests/test_case_postmortem.py::test_render_case_postmortem_html_omits_analyst_names`](https://github.com/beenuar/AiSOC/blob/main/services/api/tests/test_case_postmortem.py).

## Determinism & audit

Both endpoints are pure functions of `(case row, comments, tasks)`. The
test suite asserts this directly:

- `test_build_summary_is_deterministic` and
  `test_build_postmortem_is_deterministic` build the same artefact twice
  from identical inputs and `model_dump()` them — byte-for-byte equality.
- `test_postmortem_round_trips_through_pydantic_json` serialises the
  artefact to JSON and parses it back — the round-trip is lossless, so
  the payload is safe to checkpoint into the audit log.
- The HTML renderer is XSS-safe via `html.escape` on every untrusted
  field — the test
  `test_render_case_postmortem_html_escapes_user_data` injects
  `<script>` and `<img onerror=…>` into case titles, comments, and
  techniques and asserts they appear escaped, never as live tags.

Because the renderers are pure and the inputs are versioned (case row +
append-only comments + tasks), the artefacts can be regenerated identically
months later — useful for audit, compliance, and disputed-incident
review.

## Where the code lives

| Concern | File |
|---|---|
| Auto-summary builder + Pydantic schema | [`services/api/app/services/case_summary.py`](https://github.com/beenuar/AiSOC/blob/main/services/api/app/services/case_summary.py) |
| Auto-summary HTML renderer | [`services/api/app/services/case_summary_html.py`](https://github.com/beenuar/AiSOC/blob/main/services/api/app/services/case_summary_html.py) |
| Post-mortem builder + Pydantic schema | [`services/api/app/services/case_postmortem.py`](https://github.com/beenuar/AiSOC/blob/main/services/api/app/services/case_postmortem.py) |
| Post-mortem HTML renderer | [`services/api/app/services/case_postmortem_html.py`](https://github.com/beenuar/AiSOC/blob/main/services/api/app/services/case_postmortem_html.py) |
| HTTP endpoints | [`services/api/app/api/v1/endpoints/cases.py`](https://github.com/beenuar/AiSOC/blob/main/services/api/app/api/v1/endpoints/cases.py) |
| Tests | [`services/api/tests/test_case_summary.py`](https://github.com/beenuar/AiSOC/blob/main/services/api/tests/test_case_summary.py) · [`tests/test_case_postmortem.py`](https://github.com/beenuar/AiSOC/blob/main/services/api/tests/test_case_postmortem.py) |

## Operational tip — automate the runbook archive

The case status-change handler already drops a system comment pointing to
`/summary` whenever a case enters `resolved` or `closed`. You can mirror
that for post-mortems by curling `?format=html` on the same trigger from
your retro process, dropping the file into your runbook bucket, and
linking it back into the case as evidence. Because the renderer is
deterministic, the same case will always produce the same archive — no
diffing surprises six months later.
