---
title: Agentmetry (AI coding agents)
description: Ingest AI coding-agent activity and correlated detections from Agentmetry via the universal-capture inbox.
---

# Agentmetry (AI coding agents)

[Agentmetry](https://github.com/blitzcrieg1/agentmetry) (Apache-2.0) is an
open-source sensor for AI coding agents. It records each tool call Claude
Code, Cursor, Codex and Copilot make through their own hooks, and every call
through MCP servers wrapped by its proxy; it correlates sequences into
detections mapped to MITRE ATT&CK and ATLAS — for example a session that
pulled in an issue comment or web page and then touched credentials. It runs
on the developer machine and forwards canonical JSON events to whatever the
team already runs.

AiSOC ingests that stream through the bundled `agentmetry` inbox template.
No connector to install: Agentmetry pushes, AiSOC maps, and the events join
the same pipeline as every other source — lake, detections, correlation,
triage, and the [AI estate inventory](../concepts/ai-estate.md), which
records each coding agent with the person and device behind it.

- **Template id:** `agentmetry`
- **Category:** ai
- **Path:** `POST /v1/inbox/{tenant_token}` ([universal capture](universal-capture.md))

## Setup

1. In the console, mint an inbox token with the **Agentmetry (AI coding
   agents)** template (Settings → Data sources → Universal capture). Copy
   the URL — it is shown once.
2. Point Agentmetry's webhook sink at it:

   ```text
   AGENTMETRY_AUDIT_SINK=webhook            # or a list that includes webhook
   AGENTMETRY_AUDIT_WEBHOOK_URL=https://ingest.example.com/v1/inbox/aitnb_...
   ```

3. Keep `AGENTMETRY_AUDIT_WEBHOOK_FORMAT` at its default, `canonical` — one
   canonical JSON event per POST, which is what the template maps. The
   `batch` and `cloudevents` formats wrap the record in an envelope the
   template does not unwrap.

The token authenticates by being in the URL; mint it without a signing
secret, since Agentmetry's sink does not sign request bodies. Treat the URL
as a credential.

## What lands where

One URL carries two event kinds, and they deliberately land in different
OCSF classes — the same split the `ai-runtime` / `ai-finding` templates
encode:

| Event kind | OCSF class | What happens |
|---|---|---|
| Routine activity (`action.type: tool_called`, `session_start`, `approval_request`, `mcp_schema`, …) | `6003` API Activity | Archived to the event lake for hunting. Not promoted to an alert — a coding agent emits an event per tool call, and promoting each one floods the queue with its normal operation. |
| Correlated detections (`action.type: detection`) | `2001` Security Finding | Always promoted to an alert, whatever the severity — Agentmetry's rule engine already judged the sequence worth attention, the same reasoning that promotes a Splunk notable. |

Detection severity is read from `detection.severity`
(`critical | high | medium | low`) and preserved tier for tier — a critical
detection arrives as a critical alert, never collapsed into high. Routine
activity carries no vendor severity and surfaces as Unknown, which is the
honest value: the detections are the severity-bearing stream.

ATT&CK technique ids the sensor supplies (`detection.technique_ids`,
`tool.mitre.technique_id`) are carried as supplied, never re-inferred, and
marked `verified: true` only when AiSOC's own ATT&CK corpus confirms them.
ATLAS ids (`AML.T****`) are preserved in evidence fields and deliberately
kept out of ATT&CK-typed fields — Agentmetry's own documentation warns that
an ATLAS id there corrupts any rollup that groups by technique.

The agent, operator and host land on the same OCSF slots the AI SDK
templates use, so Agentmetry-observed coding agents appear in the AI estate
inventory and the entity graph with `(:User)-[:OPERATES]->` and
`(:Endpoint)-[:HOSTS]->` links.

## Why not the generic-json template?

Agentmetry's events do land through `generic-json` — the POST is accepted
and events reach the lake. What the generic mapping loses, verified against
real captured events in `services/ingest`'s test suite:

- **Severity flattens to Unknown on every event, including critical
  detections.** `generic-json` reads a top-level `severity` field;
  Agentmetry carries severity at `action.outcome` / `detection.severity`.
- **Every routine tool call becomes an alert.** `generic-json` maps
  everything to class `2001`, which is always promoted — one busy coding
  agent is an alert flood.
- **Titles, descriptions, ATT&CK technique ids and the event timestamp are
  lost** (`detection.title` and friends are nested fields `generic-json`
  does not map, and `timestamp_utc` is not its time field).

The bundled template exists to fix exactly those five things.

## What was verified, and what was not

**Verified:** real canonical events (schema v1.2.0, captured from
`agentmetry demo` on PyPI release 0.10.4) driven through the real embedded
template and the real registry in Go tests — class routing per event kind,
the full severity ladder including the critical tier, ATT&CK carry,
ATLAS exclusion, malformed-event handling, and the generic-json comparison
above. The promotion outcomes stated here follow the fusion promoter's
policy (category 2 always promoted; otherwise `severity_id >= 4`), which is
pinned by its own cross-service test.

**Not verified:** a live Agentmetry orchestrator POSTing to a live AiSOC
deployment over the network. The template maps the documented, captured
canonical shape; if a future Agentmetry schema release moves a field, the
unmapped half degrades exactly as the malformed-event test describes
(template defaults, severity Unknown) rather than being dropped.

**Agentmetry's own stated non-coverage**, so nobody expects otherwise: it
does not see browser chat use, model providers, or anything an agent does
with its hooks disabled. Hook removal shows up as a heartbeat change, not
as prevention.
