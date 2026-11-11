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

## Investigation context

The template preserves selected optional fields under
`finding.evidence.agentmetry`. This is vendor-reported evidence, not a new
OCSF identity object: the ingest declaration remains OCSF `1.1.0`, while
`finding.evidence.agentmetry.schema_version` records the source schema.
Existing mapped fields, including `finding.uid` (the source event ID) and
`finding.evidence.session_id`, keep their paths.

| Context below `finding.evidence.agentmetry` | What it preserves |
|---|---|
| `event_type`, `adapter`, `operator_source` | The original event kind, capture adapter and reported origin of the operator ID. |
| `account.domain`, `account.source`, `account.organization_id` | Selected reported account claims, separate from `actor.user`. The account block's full email and opaque account/user IDs are not mapped, even when present in the source payload. |
| `detection.event_ids`, `detection.first_seen_utc`, `detection.last_seen_utc` | Supporting source-event references and the sensor's correlation window. |
| `heartbeat.interval_seconds`, `heartbeat.hooks`, `heartbeat.hook_profile`, `heartbeat.hooks_uncovered`, `heartbeat.hooks_unverified`, `heartbeat.hooks_silent`, `heartbeat.spool_depth` | Recorder cadence, reported hook coverage and backlog. False, zero and empty lists are retained; missing fields stay absent. |
| `heartbeat.mcp_config_digest`, `heartbeat.mcp_schema_digest`, `heartbeat.mcp_schema_servers` | The recorder's configured and observed MCP surface. |
| `mcp_schema.server_id`, `mcp_schema.server_version`, `mcp_schema.status`, `mcp_schema.fingerprint`, `mcp_schema.tool_count`, `mcp_schema.list_changed`, `mcp_schema.tools_changed`, `mcp_schema.tools_added`, `mcp_schema.tools_removed`, `mcp_schema.unverified_baseline` | The observed schema state and available change details, without copying tool descriptions. |

Use `detection.event_ids` to find the supporting events by their
`finding.uid`, scoped to the same tenant and source host. These are
Agentmetry's event IDs, not AiSOC's generated ingest-envelope IDs. Do not
require every supporting event to share the finding's correlation ID:
host-wide findings can reference several sessions. The legacy
`finding.evidence.session_id` field retains the source `correlation_id`,
which can identify a host rather than a session for these findings. A
reference does not establish that its supporting event arrived; missing
evidence must remain missing. This mapping adds no automatic UI pivot.

Account claims do not establish who used an account or tenant membership.
`account.source: local_config` means the account last signed in on the
machine, which may differ from the account used for a call. Missing account
claims mean unknown. A domain outside an approved list is something to
review, not proof of a personal account; somebody's own domain can look the
same as a company domain. This template does not classify domains or add
account-based detections.

Heartbeat and MCP schema events remain routine `6003` activity with no
vendor severity. A downstream rule must decide whether they need attention.
A missing heartbeat can also mean an offline host or a delivery failure.
An MCP status of `new`, `same` or `rebaselined` is not `changed`; an
`unavailable` listing has no fingerprint and must not be read as a schema
change. Legitimate upgrades can also change a schema. These fields do not
prove complete capture or verify the source trail.

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

**Additional synthetic mapping coverage:**
`services/ingest/internal/inbox/agentmetry_context_test.go` extends the
captured event shapes with invented optional claims and observations. It
uses the real inbox JSON decoder, embedded template and normalized JSON
round trip to check supporting-event links, account provenance and selected
field privacy, unknown account states, zero/false/empty coverage values,
and MCP schema states. These are mapping tests, not a new live sensor or
backend run.

**Run once by hand, not gated:** the live leg, on 2026-11-02, by
Agentmetry's maintainer
([blitzcrieg1/agentmetry#367](https://github.com/blitzcrieg1/agentmetry/pull/367)).
Agentmetry 0.10.4 installed from PyPI posted `canonical` events over HTTP
to a local AiSOC v21 stack on the same host (`make up`, with `make smoke`
passing 10 of 10 first), at an inbox minted with this template:

- 11 of 11 events forwarded and accepted, none dead-lettered
- both detections (`credential-exfil`, `remote-staging-then-execute`)
  arrived as critical alerts with their ATT&CK techniques
- the 9 routine events (tool calls, a denial, session start and end)
  raised no alert
- `claude` and `cursor` appeared in the AI estate with the operator attached

No CI job repeats that run, so a later change on either side can break it
without a gate failing.

**Not verified:** a deployment where the sensor and AiSOC are on different
hosts, and any AiSOC release after v21. The template maps the documented,
captured canonical shape; if a future Agentmetry schema release moves a
field, the unmapped half degrades exactly as the malformed-event test
describes (template defaults, severity Unknown) rather than being dropped.

**Agentmetry's own stated non-coverage**, so nobody expects otherwise: it
does not see browser chat use, model providers, or anything an agent does
with its hooks disabled. Hook removal shows up as a heartbeat change, not
as prevention.
