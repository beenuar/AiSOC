---
sidebar_position: 1
---

# Cases

A **Case** is the central unit of work in AiSOC. Every security incident, alert,
or investigation is tracked as a Case.

## Case States

`open` → `investigating` → `resolved` | `closed`

## Case Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Unique identifier |
| `title` | string | Short description |
| `severity` | enum | `critical`, `high`, `medium`, `low` |
| `status` | enum | `open`, `investigating`, `resolved`, `closed` |
| `mitre_tactics` | string[] | Associated ATT&CK tactics |
| `indicators` | Indicator[] | IOCs linked to the case |
| `playbook_runs` | PlaybookRun[] | Automation runs |
| `ledger_entries` | LedgerEntry[] | Replayable agent decisions (see below) |

## AI Investigation

Click **Investigate with AI** to launch the multi-agent investigation pipeline:

1. **OrchestratorAgent** — plans the investigation graph and routes work
2. **ReconAgent** — collects case context, threat intel, environmental fit
3. **ForensicAgent** — deep-dives indicators, timeline, attack-graph paths
4. **ResponderAgent** — proposes (dry-run by default) containment steps
5. **ReportWriterAgent** — generates the PDF / Markdown executive report

The full graph lives under
[`services/agents/app/investigator/`](https://github.com/beenuar/AiSOC/tree/main/services/agents/app/investigator).

## Investigation Ledger

The **Investigation Ledger** is the structural moat that separates AiSOC from
closed-source AI SOC vendors: every prompt sent to an LLM, every response
received, every tool invocation, every evidence citation, and every decision
branch is appended to a tenant-scoped, append-only ledger and rendered as a
scrubbable timeline on the case workspace.

### What gets logged

For every agent step, the ledger captures:

- `agent_id` — which agent emitted the step (`orchestrator`, `recon`, …)
- `step_kind` — `prompt`, `response`, `tool_call`, `tool_result`,
  `decision`, `evidence_citation`, `plan_update`
- `model` — the model name and provider used for the step
- `prompt_hash` — SHA-256 of the prompt (so you can prove what was asked
  without storing every byte twice)
- `payload` — the structured content of the step (redacted per tenant
  config)
- `started_at` / `completed_at` / `latency_ms`
- `tool_name` and `tool_input_hash` for tool calls
- `evidence_uris` — links into PostgreSQL / OpenSearch / Neo4j / Qdrant
  for every cited piece of evidence

### Why it matters

- **Auditability** — every claim the agent makes on a case is backed by
  a logged tool call and evidence citation, scoped to a tenant.
- **Replayability** — analysts can scrub the timeline and replay the
  exact sequence the agent followed, including failed tool calls.
- **Compliance** — feeds the SOC 2 / ISO 27001 / NIST CSF dashboards
  with concrete, human-readable evidence of automated decisions.
- **Debugging** — when an investigation goes wrong, the ledger is the
  first place to look; you can see the exact prompt, response, and
  tool input that produced the bad output.

### Where it lives

- Schema:
  [`services/api/migrations/008_investigation_ledger.sql`](https://github.com/beenuar/AiSOC/blob/main/services/api/migrations/008_investigation_ledger.sql)
- Model:
  [`services/api/app/models/investigation.py`](https://github.com/beenuar/AiSOC/blob/main/services/api/app/models/investigation.py)
- API endpoints:
  [`services/api/app/api/v1/endpoints/investigations.py`](https://github.com/beenuar/AiSOC/blob/main/services/api/app/api/v1/endpoints/investigations.py)
- Agent-side writer:
  [`services/agents/app/investigator/ledger.py`](https://github.com/beenuar/AiSOC/blob/main/services/agents/app/investigator/ledger.py)
- UI:
  [`apps/web/src/components/cases/InvestigationLedger.tsx`](https://github.com/beenuar/AiSOC/blob/main/apps/web/src/components/cases/InvestigationLedger.tsx)

### REST surface

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/cases/{case_id}/investigations` | List ledger entries for a case |
| `GET` | `/api/v1/investigations/{id}` | Get a single ledger entry with full payload |
| `POST` | `/api/v1/cases/{case_id}/investigations:replay` | Replay an investigation deterministically |

The ledger is also surfaced through the [MCP server](../integrations/mcp), so
analysts can replay agent decisions directly from Claude / Cursor / Continue
/ Cody.

## Ambient Copilot

The case workspace is **copilot-aware**: the Ambient Copilot panel proposes
the next concrete action based on the current state of the case (e.g.
"contain host", "open jira ticket", "add indicator to threat intel feed").
Each suggestion is one click away from running the right agent tool with
the right payload, and every accepted suggestion is recorded in the
ledger.
