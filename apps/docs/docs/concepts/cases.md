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

## AI Investigation

Click **Investigate with AI** to launch the multi-agent investigation pipeline:

1. **ReconAgent** — collects case context, threat intel
2. **ForensicAgent** — deep-dives indicators and timeline
3. **ResponderAgent** — proposes (dry-run) containment steps
4. **ReportWriterAgent** — generates PDF/Markdown report
