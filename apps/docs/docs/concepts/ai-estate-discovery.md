---
sidebar_position: 9
title: Discovering the AI estate
description: How AiSOC finds AI apps, coding agents, MCP servers, IDE extensions, provider keys and OAuth grants — and exactly what each source cannot see.
---

# Discovering the AI estate

AiSOC builds its AI inventory from telemetry it already collects. There is no
new agent to deploy: the three discovery paths are an SDK or gateway you may
already route AI traffic through, the endpoint agent your fleet already runs,
and your model provider's own audit log.

The inventory lives at **AI Estate** in the console and in the
`aisoc_ai_assets` table. It records what AiSOC *observed*, which is
deliberately different from `/api/v1/mcp-servers`, which records what an
operator *declared*. The row that matters in an AI governance review is the
one present in the first and absent from the second.

## What each source can and cannot see

This is the part worth reading before you plan coverage. The three sources
see genuinely different things, and the gaps are not symmetric — so a column
on the inventory page being empty can mean "nobody is accountable for this"
or "this source has never been able to tell us", and only the first is a
finding.

### AI runtime telemetry

**Connectors:** the `ai_gateway` connector, and the `ai-runtime` /
`ai-finding` inbox templates that `packages/aisoc-ai-sdk` posts to.

| Sees | Cannot see |
| --- | --- |
| The agent's identity and name | The device, unless the app itself reports a hostname |
| The model and the provider | Anything about an agent that is not instrumented and does not route through a gateway |
| Which tools were invoked, and against which resources | A process that never called a model |
| The human the agent acted for, when there is one | |
| Which secret *shapes* a prompt contained, without the prompt ever leaving the process | |

### Endpoint telemetry

**Connectors:** `fleetdm`, `osctrl`, `auditd`, `windows_event`.

| Sees | Cannot see |
| --- | --- |
| The device | Which model was called |
| The binary and its full command line | Which tools were invoked |
| Whether an agent was started with its permission prompts disabled | What a prompt contained |
| MCP client configuration files — evidence a server is *wired in* | An agent running anywhere with no endpoint agent |
| AI IDE extension directories, with publisher and version | |
| Model-provider credential files sitting on a laptop | |

:::caution The EDR connectors do not supply this
`crowdstrike`, `sentinelone` and `azure_defender` poll the **vendor's own
detections**, not raw process telemetry — `crowdstrike.py` reads
`/alerts/combined/alerts/v1`, which returns judgements. They are classed as
OCSF Security Findings for that reason, and they cannot supply a process
start.

Endpoint discovery therefore comes from osquery (through FleetDM or osctrl),
from `auditd` on Linux, and from Windows event forwarding. If you run an EDR
and nothing else, this half of the inventory will be empty, and that is a
coverage gap rather than a quiet estate.
:::

### Provider and directory audit logs

**Connectors:** `llm_usage`, and the Workspace / Entra audit streams.

| Sees | Cannot see |
| --- | --- |
| The provider account and organisation | Any device, ever |
| Who minted or used an API key | Which application used the key |
| Role, logging and MFA changes | Anything about a key minted outside the audited organisation |
| Which AI application was granted OAuth access, and the scopes | What the application did with the grant |

## The osquery pack

`packs/aisoc-ai-estate.yaml` is the endpoint half. Assign it to a tenant the
same way as any other pack, or render it for direct import:

```
GET /api/v1/osquery/packs/aisoc-ai-estate/render?format=osctrl
GET /api/v1/osquery/packs/aisoc-ai-estate/render?format=fleetdm
```

Five queries:

| Query | Interval | What it answers |
| --- | --- | --- |
| `coding_agent_processes` | 5 min | Which coding agents are running, and with what command line |
| `mcp_server_processes` | 5 min | Which local MCP servers are running |
| `mcp_client_configurations` | 1 hour | Which MCP clients are configured, and where |
| `ai_ide_extensions` | 1 hour | Which AI assistant extensions are installed, with version |
| `provider_key_files` | 1 hour | Whether model-provider credential material sits on this laptop |

Three design decisions worth knowing, because each is a trade-off rather than
an oversight:

**Process names are an explicit list, not a pattern.** A `LIKE '%agent%'`
would match half an EDR estate, and a false positive here puts somebody's
antivirus on a security review. The cost is that an agent not on the list is
invisible to the process queries — though it still appears through the SDK
path and, if it is an editor extension, through the extension query.

**Configuration file *contents* are never collected.** An MCP configuration
routinely holds bearer tokens for third-party servers. The file's presence,
path and mtime are the evidence; an inventory has no business holding the
credentials.

**Every query is severity `info`.** Discovering that a developer runs a
coding agent is inventory, not a finding. What makes a row interesting is the
risk the inventory computes from it — nobody accountable, permission prompts
disabled, an unvetted install source — and that judgement lives in one place
rather than being duplicated into a pack.

## How a row is linked to a person and a device

Each source contributes what it has, and a later sighting never erases what
an earlier one learned:

- **Person** comes from `actor.user.name` on runtime telemetry, the acting
  user on an endpoint event, or the account on a provider audit record.
- **Device** comes from the endpoint hostname. Runtime telemetry supplies it
  only when the instrumented app reports one, and a provider audit log never
  does.
- **Permissions** are a snapshot of what the effective-permissions resolver
  returned for the linked person at the last sighting, rather than a join, so
  a later permission change does not rewrite history.

When a source did not supply a link, the console renders **"not learned"** in
the colour of a finding rather than a blank cell, and the tooltip names what
that source is blind to. An asset nobody is accountable for is the row this
inventory exists to surface.
