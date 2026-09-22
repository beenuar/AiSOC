---
title: Securing the AI estate
description: Monitor the agents, LLM applications and MCP servers your organisation runs.
---

# Securing the AI estate

Every organisation now runs software that takes instructions from text it did
not write. Coding agents with repository access, customer-facing assistants
with database credentials, MCP servers brokering tool calls on someone's
behalf. These are production systems with production privileges, and the
existing security stack does not see them: an EDR agent sees a Python process,
a SIEM sees an HTTPS call to an API endpoint, and neither sees that a prompt
asked the model to exfiltrate a table and the model agreed.

AiSOC treats the AI estate as a monitored asset class, the same way it treats
endpoints and cloud accounts.

:::note What this is not
This is not a guardrail product. AiSOC does not sit inline and block prompts;
it ingests what your gateway or application already observed and applies
detection, correlation and triage to it. If you need enforcement in the
request path, that belongs in your gateway. What belongs here is the question
a guardrail cannot answer: *was this one event, or the third step of
something*.
:::

## What gets ingested

Two OCSF shapes, because routine activity and a guardrail finding are
different things and collapsing them loses the distinction:

| Template | OCSF class | Carries |
|----------|-----------|---------|
| `ai-runtime` | `6003` | Routine model and tool activity: which model, which tool, token counts, latency, the requesting principal. |
| `ai-finding` | `6003` | A guardrail or classifier fired: injection attempt, jailbreak, refusal, sensitive-data match. Promoted to an alert. |

Routine activity is not alerted on. It is the baseline that makes a finding
interpretable — a single refused prompt means little; a refused prompt from a
principal whose token usage jumped tenfold in the same hour means something.

## Getting data in

Three paths, in order of how much you control:

**The `ai_gateway` connector** polls an AI gateway (LiteLLM, Portkey, Helicone
or anything exposing a compatible log API) on a schedule. Nothing to
instrument. See [ai-gateway](../connectors/ai-gateway.md).

**The SDK** (`packages/aisoc-ai-sdk`) emits from inside your application, for
the case where the gateway does not see what matters — a tool call the agent
made internally, a retrieval that returned more than it should have.
Dependency-free, so adding it does not change your dependency tree.

**The inbox webhook** takes whatever your platform already emits, mapped
through a template. See [universal capture](../connectors/universal-capture.md).

### Prompts are hashed by default

The SDK hashes prompt and completion text before it leaves your process, and
reports **which secret shapes the text contained** rather than the text. A
prompt that carried an AWS key is recorded as having carried one; the key does
not travel.

This is the default rather than an option because the alternative is a
security product that becomes the largest concentration of sensitive prompt
text in the organisation. If you need the text for investigation, opt in per
call — and know what you have opted into.

## What it detects

Eight rules ship against AI runtime telemetry. They divide into two kinds,
and the second kind is why this is worth doing at all:

**Single-event rules** — an injection pattern in a prompt, a jailbreak
template, a secret in a completion, an unusual tool for the agent's role. A
guardrail catches most of these in the request path, and if yours does, these
are corroboration rather than detection.

**Behavioural rules** — token usage far above the principal's baseline, tool
calls in an order the agent has never made before, a spike in refusals from
one caller, an agent reaching a resource outside its declared scope. These
need history and correlation, which is what a SOC platform has and a
request-path guardrail does not.

## AiSOC's own MCP server is monitored

`services/mcp` emits the same telemetry as any other monitored asset, through
the same ingest path. This is not a demo: the server's README previously
claimed an audit trail it did not emit, which is exactly the failure mode the
capability exists to catch. Being the first monitored asset is the cheapest
way to keep that honest — if the telemetry breaks, our own estate goes dark
first.

## Limits worth knowing before you rely on it

- **Detection rests on what your gateway reports.** An agent calling a model
  directly, bypassing the gateway, is invisible here. The estate inventory is
  only as complete as your egress controls.
- **Behavioural rules need a baseline.** Expect roughly a week before
  usage-anomaly rules are useful, and noise before that.
- **Hashed prompts bound what an investigation can conclude.** You can see
  that a prompt contained a credential shape; you cannot see the credential.
  That is the trade, and it is the right one by default.

## See also

- [Detection content](./detections.md)
- [Windowed detections](./windowed-detections.md)
- [`ai_gateway` connector](../connectors/ai-gateway.md)
