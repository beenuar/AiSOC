# aisoc-ai-sdk

Emit AI runtime telemetry — agent tool calls, model invocations, guardrail
findings — to AiSOC.

## Why this exists

AiSOC could already ingest an organisation's OpenAI and Anthropic **audit
logs**: who minted an API key, who was granted owner, whether MFA was turned
off. That is control-plane governance, and it is worth having.

It says nothing about what the agents did once they were running. Which tools
they invoked, on whose behalf, against which resources, and whether anything in
their retrieved context tried to give them new instructions.

This is the runtime half. Every span lands in the same pipeline as every other
security signal: OCSF normalized, archived to the ClickHouse lake, evaluated by
the detection engine, promoted, triaged.

## Install

```bash
pip install -e packages/aisoc-ai-sdk   # PyPI publish lands in v8.1
```

## Use

Mint two inbox tokens — `POST /api/v1/inbox/tokens` — one with the
`ai-runtime` template and one with `ai-finding`:

```python
from aisoc_ai import AiSocAiClient

aisoc = AiSocAiClient(
    endpoint="https://aisoc.example.com/v1/inbox/<runtime-token>",
    finding_endpoint="https://aisoc.example.com/v1/inbox/<finding-token>",
    agent_id="support-bot",
)

# Routine activity. Archived to the lake and hunted, not alerted on.
aisoc.tool_call(
    "search_tickets",
    on_behalf_of="alice@example.com",
    arguments={"query": "billing"},  # keys are sent, values are not
)

aisoc.model_call("gpt-4o", prompt=prompt, response=answer, prompt_tokens=412)

# A guardrail objected. Always promoted to an alert.
aisoc.finding(
    "prompt_injection",
    "Instruction override in retrieved document",
    confidence=0.91,
)
```

## Two endpoints, deliberately

The split is the design, not an inconvenience.

`tool_call` and `model_call` normalize to OCSF **6003 API Activity**. Category
6, so the promoter leaves them in the lake. An agent doing its job is not an
alert, and treating it as one floods the queue with an agent's own normal
operation.

`finding` normalizes to OCSF **2001 Security Finding**. Category 2, which the
promoter always promotes regardless of severity, because a guardrail has
already judged it worth a human's attention. Send a finding to the runtime
endpoint and it silently becomes routine telemetry — so the SDK warns loudly
when `finding_endpoint` is unset.

## What leaves your process

Prompts and model responses routinely contain whatever a user pasted in,
whatever a retrieval step pulled from an internal store, and whatever the model
then said about it. A SOC needs to detect abuse of the AI without becoming the
largest single collection of that text in the company.

So the default is `CaptureMode.HASHED`: a SHA-256 digest and a length, never
the content. That answers the questions detection actually asks — is this the
same prompt fifty times in a minute, did the response change after an injection
attempt, is this prompt anomalously long for this agent — without retaining the
text.

It also reports **which secret shapes** were present. So "this prompt contained
an AWS access key" is detectable, and the `ai-prompt-contained-credential` rule
fires, while the key itself never leaves your process.

| mode | what is sent |
| --- | --- |
| `HASHED` (default) | digest, length, matched secret-pattern names |
| `MASKED` | the above plus content with secret shapes replaced |
| `FULL` | the above plus content verbatim |

`MASKED` and `FULL` exist because incident response sometimes genuinely needs
the words. Both are opt-in per client, because that is a decision someone
should make deliberately rather than inherit from a default.

Tool arguments follow the same rule: parameter **names** are transmitted,
values are not. Which tool ran with which parameters is the detection signal;
the values are frequently the sensitive part.

## Failure behaviour

This is instrumentation inside your request path, so it is built to fail
quietly rather than loudly:

- **Never raises into your code.** Every public method returns a bool. A
  transport error, a rejected token or an unreachable AiSOC is a dropped span.
- **Never blocks.** Spans go onto a bounded queue drained by a background
  thread.
- **Never grows without limit.** A full queue drops the oldest span and counts
  the drop. Unbounded buffering inside your process is a worse outcome than
  losing telemetry.
- **Off when unconfigured.** No `endpoint` disables the client rather than
  raising, which is how an operator turns it off.

`client.stats()` returns emitted / sent / dropped / failed counters, so a
silent SDK is distinguishable from an idle one.

## Detections this feeds

`detections/application/ai-*.yaml`, authored in
`scripts/detection_specs_part3_application.py`:

| rule | fires on |
| --- | --- |
| `ai-prompt-injection-detected` | `finding_type: prompt_injection` |
| `ai-agent-excessive-agency` | `finding_type: excessive_agency` |
| `ai-sensitive-data-egress` | `finding_type: sensitive_data_egress` |
| `ai-unapproved-model` | `finding_type: unapproved_model` |
| `ai-tool-escalation` | `finding_type: tool_escalation` |
| `ai-shadow-agent-discovered` | `finding_type: shadow_ai` |
| `ai-prompt-contained-credential` | a secret shape in a prompt |
| `ai-agent-tool-call-failed-repeatedly` | a denied tool call |

## If you run a gateway instead

For apps you do not control, the `ai_gateway` connector pulls request logs from
LiteLLM, Portkey, Helicone or an in-house proxy and produces the same OCSF
shape. One connector covers every app behind the gateway, which matters because
the apps most in need of visibility are the ones nobody will retrofit an SDK
into.

## License

MIT.
