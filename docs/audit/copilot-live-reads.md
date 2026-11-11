# Copilot live-read repair

## Reproduction and root cause

At `8a06f2eb51cd9f9386b840061070c92bf18c89f0`, both Copilot chat transports
called a text-only completion with a generic system prompt and chat history.
They did not offer any tools. Page context was accepted but not included in
the model input; it was later used to mark claims as cited. The current user
message was also included twice. A connected SIEM importer therefore did not
make the chat capable of reading even alerts already ingested into AiSOC.

The dock advertised alerts, hosts and rules, but sent only a page path. It
also discarded the server's response provenance. The full page displayed
some provenance but hid notices on model-generated answers. Both surfaces
now use the same presentation helper, with suggestions limited to supported
reads rather than unsupported MTTR and rule-volume calculations.

## Scope and safeguards

The interactive chat has three typed read tools: ingested alert lists, alert
or case lookup by UUID, and observed Fusion entity risk. The original caller
credential is forwarded to the fixed core API, preserving tenant, RBAC and
attribute restrictions. A model cannot supply a tenant, URL, query language,
credential or write operation. The optional identity-badge policy is checked
when enabled. No service credential is substituted for a denied caller.

Alert windows use `event_time`, with an inclusive lower and exclusive upper
bound, rather than import time. Exact host filters cover both normalized
entities and legacy `affected_hosts`. Rows, totals and facets share the same
predicate. Pagination in one turn uses a fixed time boundary and stable sort.

Each investigation is limited to four model iterations, twelve tool calls,
ninety seconds, twenty records per result and 24 KB of cumulative projected
evidence. Risk queue reads cover at most Fusion's top 200 observed entities;
this is not a complete fleet inventory. Truncated and failed reads are named.
HTTP failures, invalid JSON and oversized responses are not empty successes.
Fusion outages return 503 instead of an empty queue, zero counts or false 404.

Citations are evaluated against the exact bounded tool records, never browser
snapshots. Ordinary and streaming responses include the same provenance, and
it is stored with the assistant message. A model answer without any lookup is
labelled as not being an investigation of the estate. The shared tool loop no
longer returns a raw tool result as the final answer when its budget expires,
and tool-bound requests cannot hit the text-only response cache.

This does **not** add direct SIEM-indexer search, arbitrary EDR access, MTTR,
rule-volume analytics or response execution to chat. The existing deep
investigation already binds its own vendor tools. Contextual action buttons
already serialize the supplied entity into their prompt; those are separate
from chat, not additional missing-tool fixes.

## Verification

`test_copilot_live_reads.py` drives both FastAPI chat transports through real
model construction, tool binding, prompt privacy filtering and tool dispatch.
Only external HTTP responses and conversation persistence are fixtures. The
new reproduction fails against the old chat implementation because no record
is read, and passes after the repair. It also rejects browser-supplied fake
sources and verifies evidence metadata in the stored reply and stream header.

`test_copilot_read_boundaries.py` covers denial, redirects, invalid input,
transport failures, byte budgets, fixed pagination windows, risk ordering,
unsupported arguments, missing credentials and the tool-loop/cache boundaries.
`test_copilot_alert_filters_live.py` executes actual PostgreSQL queries through
FastAPI, with two tenants, old events and similarly named hosts. It runs in
the integration workflow with `MSSP_ISOLATION_REQUIRED=1`, not silently skipped.
`test_fusion_risk_failure_is_not_empty.py` preserves real empty responses and
real 404s while rejecting outage-shaped false negatives. Frontend tests pin
notice, truncation and uncited-claim rendering.

Scripted-model tests prove wiring and data boundaries, not model reasoning
quality. No live hosted-model inference or production SIEM/compute change is part of
this verification. Model providers must support the gateway's tool-call API.
