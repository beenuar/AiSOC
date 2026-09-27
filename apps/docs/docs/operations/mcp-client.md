---
id: mcp-client
title: Connecting third-party MCP servers
sidebar_label: MCP client
---

AiSOC's investigation agent can call tools on Model Context Protocol (MCP)
servers you register. This page covers what the client does, the defaults it
ships with and why they are what they are, how to register a server, and what
has and has not been verified against a real vendor.

## The short version

An MCP server is somebody else's code, reached over the network, whose replies
land in the prompt that decides what the agent does next. Four defaults follow
from that:

| Default | Behaviour |
|---|---|
| Transport | Streamable HTTP. stdio is refused unless you enable it **and** allowlist the command. |
| Tool allowlist | Empty. A newly registered server offers the agent nothing until you name tools. |
| State-changing tools | Refused. A tool annotated destructive, or declaring itself not read-only, is never offered to the model. |
| Results | Untrusted. Capped, fenced with a per-run nonce, scanned by the injection guard, and recorded in the Investigation Ledger. |

Nothing above is a configuration switch you can turn off from the console.

## Registering a server

Registration is two decisions, deliberately separated. Saving the row records
the address and the credential; enabling it is what lets an investigation
reach it.

```bash
curl -X POST https://your-aisoc/api/v1/mcp-servers \
  -H "Authorization: Bearer $AISOC_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
        "name": "vendor-edr",
        "label": "Vendor EDR MCP",
        "url": "https://mcp.vendor.example/mcp",
        "credential": {"Authorization": "Bearer <vendor token>"},
        "tool_allowlist": ["get_host", "get_detections"],
        "timeout_seconds": 20,
        "max_response_bytes": 65536,
        "enabled": true
      }'
```

`name` becomes part of the tool id the model sees, so it is lowercase letters,
digits, dash and underscore, two to forty characters. A tool discovered on
this server is offered to the agent as `mcp.vendor-edr.get_host`.

`credential` is a map of HTTP header names to values. It is encrypted with the
same credential vault connector secrets use, is never returned by the console
API (which reports `has_credential: true` and nothing more), and reaches the
agents service only over the internal service-token route. Nothing invents an
authentication scheme: if your vendor wants `X-Api-Key`, store that key.

`timeout_seconds` and `max_response_bytes` are the budget this server may
consume. Both have hard bounds in the schema, so no row can mean "unbounded".

Requires the `settings:write` permission, which the `tenant_admin` role holds.

### Listing and changing

- `GET /api/v1/mcp-servers` lists the tenant's servers with `has_credential`
  rather than the credential.
- `PATCH /api/v1/mcp-servers/{id}` updates any subset of fields. Sending
  `credential` re-encrypts it; omitting it leaves the stored one alone.
- `DELETE /api/v1/mcp-servers/{id}` removes the row.

## What the agent may call

A tool is offered to the model only when **both** of these hold:

1. You named it in `tool_allowlist`. That is your assertion.
2. The server did not annotate it as `destructiveHint: true` or
   `readOnlyHint: false`. That is the vendor's.

Either one saying no is a no, and they say different things. The allowlist is
what admits a tool the vendor did not annotate at all, because absent
annotations are not a claim to be read-only.

The allowlist is checked before anything opens a socket, and it is checked
twice: once at discovery, where a refused tool is simply never turned into a
tool the model can see, and again at dispatch, by the same function over the
same inputs.

### State-changing tools

A tool the server marks destructive is refused. AiSOC's position is that
changing state at a vendor is a live action with a declared capability
contract (impact, reversal, verification probe) graded by the approval matrix,
not something an MCP server can opt into by publishing a tool.

**No MCP tool has such a contract today**, so the current behaviour is
refusal, full stop. The refusal is recorded in the Investigation Ledger with
the reason, so an operator who allowlisted a tool and cannot find it in a run
gets an answer rather than silence.

## Results are untrusted

Every result is:

- **Capped** at `max_response_bytes`, counted on the socket so an oversized
  reply is cut mid-response rather than read into memory first, and capped
  again on the way into the prompt. A truncated result says so, in words the
  model reads, because a list it does not know was cut gets reasoned about as
  complete.
- **Fenced** inside the run's nonce envelope, the same containment triage
  uses, with the standing data-only system rule added to the investigation's
  system message. The nonce is unguessable when a payload is planted, so
  fenced text cannot forge its own closing marker.
- **Scanned** by the prompt-injection guard. The verdict travels with the
  result and into the ledger.

The guard is not a filter and is not what this rests on. It measures 0.852
against prose and 66.7% against payloads written to fit a constrained field,
so roughly a third of field-shaped payloads reach the model regardless. The
fence and the system rule are the controls; the guard is what makes a miss
visible afterwards.

### A malicious tool *description*

The server supplies each tool's description and input schema, and both are
rendered into the prompt that chooses which tool to call. That injection
arrives before any result does, and it is the quieter of the two.

AiSOC handles it structurally rather than by scanning alone:

- The name, title, description and every parameter description are scanned,
  and a high-severity hit **drops the tool entirely** rather than sanitising
  it. A description trying to instruct the model has no legitimate content to
  preserve.
- What survives is sanitised and capped at 400 characters, and is prefixed
  with a first-party marker naming the server, so the model is told whose
  words it is reading.
- The input schema is **projected**: an object, typed properties, a required
  list, and nothing else. `$ref`, `default`, `examples`, `additionalProperties`
  and any nesting beyond one level are dropped, so a server cannot put
  arbitrary JSON in front of the model by way of its schema.

The projection is the load-bearing half. It holds whatever the guard scores.

### Response size and the tool loop

The agent's tool loop applies its own cut to every tool result, at roughly
4,000 characters, before handing it to the model. A `max_response_bytes`
above about 3,500 will therefore be cut a second time by the loop, without the
partial-result note. Set the cap at or below that if you need the note to be
reliable; above it, treat the cap as a protection for the process rather than
a statement about what the model sees.

## Network and deployment policy

- **SSRF.** The server URL is validated immediately before the connection is
  opened: scheme, userinfo, and every address the hostname resolves to, with
  loopback, link-local, private, reserved and cloud-metadata targets refused.
  The registry also refuses an obviously unsafe URL when you save it, so you
  get an immediate answer, but that check does not resolve DNS: a name that
  resolved publicly at save time can resolve to link-local an hour later, so
  the enforcing check is the one at connect time.
- **Air-gap.** With `AISOC_AIRGAPPED` set, a server outside
  `AISOC_AIRGAP_ALLOWLIST` that is not an internal host or a private address
  is refused. Internal MCP servers keep working.
- **stdio.** Off. A stdio server is a local process the agents container would
  start, which is code execution rather than an HTTP request. Two switches
  turn it on:

  ```bash
  AISOC_MCP_STDIO_ENABLED=1
  AISOC_MCP_STDIO_ALLOWED_COMMANDS=/usr/local/bin/vendor-mcp
  ```

  The command is matched whole, not by prefix and not by basename, and an
  argument containing shell metacharacters is refused. Even then, this release
  does not start local processes for MCP servers: the policy admits the
  configuration and the client refuses it by name rather than silently falling
  back to HTTP. Treat stdio as unimplemented, not merely disabled.

## What ends up in the ledger

Every MCP interaction writes an Investigation Ledger event under the
`mcp_client` agent:

| Kind | Written when |
|---|---|
| `mcp_tools_discovered` | A server was listed. Carries the offered and bound counts. |
| `mcp_tool_call` | A tool ran. Carries argument *names*, response bytes, truncation, and the injection verdict. |
| `mcp_tool_refused` | A tool was refused, at discovery or at dispatch, with the classification. |
| `mcp_tool_failed` | A call failed or timed out. |
| `mcp_server_refused` | A server was refused before any connection. |
| `mcp_discovery_failed` | A server could not be listed. |

Argument values and result text are deliberately absent. A ledger row is an
audit record; copying a third party's reply into it would put untrusted
content somewhere with none of the containment applied.

An MCP call spends the vendor's compute and no AiSOC model tokens, so the row
carries no dollar figure at all. It records
`cost_provenance: not_applicable_no_model_call` instead, because a zero would
read as "free" rather than as "no model was called".

## Failures reach the model as "could not check"

A timeout, a refusal or an unreachable server returns a result saying the
lookup failed and telling the model not to conclude the activity did not
occur. It never returns an empty result, which reads as evidence of absence.

## Vendor servers

Several security vendors publish MCP servers. The ones operators are most
likely to already have are listed below with the configuration shape AiSOC
needs.

> **Unverified.** None of the entries below has been exercised against a live
> vendor server by this project. They describe how to point AiSOC at one, not
> a tested integration. The tool names in particular are examples: read the
> names from the vendor's own `tools/list` output and allowlist those. If you
> run one of these successfully, the tool names and any corrections are worth
> contributing back.

| Vendor server | Transport | Credential | Notes |
|---|---|---|---|
| CrowdStrike Falcon | Streamable HTTP | `Authorization: Bearer <OAuth2 token>` | Token is minted from a client id and secret; AiSOC stores the resulting header and does not perform the OAuth exchange. **Unverified.** |
| SentinelOne | Streamable HTTP | `Authorization: ApiToken <token>` | Scope the service-user token to read-only. **Unverified.** |
| Splunk | Streamable HTTP | `Authorization: Bearer <token>` | Search-only role recommended; AiSOC's own federated search remains the supported path for SPL. **Unverified.** |
| Microsoft Sentinel | Streamable HTTP | `Authorization: Bearer <Entra token>` | Entra tokens are short-lived, so expect to rotate the stored credential. **Unverified.** |
| Google Security Operations | Streamable HTTP | `Authorization: Bearer <token>` | **Unverified.** |

Because the allowlist starts empty, the safe way to bring one up is: register
the server enabled with an empty allowlist, read the discovery refusals out of
the ledger to learn the tool names the server actually publishes, then
allowlist the read tools you want.

## Environment reference

| Variable | Default | Meaning |
|---|---|---|
| `AISOC_AGENTS_SERVICE_TOKEN` | unset | Shared secret the agents service presents to read the registry. Unset means no MCP tool is offered, and the agents service says so at `warning`. |
| `AISOC_API_URL` | `http://api:8000` | Where the agents service reaches the API. |
| `AISOC_MCP_REGISTRY_TIMEOUT_S` | `5` | How long the agent waits for the registry. |
| `AISOC_MCP_STDIO_ENABLED` | unset | First of the two switches for stdio transports. |
| `AISOC_MCP_STDIO_ALLOWED_COMMANDS` | unset | Comma-separated commands, matched whole. |
| `AISOC_AIRGAPPED` | unset | Refuses external MCP servers when set. |
| `AISOC_AIRGAP_ALLOWLIST` | unset | Hosts that stay reachable in air-gap mode. |

## Related

- [Credentials and the vault](./credentials.md)
- [Air-gapped deployment](./airgap.md)
- [Action approvals](./action-approvals.md)
