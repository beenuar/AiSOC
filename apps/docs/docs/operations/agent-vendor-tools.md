---
id: agent-vendor-tools
title: Letting the agent reach your own tools
sidebar_label: Agent vendor tools
---

The investigation agent used to read one thing: AiSOC's own event lake.
Anything your estate held and AiSOC never ingested was invisible to it, and on
the default `core` profile there is no lake at all, so the agent had no
evidence source.

It can now search your SIEM platforms and read your EDR, identity provider and
cloud audit trail. This page covers what it can reach, what it deliberately
cannot do, and how to tell a failed lookup from a clean result, which is the
distinction that matters most on this surface.

## What the agent can reach

| Tool | Reaches | Needs |
|---|---|---|
| `siem_indicator_search` | Every federated-capable SIEM you have connected, in one call | A Splunk, Microsoft Sentinel, Elastic or IBM QRadar connector |
| `edr_host_details` | A host's record in your EDR: platform, agent version, last seen, containment state | CrowdStrike Falcon, Microsoft Defender or SentinelOne |
| `edr_host_detections` | Detections your EDR already raised on a host, including closed ones | The same |
| `identity_user_activity` | Recent sign-ins with their source addresses and outcomes, plus the provider's own risk assessment | Okta, Microsoft Entra ID or Google Workspace |
| `cloud_audit_lookup` | A principal's control-plane activity, and which calls were denied | AWS credentials with `cloudtrail:LookupEvents` |
| `endpoint_telemetry_sightings` | Sightings of one indicator in endpoint telemetry, through your EDR's hunting index | Microsoft Defender |

There is one tool per capability rather than one per vendor. `edr_host_details`
means "ask whichever EDR this deployment has", and AiSOC resolves the vendor
from your connectors. A model choosing between a CrowdStrike tool and a
SentinelOne tool would be choosing on information it does not have.

## The model never writes a query

This is the constraint the whole surface is built around, and it is a security
boundary rather than a preference.

An indicator an agent passes was lifted out of a process command line, a file
name, an email subject or a ticket body. All of those are attacker-influenced.
A model relaying one into SPL, KQL or ES|QL would be one injected instruction
away from running an arbitrary query against your SIEM, and a read is not
harmless at that scale: a query can return an estate's worth of telemetry, and
an unbounded one costs real money on a metered licence.

So no tool accepts a query, a field name or free text. `siem_indicator_search`
takes a **kind** of indicator from a closed list (`ip`, `domain`, `url`,
`sha256`, `sha1`, `md5`, `hostname`, `username`, `process_name`), a value and a
window. AiSOC resolves the field per backend, from each vendor's own normalized
schema: Splunk CIM, Sentinel ASIM, Elastic Common Schema and QRadar's AQL
columns.

What it refuses, and why each refusal is specific:

- **A type outside the list.** There is no default. A default would answer a
  question nobody asked, and the answer would look like evidence.
- **A value that is not the shape it claims.** A "sha256" that is not 64
  hexadecimal characters is not a hash. Searching for it costs a round trip
  and returns a confident empty result.
- **Free text, in any form.** Free text is the one input that lands in a
  backend's default search as a bare term, and there is no shape to validate
  it against, so it cannot be told apart from query syntax.

`endpoint_telemetry_sightings` is the same idea where the underlying product
genuinely takes a query language. Defender advanced hunting takes KQL, so the
KQL lives in AiSOC as four named templates (`file_hash_sightings`,
`process_sightings`, `network_sightings`, `logon_sightings`) and the agent
supplies a template name and an indicator. An unknown template name is refused
before your credentials are even read.

## A failed read is never an empty result

An empty result reads as evidence of absence, and a model will reason on it as
though the host were clean. So every failure path returns an explicit
"could not check", with wording that says the lookup did not happen:

> This is a lookup failure, not a clean result: `get_host for WS-42` was NOT
> checked. Do not treat this as evidence that the activity did not occur.
> Record it as a gap in visibility and say so in your conclusion.

Three outcomes are kept apart all the way to the agent's conclusion:

- **`ok` with rows.** Sightings.
- **`ok` with no rows.** Genuine evidence of absence, **for the sources that
  answered and for that window only**. The tool says so explicitly, including
  that it says nothing about sources you have not connected.
- **`could_not_check`.** Nothing was looked at. Never an absence.

A partly-failed search is its own outcome rather than being rounded to a clean
one: zero rows from two SIEMs while a third errored is a different finding
from zero rows across all three, and the tool names which sources were not
searched.

Two vendor-specific cases follow the same rule:

- **Entra ID Protection is licensed.** Its risk record may be unavailable
  without the sign-in read failing, and its absence reads as unknown rather
  than as "no risk detected".
- **Google Workspace's login audit needs a third scope.** A 403 names
  `admin.reports.audit.readonly` rather than reporting an account with no
  logins.

## Only what you have connected is offered

Before each investigation the agent asks AiSOC which of your tools are
configured, and binds only those. A tenant with a Splunk and an Okta gets the
SIEM tool and the identity tool, and no EDR tools.

What is *not* connected goes into the prompt as prose, so the agent records a
gap rather than quietly investigating with less:

> The customer has no EDR, identity provider or cloud audit connector that
> AiSOC can read, so this investigation could not consult any vendor directly.

If AiSOC cannot determine what you have connected, it binds **no** tools and
says that too. Binding everything would offer tools that answer "no
integration"; binding nothing silently would let the agent conclude without
noticing that whole classes of evidence were never consulted.

## Vendor output is treated as untrusted

Every payload the agent receives from one of your products carries an explicit
notice that it is data and not instructions. Rows are also projected down to
the fields that carry signal and capped in both row count and serialized size.
That bounds token cost, and it bounds how much attacker-chosen text reaches the
prompt: a SIEM row can carry a whole command line, and a CrowdStrike device
record has around ninety fields.

When a result is capped the agent is told, so a truncated answer is legible as
truncated rather than as the whole picture.

## What is read-only, and how that is kept true

Only capabilities the action contract grades `READ_ONLY` are reachable this
way, and that is checked twice by two independent controls:

1. a closed allowlist in the API, so a verb cannot become agent-reachable as a
   side effect of being added to the contract file;
2. a live check against the action registry before each dispatch, so a verb
   whose classification changes stops flowing even if the allowlist is stale.

If the registry cannot be reached, the read is **refused**. Refusing a read is
inconvenient; allowing a containment through the investigation door is not.

`scripts/check_agent_read_tools.py` enforces all of it in CI, in both
directions, and `scripts/check_investigation_depth.py` asserts every tool is
reachable from an investigation strategy and that the binding is still wired
into the production path.

Anything that changes your estate still goes through the
[approval path](./action-approvals.md). There is no tool here that an agent can
call to isolate a host.

## Setting it up

1. Connect the products you want the agent to reach, in **Settings ->
   Connectors**. Credentials are encrypted with the
   [credential vault](./credentials.md).
2. Give AiSOC's agent service an API key so it can authenticate to the API.
   Set `AISOC_AGENTS_API_KEY` on the `agents` service. **The tenant comes from
   that credential**, never from a request field, which is what stops an
   injected instruction redirecting a read at another tenant's estate.
3. `connectors` and `actions` both run in the default `core` profile
   ([ADR-0007](https://github.com/beenuar/AiSOC/blob/main/docs/decisions/0007-connectors-and-actions-in-core.md)),
   so no profile change is needed.

Every model call and every tool call is written to the Investigation Ledger,
so an audit can replay which host was read, with which arguments, in which
order.

## Unverified against live vendors

Each vendor read is built against that vendor's published API and tested
against recorded, vendor-shaped payloads on the real HTTP path. **None has
been exercised against a live vendor account from this repository**, because
there is no funded CrowdStrike, SentinelOne, Entra, Google Workspace, Defender
or AWS tenancy here. The AWS CloudTrail signer is the one worth calling out
specifically: SigV4 is implemented from its specification and pinned by tests
against the documented canonical form, and no signature has ever been offered
to AWS itself.

Treat each as unverified until you have run it in your own environment, and
please open an issue if a wire shape has moved.
