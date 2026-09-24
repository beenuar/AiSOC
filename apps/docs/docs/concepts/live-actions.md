---
sidebar_position: 5
title: Live Actions
description: Generic, vendor-agnostic action interface that lets agents and playbooks execute response capabilities (isolate host, block IP, disable user) against any registered vendor.
---

# Live Actions

The **live action interface** is AiSOC's generic action substrate. Where the
older Action Execution API was organised around `ActionType` enums and
auto-selected the vendor at call time based on which credentials happened
to be in scope, the live action interface inverts that contract:

- **Capability is a free-form string** (`isolate_host`, `block_ip`,
  `disable_user`, ...) drawn from the [capability taxonomy](./capabilities).
- **Vendor is explicit** (`crowdstrike`, `defender`, `okta`,
  `aws_security_groups`, ...) so the planner — agent, playbook, or human —
  always knows which back-end will run.
- **Executors are pluggable**. In-tree adapters wrap the existing executors
  for the canonical vendors. Plugins register their own
  `LiveActionExecutor` against a `(vendor_id, capability)` pair and instantly
  appear in discovery, dispatch, and the dry-run sandbox.

The result is one entry point — `POST /api/v1/live-actions/dispatch` — that
the agent layer can plan against without learning the legacy `ActionType`
enum or guessing which vendor a credential belongs to.

---

## When to use live actions vs the legacy Action API

| You want to... | Use |
|---|---|
| Have an LLM agent pick a vendor based on a capability | **Live actions** |
| Add a custom integration via a plugin | **Live actions** |
| Show a "preview before executing" experience to a human | **Live actions** (dry-run) |
| Continue using existing playbooks with `action_type: ISOLATE_HOST` | **Legacy `/api/v1/actions`** |
| Execute with rollback / approvals / audit-chain enforcement today | **Legacy `/api/v1/actions`** (live actions inherits this in v1.1) |

The two APIs coexist. Live actions delegate to the same legacy executors
under the hood, so behaviour (simulation mode, parameter validation,
vendor-side calls) is identical. The choice is just about which planning
model fits the caller.

---

## Concepts

### LiveActionRequest

```jsonc
{
  "request_id": "0f2a…",         // optional, server generates if absent
  "capability": "isolate_host",  // required, free-form string
  "vendor_id": "crowdstrike",    // required, picks the executor
  "target": "host-77",           // required, capability-specific shape
  "params": {                     // optional, vendor-specific creds + options
    "cs_client_id": "...",
    "cs_client_secret": "...",
    "cs_base_url": "https://api.crowdstrike.com"
  },
  "case_id": "…",                // optional, links result to a case
  "tenant_id": "…",              // optional, tenant scope
  "requested_by": "alice@org",   // optional, audit trail
  "dry_run": false                // optional, defaults to false
}
```

`target` is intentionally a free-form string so each capability decides its
own shape: a hostname for `isolate_host`, a CIDR for `block_ip`, a username
for `disable_user`. Vendor-specific options go in `params`.

### LiveActionResult

Every dispatch returns a `LiveActionResult` regardless of outcome. Unknown
vendors, executor exceptions, and credentialless simulation all map to a
structured result so REST handlers, the agent loop, and the audit log have
a single contract:

```jsonc
{
  "request_id": "0f2a…",
  "status": "succeeded",         // succeeded | simulated | failed
  "capability": "isolate_host",
  "vendor_id": "crowdstrike",
  "summary": "Isolate host-77",
  "details": { "agent_id": "…", "containment_id": "…" },
  "error": null,                 // structured error code if status=failed
  "completed_at": "2026-05-12T18:30:00Z"
}
```

The three statuses have explicit meanings:

- **`succeeded`** — the executor talked to the real vendor and the action
  took effect.
- **`simulated`** — the executor fell into its simulation branch, usually
  because credentials were absent or `dry_run=true` stripped them. **No
  vendor was contacted.**
- **`failed`** — the executor returned a failure or threw. The `error`
  field carries a structured code (`executor_not_found`, the exception
  class name, ...) so the agent loop can decide whether to fall back to a
  different vendor.

### Discovery

The discovery endpoint is what the agent's planning prompt sees. It lists
every registered `(vendor_id, capability)` pair with a one-line description
and a `requires_credentials` hint:

```bash
GET /api/v1/live-actions
GET /api/v1/live-actions?capability=isolate_host
GET /api/v1/live-actions?vendor_id=crowdstrike
GET /api/v1/live-actions/by-capability/isolate_host
GET /api/v1/live-actions/by-vendor/crowdstrike
```

Each entry also reports its `source` (`builtin` for shipped adapters,
`plugin` for executors registered by a plugin), which the marketplace UI
uses to render provenance badges.

---

## Built-in adapters

The 19 adapters that ship out of the box wrap the existing executors for:

| Vendor | Capabilities |
|---|---|
| **CrowdStrike** | `isolate_host`, `quarantine_file`, `kill_process`, `run_script` |
| **Microsoft Defender** | `isolate_host`, `run_av_scan`, `block_ioc` |
| **Okta** | `disable_user`, `reset_password`, `suspend_session`, `force_mfa` |
| **AWS Security Groups** | `block_ip`, `allow_ip` |
| **Generic** | `block_domain` (placeholder pending Route53/Umbrella integration) |
| **Splunk** | `search_siem`, `create_notable_event`, `sync_detection_rule` |
| **Elastic** | `search_siem`, `update_watcher` |

These are registered automatically at `services/actions` startup. Every
adapter inherits the legacy executor's simulation branch — calling
`isolate_host` against `crowdstrike` without `cs_client_id` returns
`status="simulated"`, never `"succeeded"`.

---

## Dry-run

```bash
POST /api/v1/live-actions/dry-run
```

The dry-run endpoint forces `dry_run=true` regardless of the request body
and short-circuits the executor's credential path: even if real credentials
are present, the adapter strips them before delegating, guaranteeing the
back-end vendor is never contacted. The returned result will always have
`status="simulated"` for adapters that wrap the legacy executors.

The same effect is available on the main dispatch endpoint by setting
`dry_run: true` in the request body, but the dedicated `/dry-run` endpoint
makes it easier to wire up "Preview action" buttons in UIs that should
*never* be allowed to execute live.

---

## Writing a plugin executor

Plugin authors implement [`LiveActionExecutor`](https://github.com/beenuar/AiSOC/blob/main/services/actions/app/live_actions/executor.py)
and call `register_executor()` from their plugin's `setup()` hook:

```python
from app.live_actions import (
    LiveActionExecutor,
    LiveActionRequest,
    LiveActionResult,
    LiveActionStatus,
    register_executor,
)


class TanIumIsolate(LiveActionExecutor):
    vendor_id = "tanium"
    capability = "isolate_host"
    description = "Isolate a host on Tanium Threat Response."
    requires_credentials = True

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        # ... call Tanium's API ...
        return LiveActionResult(
            request_id=request.request_id,
            status=LiveActionStatus.SUCCEEDED,
            capability=self.capability,
            vendor_id=self.vendor_id,
            summary=f"Isolated {request.target} on Tanium",
            details={"tanium_action_id": "..."},
        )


def setup() -> None:
    register_executor(TanIumIsolate(), source="plugin")
```

Once registered, the new `(tanium, isolate_host)` pair shows up in
`/api/v1/live-actions` discovery, can be dispatched, and is automatically
included in the agent's planning catalogue. No core changes required.

### Contract guarantees

- **Unknown `(vendor_id, capability)` returns 200 with `status="failed"`**,
  not 500. This lets the agent loop fall back to another vendor without
  treating a missing executor as an exceptional condition.
- **Executor exceptions are caught and converted to `failed`.** A buggy
  plugin cannot crash the actions service.
- **Result fields are patched.** If an executor returns a result whose
  `vendor_id`, `capability`, or `request_id` doesn't match the request,
  the dispatcher overwrites them so audit logs and UIs can always trust
  these fields.
- **Soft capability validation.** Capabilities outside the canonical
  enum are accepted (with a warning) so plugins can ship novel verbs
  without waiting for a core release. That leniency is for *plugins*.
  In-tree executors are held to the vocabulary by the reachability gate
  below, because a warning in a startup log is not a control.

---

## Reachability

Five registries have to agree before a verb can be recommended and then
dispatched under governance:

| Registry | What it supplies |
| --- | --- |
| `EXECUTOR_REGISTRY` | The vendor call itself, keyed by `ActionType` |
| `_BUILTIN_ADAPTERS` | The `(vendor_id, capability)` pair the dispatcher looks up |
| `CAPABILITY_CONTRACTS` | Impact, reversibility, verification, approval tier |
| `KNOWN_CAPABILITIES` | The vocabulary everything validates against |
| `ProposedAction(action_type=...)` | What the agent puts in front of an analyst |

A verb can be complete in four of the five and unreachable, and nothing in
the failure message says which one is missing. `ack_alert` and
`suppress_alert` were exactly that for several releases: real executors with
Splunk, Elastic and Defender arms, wired into `EXECUTOR_REGISTRY`, and absent
from the other four. Governed dispatch answered `executor_not_found` for code
that worked, which reads as a misconfigured integration rather than a
capability nobody connected.

`scripts/check_action_contract.py` now compares all five, **in both
directions**, on every pull request. Both directions is the part that matters.
The characteristic failure of a drift check is that it compares A against B
and never B against A, so drift in the direction things actually change passes
while the check prints OK — this repository's graph-schema check did precisely
that, reporting OK with 17 node labels declared in YAML and 28 implemented in
Go, because it only ever looked for labels the YAML had and the code lacked.

The gate reports:

- an executor whose capability is absent from the vocabulary, or from the
  contracts, or which never registers;
- a capability with a contract and no executor behind it;
- a legacy `ActionType` executor that no adapter reaches, so it bypasses the
  contract, the approval matrix and the autonomy policy;
- an adapter pointing at an `ActionType` with no executor, which would fail at
  execution rather than at registration;
- an `ActionType` with no executor at all;
- a verb the agent proposes by name that no executor implements;
- an `ActionType` that resolves no capability contract, so the approval
  matrix is skipped for it and blast radius decides alone;
- an alias in `ACTION_TYPE_CAPABILITY_ALIASES` that points at a capability
  with no contract, keys an `ActionType` that does not exist, shadows a real
  capability of the same name, or claims two names are one verb when no
  adapter pairs them.

That last one is the check that spans two services, and it is the one that
mattered most. `investigation_agent` proposes `capture_forensics` whenever an
investigation reaches the C2 or exfiltration stage, with
`requires_approval=True`. No executor implemented it, so on the most serious
class of incident the product recommended evidence acquisition, raised an
approval for it, and answered `No executor found for action type` when
somebody approved — a control reachable from a recommendation and dead on
approval. The other checks compare the actions service against itself; this
one compares it against the thing that puts a verb in front of a person.

**Both exemption lists are empty.** They are ratchets: an entry that gains an
implementation and is not removed fails the build, because a baseline nobody
prunes is a gate that quietly stops checking. Emptying them meant making a
decision per verb rather than recording one:

| Verb | Outcome |
| --- | --- |
| `capture_forensics` | Implemented — a Defender investigation-package arm with a probe that reads the package back |
| `chatops_verify` | Implemented — needed `LiveActionStatus.AWAITING_COMPLETION` before it could report honestly |
| `add_ioc_to_blocklist` | Removed — a second name for `block_ioc`, which is fully wired |
| `run_playbook` | Removed — playbook execution belongs to `services/agents`, and "run an arbitrary bundle of verbs" has no verb-level contract |

The rule the last two follow: a verb with no implementation path should leave
the `ActionType` surface rather than sit on it dead. The API accepts any
member of the enum, so a member with nothing behind it is a request that is
accepted and then fails with a message that reads like a broken deployment.

### The one alias, and when it goes

`notify_slack` was the last `ActionType` with no capability contract, and it
was never a missing capability: the verb is `notify`, it has had a contract
throughout, and the `SlackNotify` adapter already bridges the two names. What
was missing was anything connecting a lookup *by `ActionType` value* to that
bridge — so `approval_gate` found no contract, skipped the confidence matrix,
and the verb most likely to auto-execute was the one verb graded without
reference to confidence. A 10%-confidence `notify_slack` was approved for
auto-execution; it now needs an analyst under the default tier.

It is closed with an alias rather than a rename. `action_type` is persisted
operator intent: `remediation_whitelist` (migration 015) stores per-tenant
pre-approvals keyed `UNIQUE (tenant_id, action_type)`, so renaming the member
silently orphans every row an operator created for `notify_slack` — their
pre-approval stops matching and nobody is told. It is also a documented
request field and a member of the `ActionType` union in `packages/types`.

A permanent alias nothing ever retires is debt, so the retirement condition
is stated: this map goes when `ActionType` does. The enum is already the
legacy half of the registry — every adapter carries a `_legacy_action_type`
pointing back at it, and governed dispatch works in capability strings. When
`POST /actions` takes a capability and the `remediation_whitelist` rows have
been migrated, the map and the enum go together. Until then a new entry needs
the same justification: a *naming* difference for a verb that already has a
contract, never a stand-in for a capability nobody wrote. The gate enforces
each of those conditions rather than trusting the note.

### Actions that are not finished when they return

Most executors are synchronous: the vendor call returns and the action is
over. Two are not, and both report `AWAITING_COMPLETION`:

- `chatops_verify` delivers a prompt and waits for a person to click.
- `capture_forensics` queues an MDE machine action that completes minutes
  later, or fails.

`AWAITING_COMPLETION` means the vendor was touched and the outcome is not yet
known. It is the opposite of `PENDING_APPROVAL`, which means nothing ran
because policy wants a human first. Post-action verification deliberately does
not run against it — there is no effect to read back yet.

Both executors were unreachable through governed dispatch until this state
existed, and leaving them that way was the right call at the time: the status
translation folded everything that was not `FAILED` or a simulation into
`SUCCEEDED`, so registering them would have reported an unanswered question
and an uncollected evidence package as completed actions.

---

## Roadmap

The live-action layer is intentionally minimal in v1.0. Planned extensions:

- **Approval gating.** Hook into the existing approval workflow used by
  the legacy Action API.
- **Rollback.** Expose a `rollback()` method on `LiveActionExecutor` so
  plugins can undo their own actions.
- **Per-tenant vendor pinning.** Let an org say "for `isolate_host`,
  always prefer Defender over CrowdStrike" without having to specify
  it on every request.
- **Cost + quota metering.** Tag each dispatch with the vendor's
  per-call cost so the operator dashboard can include vendor-side spend
  in the same view.
