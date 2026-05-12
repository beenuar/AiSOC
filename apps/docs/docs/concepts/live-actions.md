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

Plugin authors implement [`LiveActionExecutor`](https://github.com/aisoc-platform/aisoc/blob/main/services/actions/app/live_actions/executor.py)
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
  without waiting for a core release.

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
