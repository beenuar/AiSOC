# AiSOC Playbooks

This directory contains AiSOC response playbooks. A playbook is a JSON
document that wires alerts and cases to a deterministic, auditable sequence
of agent + automation steps with explicit human-approval gates and
rollback paths.

## Layout

```
playbooks/
└── packs/                        # Canonical, versioned production pack: 62 playbooks
    └── v1/                       #   across 21 directories — the figure
                                  #   marketplace/index.json publishes
        ├── account-takeover/     # ATO, MFA fatigue, session theft, OAuth abuse
        ├── ransomware/           # host isolate, shadow-copy, fileserver, C2, exposure
        ├── bec/                  # inbox rules, payment redirect, impersonation, token theft
        ├── cloud-misconfig/      # S3, IAM, key-leak, root MFA, CloudTrail, SG, RDS, GKE, Azure
        ├── …                     # 17 more: phishing, malware, privilege-escalation,
        └── ddos/                 #   container-escape, brute-force, web-compromise, …
```

`ls playbooks/packs/v1` is the list; the four above are a sample, not the
whole tree. Counts per directory are not published here because they move
with the generator and nothing would hold them true.

The runtime (`services/agents/app/playbook/store.py`) loads `packs/v1/**`
on startup and merges with user-defined playbooks in
`services/agents/data/playbooks/index.json`. User playbooks win over pack
playbooks of the same ID; the pack is the seed, not a hard-coded floor.

## Playbook format

Each file is a `*.playbook.json` document validated against the Pydantic
[`Playbook`](../services/agents/app/playbook/models.py) model.

```json
{
  "id": "ato-impossible-travel-block-v1",
  "name": "ATO: Impossible Travel — Block & Reset",
  "description": "...",
  "version": "1.0.0",
  "tags": ["account-takeover", "ato", "identity", "mitre.t1078"],
  "trigger": {
    "on": "alert",
    "severity": ["high", "critical"],
    "tags": ["account-takeover"]
  },
  "author": "AiSOC",
  "enabled": true,
  "created_at": "2026-05-03T00:00:00+00:00",
  "updated_at": "2026-05-03T00:00:00+00:00",
  "steps": [
    {
      "id": "e1",
      "name": "Geo-enrich source IP",
      "type": "enrich",
      "params": { "indicator_field": "alert.source_ip" },
      "on_failure": "continue",
      "retry_max": 0,
      "timeout_seconds": 30
    }
  ]
}
```

### Supported step types

All twenty-five members of `StepType` in
[`models.py`](../services/agents/app/playbook/models.py), which is the only
place this vocabulary is defined. This table listed nine of them for a long
time, which is how the approval pattern below came to be documented wrongly.

| Type | Purpose |
| --- | --- |
| `enrich` | Call the enrichment service for an indicator |
| `investigate` | Hand off to the AI investigator agent |
| `notify` | Slack / Teams / email / PagerDuty / signed webhook. A governed verb |
| `http` | Outbound HTTP to a **named** tenant integration, through the SSRF guard |
| `condition` | Branching gate; reads `field op value` from run context |
| `wait` | Hold for a timer or a callback. Short timers sleep in place; longer ones become a durable pause |
| `parallel` | Run child steps concurrently, then join |
| `loop` | Run child steps once per item, bounded |
| `approval` | Suspend the run until an analyst decides. Durable — see below |
| `block_ip` | Edge or firewall IP block |
| `block_ioc` | Block an IOC (hash, domain, IP) |
| `isolate_host` | EDR host isolation |
| `kill_process` | Terminate a process on an endpoint |
| `quarantine_file` | Quarantine a file on an endpoint |
| `run_av_scan` | Trigger an on-demand AV scan |
| `run_script` | Run a vendor-side response script |
| `osquery_live_query` | Distributed osquery via osctrl / FleetDM / `aisoc-direct`. A governed verb |
| `disable_user` | Disable an identity |
| `reset_password` | Force a password reset |
| `revoke_session` | Revoke active sessions |
| `force_mfa` | Force re-authentication with a second factor |
| `search_siem` | Run a query against a connected SIEM |
| `create_notable_event` | Write a notable / incident back to the SIEM |
| `create_ticket` | Open a ticket in the SOC / HR / procurement queue |
| `close_case` | Auto-close (typically gated on `verdict`) |

Every verb that touches somebody's estate is graded against its own
capability contract at dispatch, and previews rather than acts unless
`AISOC_PLAYBOOK_ACTIONS_EXECUTE` is set. See
[Playbooks](../apps/docs/docs/concepts/playbooks.md) for the full
`status` / `executed` table.

### Human-approval gates

Use an `approval` step. The run suspends to Postgres, survives a restart of
the agents service, resumes at the step after the approval once it is
decided, and expires with a recorded outcome rather than hanging.

```json
{
  "id": "approve",
  "name": "Approve credential reset",
  "type": "approval",
  "params": { "prompt": "Reset this account's password?" },
  "on_failure": "abort"
}
```

**Do not model a gate as a `condition` step reading a flag somebody sets out
of band.** This file used to document exactly that, and it never worked: the
engine evaluates each condition once against the run context and moves on, so
the "wait" was a single false evaluation, and no endpoint ever existed to flip
the flag. A playbook written that way ran straight through its gate into
whatever it was gating.

### Rollback

Rollback is modelled by pairing every containment action with a
`condition` step gated on `verdict == false_positive` plus a matching
reverse-action step. The pattern is intentionally explicit so the
reviewer can see exactly what will be undone.

## Adding or editing playbooks

The pack is generated from a single source of truth:
[`scripts/generate_playbooks.py`](../scripts/generate_playbooks.py).

```bash
# Regenerate playbooks/packs/v1/ from spec
python3 scripts/generate_playbooks.py

# Validate the pack (schema + step graph + uniqueness)
python3 scripts/validate_playbooks.py
```

CI runs both on every PR (`.github/workflows/validate-playbooks.yml`)
and fails if the committed tree drifts from the generator output.

If you need a new playbook:
1. Add a new builder function (or extend an existing category builder)
   in `scripts/generate_playbooks.py`.
2. Run `python3 scripts/generate_playbooks.py`.
3. Run `python3 scripts/validate_playbooks.py`.
4. Commit the script change *and* the regenerated JSON together.

## Loading order

`PlaybookStore._load()` resolves IDs in this order — last writer wins:

1. Per-runtime fixture files in
   `services/agents/data/playbooks/*.playbook.json` (legacy + dev-only).
2. Canonical pack tree at `playbooks/packs/v1/**/*.playbook.json` (this
   directory).
3. The mutable `services/agents/data/playbooks/index.json` (any
   user-defined or API-created playbooks).

Forking a pack playbook is therefore a one-line operation: save your
edited copy under the same `id` via the API and the runtime serves that
version. No repo fork required.

## Versioning

The `v1/` segment in `packs/v1/` is the pack version. Breaking changes
to the schema or runtime semantics will land as a sibling `packs/v2/`
tree, so existing deployments can pin against `v1/`. Individual playbook
IDs carry their own `-v1` suffix for the same reason; the runtime treats
`ato-mfa-fatigue-response-v1` and `ato-mfa-fatigue-response-v2` as
distinct, side-by-side playbooks.
