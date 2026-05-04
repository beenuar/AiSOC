# AiSOC Playbooks

This directory contains AiSOC response playbooks. A playbook is a JSON
document that wires alerts and cases to a deterministic, auditable sequence
of agent + automation steps with explicit human-approval gates and
rollback paths.

## Layout

```
playbooks/
└── packs/
    └── v1/                       # Canonical, versioned production pack (50 playbooks)
        ├── account-takeover/     # 5  — ATO, MFA fatigue, session theft, OAuth abuse
        ├── ransomware/           # 5  — host isolate, shadow-copy, fileserver, C2, exposure
        ├── bec/                  # 5  — inbox rules, payment redirect, impersonation, token theft
        ├── insider-risk/         # 5  — mass download, exit-risk, privilege misuse, src-exfil
        ├── cloud-misconfig/      # 10 — S3, IAM, key-leak, root MFA, CloudTrail, SG, RDS, GKE, Azure, x-account
        ├── data-exfil/           # 5  — large upload, archive, DNS tunnel, personal cloud, USB
        ├── lateral-movement/     # 5  — PsExec, RDP, kerberoast, PTH, cross-domain
        ├── supply-chain/         # 5  — npm, PyPI, GH Action, vendor breach, IaC drift
        └── ddos/                 # 5  — L3/L4, L7, DNS amp, SYN flood, auth-endpoint
```

The runtime (`services/agents/app/playbook/store.py`) loads `packs/v1/**`
on startup and merges with user-defined playbooks in
`services/agents/data/playbooks/index.json`. **User playbooks always win
over pack playbooks of the same ID** — the pack is the seed, not a
hard-coded floor.

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

| Type            | Purpose                                                |
| --------------- | ------------------------------------------------------ |
| `enrich`        | Call enrichment service for an indicator               |
| `investigate`   | Hand off to the AI investigator agent                  |
| `notify`        | Slack / email / PagerDuty / webhook                    |
| `block_ip`      | Edge or firewall IP block                              |
| `isolate_host`  | EDR host isolation                                     |
| `create_ticket` | Open a ticket in the SOC / HR / procurement queue      |
| `close_case`    | Auto-close (typically gated on `verdict`)              |
| `http`          | Generic outbound HTTP for any custom integration       |
| `condition`     | Branching gate; reads `field op value` from run context |

### Human-approval gates

Approval gates are modelled as `condition` steps that read a flag from
run context (e.g. `context.approved_by_oncall`). The flag is expected to
be set by an out-of-band approval system — Slack interactive button,
email link, or the AiSOC web console — before the gated step runs.

```json
{
  "id": "approve",
  "name": "Wait for human approval",
  "type": "condition",
  "params": {},
  "condition": {
    "field": "context.approved_by_oncall",
    "operator": "eq",
    "value": true
  },
  "next_true": "reset",
  "on_failure": "abort",
  "retry_max": 0,
  "timeout_seconds": 5
}
```

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

That means: forking a pack playbook is a one-line operation. Save your
edited copy under the same `id` via the API and the runtime serves your
version forever — no need to fork the repo.

## Versioning

The `v1/` segment in `packs/v1/` is the pack version. Breaking changes
to the schema or runtime semantics will land as a sibling `packs/v2/`
tree, so existing deployments can pin against `v1/`. Individual playbook
IDs carry their own `-v1` suffix for the same reason; the runtime treats
`ato-mfa-fatigue-response-v1` and `ato-mfa-fatigue-response-v2` as
distinct, side-by-side playbooks.
