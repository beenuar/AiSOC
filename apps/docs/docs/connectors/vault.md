---
sidebar_position: 83
title: HashiCorp Vault
description: Stream HashiCorp Vault audit-device events (secrets ops, policy changes, token issuance) into AiSOC.
---

# HashiCorp Vault

The Vault connector pulls **audit-device events** from HashiCorp Vault — every secret read, write, lease renewal, policy change, and token issuance. It surfaces the control-plane activity that almost no other source captures, so privilege-elevating actions (root tokens, broad policies, auth-method enrolment) land in AiSOC alongside the rest of the identity-plane signal.

> Vault deliberately **does not expose audit events through its HTTP API**. Audit data flows out of the cluster via Vault's audit devices (`file`, `socket`, `syslog`). This connector consumes the AiSOC ingest buffer that the recommended sidecar topology writes to.

## What you get

| Event class | Examples |
|---|---|
| **Secret reads/writes** | `kv/data/database/prod` read, secret rotated |
| **Lease operations** | Token issued, lease renewed, lease revoked |
| **Auth method changes** | New auth method mounted, role added, identity entity edited |
| **Policy changes** | `policy/write`, `policy/delete` on named policies |
| **Token operations** | Root token issued, periodic token renewed, accessor lookup |
| **Audit device changes** | `sys/audit` mount edits — **critical**: an attacker disabling the audit device hides their own tracks |

Events are normalized with `source: vault`, `category: identity`.

## Deployment topologies

### Topology A — Sidecar tail (recommended)

```
┌───────────────┐    JSONL    ┌────────────────────────┐
│ Vault server  ├──────────► │ aisoc-vault-sidecar    │
│ file audit    │            │ (tails the audit file) │
└───────────────┘            └─────────────┬──────────┘
                                           │ POST JSON line
                                           ▼
                              ┌────────────────────────┐
                              │ connectors service     │
                              │ POST /v1/_/audit_ingest│
                              └─────────────┬──────────┘
                                            │ in-memory buffer
                                            ▼
                              ┌────────────────────────┐
                              │ Vault connector poll   │
                              │ drains buffer → AiSOC  │
                              └────────────────────────┘
```

Add a `file` audit device on the Vault server:

```bash
vault audit enable file file_path=/var/log/vault/audit.log
```

Then run the AiSOC Vault sidecar (image at `ghcr.io/beenuar/aisoc-vault-sidecar`) with read access to `/var/log/vault/audit.log` and the AiSOC connectors service URL in `AISOC_CONNECTORS_URL`. The sidecar `tail -F`s the file and posts each JSON line to `POST /v1/_/audit_ingest`, which the AiSOC connectors service holds in an in-memory ring buffer keyed by tenant. The connector's poll loop drains the buffer.

### Topology B — Pull (small / single-node Vault)

For lab and single-node deployments only. Configure `audit_log_path` in the connector to point at the audit file directly. The connector tails the file on its own poll cycle. **Not supported** for HA Vault clusters because file rotation across the cluster breaks the cursor.

## Prerequisites

- Vault 1.13 or later (older versions have a different audit JSON schema).
- A Vault token with at minimum `read` on `sys/health` for the test-connection probe. We recommend a renewable periodic token bound to a dedicated `aisoc-readonly` policy — **never use the root token**.

Example minimal policy:

```hcl
path "sys/health" {
  capabilities = ["read"]
}
```

## Setup walkthrough

### 1. Enable the audit device on Vault

```bash
vault audit enable file file_path=/var/log/vault/audit.log log_raw=false
```

`log_raw=false` keeps Vault's HMAC redaction on, so secret values do not leak into AiSOC even though AiSOC ingests the audit stream.

### 2. Deploy the AiSOC Vault sidecar next to the Vault node

```yaml
# Helm values excerpt
sidecar:
  enabled: true
  auditLogPath: /var/log/vault/audit.log
  aisocConnectorsUrl: https://connectors.aisoc.your-domain
```

### 3. Add the connector in AiSOC

1. **Connectors → Add connector → HashiCorp Vault**.
2. `vault_addr` = the cluster address (e.g. `https://vault.acme.internal:8200`).
3. `vault_token` = the read-only token from above.
4. `ingest_endpoint` = leave default (`/v1/_/audit_ingest`).
5. **Test connection** → calls `GET /v1/sys/health`.
6. **Save**.

## Polling details

- Default interval: **60 seconds**.
- Each poll drains the in-memory audit buffer for the tenant. Vault audit can be very high-volume on busy clusters — keep the poll cadence short so the buffer never approaches its bound.
- The connector adds a `vault_health` field to its periodic heartbeat reflecting `GET /v1/sys/health` (sealed, standby, version) so dashboards can show cluster status without re-querying.

## Severity heuristics

| Action | Severity |
|---|---|
| `revoke` on a root token, `policy/write` on a `*` policy, `sys/audit` device disabled | `high` |
| `update` on any `auth/` or `sys/` path, root-token issuance | `medium` |
| Routine read/write on `kv/*` or `database/*` | `info` |

The mapping lives in the connector source — open a PR if your environment classifies these differently and you want the defaults changed.

## Troubleshooting

**`HTTP 403 from /sys/health`** — token lacks the `read` capability on `sys/health`. Add the minimal policy above and re-issue the token.

**`HTTP 503: sealed`** — Vault cluster is sealed. The health probe correctly fails until the cluster is unsealed; no action required other than to unseal.

**No events arriving despite Vault activity** — the sidecar isn't running, or it cannot reach the AiSOC connectors service. Check the sidecar logs and confirm `/v1/_/audit_ingest` is reachable from the sidecar pod.

**Audit events show `***HMAC-SHA256:...***` instead of the secret value** — that's intentional. Vault HMACs values before they leave the cluster so audit logs don't leak secrets. AiSOC stores them in the redacted form.

## Related

- [Auth0](./auth0.md) and [Okta](./okta.md) — for IdP-side identity events. Pair them with Vault to cover both the identity plane (who logged in) and the secrets plane (what they read once they did).
- [Kubernetes Audit](./kubernetes-audit.md) — for the cluster control plane that often hosts Vault itself.
