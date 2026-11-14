---
sidebar_position: 1
title: Credential vault & secrets
description: How AiSOC stores connector credentials at rest, how to rotate the master key, and the roadmap for hosted OAuth.
---

# Credential vault and secret management

Connectors need real secrets — Azure client secrets, GCP service-account keys, GitHub tokens. AiSOC stores them with a defense-in-depth design: **encrypted at the application layer, with the database as a transport medium, not a trust boundary**.

This page documents the model, how to operate it, and what changes when you move from local dev to production.

## At a glance

| Property | Value |
|---|---|
| **Cipher** | Fernet (AES-128-CBC + HMAC-SHA256, RFC-aligned) |
| **Library** | `cryptography.fernet` from the `cryptography` package |
| **Storage** | `connector_instances.auth_config` JSONB column, encrypted-at-write |
| **Master key** | `AISOC_CREDENTIAL_KEY` environment variable, 32 url-safe base64 bytes |
| **Implementation** | [`services/api/app/security/credential_vault.py`](https://github.com/beenuar/AiSOC/blob/main/services/api/app/security/credential_vault.py) |
| **Plaintext exposure** | Only inside the connector microservice process at fetch time |

## Why application-layer encryption

We deliberately do **not** rely on the database's own at-rest encryption (e.g. AWS RDS `STORAGE_ENCRYPTED`, Postgres `pgcrypto`) as the only line of defense. Those mechanisms protect against disk theft but **not against a compromised read-only DB role, a leaky backup, or a misconfigured replica**.

Fernet at the API layer means:

- A leaked `pg_dump` is useless without `AISOC_CREDENTIAL_KEY`.
- A read-only support role can see *that* a connector exists (its name, type, last-sync time) but cannot read the secret payload.
- Rotation is a key-swap operation, not a database migration.

## How a credential moves through the system

```
   Browser                    API service                       Connector microservice
   ------                     --------------                    ---------------------
   POST /connectors        →  CredentialVault.encrypt()      →  (stored as ciphertext in DB)
   { auth_config: {…} }       fernet(key, plaintext)
                                   │
                                   ▼
                          connector_instances.auth_config        Scheduler tick:
                          (BYTEA / JSONB ciphertext)             CredentialVault.decrypt()
                                                                 → connector.fetch_alerts()
                                                                 → IngestClient.post()
                                                                   (plaintext drops out of scope)
```

Plaintext exists only inside `services/connectors` for the duration of one fetch. It is never returned in any HTTP response — the API redacts secret-typed fields when reading instances back to the UI.

## Generating the master key

In development, the `.env.example` file ships a placeholder; real keys are generated locally:

```bash
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

This produces a 44-character url-safe base64 string. Set it in the environment of every service that needs to encrypt or decrypt:

```bash
export AISOC_CREDENTIAL_KEY="kY7w…=" # never commit this value
```

The API service writes encrypted blobs; the connector microservice decrypts them at fetch time. **Both services must share the same key value** or polling will fail with `InvalidToken`.

## Production deployment

### Where to put the key

| Platform | Recommended location |
|---|---|
| Kubernetes | A `Secret` named `aisoc-credential-vault`, mounted as env into both `aisoc-api` and `aisoc-connectors` Deployments |
| Fly.io | `fly secrets set AISOC_CREDENTIAL_KEY=…` in **both** apps |
| AWS ECS / Fargate | An SSM Parameter referenced via `secrets:` in the task definition |
| Docker Compose (single-host) | A `.env` file outside the repo, mounted into both services |

Do **not** bake the key into a Docker image, a public Helm chart, or a Terraform `tfvars` file checked into git.

### Sealing it further (optional, recommended)

For higher-assurance deployments, treat `AISOC_CREDENTIAL_KEY` as a long-lived encryption key and protect it with an external KMS. Two patterns work:

1. **KMS-wrapped key**: store an AWS KMS / GCP KMS / Vault Transit-encrypted blob in the secret manager. A small init-container decrypts it at pod start and writes the plaintext key to a tmpfs the application can read.
2. **External KMS for envelope encryption**: replace `CredentialVault` with a wrapper that delegates `encrypt()` / `decrypt()` to a KMS Encrypt/Decrypt API call. This keeps the master key off your fleet entirely. A reference implementation will land in a follow-on release; the `CredentialVault` interface is intentionally narrow to make this swap a single-class change.

## Key rotation

Rotation is supported via Fernet's **MultiFernet** primitive: the new key encrypts new writes; the old key decrypts old data; old data is rewritten on next update. The procedure:

1. Generate a new key with the same one-liner above.
2. Set both keys in the environment as a comma-separated list:

   ```bash
   AISOC_CREDENTIAL_KEY="<NEW>,<OLD>"
   ```

   The first entry is used for new encryption; subsequent entries are decrypt-only.
3. Roll the API and connector services. Existing connector instances continue to work because the old key is still in the decrypt set.
4. Run the rotation job (or simply edit each connector instance once in the UI) to force re-encryption with the new key.
5. After confirming all instances have been re-written with the new key, drop the old entry:

   ```bash
   AISOC_CREDENTIAL_KEY="<NEW>"
   ```

A scheduled rotation cadence of 90 days is a reasonable default; treat any suspected key compromise as an emergency requiring immediate rotation **and** invalidation of all upstream credentials (Azure secrets, GCP keys, GitHub tokens).

## Per-connector secret rotation

Independent of the master key, the upstream credentials inside each connector instance should be rotated on the cadence of your identity provider's policy (typically 90–180 days for OAuth client secrets and PATs). The AiSOC UI supports in-place editing: the **Configure** action on a connector card opens the schema-driven form pre-populated with masked values, lets you paste a new secret, and re-encrypts on save. No restart, no scheduler downtime.

## What lives in the vault, and what does not

In the vault:

- `client_secret`, `api_token`, `service_account_json`, and any field marked `secret: true` in a connector's `schema()`.

Not in the vault (stored as plaintext JSON for operational visibility):

- `tenant_id`, `client_id`, `account_id`, `organization`, `project_id`, and any field marked `secret: false`.

This split is deliberate. Identifiers are useful for support and observability (logs, dashboards, error messages); secrets must never appear in either.

## Per-tenant LLM credentials (BYOK)

In addition to connector secrets, the same vault encrypts **per-tenant
LLM credentials**. This is the substrate for "bring your own key"
(BYOK): each tenant can point AiSOC at its own OpenAI account, Azure
OpenAI deployment, Anthropic key, or self-hosted OpenAI-compatible
gateway (Ollama / vLLM / LiteLLM) without leaking that key to other
tenants on the same control plane.

### Storage

Migration `038_tenant_llm_credentials.sql` creates one row per tenant
in `tenant_llm_credentials`:

| Column | Notes |
|---|---|
| `tenant_id` (PK) | Foreign key to `tenants.id`; one BYOK row per tenant |
| `provider` | `openai`, `anthropic`, `azure-openai`, `openai-compatible` (CHECK constraint) |
| `base_url` | Required for `openai-compatible`, optional for hosted providers |
| `model` | Optional override; falls back to env if blank |
| `api_key_vault` | The vault-encrypted token (`vault:v1:…`); never returned to the UI |
| `settings` | Free-form JSONB for provider-specific knobs (e.g. Azure `api_version`) |
| `enabled` | Operators can pause BYOK without deleting the row |
| `created_at` / `updated_at` / `last_rotated_at` | Audit timestamps |

The table has Row-Level Security bound to the same `app.tenant_id`
GUC as every other tenant-scoped table; an authenticated user can
only read or write their own tenant's row.

### API surface

Three endpoints under `/api/v1/llm/credentials`, gated by the
`settings:read` and `settings:write` RBAC permissions:

```http
GET    /api/v1/llm/credentials   # returns LlmCredentialView | null
PUT    /api/v1/llm/credentials   # upsert; encrypts api_key on the way in
DELETE /api/v1/llm/credentials   # remove the row entirely
```

The `LlmCredentialView` projection deliberately exposes only
`has_api_key: bool` — never the plaintext key, never the ciphertext.
Rotation is "send a new `api_key`"; updating other fields without
sending `api_key` keeps the existing ciphertext in place and bumps
`last_rotated_at` only when a new key was actually written.

Provider invariants are enforced server-side:

- `openai-compatible` rows require a `base_url` (we won't silently
  default to `api.openai.com` for self-hosted gateways).
- Hosted providers (`openai`, `anthropic`, `azure-openai`) require an
  `api_key` on **first** write; subsequent writes can omit it to update
  only `base_url` / `model` / `settings`.

### Audit

Every mutation emits a structured audit log via `emit_audit`:

```
audit.llm_credential.created  tenant_id=… actor_user_id=… provider=…
audit.llm_credential.updated  tenant_id=… actor_user_id=… provider=… rotated=true|false
audit.llm_credential.deleted  tenant_id=… actor_user_id=… provider=…
```

The plaintext key is **never** logged.

### Read path in the agents service

`services/agents/app/security/llm_resolver.py:resolve_llm_config`
is the single source of truth for "what config does this request
actually use?". It:

1. Reads the env baseline (`OPENAI_*` / `LLM_*` / `AISOC_LLM_MODEL`).
2. Looks up the tenant's row via a vendored read-path
   `CredentialVault` (see `services/agents/app/security/credential_vault.py`),
   layering tenant-supplied fields over env values.
3. Reports the resolved `source` (`tenant | environment | mixed |
   none`) so `/api/v1/llm/status` and the Settings UI can show the
   buyer where each field came from.
4. Applies the air-gap rule (`AISOC_AIRGAPPED=true` blocks
   `api.openai.com` even with a valid tenant key, but allows private
   gateways like `litellm.internal:4000`).

The agents-side vault is read-only. If `AISOC_CREDENTIAL_KEY` is
missing on the agents box, `resolve_llm_config` degrades gracefully
to the env baseline rather than refusing to serve.

### UI

The Settings → "Deployment & AI" panel
(`apps/web/src/components/settings/SettingsView.tsx`) exposes the BYOK
form to users with `settings:write`. Read-only viewers see the same
provenance badges (provider, model, `has_api_key`, last rotated,
resolved source) without the form controls.

## Hosted OAuth roadmap

Several connectors (Azure, GCP, Google Workspace) currently require the operator to do an Azure-AD-app or service-account dance before they can be added in AiSOC. This is fine for SOC engineers but a friction point for everyone else. Hosted OAuth is the planned solution:

- **Phase 1 (current)**: connector schemas already declare OAuth metadata (`authorize_url`, `token_url`, `scopes`, `supported_in_hosted`). The UI shows an "OAuth coming soon" badge for capable connectors.
- **Phase 2 (planned)**: AiSOC Cloud (and self-hosted with an OAuth-app config) will surface a one-click flow that exchanges an authorization code for an offline refresh token, encrypts it via the vault, and stores it as the connector's `auth_config`.
- **Phase 3 (planned)**: scoped tokens for self-hosted air-gapped installs that cannot reach an OAuth provider — operators ship a refresh-token bundle out-of-band.

The `CredentialVault` and connector schema model are stable shapes. Adding hosted OAuth does not require any change to existing connector implementations.

## Auditing

Every encrypt and decrypt call emits a structured log line through `structlog`:

```
event=credential.encrypt connector_id=<uuid> tenant_id=<uuid> bytes=412
event=credential.decrypt connector_id=<uuid> tenant_id=<uuid> caller=scheduler
```

The plaintext is **never** logged. Pair this with your existing log pipeline (Elastic, Datadog, Splunk, Loki) to alert on unexpected decrypt patterns — e.g. a decrypt outside the scheduler context, or a sudden burst of decrypts from a single tenant.

## Threat model summary

| Threat | Mitigation |
|---|---|
| Stolen DB backup | Useless without `AISOC_CREDENTIAL_KEY` |
| Read-only DB role compromised | Cannot read secret payloads (only metadata) |
| Plaintext secret in API logs | Vault never logs plaintext; secret fields are filtered before request logging |
| Plaintext in HTTP response to UI | API redacts secret-typed fields on read |
| Compromised connector pod | Plaintext exposed only in-memory for the duration of one fetch |
| Lost master key | **Catastrophic** — stored credentials are unrecoverable. This is the intended failure mode. Recovery path: rotate every upstream credential and reconfigure each connector instance. |
| Compromised master key | Rotate via MultiFernet (see above), then rotate every upstream credential as a precaution |

## Related

- [Connectors overview](/docs/connectors/) — how the vault fits into the broader connector lifecycle.
- [Environment Variables](/docs/deployment/env-vars) — full env reference including `AISOC_CREDENTIAL_KEY` and related settings.
