---
sidebar_position: 2
title: Security model
description: How AiSOC handles authentication, authorization, multi-tenant isolation, audit logging, and secrets — the controls operators care about.
---

# Security model

This page is the operator-facing summary of how AiSOC protects the data flowing through it. If you're evaluating AiSOC for a regulated environment, this is the page to read first; if you're already running it, this is the reference for the controls you have available.

The companion page [Credentials & secrets](./credentials) covers connector-credential encryption in depth. This page covers the rest of the security surface: identity, access, audit, and tenant isolation.

## At a glance

| Control | Mechanism | Scope |
|---|---|---|
| **User auth** | Local password (bcrypt), OIDC, SAML 2.0, JWT access + refresh tokens | All web/API traffic |
| **MFA** | WebAuthn / passkeys (Responder PWA), TOTP for analyst accounts | Per-user |
| **API auth** | Scoped API keys (`aisoc_<48-hex>`, SHA-256 stored), JWT bearer tokens | Programmatic clients |
| **Authorization** | Role-Based Access Control (8 built-in roles, fine-grained permissions) | Every endpoint |
| **Tenant isolation** | Postgres Row-Level Security with `app.current_tenant_id` session variable | Every tenant-partitioned table |
| **Secret storage** | Fernet (AES-128-CBC + HMAC-SHA256) at the application layer | Connector credentials, per-tenant LLM keys (BYOK) |
| **Audit log** | Immutable append-only log with actor, IP, user-agent, request-ID | All write actions |
| **Plugin verification** | Ed25519 signature verification on plugin manifests | Marketplace + private plugins |
| **Transport** | TLS terminated at the ingress; service-mesh mTLS optional | All traffic |

## Identity and authentication

### Local accounts

The default install ships with local username/password authentication. Passwords are hashed with **bcrypt** (truncated to bcrypt's 72-byte limit, mirroring passlib's historical behaviour) and stored only as the hash. The verifier is implemented in [`services/api/app/core/security.py`](https://github.com/beenuar/AiSOC/blob/main/services/api/app/core/security.py).

Tokens issued at login:

- **Access token** — short-lived JWT (`ACCESS_TOKEN_EXPIRE_MINUTES`, default 30 min). Carries `sub`, `role`, `tenant_id`, `exp`, `type=access`. Signed with `SECRET_KEY` using `ALGORITHM` (default HS256).
- **Refresh token** — longer-lived JWT (`REFRESH_TOKEN_EXPIRE_DAYS`, default 7 days). Used only to mint new access tokens.

Rotate `SECRET_KEY` periodically. Doing so invalidates every active session, which is the desired behaviour after a suspected key leak.

### Single Sign-On (SSO)

AiSOC supports two enterprise SSO protocols out of the box:

- **OIDC** — configured via `services/api/app/auth/oidc.py`. Point AiSOC at your IdP's discovery URL, set the client ID/secret, and map IdP groups to AiSOC roles in the role mapping config. Common IdPs tested: Okta, Entra ID (Azure AD), Google Workspace, Auth0.
- **SAML 2.0** — configured via `services/api/app/auth/saml.py`. Upload your IdP metadata XML or set the `SAML_IDP_METADATA_URL`. Group-to-role mapping uses the same shape as OIDC.

Both providers issue the same internal JWT after authentication, so authorization (RBAC, RLS) works identically regardless of how the user signed in.

### Multi-Factor Authentication

Two MFA paths are available:

- **WebAuthn / passkeys** — implemented in [`services/api/app/api/v1/endpoints/passkeys.py`](https://github.com/beenuar/AiSOC/blob/main/services/api/app/api/v1/endpoints/passkeys.py). Required for the [Responder PWA](../intro) (`/responder/*` route). Passkey-only login means there is no password fallback for on-call responders — you authenticate with the device, biometric, or hardware key the user registered.
- **TOTP** — standard 6-digit time-based codes for analyst console accounts when SSO is not in use. Backup codes are generated at enrolment and shown once.

Both MFA methods are enforced per-user, configurable per-role: tenant admins can require MFA for any role they choose.

### API keys

For programmatic clients (CI runners, external integrations, scripts) AiSOC issues scoped API keys:

```
aisoc_<48 hex chars>
└────┘ └─────────────┘
prefix    192 bits of entropy
```

The full key is shown to the user **once**, at creation time. The server stores only the SHA-256 hash and the 12-character prefix (used for display and for routing the key to the right tenant). API keys carry a role and a list of permissions the same way user accounts do, and they appear in the audit log under the actor email of the user who minted them.

Generation logic: [`generate_api_key()` in `services/api/app/core/security.py`](https://github.com/beenuar/AiSOC/blob/main/services/api/app/core/security.py).

## Authorization (RBAC)

Every API endpoint is wrapped in a `require_permission(...)` dependency. Permissions are dot-or-colon strings of the form `<resource>:<verb>` (e.g. `cases:read`, `playbooks:execute`, `lake:query`).

### Built-in roles

Defined in [`ROLE_PERMISSIONS`](https://github.com/beenuar/AiSOC/blob/main/services/api/app/core/security.py):

| Role | Intended user | Notable permissions |
|---|---|---|
| `platform_admin` | AiSOC operator (you) | `*` — every permission |
| `admin` | Demo / dev mode | `*` — same as `platform_admin` (kept aligned to avoid auth drift) |
| `tenant_admin` | Customer security lead | Full read/write on alerts, cases, playbooks, connectors, users, rules, reports, threat intel, settings, lake |
| `soc_lead` | SOC manager | Read/write alerts, cases; execute playbooks; manage rules; lake query |
| `soc_analyst` | Tier-1/Tier-2 analyst | Read/write alerts, cases; execute playbooks; lake query (rate-limited) |
| `threat_hunter` | Hunt-as-Code author | Read alerts; read/write cases, threat intel, rules; full lake access |
| `viewer` | Read-only stakeholder | Read alerts, cases, reports, threat intel |
| `api_service` | Service-to-service token | Read/write alerts and cases; read threat intel |

Wildcards are supported (`*` grants everything). For everything else, the check is exact string match — no implicit hierarchies, no inherited verbs. This is deliberate: it keeps the permission list auditable.

### Custom roles

Custom roles can be defined by inserting rows into the `roles` table with the desired permission list. They are scoped per-tenant; one tenant's `compliance_auditor` does not bleed into another's.

### Permission denied vs. not found

When a user hits an endpoint they don't have permission for, AiSOC returns `403 Forbidden` with the missing permission name in the body. It does **not** return `404` to hide existence — the resource ID is already in the URL the caller chose, so hiding it offers no real protection and complicates support.

## Multi-tenant isolation (RLS)

AiSOC is multi-tenant by design. Every tenant-partitioned table has Postgres Row-Level Security enforced. The migration that sets this up is [`002_rls.sql`](https://github.com/beenuar/AiSOC/blob/main/services/api/migrations/002_rls.sql).

The model:

1. The application layer authenticates the user and resolves their `tenant_id`.
2. Before issuing any query, the SQLAlchemy middleware sets `SET LOCAL app.current_tenant_id = '<uuid>'`.
3. RLS policies on every tenant-scoped table (`cases`, `alerts`, `connectors`, `detection_rules`, `api_keys`, `playbooks`, `audit_log`, …) enforce `tenant_id = current_tenant_id()`.
4. The `FORCE ROW LEVEL SECURITY` flag ensures even the table owner is subject to the policy — there is no superuser escape hatch via the application's DB role.

If `app.current_tenant_id` is not set (e.g. an internal job that needs to operate cross-tenant), the policy permits the query. This is intentional for system-level workers but means **the application-level ORM session must always set the tenant** before serving user requests. The middleware that does this is wired in [`services/api/app/api/deps.py`](https://github.com/beenuar/AiSOC/blob/main/services/api/app/api/deps.py).

The `users` table is excluded from RLS deliberately — it would create a chicken-and-egg problem during authentication. Tenant filtering on `users` is enforced at the application layer through `get_current_user()`.

## Audit logging

Every state-changing API action is appended to an immutable audit log. The schema lives in [`004_audit_log.sql`](https://github.com/beenuar/AiSOC/blob/main/services/api/migrations/004_audit_log.sql), the model in `services/api/app/models/audit.py`, and the helper that emits events in [`services/api/app/services/audit.py`](https://github.com/beenuar/AiSOC/blob/main/services/api/app/services/audit.py).

Each event captures:

| Field | Source |
|---|---|
| `tenant_id` | Resolved from the actor's session |
| `actor_id`, `actor_email` | Authenticated user (or API-key owner) |
| `actor_ip` | `X-Forwarded-For` (first hop) or `request.client.host` |
| `action` | Dot/colon string — e.g. `cases:create`, `connectors:delete`, `playbooks:execute` |
| `resource`, `resource_id` | What was touched |
| `changes` | Before/after delta JSON |
| `metadata_` | `user_agent`, `request_id`, and any caller-supplied context |
| `created_at` | UTC timestamp, set by Postgres |

The log is **append-only**: there is no `UPDATE` or `DELETE` endpoint, and the table has RLS enabled so a tenant can only read their own events. The middleware that auto-populates audit on common write paths is `services/api/app/middleware/audit_middleware.py`; high-value actions (case state transitions, playbook executions, credential rotations) call `emit_audit(...)` explicitly so the `changes` payload is precise.

For SOC 2 / ISO 27001 evidence collection, the [Compliance service](https://github.com/beenuar/AiSOC/blob/main/services/api/app/services/compliance.py) reads from this log directly — there is no separate compliance event store to keep in sync.

## Secrets at rest

Connector credentials and per-tenant LLM keys (BYOK) are encrypted with Fernet at the application layer before they hit Postgres. The full threat model, key rotation procedure (`MultiFernet` + `AISOC_CREDENTIAL_KEY_ROTATION_FROM`), the BYOK API surface (`/api/v1/llm/credentials`), and the hosted-OAuth roadmap live in [Credentials & secrets](./credentials). The agents-side read path is intentionally read-only — the encrypt/decrypt key authority lives in the API service; agents only decrypt at request time to layer tenant-supplied LLM config over the env baseline.

For all other secrets (database URLs, JWT signing keys, Kafka credentials, fallback/operator LLM API keys), AiSOC reads from environment variables. In production, point those env vars at your secret manager of choice — AWS Secrets Manager, GCP Secret Manager, HashiCorp Vault, sealed-secrets, etc. The full list is in [Deployment → Environment variables](../deployment/env-vars).

The two never-commit rules:

1. `SECRET_KEY` and `AISOC_CREDENTIAL_KEY` are not in any committed `.env*` file. They are generated at install time and stored in your secret manager.
2. The `.env.example` files in the repo contain placeholder values only. CI fails any PR that introduces a live-looking key.

## Plugin trust

Plugins published to the AiSOC marketplace are signed with Ed25519. The publisher generates a keypair, registers the public key in their tenant settings, and signs every release manifest. On install, the API service verifies the signature against the registered public key before executing any plugin code.

Verification entry point: `verify_ed25519_signature()` in `services/api/app/core/security.py`.

If you run private plugins (not from the public marketplace), the same flow applies — register the publisher's public key and AiSOC will refuse unsigned or tampered manifests.

## Network and transport

AiSOC is HTTP-first. The expected production deployment terminates TLS at an ingress (nginx, Envoy, ALB, Cloud Run, …) and forwards plaintext to the API service over a private network. The API trusts `X-Forwarded-For` and `X-Forwarded-Proto` for IP attribution and HTTPS-redirect logic; configure your ingress to strip and replace those headers from external traffic.

For service-to-service traffic between the API, ingest, fusion, and agents, mTLS via a service mesh (Istio, Linkerd, Consul Connect) is the recommended posture. AiSOC does not ship its own mesh.

The ingest service exposes the public `/v1/ingest/batch` endpoint that connectors push into. It requires either a connector-scoped API key or a signed JWT with the `connector` role; raw events from unauthenticated callers are rejected at the gateway.

## Playbook outbound traffic — SSRF guard

Playbook `http_request` and `notify` steps run inside the agents service and can reach arbitrary URLs supplied by playbook authors. To keep this from being abused as a metadata-service or internal-network pivot, every outbound URL is validated by the SSRF guard before any socket is opened:

- Only `http://` and `https://` are allowed by default (override with `AISOC_SSRF_ALLOWED_SCHEMES` if you genuinely need `https` only or an additional scheme).
- URLs that embed credentials (`https://user:pass@host`) are rejected outright.
- The hostname is resolved through `socket.getaddrinfo`; every resolved IP must be a global-unicast address. Loopback (`127.0.0.0/8`, `::1`), RFC1918 ranges, link-local, multicast, and the IETF reserved blocks are blocked.
- Cloud metadata endpoints — `169.254.169.254`, `fd00:ec2::254`, `metadata.google.internal`, `metadata.azure.com`, `metadata`, `metadata.aws` — are blocked even if `AISOC_SSRF_ALLOW_PRIVATE=true`.
- Operators can extend the deny list with `AISOC_SSRF_EXTRA_BLOCKED_HOSTS=internal-only.example.com,10.0.0.5`.

If a playbook needs to reach a private webhook (Slack on a private network, an internal Jira, etc.), set `AISOC_SSRF_ALLOW_PRIVATE=true` **only** on the agents service and keep network-level egress controls in place. The metadata block list always applies.

The guard is a single chokepoint at `services/agents/app/playbook/ssrf_guard.py`; both `_handle_http` and `_handle_notify` call it before the HTTP client makes any request. New action handlers that perform outbound HTTP should call `validate_outbound_url` first.

## Hardening checklist

When you move from `pnpm aisoc:demo` to a production deployment, walk through this list:

- [ ] Rotate `SECRET_KEY` and `AISOC_CREDENTIAL_KEY` to fresh, randomly generated values stored in your secret manager.
- [ ] Configure SSO (OIDC or SAML) and disable local password login for human users — leave it on only for break-glass platform admins.
- [ ] Require WebAuthn/passkeys for any role that triggers destructive playbook actions or credential changes.
- [ ] Confirm `FORCE ROW LEVEL SECURITY` is set on every tenant-partitioned table (verify with `\d+ <tablename>` in `psql`).
- [ ] Set up an external log sink for the audit log (Splunk, Elastic, Loki) — the in-DB log is the source of truth, but a copy in your SIEM is good practice.
- [ ] Confirm TLS is terminated at the ingress and that internal traffic is on a private network.
- [ ] Enable mTLS between services if you're running on Kubernetes with a mesh.
- [ ] Subscribe to the AiSOC GitHub Security Advisories for vulnerability notifications.

## Reporting a vulnerability

Security issues should be reported privately via [GitHub Security Advisories](https://github.com/beenuar/AiSOC/security/advisories/new), not as public issues. We aim to acknowledge reports within 2 business days and ship a coordinated disclosure with the reporter. The [Contributing guidelines](../contributing/guidelines) cover the full process.
