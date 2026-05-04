# Production Hardening Runbook

This runbook is the operator's checklist for taking an AiSOC deployment from "it boots" to "I would put real customer telemetry through it." It assumes you are running the platform from official images on Kubernetes via the Helm chart in [`infra/helm/aisoc/`](../../infra/helm/aisoc/), or via the production Compose profile.

If you only need a quick local demo, use [`pnpm aisoc:demo`](../../README.md#quickstart) instead — that flow intentionally skips most of the controls below.

---

## 1. Identity, secrets, and keys

- [ ] Generate fresh values for every secret in `.env` / `values.yaml`. Do **not** ship the example secrets to staging or prod.
  - `SECRET_KEY` (API JWT signing) and `JWT_SECRET` (SSO/SAML/OIDC flows) — 32+ random bytes each (`openssl rand -hex 32`).
  - `HONEYTOKEN_ALERT_WEBHOOK_SECRET` — HMAC secret for honeytoken webhook callbacks.
  - `REALTIME_INTERNAL_TOKEN` — shared secret between API and realtime for internal push fan-out.
  - `VAPID_PRIVATE_KEY` / `VAPID_PUBLIC_KEY` / `VAPID_SUBJECT` — generate via `npx web-push generate-vapid-keys`.
- [ ] Store secrets in your platform's secret manager (Kubernetes `Secret` + sealed-secrets, AWS Secrets Manager, Vault, …) rather than committed YAML.
- [ ] Roll out passkeys (WebAuthn) for every human account before exposing the UI on the public internet — set `PASSKEY_RP_ID`, `PASSKEY_RP_NAME`, and `PASSKEY_RP_ORIGINS` to your real domain (no scheme, no port for `RP_ID`; full origin URLs for `RP_ORIGINS`).
- [ ] Configure SSO via [`services/api/app/auth/`](../../services/api/app/auth/) (`oidc.py` or `saml.py`) — set `OIDC_ISSUER`/`OIDC_CLIENT_ID`/`OIDC_CLIENT_SECRET` or the matching `SAML_*` variables — and disable local password sign-up once IdP-backed sign-in works end-to-end.
- [ ] Rotate JWT signing keys (`SECRET_KEY`, `JWT_SECRET`) and webhook secrets every 90 days. Plan for a brief overlap window where both old and new tokens are accepted so the rotation is non-disruptive.
- [ ] The Investigation Ledger is database-backed with Row-Level Security and an immutability trigger — there is no separate signing key to manage. Review `services/api/app/models/investigation.py` for the schema if you need to audit it.

## 2. Transport and network surface

- [ ] Terminate TLS 1.3 at the ingress (NGINX, Traefik, ALB, or your service mesh). Internal services should also speak TLS where supported.
- [ ] Restrict ingress to:
  - the web app,
  - the public API on `/api/*`,
  - the realtime websocket on `/ws/*`,
  - the MCP endpoint on `/mcp/*` (only if you actually expose it).
  Everything else (Postgres, NATS, OpenSearch, Redis, the eval harness) must stay on the cluster network.
- [ ] Apply Kubernetes `NetworkPolicy` resources from the chart so each service only reaches its required dependencies.
- [ ] Set sane CORS defaults: explicit allow-list of origins, no wildcard `*` once you have a real frontend hostname.
- [ ] Enable rate limiting middleware (see [`services/api/app/middleware/`](../../services/api/app/middleware/)) and tune the per-token / per-API-key limits to your load profile.

## 3. Data plane

- [ ] Run Postgres in a managed service (RDS, Cloud SQL, Aiven, …) with point-in-time recovery enabled.
- [ ] Confirm Row-Level Security is on for every multi-tenant table. The migration suite enforces this; do not disable it.
- [ ] Snapshot OpenSearch and the object store (R2, S3, GCS, …) at least daily. Test a restore quarterly.
- [ ] Encrypt at rest:
  - Database volumes — managed encryption is fine.
  - Object storage — bucket-level KMS keys.
  - Audit log archive — separate KMS key, immutable bucket policy.
- [ ] Pin a retention policy per data class (alerts, cases, audit, ledger) and document who can lower it.

## 4. Container and supply chain

- [ ] Pull only signed images from `ghcr.io/beenuar/aisoc-*` and verify Cosign signatures in your admission controller.
- [ ] Keep `securityContext.runAsNonRoot: true` and `readOnlyRootFilesystem: true` for every workload — these are the chart defaults; do not override unless you genuinely need to.
- [ ] Run images with a read-only root filesystem and the minimum capability set (`drop: ["ALL"]`).
- [ ] Enable `PodSecurityAdmission` in `restricted` mode on the namespace AiSOC runs in.
- [ ] Subscribe to GitHub Security Advisories for [`beenuar/AiSOC`](https://github.com/beenuar/AiSOC/security/advisories) and patch within the SLA window in [`SECURITY.md`](../../SECURITY.md).

## 5. Observability and audit

- [ ] Forward audit logs to an immutable sink (S3 Object Lock, GCS Bucket Lock, or a SIEM with WORM storage).
- [ ] Verify the Investigation Ledger periodically:
  ```bash
  curl -fsSL "$AISOC_API/api/v1/ledger/verify?case_id=$CASE_ID" \
    -H "Authorization: Bearer $TOKEN"
  ```
  Add this to a synthetic check that pages on a non-200 response.
- [ ] Wire OpenTelemetry traces from all services to your collector and keep at least 7 days of trace data for incident response.
- [ ] Send platform metrics (`/metrics`) to Prometheus or a managed equivalent. Alert on saturation, p99 latency, and 5xx rates per service.

## 6. AI and agent controls

- [ ] Set explicit allow-lists for every LLM tool the Ambient Copilot can invoke. Default to read-only.
- [ ] Require human approval for any destructive responder action (`isolate-host`, `disable-user`, `block-domain`). The Responder PWA enforces this client-side; mirror it server-side in your policy bundle.
- [ ] Run the [public eval harness](../../apps/docs/docs/benchmark.md) on a release candidate before promoting it. Block the rollout if the MITRE-tactic substrate self-consistency gate regresses by more than 2 points, or if alert reduction (the one real measurement in the harness) drops materially.
- [ ] Log every Copilot prompt + response into the audit stream with the active tenant ID and user ID.

## 7. Incident response readiness

- [ ] Document the on-call rotation, escalation contacts, and the runbook for revoking compromised tokens / API keys.
- [ ] Practice the kill-switch: scaling the API to zero, rotating `SECRET_KEY` (and `JWT_SECRET` if SSO is enabled), and re-issuing tokens — make sure the team can do all three in under 15 minutes.
- [ ] Keep an offline copy of [`SECURITY.md`](../../SECURITY.md) and this runbook so they remain accessible when the cluster is offline.

---

If something here is wrong, missing, or no longer matches reality, please open a PR. We treat hardening drift as a bug.
