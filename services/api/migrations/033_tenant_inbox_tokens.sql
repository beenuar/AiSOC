-- Workstream 6 (universal capture push paths).
--
-- For every closed-proprietary tool that has neither a read API nor an
-- OAuth flow, we mint a per-tenant, rotatable inbox URL. Vendors point
-- their existing webhook at it; we resolve the token to a tenant +
-- vendor template and reuse the existing OCSF normalizer + Kafka
-- publisher.
--
-- This is distinct from the per-connector ``connectors.ingest_token``
-- column (migration 029): that one ties a webhook to a *specific*
-- connector instance, while ``tenant_inbox_tokens`` ties it to a
-- tenant + template_id (e.g. ``pagerduty``, ``opsgenie``,
-- ``generic-json``). The "Push (any vendor)" card in the onboarding
-- flow mints rows here without requiring a connector to exist yet.
--
-- Columns:
--   tenant_id    - owner tenant; used as the OCSF ``tenant_uid``.
--   token        - URL-safe random secret embedded in the inbox URL.
--                  Treated as a credential; never logged.
--   template_id  - filename stem in
--                  services/ingest/internal/normalizer/templates/*.yaml
--                  used to map the vendor payload onto OCSF.
--   label        - human-readable label shown in the UI (e.g. "PagerDuty
--                  on-call", "Cloudflare Logpush prod").
--   hmac_secret  - optional HMAC secret for signature verification on
--                  the ``X-Signature`` header. NULL means no signature
--                  verification (still secured by the token in the URL).
--   created_at   - mint timestamp.
--   revoked_at   - non-NULL means the token has been rotated; the
--                  ingest service rejects requests for revoked tokens.
--   last_used_at - last successful inbound request, for staleness
--                  reporting in the UI.

BEGIN;

CREATE TABLE IF NOT EXISTS tenant_inbox_tokens (
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    token         VARCHAR(80) NOT NULL,
    template_id   VARCHAR(80) NOT NULL,
    label         VARCHAR(255),
    hmac_secret   TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at    TIMESTAMPTZ,
    last_used_at  TIMESTAMPTZ,
    PRIMARY KEY (token)
);

-- Per-tenant lookup for the operator UI ("show me all my push URLs").
CREATE INDEX IF NOT EXISTS tenant_inbox_tokens_tenant_idx
    ON tenant_inbox_tokens (tenant_id);

-- Fast resolve path used by services/ingest on every push request.
-- Partial index keeps the hot path tiny — revoked tokens fall out.
CREATE INDEX IF NOT EXISTS tenant_inbox_tokens_active_idx
    ON tenant_inbox_tokens (token)
    WHERE revoked_at IS NULL;

-- ============================================================
-- RLS: each tenant sees only its own inbox tokens.
--
-- The Go ingest service connects with a service-role DSN that has
-- BYPASSRLS, so it can resolve any tenant's token on the hot path.
-- The Python API service runs every operator query inside a
-- ``SET LOCAL app.current_tenant_id = ...`` transaction (see
-- app/db/rls.py), which makes this policy a hard backstop against
-- a missing WHERE clause leaking another tenant's tokens.
-- ============================================================
ALTER TABLE tenant_inbox_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_inbox_tokens FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_inbox_tokens_tenant_isolation ON tenant_inbox_tokens;
CREATE POLICY tenant_inbox_tokens_tenant_isolation ON tenant_inbox_tokens
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

COMMIT;
