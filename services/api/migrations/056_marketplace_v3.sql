-- Marketplace v3: publisher identity, durable submissions, and paid listings.
--
-- Three things were missing, and the first one made the other two unsafe to
-- build on.
--
-- 1. There was no publisher identity. `_get_registered_pub_key` returned
--    `None` unconditionally, so `publish_plugin` skipped verification
--    entirely and stored `verified: False`. A submitted plugin was **never**
--    rejected for a bad signature — the signing path existed end to end and
--    could not fail. Commerce on top of that would be paying people we
--    cannot identify for code we cannot attribute.
--
-- 2. Community submissions and install records were module-global dicts,
--    documented as "replace with DB in production". They died with the
--    process and were invisible to a second replica.
--
-- 3. There was no notion of a paid listing anywhere: no price, no publisher,
--    no entitlement. `marketplace/index.json` carries `license` on 77 of
--    7,155 items and it is `MIT` for every one of them.

-- ── Publisher identity ───────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS marketplace_publishers (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    display_name    TEXT NOT NULL,
    contact_email   TEXT NOT NULL,
    -- Set by a platform admin after out-of-band checks. A self-asserted
    -- publisher is still a publisher; it is just not a verified one, and the
    -- distinction has to be visible rather than implied.
    verified        BOOLEAN NOT NULL DEFAULT FALSE,
    verified_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, user_id)
);

CREATE TABLE IF NOT EXISTS marketplace_publisher_keys (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    publisher_id    UUID NOT NULL REFERENCES marketplace_publishers(id) ON DELETE CASCADE,
    -- PEM-encoded Ed25519 public key. Stored as text rather than bytes so it
    -- is readable in a psql session during an incident.
    public_key_pem  TEXT NOT NULL,
    -- SHA-256 of the DER form, for "which key signed this" without parsing.
    fingerprint     TEXT NOT NULL,
    label           TEXT NOT NULL DEFAULT '',
    -- Revocation is a timestamp, not a delete: a signature made before
    -- revocation stays explicable afterwards.
    revoked_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (fingerprint)
);

CREATE INDEX IF NOT EXISTS ix_publisher_keys_publisher
    ON marketplace_publisher_keys (publisher_id) WHERE revoked_at IS NULL;

-- ── Durable community submissions ────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS marketplace_submissions (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    publisher_id    UUID REFERENCES marketplace_publishers(id) ON DELETE SET NULL,
    kind            TEXT NOT NULL CHECK (kind IN ('plugin', 'detection', 'playbook')),
    slug            TEXT NOT NULL,
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    version         TEXT NOT NULL DEFAULT '0.1.0',
    status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'approved', 'rejected')),
    -- Whether the signature actually verified against a registered key. This
    -- column is the whole point of the publisher tables: before them it was
    -- always false and could never be anything else.
    signature_verified BOOLEAN NOT NULL DEFAULT FALSE,
    signing_fingerprint TEXT,
    -- Commercial listing. NULL price means free, which is every listing
    -- today; a zero price would be a different and confusing claim.
    price_cents     INTEGER CHECK (price_cents IS NULL OR price_cents >= 0),
    currency        TEXT CHECK (currency IS NULL OR char_length(currency) = 3),
    license         TEXT NOT NULL DEFAULT 'MIT',
    definition      JSONB NOT NULL DEFAULT '{}'::jsonb,
    review_notes    TEXT,
    install_count   INTEGER NOT NULL DEFAULT 0,
    submitted_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, kind, slug)
);

CREATE INDEX IF NOT EXISTS ix_submissions_kind_status
    ON marketplace_submissions (kind, status);

-- ── Durable install records ──────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS marketplace_installs (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    item_id         TEXT NOT NULL,
    item_type       TEXT NOT NULL,
    version         TEXT NOT NULL DEFAULT '',
    -- The digest the image resolved to at install time. Without it a `:latest`
    -- install is mutable after the fact and "what is running" has no answer.
    image_digest    TEXT,
    installed_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    installed_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, item_id)
);

CREATE INDEX IF NOT EXISTS ix_installs_tenant
    ON marketplace_installs (tenant_id);

-- ── Entitlements ─────────────────────────────────────────────────────────────
--
-- A row here says a tenant may run a paid listing. Nothing in this repository
-- creates one from a payment: there is no payment processor, and wiring one
-- is an account action rather than an engineering task. What exists is the
-- check — a paid listing without an entitlement does not load — so the
-- enforcement point is real and testable before any money moves through it.

CREATE TABLE IF NOT EXISTS marketplace_entitlements (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    item_id         TEXT NOT NULL,
    -- How this tenant came to be entitled. 'grant' is an operator action and
    -- is the only source that exists today; 'purchase' is reserved.
    source          TEXT NOT NULL DEFAULT 'grant'
                    CHECK (source IN ('grant', 'purchase', 'trial')),
    granted_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    expires_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, item_id)
);

CREATE INDEX IF NOT EXISTS ix_entitlements_tenant
    ON marketplace_entitlements (tenant_id);
