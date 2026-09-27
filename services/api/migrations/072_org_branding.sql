-- 072: per-organisation white-label branding, with assets held locally.
--
-- Gap-closure Phase 13.2.
--
-- Why the bytes live in this database
-- ------------------------------------
-- The plan is explicit that assets are stored locally and never fetched from
-- a third-party URL, and the reason is not convenience. A logo referenced by
-- URL is an outbound request made by whatever renders it: the console (from
-- the operator's browser, leaking who is looking at what to whoever hosts the
-- image) and the PDF renderer (from inside the server, which is a
-- server-side request forgery primitive aimed at a URL a customer
-- administrator supplied). Holding the bytes removes both, and it removes the
-- third failure mode too: a logo that renders in a report today and 404s in
-- the same report opened next quarter.
--
-- BYTEA rather than a volume, because a logo is small, the cap is enforced in
-- the application, and a file on one replica's disk is a file the other
-- replicas cannot serve.
--
-- Why branding hangs off the organisation and not the tenant
-- -----------------------------------------------------------
-- A managed-service provider brands what its customers see, across every
-- tenant in its portfolio. One row per organisation is the whole point: a
-- per-tenant table would make "our branding" something an operator had to
-- apply N times and keep in agreement.
--
-- Why there is no row-level-security policy here
-- -----------------------------------------------
-- These tables carry no `tenant_id`, so the tenant policy shape does not
-- apply to them. They follow `organizations` and `organization_members` from
-- migration 058, which are scoped at the query layer by
-- `app/services/org_scope.py`. `check_rls_policy_shape.py` judges the shape
-- of tenant policies; adding one keyed on a column that does not exist would
-- be theatre.

CREATE TABLE IF NOT EXISTS aisoc_org_brand_assets (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- `logo` renders in the console header and at the top of a PDF report.
    -- `favicon` is the browser tab. Constrained so a third kind has to be
    -- added deliberately, with somewhere to render it.
    kind         TEXT        NOT NULL CHECK (kind IN ('logo', 'favicon')),

    content_type TEXT        NOT NULL,
    -- The sanitised bytes for an SVG, the original bytes for a raster. What
    -- is stored is what is served: nothing re-sanitises at render time, so a
    -- row here is trusted and the sanitiser is the only thing that writes it.
    content      BYTEA       NOT NULL,
    byte_size    INTEGER     NOT NULL CHECK (byte_size > 0 AND byte_size <= 262144),
    -- SHA-256 of the stored bytes, so a cache can revalidate and an operator
    -- can confirm the asset they uploaded is the asset being served.
    sha256       TEXT        NOT NULL,
    -- TRUE when the uploaded SVG had constructs removed. Surfaced to the
    -- administrator, because "your logo renders differently than it did in
    -- your graphics program" needs an explanation and not a mystery.
    was_sanitized BOOLEAN    NOT NULL DEFAULT FALSE,

    uploaded_by  UUID        REFERENCES users(id) ON DELETE SET NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- One current asset per kind per organisation. Replacing is an UPDATE,
    -- so a stale logo cannot linger beside its replacement.
    UNIQUE (org_id, kind)
);

COMMENT ON TABLE aisoc_org_brand_assets IS
    'Uploaded brand assets, held as bytes. Never a URL: a remote logo is an '
    'outbound request from the console and from the PDF renderer, and the '
    'second of those is server-side request forgery against a customer-'
    'supplied address.';
COMMENT ON COLUMN aisoc_org_brand_assets.content IS
    'Sanitised bytes for an SVG, original bytes for a raster. Nothing '
    're-sanitises at render time, so the sanitiser is the only writer.';

CREATE INDEX IF NOT EXISTS idx_org_brand_assets_org ON aisoc_org_brand_assets (org_id);


CREATE TABLE IF NOT EXISTS aisoc_org_branding (
    org_id        UUID        PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,

    -- Every field is nullable and every one falls back to the platform
    -- default at read time. A half-configured organisation therefore renders
    -- a coherent product rather than a page with holes in it, which is what
    -- an operator sees during the ten minutes between creating the row and
    -- finishing it.
    product_name  TEXT        CHECK (product_name IS NULL OR length(product_name) BETWEEN 1 AND 80),
    primary_color TEXT        CHECK (primary_color IS NULL OR primary_color ~ '^#[0-9A-Fa-f]{6}$'),
    accent_color  TEXT        CHECK (accent_color IS NULL OR accent_color ~ '^#[0-9A-Fa-f]{6}$'),

    support_email TEXT        CHECK (support_email IS NULL OR support_email ~ '^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$'),
    -- Constrained to https at the database as well as in the application.
    -- This string is rendered as a link in an email and in a PDF, so a
    -- `javascript:` value here would be a stored script in somebody else's
    -- inbox.
    support_url   TEXT        CHECK (support_url IS NULL OR support_url ~ '^https://'),

    -- The display name on outbound mail and ChatOps messages.
    sender_name   TEXT        CHECK (sender_name IS NULL OR length(sender_name) BETWEEN 1 AND 80),
    footer_text   TEXT        CHECK (footer_text IS NULL OR length(footer_text) <= 300),

    updated_by    UUID        REFERENCES users(id) ON DELETE SET NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE aisoc_org_branding IS
    'White-label settings for one operator organisation. Every column is '
    'nullable and falls back to the platform default at read time, so a '
    'half-configured organisation renders a coherent product.';
COMMENT ON COLUMN aisoc_org_branding.support_url IS
    'https only, enforced here as well as in the application: this string is '
    'rendered as a link in email and in PDF reports.';

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON aisoc_org_branding TO aisoc_app;
        GRANT SELECT, INSERT, UPDATE, DELETE ON aisoc_org_brand_assets TO aisoc_app;
    END IF;
END
$$;
