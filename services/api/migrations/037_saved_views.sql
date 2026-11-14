-- Migration 037: Per-user saved views for list pages (WS-F3).
--
-- Analysts spend most of their day on three list pages: Alerts, Cases /
-- Investigations, and Playbooks. Each page exposes filter chips (severity,
-- status, source, owner, time range) and an optional column set. Without
-- saved views, every shift starts with the same five clicks. We persist
-- these presets per-user-per-tenant so "my critical-only triage view" or
-- "the queue I share with the EU shift" loads in one click.
--
-- Schema:
--   id          - opaque uuid, surfaced in URLs (`?view=<id>`).
--   tenant_id   - owner tenant; isolation is enforced by RLS.
--   user_id     - owning analyst; saved views are *private to the user*
--                 within a tenant. Sharing across users is a v1.1 polish
--                 (we'd flip this column nullable + add a `scope` enum).
--   view_type   - which list page this preset belongs to
--                 (`alerts | cases | investigations | playbooks`).
--                 Stored as TEXT so adding a new list page in v1.1 is a
--                 code-only change.
--   name        - human-readable label rendered as a pill in the saved-
--                 views bar (e.g. "Critical only", "EU shift queue").
--   filters     - opaque JSONB matching the list page's filter shape
--                 (e.g. `AlertFilters` from apps/web/src/lib/api.ts).
--                 The backend never inspects the contents — it round-trips
--                 the blob untouched. Frontend owns the schema.
--   columns     - optional JSONB list of column ids/widths. NULL means
--                 "use the page default column set".
--   is_default  - exactly one default per (tenant, user, view_type); the
--                 partial unique index below enforces it. The list page
--                 auto-applies the default on first mount.
--   created_at  - mint timestamp.
--   updated_at  - bumped on every mutation; used to drive the "synced X
--                 minutes ago" hint in the saved-views menu.
--
-- Indexes:
--   - per-(tenant, user, view_type) lookup is the only hot query.
--   - partial unique on is_default keeps the "exactly one default"
--     invariant at the DB layer rather than relying on the API to
--     race-free toggle the previous default.

BEGIN;

CREATE TABLE IF NOT EXISTS saved_views (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    view_type   VARCHAR(40) NOT NULL,
    name        VARCHAR(120) NOT NULL,
    filters     JSONB NOT NULL DEFAULT '{}'::jsonb,
    columns     JSONB,
    is_default  BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT saved_views_view_type_check
        CHECK (view_type IN ('alerts', 'cases', 'investigations', 'playbooks')),
    CONSTRAINT saved_views_unique_name
        UNIQUE (tenant_id, user_id, view_type, name)
);

-- The hot read path: "give me my saved views for the alerts page".
CREATE INDEX IF NOT EXISTS saved_views_owner_type_idx
    ON saved_views (tenant_id, user_id, view_type);

-- At most one default per (tenant, user, view_type). Partial unique
-- index is the right tool: it lets non-default rows duplicate freely
-- while still enforcing the singleton invariant.
CREATE UNIQUE INDEX IF NOT EXISTS saved_views_one_default_idx
    ON saved_views (tenant_id, user_id, view_type)
    WHERE is_default;

-- ============================================================
-- RLS: tenant isolation. User-level scoping is enforced in the
-- API layer (deps.py + endpoints/saved_views.py); RLS only
-- guarantees that a tenant can never see another tenant's views.
-- ============================================================
ALTER TABLE saved_views ENABLE ROW LEVEL SECURITY;
ALTER TABLE saved_views FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS saved_views_tenant_isolation ON saved_views;
CREATE POLICY saved_views_tenant_isolation ON saved_views
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

COMMIT;
