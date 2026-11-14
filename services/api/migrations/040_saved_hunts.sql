-- Migration 040: Saved natural-language hunts (Track 3, T3.4 — `/hunt` NL surface).
--
-- The `/hunt` page lets analysts ask plain-English questions ("Did we get
-- any new attacks from Iran?", "Show GitHub auth from a new device this
-- week", etc.), see the parsed query in ES|QL/SPL/KQL, and save the prompt
-- so the next shift can re-run it in one click — optionally on a cron.
--
-- This is intentionally a separate table from `aisoc_hunts` (the
-- hypothesis-driven hunt workbench from migration 014). The two surfaces
-- serve different jobs:
--
--   * `aisoc_hunts`           — heavyweight, detection-engineer authored.
--                               Carries hypothesis, MITRE mapping, status,
--                               findings rollup, multi-platform queries.
--                               Surfaced on the Hunt Workbench page.
--   * `aisoc_saved_hunts`     — lightweight, tier-1 analyst authored.
--                               Stores the NL question + translator output.
--                               Surfaced as pills on the `/hunt` page.
--
-- Schema:
--   id                 - opaque uuid, surfaced in URLs (`?hunt=<id>`).
--   tenant_id          - owner tenant; isolation enforced by RLS below.
--   created_by         - author user; nullable so demo/system seeds can
--                        omit it. Used for the "saved by" badge in the UI.
--   name               - human-readable label, unique per tenant.
--   nl_query           - the original plain-English question, kept verbatim
--                        so we can re-translate when the translator
--                        improves and re-show the prompt to the analyst.
--   translated_query   - opaque JSONB { esql, kql, spl, explanation, intents }
--                        — the translator owns the schema; the API never
--                        inspects the contents.
--   language           - preferred dialect at save time (esql|kql|spl); the
--                        translator emits all three but the UI re-opens in
--                        the dialect the analyst was looking at.
--   schedule           - optional cron string ("0 */6 * * *"). NULL → manual
--                        run only. The hunt scheduler worker picks up rows
--                        where this is non-null and fires the hunt on cadence.
--   last_run_at        - timestamp of the most recent execution (manual or
--                        scheduled); used by the scheduler to gate cadence.
--   created_at         - mint timestamp.
--   updated_at         - bumped on every mutation.
--
-- Indexes:
--   - tenant_id index for the hot list path.
--   - partial index on `schedule IS NOT NULL` so the scheduler's "any
--     scheduled hunts due?" sweep stays cheap as the table grows.
--   - unique (tenant_id, name) keeps the saved-hunts list searchable; we
--     deliberately don't scope this to `created_by` so a teammate can find
--     "Iran inbound" without guessing who saved it.

BEGIN;

CREATE TABLE IF NOT EXISTS aisoc_saved_hunts (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    created_by          UUID REFERENCES users(id) ON DELETE SET NULL,
    name                VARCHAR(160) NOT NULL,
    nl_query            TEXT NOT NULL,
    translated_query    JSONB NOT NULL DEFAULT '{}'::jsonb,
    language            VARCHAR(16) NOT NULL DEFAULT 'esql',
    schedule            VARCHAR(120),
    last_run_at         TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT aisoc_saved_hunts_unique_name
        UNIQUE (tenant_id, name),
    CONSTRAINT aisoc_saved_hunts_language_check
        CHECK (language IN ('esql', 'kql', 'spl'))
);

CREATE INDEX IF NOT EXISTS aisoc_saved_hunts_tenant_idx
    ON aisoc_saved_hunts (tenant_id);

-- Partial index — the scheduler's hot read path is "any rows in this tenant
-- with a cron set?". Indexing only the scheduled subset keeps the index
-- tiny while still serving the sweep query in microseconds.
CREATE INDEX IF NOT EXISTS aisoc_saved_hunts_scheduled_idx
    ON aisoc_saved_hunts (tenant_id, schedule)
    WHERE schedule IS NOT NULL;

-- ============================================================
-- RLS: tenant isolation. Saved hunts are tenant-shared (every
-- analyst in the tenant can see every saved hunt) so we enforce
-- only the tenant boundary at the DB layer; user-level
-- permissions (who can delete) live in the API layer.
-- ============================================================
ALTER TABLE aisoc_saved_hunts ENABLE ROW LEVEL SECURITY;
ALTER TABLE aisoc_saved_hunts FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS aisoc_saved_hunts_tenant_isolation ON aisoc_saved_hunts;
CREATE POLICY aisoc_saved_hunts_tenant_isolation ON aisoc_saved_hunts
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

COMMIT;
