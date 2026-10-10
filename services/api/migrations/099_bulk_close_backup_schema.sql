-- 095: dedicated schema for bulk-close backup snapshots.
--
-- POST /api/v1/alerts/bulk-close snapshots every matched row into a
-- per-call table (bulk_close_backup_<uuid>) immediately before the
-- tenant-scoped UPDATE, so any sweep is reversible row-for-row. The
-- runtime role aisoc_app deliberately has no CREATE in schema public —
-- that is least-privilege working as intended (live-caught 2026-10-06:
-- the endpoint 500'd with "permission denied for schema public").
--
-- Rather than widen public, grant CREATE on a purpose-built schema the
-- app can only use for backups. Tables created there are owned by
-- aisoc_app itself, so read-back and drop need no further grants.
--
-- Idempotent: CREATE SCHEMA IF NOT EXISTS + GRANT are re-applable no-ops.

CREATE SCHEMA IF NOT EXISTS aisoc_bulk_close_backup AUTHORIZATION aisoc;

GRANT USAGE, CREATE ON SCHEMA aisoc_bulk_close_backup TO aisoc_app;

-- Anything the operator role creates here stays readable to the app too
-- (forensic imports), and vice versa the app-owned backups stay readable
-- to the owner role for manual restores.
ALTER DEFAULT PRIVILEGES IN SCHEMA aisoc_bulk_close_backup
    GRANT SELECT ON TABLES TO aisoc_app;
