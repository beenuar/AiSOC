-- Migration 043: Managed-instance tenant provisioning (T6.1 — `tryaisoc.com`).
--
-- Wires the waitlist (migration 042) into the existing ``tenants`` table so
-- the support / sales team can promote a waitlist entry into a real tenant
-- without dropping into the database by hand.
--
-- Two ``tenants`` columns:
--
--   * ``provisioned_from_waitlist_id`` — UUID FK back to
--     ``aisoc_waitlist_entries.id``. Nullable because the column is
--     additive: hand-curated tenants (the demo tenant, MSSP child tenants,
--     fixture rows in test data) were never on the waitlist and should
--     keep working. ``ON DELETE SET NULL`` keeps a tenant row alive even
--     if an operator deletes the originating waitlist entry (we still
--     want the live tenant; we just lose the breadcrumb).
--
--   * ``provisioned_at`` — TIMESTAMPTZ stamped by the provisioner the
--     first time it crosses a waitlist entry into a tenant. Nullable for
--     the same reason: pre-existing tenants don't have a provisioning
--     timestamp and back-filling one would be a lie.
--
-- The complementary FK in the *other direction* lives on the waitlist
-- table itself: ``aisoc_waitlist_entries.provisioned_tenant_id``. That
-- column was created in migration 042 as a plain UUID so the import
-- graph stays free of an ordering dependency. We add the actual FK at
-- this layer once both tables exist.
--
-- Indexes:
--
--   * ``idx_tenants_provisioned_from_waitlist`` — partial index keyed
--     on the FK, scoped to NON-NULL rows. The support UI's "find the
--     tenant we just provisioned for $waitlist_entry" lookup is the
--     only consumer.
--   * ``idx_tenants_provisioned_at`` — sorted lookup for the admin
--     tenants table ("newest provisioned tenants first").
--
-- This migration is intentionally **additive-only**. It does not touch
-- existing rows or RLS policies. Re-running it on a database that
-- already has 043 applied is a no-op thanks to the ``IF NOT EXISTS``
-- guards on every statement.

BEGIN;

-- ============================================================
-- Tenants table: tag rows with their waitlist origin (if any).
-- ============================================================
ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS provisioned_from_waitlist_id UUID,
    ADD COLUMN IF NOT EXISTS provisioned_at               TIMESTAMPTZ;

-- The FK back to aisoc_waitlist_entries(id). We use a NOT VALID FK plus
-- a deferred VALIDATE to keep the ALTER cheap on tables with existing
-- rows: pre-existing tenants have NULL in the new column so no row
-- needs scanning anyway, but the `NOT VALID` step keeps the lock window
-- tight on busy databases. Wrapped in a DO block so the migration is
-- idempotent and survives a re-run on a database where the constraint
-- is already present.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM   information_schema.table_constraints
        WHERE  table_name = 'tenants'
        AND    constraint_name = 'tenants_provisioned_from_waitlist_fk'
    ) THEN
        ALTER TABLE tenants
            ADD CONSTRAINT tenants_provisioned_from_waitlist_fk
            FOREIGN KEY (provisioned_from_waitlist_id)
            REFERENCES aisoc_waitlist_entries(id)
            ON DELETE SET NULL
            NOT VALID;

        ALTER TABLE tenants
            VALIDATE CONSTRAINT tenants_provisioned_from_waitlist_fk;
    END IF;
END
$$ LANGUAGE plpgsql;

-- ============================================================
-- Waitlist table: now that ``tenants`` exists, we can wire the
-- reverse FK on aisoc_waitlist_entries.provisioned_tenant_id.
-- ============================================================
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM   information_schema.table_constraints
        WHERE  table_name = 'aisoc_waitlist_entries'
        AND    constraint_name = 'aisoc_waitlist_entries_provisioned_tenant_fk'
    ) THEN
        ALTER TABLE aisoc_waitlist_entries
            ADD CONSTRAINT aisoc_waitlist_entries_provisioned_tenant_fk
            FOREIGN KEY (provisioned_tenant_id)
            REFERENCES tenants(id)
            ON DELETE SET NULL
            NOT VALID;

        ALTER TABLE aisoc_waitlist_entries
            VALIDATE CONSTRAINT aisoc_waitlist_entries_provisioned_tenant_fk;
    END IF;
END
$$ LANGUAGE plpgsql;

-- ============================================================
-- Indexes.
-- ============================================================
CREATE INDEX IF NOT EXISTS idx_tenants_provisioned_from_waitlist
    ON tenants (provisioned_from_waitlist_id)
    WHERE provisioned_from_waitlist_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_tenants_provisioned_at
    ON tenants (provisioned_at DESC)
    WHERE provisioned_at IS NOT NULL;

COMMIT;
