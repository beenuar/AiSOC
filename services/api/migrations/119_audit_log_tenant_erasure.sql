-- 119_audit_log_tenant_erasure.sql
--
-- Tenant deletion is impossible: the audit_log immutability trigger refuses
-- the cascade from tenants (issue #1330; ADR 0014).
--
-- ── The defect ───────────────────────────────────────────────────────────────
--
-- `audit_log.tenant_id` has carried `REFERENCES tenants(id) ON DELETE CASCADE`
-- since migration 004, and the immutability trigger (004, restated by 101 and
-- again by 117) refuses every DELETE that is not the retention purge. A
-- cascade is an ordinary DELETE on the child, so `DELETE FROM tenants` raises
-- for any tenant that has ever written an audit row — which is every tenant.
-- `services/api/app/services/tenant_deletion.py` ends with exactly that
-- statement, so the tenant-offboarding path (the one a GDPR erasure request
-- goes through) could never complete. The behaviour reads as the control
-- working, which is why nothing noticed until someone deleted a tenant
-- against a database that held audit rows.
--
-- ── The fix, and why it is safe ──────────────────────────────────────────────
--
-- Migration 117 already solved this exact problem for the checkpoint table it
-- added: PostgreSQL runs `ON DELETE CASCADE` as an AFTER trigger on the
-- parent, so by the time the child's BEFORE DELETE trigger runs, the parent
-- row is already gone — while a caller deleting child rows directly still has
-- their tenant. `tenant_id` is NOT NULL (004), so the probe cannot be
-- confused by an orphan row. The same arm is applied here.
--
-- What this deliberately does NOT relax (ADR 0014 records the trade):
--   * A direct `DELETE FROM audit_log` while the tenant exists is still
--     refused twice over — by privilege (117 revoked DELETE from the runtime
--     role) and by this trigger for any role that does hold the privilege.
--   * Selective erasure stays impossible. The only way to remove a tenant's
--     audit history outside the checkpointed retention window is to destroy
--     the whole tenant — every alert, case and credential with it — which is
--     visible, irreversible, and not tampering in any useful sense.
--   * The retention-purge arm is unchanged: `audit_retention_truncate`
--     (117) remains the only selective path, and it writes a checkpoint the
--     chain verifier re-anchors on.
--
-- Restated in full rather than patched, because a trigger function assembled
-- from two migrations is one nobody can read in one place. Byte-identical to
-- 117's statement apart from the cascade arm and this header.

CREATE OR REPLACE FUNCTION public.audit_log_immutable()
RETURNS trigger
LANGUAGE plpgsql
AS $fn$
DECLARE
    key text;
    old_row jsonb := to_jsonb(OLD);
    new_row jsonb := to_jsonb(NEW);
BEGIN
    IF TG_OP = 'DELETE' THEN
        -- The retention window, and nothing else. `audit_retention_truncate`
        -- is the only thing that sets this, it is `SET LOCAL` so it cannot
        -- outlive the statement that needed it, and the application role has
        -- no DELETE privilege here anyway — so a caller who sets the setting
        -- by hand is refused by Postgres before this trigger is reached.
        IF coalesce(current_setting('app.audit_retention_purge', TRUE), 'off') = 'on' THEN
            RETURN OLD;
        END IF;
        -- Tenant erasure. `ON DELETE CASCADE` runs as an AFTER trigger on
        -- `tenants`, so when this BEFORE trigger sees the child row the
        -- parent is already gone; a direct DELETE still finds its tenant and
        -- falls through to the refusal. `tenant_id` is NOT NULL, so a row
        -- whose tenant is absent can only be mid-cascade.
        IF NOT EXISTS (SELECT 1 FROM tenants WHERE id = OLD.tenant_id) THEN
            RETURN OLD;
        END IF;
        RAISE EXCEPTION 'audit_log rows are immutable (attempted %)', TG_OP;
    END IF;

    FOR key IN SELECT jsonb_object_keys(new_row) LOOP
        IF old_row -> key IS DISTINCT FROM new_row -> key THEN
            -- The ONE legal mutation, pinned to its column: only actor_id
            -- carries ON DELETE SET NULL.
            IF key = 'actor_id'
               AND jsonb_typeof(old_row -> key) <> 'null'
               AND jsonb_typeof(new_row -> key) = 'null'
            THEN
                CONTINUE;
            END IF;
            RAISE EXCEPTION 'audit_log rows are immutable (attempted UPDATE of %)', key;
        END IF;
    END LOOP;
    RETURN NEW;
END;
$fn$;
