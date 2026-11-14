-- An enforced retention window for the audit log, without breaking the chain.
--
-- Depth 8.1 (parity 4.4's remainder).
--
-- `retention_policies.audit_days` has been storable since the table existed
-- and purged by nothing. `app/workers/retention_purge.py` says so in its own
-- module docstring, and says why:
--
--   > The audit log is an append-only hash chain (migration 043) whose entire
--   > value is that no row was deleted, reordered, or rewritten; a retention
--   > purge would break the chain and make every subsequent verification
--   > fail. Enforcing an audit retention window needs chain-aware truncation
--   > with a re-anchored checkpoint, which is a different piece of work.
--
-- This is that piece of work. Saying it in one place beat a purge that
-- silently errored every tick, but it left an operator who configured
-- `audit_days` with a setting the product ignored — and a regulator's
-- erasure request with no mechanism behind it.
--
-- ── Why a checkpoint rather than a plain DELETE ─────────────────────────────
--
-- `verify_chain_breaks` replays a tenant's rows oldest-first starting from
-- `prev_hash = NULL`. Remove the oldest rows and the new first row names a
-- predecessor that is gone, so the replay reports `prev_hash mismatch` at
-- index 0 — a chain that is perfectly intact reads as tampered with, which
-- is the worst possible outcome for a control whose only job is to tell
-- those two apart.
--
-- A checkpoint re-anchors it. It records the cutoff that was applied, how
-- many rows went, the hash of the last one removed, and the hash the oldest
-- survivor names as its predecessor. Verification then starts from that
-- anchor and the surviving chain replays clean — and the removal itself is
-- now a fact an auditor can read, which a plain DELETE would not be.

CREATE TABLE IF NOT EXISTS aisoc_audit_checkpoints (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id                UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- The cutoff applied, and the policy that produced it. Both, because
    -- "everything before 1 March went" and "a 90-day window was in force"
    -- answer different questions and an auditor asks the second one.
    truncated_before         TIMESTAMPTZ NOT NULL,
    window_days              INTEGER NOT NULL,

    rows_removed             BIGINT NOT NULL,

    -- The last link of what was removed, and the first link of what stayed.
    -- `first_retained_prev_hash` is what makes the remainder verifiable: it
    -- is the anchor the replay starts from, and it must equal
    -- `last_removed_hash` on an untampered chain. Storing both means the
    -- checkpoint can be checked against itself.
    last_removed_hash        TEXT,
    first_retained_prev_hash TEXT,
    first_retained_hash      TEXT,

    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS aisoc_audit_checkpoints_tenant_idx
    ON aisoc_audit_checkpoints (tenant_id, created_at DESC);

-- ── The checkpoint is immutable too ─────────────────────────────────────────
--
-- A record of what was deleted, which can itself be edited or deleted, is
-- not a record. This is the same trigger shape migration `004` uses on
-- `audit_log` and `101` repaired: DELETE is refused first and
-- unconditionally, because on DELETE there is no NEW and `RETURN NEW`
-- returns NULL, which in a BEFORE trigger silently *cancels* the statement
-- and reports "DELETE 0" as success.
--
-- The one exception is the cascade from `tenants`. The foreign key above
-- declares `ON DELETE CASCADE`, and an unconditional refusal here would
-- make that declaration a lie: the tenant delete would raise instead of
-- cascading, so the row could never be removed by any means at all.
--
-- A cascade is told apart from a direct DELETE by whether the parent is
-- still there. PostgreSQL implements `ON DELETE CASCADE` as an AFTER
-- trigger on the parent, so by the time this BEFORE trigger runs on the
-- child the tenant row is already gone; a caller deleting checkpoints
-- directly still has their tenant. Measured both ways rather than assumed.
--
-- That is a narrow hole and deliberately an expensive one: erasing the
-- record of a truncation means destroying the entire tenant, which takes
-- every alert, case and credential with it. Selective erasure -- the thing
-- this table exists to prevent -- is still refused.
CREATE OR REPLACE FUNCTION public.audit_checkpoint_immutable()
RETURNS trigger
LANGUAGE plpgsql
AS $fn$
BEGIN
    IF TG_OP = 'DELETE' AND NOT EXISTS (SELECT 1 FROM tenants WHERE id = OLD.tenant_id) THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'aisoc_audit_checkpoints rows are immutable (attempted %)', TG_OP;
END;
$fn$;

DROP TRIGGER IF EXISTS audit_checkpoint_immutable ON aisoc_audit_checkpoints;
CREATE TRIGGER audit_checkpoint_immutable
    BEFORE UPDATE OR DELETE ON aisoc_audit_checkpoints
    FOR EACH ROW EXECUTE FUNCTION public.audit_checkpoint_immutable();

ALTER TABLE aisoc_audit_checkpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE aisoc_audit_checkpoints FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON aisoc_audit_checkpoints;
CREATE POLICY tenant_isolation ON aisoc_audit_checkpoints
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)
    WITH CHECK (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

-- ── The one sanctioned way to remove an audit row ───────────────────────────
--
-- `SECURITY DEFINER`, so it runs as the table owner, and the application
-- role has **no DELETE privilege on `audit_log` at all** after this
-- migration. That is the gate that cannot be talked around: the
-- transaction-local setting below is a second one, but a custom GUC can be
-- set by anybody, so on its own it would be a comment rather than a
-- control.
--
-- `SET search_path` is pinned on the function. Without it a caller who
-- controls `search_path` can put their own `audit_log` in front of the real
-- one and have a definer-rights function operate on it.
CREATE OR REPLACE FUNCTION public.audit_retention_truncate(
    p_tenant_id  UUID,
    p_cutoff     TIMESTAMPTZ,
    p_window_days INTEGER
)
RETURNS BIGINT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $fn$
DECLARE
    v_rows               BIGINT;
    v_last_removed_hash  TEXT;
    v_first_prev_hash    TEXT;
    v_first_hash         TEXT;
BEGIN
    IF p_tenant_id IS NULL OR p_cutoff IS NULL THEN
        RAISE EXCEPTION 'audit_retention_truncate needs a tenant and a cutoff';
    END IF;

    SELECT count(*) INTO v_rows
      FROM audit_log
     WHERE tenant_id = p_tenant_id AND created_at < p_cutoff;

    IF v_rows = 0 THEN
        -- No checkpoint for a no-op. A table of "removed 0 rows" entries
        -- every tick buries the ones that mean something.
        RETURN 0;
    END IF;

    SELECT entry_hash INTO v_last_removed_hash
      FROM audit_log
     WHERE tenant_id = p_tenant_id AND created_at < p_cutoff
     ORDER BY created_at DESC, chain_index DESC
     LIMIT 1;

    SELECT prev_hash, entry_hash INTO v_first_prev_hash, v_first_hash
      FROM audit_log
     WHERE tenant_id = p_tenant_id AND created_at >= p_cutoff
     ORDER BY created_at ASC, chain_index ASC
     LIMIT 1;

    -- Recorded before the delete and in the same transaction, so there is
    -- no ordering in which rows are gone and the record of them is not.
    INSERT INTO aisoc_audit_checkpoints (
        tenant_id, truncated_before, window_days, rows_removed,
        last_removed_hash, first_retained_prev_hash, first_retained_hash
    )
    VALUES (
        p_tenant_id, p_cutoff, p_window_days, v_rows,
        v_last_removed_hash, v_first_prev_hash, v_first_hash
    );

    -- The trigger on `audit_log` refuses every DELETE unless this is set,
    -- and it is `SET LOCAL`, so it lapses at the end of this transaction
    -- rather than leaving the door open for the rest of the session.
    PERFORM set_config('app.audit_retention_purge', 'on', TRUE);
    DELETE FROM audit_log WHERE tenant_id = p_tenant_id AND created_at < p_cutoff;
    PERFORM set_config('app.audit_retention_purge', 'off', TRUE);

    RETURN v_rows;
END;
$fn$;

-- ── Teach the immutability trigger about the one exception ──────────────────
--
-- Byte-identical to `101_audit_immutable_nullify.sql` apart from the DELETE
-- arm. Restated in full rather than patched, because a trigger function
-- assembled from two migrations is one nobody can read in one place.
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

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        GRANT SELECT, INSERT ON aisoc_audit_checkpoints TO aisoc_app;
        GRANT EXECUTE ON FUNCTION public.audit_retention_truncate(UUID, TIMESTAMPTZ, INTEGER) TO aisoc_app;

        -- The privilege half of the control. The trigger has always
        -- refused a direct DELETE; this makes the refusal happen one layer
        -- lower, where no setting a caller can reach has any say.
        REVOKE DELETE ON audit_log FROM aisoc_app;
    END IF;
END
$$;
