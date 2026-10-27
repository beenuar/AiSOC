-- 122_closure_authorization_default_deny.sql
--
-- Record what the closure default-deny change means for each tenant on this
-- deployment, so an operator can see who is affected and re-authorize
-- deliberately.
--
-- What changed in the code
-- ────────────────────────
-- ``app/closure/policy.py`` used to treat a tenant with no row in
-- ``aisoc_closure_policies`` as permission to auto-close at the process-wide
-- threshold (``AISOC_AUTO_CLOSE_THRESHOLD``, 0.85). Every tenant therefore
-- auto-closed from the first confident benign verdict, including one that had
-- never opened the screen. The absence of a decision was being read as a
-- decision.
--
-- From now on, automatic closure requires an explicit, enabled policy row.
--
-- What this migration does NOT do, and why
-- ────────────────────────────────────────
-- It creates no policy rows. It would be easy to write an INSERT that gave a
-- row to every tenant that had auto-closed in the past — and that would be
-- the same mistake in a different place: inferring authorization from
-- behaviour that the old default produced. A tenant that was auto-closing
-- yesterday *because nobody had decided anything* has still not decided
-- anything. Only a human may grant this, through the console or by the SQL in
-- the rollback section below.
--
-- Deliberately configured tenants are untouched. A row that says
-- ``enabled = true`` keeps auto-closing at its own threshold, and a row that
-- says ``enabled = false`` keeps refusing: both are explicit, and this change
-- is about the tenants who had neither.
--
-- What it does instead
-- ────────────────────
-- Writes one row per existing tenant saying which side of the change that
-- tenant fell on, at the moment the migration ran. That is the "recorded
-- outcome": a deployment upgrading into default-deny can answer "which of my
-- tenants just lost automatic closure" with a query rather than with a
-- support ticket from the tenant.
--
-- Forward-only. Re-running it is safe and records nothing a second time.

CREATE TABLE IF NOT EXISTS aisoc_closure_authorization_migration (
    tenant_id           UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,

    -- TRUE when the tenant already had at least one row in
    -- `aisoc_closure_policies` at migration time, i.e. somebody had made a
    -- deliberate choice that this change preserves verbatim.
    had_explicit_policy BOOLEAN NOT NULL,

    -- TRUE when at least one of those rows was enabled. NULL when there were
    -- no rows at all — "not applicable", which is a different fact from
    -- "there was a row and it was off".
    was_enabled         BOOLEAN,

    -- The tenant's posture after this change, in one word, so the common
    -- question needs no joins: 'preserved' (an explicit row decides, as
    -- before) or 'requires_authorization' (closure was implicit and is now
    -- withheld until somebody authorizes it).
    outcome             TEXT NOT NULL
                        CHECK (outcome IN ('preserved', 'requires_authorization')),

    recorded_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE aisoc_closure_authorization_migration IS
    'Per-tenant outcome of the closure default-deny change (migration 122). '
    'An audit record, not a control: nothing reads it to make a decision.';

INSERT INTO aisoc_closure_authorization_migration (tenant_id, had_explicit_policy, was_enabled, outcome)
SELECT
    t.id,
    p.row_count > 0,
    CASE WHEN p.row_count > 0 THEN p.enabled_count > 0 ELSE NULL END,
    CASE WHEN p.row_count > 0 THEN 'preserved' ELSE 'requires_authorization' END
FROM tenants t
LEFT JOIN LATERAL (
    SELECT
        COUNT(*)                                       AS row_count,
        COUNT(*) FILTER (WHERE c.enabled)              AS enabled_count
    FROM aisoc_closure_policies c
    WHERE c.tenant_id = t.id
) p ON TRUE
ON CONFLICT (tenant_id) DO NOTHING;

-- Same posture as every other tenant-scoped table here. The read is an audit
-- read, so the usual `current_tenant_id() IS NULL` arm is kept: a platform
-- operator running the upgrade report has no single tenant bound.
ALTER TABLE aisoc_closure_authorization_migration ENABLE ROW LEVEL SECURITY;
ALTER TABLE aisoc_closure_authorization_migration FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON aisoc_closure_authorization_migration;
CREATE POLICY tenant_isolation ON aisoc_closure_authorization_migration
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)
    WITH CHECK (tenant_id = current_tenant_id());

GRANT SELECT, INSERT, UPDATE, DELETE ON aisoc_closure_authorization_migration TO aisoc_app;

-- Upgrade report — which tenants just lost implicit automatic closure:
--
--     SELECT t.slug, m.outcome
--       FROM aisoc_closure_authorization_migration m
--       JOIN tenants t ON t.id = m.tenant_id
--      WHERE m.outcome = 'requires_authorization'
--      ORDER BY t.slug;
--
-- Rollback
-- ────────
-- There is no schema change to undo beyond dropping the audit table:
--
--     DROP TABLE IF EXISTS aisoc_closure_authorization_migration;
--
-- Restoring the previous *behaviour* for a tenant is a deliberate grant, and
-- is the same statement the console writes. Per tenant, with a reason, never
-- in bulk across the table:
--
--     INSERT INTO aisoc_closure_policies
--         (tenant_id, alert_class, enabled, threshold, require_grant, updated_by, reason)
--     VALUES ('<tenant-uuid>'::uuid, NULL, TRUE, 0.85, FALSE,
--             '<operator>', 'restoring pre-122 automatic closure, reviewed <date>');
--
-- `require_grant = FALSE` reproduces the old default exactly. Leaving it TRUE
-- is the safer choice: closure then additionally waits for an `auto_close`
-- grant that shadow mode has to earn.
