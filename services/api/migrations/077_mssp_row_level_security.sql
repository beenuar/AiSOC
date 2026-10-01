-- Row-level security on the six `mssp_*` tables that had none.
--
-- `mssp_tenant_metrics` already had a policy; these six did not, so the only
-- thing standing between one MSSP's portfolio and another's was the query
-- layer. That is not a hypothetical: `POST /mssp/overrides` with
-- `action: "exclude"` wrote a caller-supplied child tenant id onto a row that
-- the effective-rule resolver then read back filtered on the *victim's*
-- tenant id, so any authenticated user could silently delete a critical
-- detection from any other tenant. The route guard was fixed; this is the
-- layer that would have contained it if the guard had been wrong, which is
-- the whole argument for defence in depth.
--
-- These rows are not shaped like the rest of the schema. A normal table has
-- one `tenant_id` and the policy is `tenant_id = current_tenant_id()`. An
-- MSSP row joins **two** tenants — the parent that manages the relationship
-- and the child that is managed — and both have a legitimate read. A policy
-- naming only the parent would hide from a customer the overrides being
-- applied to their own detections, which is the transparency the MSSP
-- adoption flow was rebuilt around: a child must invite a parent, so a child
-- must also be able to see what that parent has done.
--
-- So each policy is `parent = current_tenant_id() OR child = current_tenant_id()`.
--
-- `mssp_rule_pack_rules` has no tenant column at all; it joins a pack to a
-- rule. Its tenancy is inherited, so the policy is an EXISTS over the
-- owning pack. Writing it any other way would mean denormalising a tenant id
-- onto a join table and keeping two copies in step.
--
-- `current_tenant_id() IS NULL` is permitted throughout, matching every other
-- policy in this schema: a connection that has not set the context is an
-- out-of-band migration or an exempt superuser, and the services now connect
-- as the non-exempt `aisoc_app` role, so they cannot reach that branch.

BEGIN;

-- ── parent/child pairs ──────────────────────────────────────────────────────

ALTER TABLE mssp_delegations ENABLE ROW LEVEL SECURITY;
ALTER TABLE mssp_delegations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS mssp_delegations_tenant ON mssp_delegations;
CREATE POLICY mssp_delegations_tenant ON mssp_delegations
    USING (
        parent_tenant_id = current_tenant_id()
        OR child_tenant_id = current_tenant_id()
        OR current_tenant_id() IS NULL
    );

ALTER TABLE mssp_rule_overrides ENABLE ROW LEVEL SECURITY;
ALTER TABLE mssp_rule_overrides FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS mssp_rule_overrides_tenant ON mssp_rule_overrides;
CREATE POLICY mssp_rule_overrides_tenant ON mssp_rule_overrides
    USING (
        parent_tenant_id = current_tenant_id()
        OR child_tenant_id = current_tenant_id()
        OR current_tenant_id() IS NULL
    );

ALTER TABLE mssp_tenant_notes ENABLE ROW LEVEL SECURITY;
ALTER TABLE mssp_tenant_notes FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS mssp_tenant_notes_tenant ON mssp_tenant_notes;
CREATE POLICY mssp_tenant_notes_tenant ON mssp_tenant_notes
    USING (
        parent_id = current_tenant_id()
        OR child_id = current_tenant_id()
        OR current_tenant_id() IS NULL
    );

-- ── parent-owned, and the recursion that forced a schema change ────────────
--
-- The first draft wrote these two policies as mutual subqueries: a pack was
-- visible to its parent or to any tenant with an assignment, and an
-- assignment was visible to its child or to the owning pack's parent. Both
-- are correct statements about who should see what, and together they are
-- unusable — Postgres answers `infinite recursion detected in policy for
-- relation "mssp_rule_packs"` on the first SELECT.
--
-- Nothing static caught it. `check_rls_policy_shape.py` passed, because the
-- policies have the right shape; it took running them against a real
-- Postgres with two seeded MSSPs to see it at all.
--
-- The cycle is broken by giving the assignment row its own
-- `parent_tenant_id`, so its policy needs no subquery. That is a
-- denormalisation, and a denormalisation that drifts is worse than the
-- recursion it replaced — so it is not maintained by a trigger or by
-- application code, it is a **composite foreign key**: the pair
-- `(pack_id, parent_tenant_id)` must exist in `mssp_rule_packs`. A row
-- naming the wrong parent cannot be inserted, and a pack cannot change
-- owner without the referencing rows moving with it.
--
-- The alternative was a SECURITY DEFINER helper reading the pack table with
-- RLS bypassed. This schema has been bitten by exactly that before — two
-- views that read as their owner silently undid tenant isolation — so a
-- constraint the database enforces is the better trade.

-- Added only if absent, never dropped-then-added. The foreign key below
-- depends on this constraint, so a DROP on a second run fails with
-- `Use DROP ... CASCADE to drop the dependent objects too` — which is how
-- a migration that applied cleanly the first time breaks on re-run, and
-- re-runs happen whenever a deployment replays its chain.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conname = 'mssp_rule_packs_id_parent_key'
           AND conrelid = 'mssp_rule_packs'::regclass
    ) THEN
        ALTER TABLE mssp_rule_packs
            ADD CONSTRAINT mssp_rule_packs_id_parent_key UNIQUE (id, parent_tenant_id);
    END IF;
END
$$;

ALTER TABLE mssp_rule_pack_assignments
    ADD COLUMN IF NOT EXISTS parent_tenant_id UUID;

-- Backfill before the constraint, or an existing deployment cannot migrate.
UPDATE mssp_rule_pack_assignments a
   SET parent_tenant_id = p.parent_tenant_id
  FROM mssp_rule_packs p
 WHERE p.id = a.pack_id
   AND a.parent_tenant_id IS DISTINCT FROM p.parent_tenant_id;

ALTER TABLE mssp_rule_pack_assignments
    ALTER COLUMN parent_tenant_id SET NOT NULL;
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conname = 'mssp_rule_pack_assignments_pack_parent_fk'
           AND conrelid = 'mssp_rule_pack_assignments'::regclass
    ) THEN
        ALTER TABLE mssp_rule_pack_assignments
            ADD CONSTRAINT mssp_rule_pack_assignments_pack_parent_fk
            FOREIGN KEY (pack_id, parent_tenant_id)
            REFERENCES mssp_rule_packs (id, parent_tenant_id) ON DELETE CASCADE;
    END IF;
END
$$;

-- No subquery: this is the end of the chain, so nothing it reads can read
-- back into it.
ALTER TABLE mssp_rule_pack_assignments ENABLE ROW LEVEL SECURITY;
ALTER TABLE mssp_rule_pack_assignments FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS mssp_rule_pack_assignments_tenant ON mssp_rule_pack_assignments;
CREATE POLICY mssp_rule_pack_assignments_tenant ON mssp_rule_pack_assignments
    USING (
        child_tenant_id = current_tenant_id()
        OR parent_tenant_id = current_tenant_id()
        OR current_tenant_id() IS NULL
    );

-- Reads assignments, which now reads nothing. One level, no cycle.
ALTER TABLE mssp_rule_packs ENABLE ROW LEVEL SECURITY;
ALTER TABLE mssp_rule_packs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS mssp_rule_packs_tenant ON mssp_rule_packs;
CREATE POLICY mssp_rule_packs_tenant ON mssp_rule_packs
    USING (
        parent_tenant_id = current_tenant_id()
        -- A child can see a pack assigned to them. Without this half the
        -- assignment row is readable while the pack it names is not, which
        -- renders as a detection set with no name.
        OR EXISTS (
            SELECT 1
              FROM mssp_rule_pack_assignments a
             WHERE a.pack_id = mssp_rule_packs.id
               AND a.child_tenant_id = current_tenant_id()
        )
        OR current_tenant_id() IS NULL
    );

-- Which rules a pack contains has no tenant of its own. Reads packs, which
-- reads assignments, which reads nothing: two levels, still no cycle.
ALTER TABLE mssp_rule_pack_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE mssp_rule_pack_rules FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS mssp_rule_pack_rules_tenant ON mssp_rule_pack_rules;
CREATE POLICY mssp_rule_pack_rules_tenant ON mssp_rule_pack_rules
    USING (
        EXISTS (
            SELECT 1
              FROM mssp_rule_packs p
             WHERE p.id = mssp_rule_pack_rules.pack_id
        )
        OR current_tenant_id() IS NULL
    );

-- The EXISTS above reads `mssp_rule_packs` from inside a policy on another
-- table, and a policy subquery runs as the querying role — so `aisoc_app`
-- needs SELECT on it, or the EXISTS raises a permission error instead of
-- returning false. That fails closed, but an operator reading the error
-- would go looking for a missing grant on the wrong table.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        GRANT SELECT ON mssp_rule_packs, mssp_rule_pack_assignments TO aisoc_app;
    END IF;
END
$$;

COMMIT;
