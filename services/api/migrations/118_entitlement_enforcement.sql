-- Opt-in enforcement of the per-tenant limits that were reported and never applied.
--
-- Depth 8.1 (parity 4.5's second bullet).
--
-- `app/services/entitlements.py` says in its own docstring that enforcement
-- is not its job:
--
--   > So the point of this module is not enforcement — it is making
--   > exhaustion *visible*, per tenant, across a whole portfolio, before
--   > anyone phones in.
--
-- That was the right first move and it leaves an operator who configured a
-- ceiling with a number the product reports and never applies. This adds the
-- second half, and the shape of it is the whole decision.
--
-- ── Why opt-in, per tenant, per key ─────────────────────────────────────────
--
-- Enforcement that arrives switched on would, on upgrade, start refusing work
-- on every deployment whose operator had written a ceiling for *reporting*.
-- `tenants.limits` has been a reporting input since it existed, so the
-- numbers already in it were never chosen as hard caps and must not silently
-- become them. Absence of a row therefore means **not enforced**, and no
-- migration writes one: a backfill of a row per tenant would change the
-- meaning of every value already stored.
--
-- Per key rather than per tenant, because the keys are not alike. Refusing a
-- fifth connector is a product decision an operator may well want; refusing
-- to triage an alert because the month's AI quota ran out stops a SOC
-- working, and an operator should have to say so one key at a time.
CREATE TABLE IF NOT EXISTS aisoc_tenant_entitlement_enforcement (
    tenant_id   UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    limit_key   TEXT        NOT NULL,
    enforce     BOOLEAN     NOT NULL DEFAULT FALSE,
    updated_by  UUID        REFERENCES users(id) ON DELETE SET NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (tenant_id, limit_key)
);

COMMENT ON TABLE aisoc_tenant_entitlement_enforcement IS
    'Which per-tenant limits are enforced rather than merely reported. No row means not enforced.';

-- The vocabulary is `entitlements.LIMIT_KEYS`, and a typo stored here would
-- match no key, enforce nothing, and leave an operator reading a settings
-- page that says a limit is enforced while it is not — the quiet direction.
-- Checked in SQL as well as in the route, because the route is not the only
-- thing that can write this table.
--
-- Listed rather than derived: there is no table of keys to reference, and
-- inventing one would put the vocabulary in two places. Adding a key means
-- editing this constraint, which is the visible edit it should be.
ALTER TABLE aisoc_tenant_entitlement_enforcement
    DROP CONSTRAINT IF EXISTS aisoc_tenant_entitlement_enforcement_key_known;
ALTER TABLE aisoc_tenant_entitlement_enforcement
    ADD CONSTRAINT aisoc_tenant_entitlement_enforcement_key_known
    CHECK (limit_key IN ('connectors', 'seats', 'alerts_per_day', 'triages_per_month'));

ALTER TABLE aisoc_tenant_entitlement_enforcement ENABLE ROW LEVEL SECURITY;
ALTER TABLE aisoc_tenant_entitlement_enforcement FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON aisoc_tenant_entitlement_enforcement;
CREATE POLICY tenant_isolation ON aisoc_tenant_entitlement_enforcement
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)
    WITH CHECK (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE
            ON aisoc_tenant_entitlement_enforcement TO aisoc_app;
    END IF;
END
$$;
