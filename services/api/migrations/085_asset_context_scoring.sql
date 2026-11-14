-- Asset and identity context that changes the queue order.
--
-- Gap-closure wave 11.
--
-- `assets.criticality` is a free-text string that reaches a prompt and
-- a sort order and nothing else. Two alerts of equal severity, one on
-- a domain controller and one on a meeting-room display, arrive in the
-- queue in the order they were raised — and an analyst finds out which
-- is which by reading the hostname.
--
-- Three things were missing, and the third is the one that makes the
-- other two actionable.
--
-- **A score, not a label.** "high" cannot be multiplied by anything.
-- Prioritisation needs a number, and the number has to be derived from
-- the label rather than typed alongside it, or the two drift.
--
-- **Privileged accounts.** No such field exists anywhere. An alert on
-- a service account with domain-admin rights is not the same alert as
-- one on a contractor's laptop login, and nothing in the schema could
-- say so.
--
-- **Vulnerability context from the tenant's own inventory.**
-- `asset_vulnerabilities` exists and is read only by the enrichment
-- response — so "is this host running something on the KEV catalogue"
-- is answerable from data already held and is not asked.
--
-- And `alert_asset_correlations` (migration 013) has had **zero
-- readers and zero writers** since it was created. It is the join that
-- makes all of the above reachable from an alert, which is why it is
-- wired here rather than deleted.

-- ── Identity privilege ─────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS identity_privilege (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- The principal as the log sources name it. Lowercased by the
    -- application before write: `SVC-Backup` and `svc-backup` are one
    -- account, and two rows would make the lookup depend on which
    -- connector happened to report first.
    principal       TEXT NOT NULL,

    -- Standing privilege the account holds. Separate from `is_admin`
    -- because the useful question is usually "how much", not "yes or
    -- no" — a break-glass account and a helpdesk password-reset role
    -- are both privileged and not equally so.
    privilege_tier  TEXT NOT NULL DEFAULT 'standard',

    -- A service account behaves differently from a human one: no
    -- interactive logons, predictable hours, and a compromise usually
    -- means a stolen key rather than a phished password.
    is_service      BOOLEAN NOT NULL DEFAULT FALSE,
    is_break_glass  BOOLEAN NOT NULL DEFAULT FALSE,

    source          TEXT,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (tenant_id, principal)
);

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'ck_identity_privilege_tier') THEN
        ALTER TABLE identity_privilege
            ADD CONSTRAINT ck_identity_privilege_tier
            CHECK (privilege_tier IN ('standard', 'elevated', 'admin', 'domain_admin'));
    END IF;
END
$$;

CREATE INDEX IF NOT EXISTS ix_identity_privilege_tenant ON identity_privilege (tenant_id, principal);

ALTER TABLE identity_privilege ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity_privilege FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON identity_privilege;
CREATE POLICY tenant_isolation ON identity_privilege
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)
    WITH CHECK (tenant_id = current_tenant_id());

-- ── Effective priority on the alert ────────────────────────────────────────
--
-- Stored rather than computed at read time, for two reasons. The queue
-- sorts on it and a computed sort over a join is the thing that makes
-- a queue slow at exactly the moment it is busiest; and an analyst
-- asking "why was this top of my queue" needs the answer that applied
-- *then*, not the one today's CMDB produces.

ALTER TABLE alerts ADD COLUMN IF NOT EXISTS priority_score INTEGER;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS priority_rationale JSONB NOT NULL DEFAULT '[]'::jsonb;

CREATE INDEX IF NOT EXISTS ix_alerts_priority
    ON alerts (tenant_id, priority_score DESC NULLS LAST, created_at DESC);

COMMENT ON COLUMN alerts.priority_score IS
    'Severity weighted by asset criticality, identity privilege and known-exploited '
    'vulnerability exposure. NULL means not yet scored — distinct from 0, which means '
    'scored and genuinely low.';

COMMENT ON COLUMN alerts.priority_rationale IS
    'Each factor that moved the score, with its contribution. An ordering a person '
    'cannot interrogate is one they stop trusting the first time it surprises them.';

-- ── Make the correlation table reachable ───────────────────────────────────
--
-- `alert_asset_correlations` has had no reader and no writer since
-- migration 013. The index below is what the scorer needs to resolve
-- an alert's assets without a sequential scan.

CREATE INDEX IF NOT EXISTS idx_aacorel_asset_lookup
    ON alert_asset_correlations (tenant_id, alert_id, asset_id);

COMMENT ON TABLE alert_asset_correlations IS
    'Which assets an alert touches. Created in migration 013 and unread until wave 11 — '
    'it is the join that makes asset criticality reachable from an alert at all.';
