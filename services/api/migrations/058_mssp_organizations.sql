-- Migration 058: a real operator organisation above tenants
--
-- Migration 012 added `tenants.parent_tenant_id`, which makes the managing
-- provider *a tenant*. That is enough to draw a tree and not enough to run a
-- managed service, for three reasons:
--
--   1. It conflates the operator with a security boundary. Every consumer of
--      `current_user.tenant_id` on an /mssp route is simultaneously asking
--      "who is the operator" and "whose data is this", and those must be
--      different questions or a cross-tenant surface has no boundary to
--      enforce.
--   2. There is no per-principal scoping. `parent_tenant_id` grants every
--      user of the parent tenant the same reach over every child. A managed
--      provider assigns analysts to accounts; it cannot express that here.
--   3. `ON DELETE SET NULL` means deleting the parent silently detaches the
--      entire portfolio with no record that it ever existed.
--
-- So the parent concept moves up a level, onto its own object, and the
-- relationship becomes explicit membership rather than an inherited column.
--
-- `tenants.parent_tenant_id` is kept and backfilled from, not dropped: it is
-- what `GET /api/v1/mssp/children` and `mssp_rule_resolver` read today, and
-- existing deployments have data in it.

BEGIN;

-- 1. The operator ------------------------------------------------------------
--
-- `home_tenant_id` is the tenant the operator's own staff log in to. It
-- cascades: if that tenant is erased under a deletion request, the operator
-- object goes with it. The managed tenants do *not* — they are separate
-- customers and simply become unclaimed. Getting this backwards is how an
-- offboarding turns into someone else's outage.
CREATE TABLE IF NOT EXISTS organizations (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug           TEXT NOT NULL UNIQUE,
    name           TEXT NOT NULL,
    kind           TEXT NOT NULL DEFAULT 'mssp'
                   CHECK (kind IN ('mssp', 'enterprise')),
    home_tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    is_active      BOOLEAN NOT NULL DEFAULT TRUE,
    settings       JSONB NOT NULL DEFAULT '{}',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_organizations_home_tenant
    ON organizations (home_tenant_id) WHERE home_tenant_id IS NOT NULL;

-- 2. Who belongs to the operator, and with what authority ---------------------
--
-- Two axes, deliberately separated, because they answer different questions:
--
--   breadth   owner/admin reach the whole portfolio; operator/viewer reach
--             only tenants granted to them in organization_member_tenants,
--             and reach nothing at all when they have no grants.
--   authority owner/admin/operator may act; viewer is read-only.
--
-- The empty case is the important one. A member with no grants gets an empty
-- portfolio, never an unfiltered one — "no scope" must not degrade into "all
-- scopes", which is the shape every cross-tenant leak in this codebase has
-- had.
CREATE TABLE IF NOT EXISTS organization_members (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id     UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_role   TEXT NOT NULL DEFAULT 'viewer'
               CHECK (org_role IN ('owner', 'admin', 'operator', 'viewer')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_org_members_user ON organization_members (user_id);

-- 3. The managed portfolio ----------------------------------------------------
--
-- `UNIQUE (tenant_id)` is a boundary, not a convenience: it makes it
-- impossible for two operators to both claim the same customer, so "which
-- portfolio does this tenant belong to" has exactly one answer.
CREATE TABLE IF NOT EXISTS organization_tenants (
    org_id       UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    tenant_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    relationship TEXT NOT NULL DEFAULT 'managed'
                 CHECK (relationship IN ('managed', 'own')),
    onboarded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    onboarded_by UUID REFERENCES users(id) ON DELETE SET NULL,
    PRIMARY KEY (org_id, tenant_id),
    UNIQUE (tenant_id)
);

CREATE INDEX IF NOT EXISTS idx_org_tenants_tenant ON organization_tenants (tenant_id);

-- 4. Which managed tenants a given principal may act on -----------------------
--
-- The composite foreign keys are the point. Granting a member a tenant the
-- organisation does not manage is rejected by Postgres, not by whichever
-- application code path happened to write the row — and a tenant leaving the
-- portfolio takes every grant over it along, so a revoked customer cannot
-- leave a live grant behind.
CREATE TABLE IF NOT EXISTS organization_member_tenants (
    org_id     UUID NOT NULL,
    user_id    UUID NOT NULL,
    tenant_id  UUID NOT NULL,
    granted_by UUID REFERENCES users(id) ON DELETE SET NULL,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, user_id, tenant_id),
    FOREIGN KEY (org_id, user_id)
        REFERENCES organization_members (org_id, user_id) ON DELETE CASCADE,
    FOREIGN KEY (org_id, tenant_id)
        REFERENCES organization_tenants (org_id, tenant_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_org_member_tenants_user
    ON organization_member_tenants (org_id, user_id);

-- 5. Backfill from the tenant-tree model --------------------------------------
--
-- Every tenant that already names a parent becomes a managed tenant of an
-- organisation derived from that parent. Idempotent, so re-running the
-- migration chain is safe.
INSERT INTO organizations (slug, name, kind, home_tenant_id)
SELECT
    'org-' || p.slug,
    p.name,
    'mssp',
    p.id
FROM tenants p
WHERE EXISTS (SELECT 1 FROM tenants c WHERE c.parent_tenant_id = p.id)
ON CONFLICT (slug) DO NOTHING;

-- The operator's own tenant joins its portfolio as `own`, so a provider that
-- also runs its own estate sees it in the same rollup.
INSERT INTO organization_tenants (org_id, tenant_id, relationship)
SELECT o.id, o.home_tenant_id, 'own'
FROM organizations o
WHERE o.home_tenant_id IS NOT NULL
ON CONFLICT DO NOTHING;

INSERT INTO organization_tenants (org_id, tenant_id, relationship)
SELECT o.id, c.id, 'managed'
FROM organizations o
JOIN tenants c ON c.parent_tenant_id = o.home_tenant_id
ON CONFLICT DO NOTHING;

-- Users of the operator's own tenant become members. A tenant admin becomes
-- an org owner; everyone else becomes an operator, which can act but only on
-- tenants explicitly granted to them — so the backfill cannot widen anyone's
-- reach beyond what an administrator later chooses to grant.
INSERT INTO organization_members (org_id, user_id, org_role)
SELECT
    o.id,
    u.id,
    CASE WHEN u.role IN ('admin', 'tenant_admin', 'owner') THEN 'owner' ELSE 'operator' END
FROM organizations o
JOIN users u ON u.tenant_id = o.home_tenant_id
ON CONFLICT (org_id, user_id) DO NOTHING;

COMMIT;
