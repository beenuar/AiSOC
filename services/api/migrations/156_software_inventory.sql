-- Wave 2, Phase 5.4 — "where does package P at version V run?"
--
-- What existed, and why it could not answer that
-- ----------------------------------------------
-- `assets` (migration 013) and `asset_vulnerabilities` are **host-level**.
-- They record that a host exists and that a CVE applies to it; neither
-- records what is installed. `packs/aisoc-inventory-baseline.yaml` already
-- queried `deb_packages`, `rpm_packages` and `homebrew_packages` — and not
-- the Windows `programs` table, so the largest estate in most tenants was
-- not queried at all — but **nothing consumed the results**. The queries ran
-- on the endpoint, the rows came back, and there was nowhere to put them.
--
-- So on the day a maintainer is asked "are we running the version of this
-- library that was just published as exploited, and where?", the honest
-- answer the product could give was that it did not know.
--
-- One table, two sources
-- ----------------------
-- Package rows arrive from two places and they are deliberately the same
-- shape: an endpoint agent enumerating what is installed, and a code
-- platform's SBOM describing what a repository depends on. `source`
-- distinguishes them because the answer differs in kind — `osquery` means
-- this is installed on a running host, `sbom` means a repository declares
-- it — and an operator deciding where to patch must not have the two
-- silently merged.
--
-- `asset_id` is nullable for exactly that reason: an SBOM package belongs to
-- a repository, not to a host, and inventing a host for it would be a
-- fabricated location on the one surface whose entire job is to say where
-- something runs.
--
-- Why a `(tenant, source, location, name, version)` key
-- -----------------------------------------------------
-- The same package at the same version on two hosts is two facts, and
-- collapsing them would answer "where does it run?" with one host. The same
-- package at *different* versions on one host is also two facts — that is
-- the normal state of a machine with several runtimes installed, and
-- upserting on name alone would make the inventory report whichever one was
-- seen last.

CREATE TABLE IF NOT EXISTS software_packages (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Where this was observed. NULL for an SBOM package, which belongs to a
    -- repository rather than a host; `location` carries the repository.
    asset_id       UUID        REFERENCES assets(id) ON DELETE CASCADE,

    -- 'osquery' = installed on a running host. 'sbom' = declared by a
    -- repository. Kept distinct because the remediation differs.
    source         TEXT        NOT NULL CHECK (source IN ('osquery', 'sbom')),

    -- Hostname or repository full name. Denormalised deliberately: the
    -- answer to "where does it run?" must survive the asset row being
    -- re-keyed, and an SBOM package has no asset to join to at all.
    location       TEXT        NOT NULL,

    name           TEXT        NOT NULL,
    version        TEXT        NOT NULL,

    -- 'deb' | 'rpm' | 'homebrew' | 'windows' | 'npm' | 'pypi' | ... — the
    -- packaging ecosystem, which is what makes two identically-named
    -- packages different things.
    ecosystem      TEXT        NOT NULL,

    -- Package URL when the source gives one. Not synthesised: a purl this
    -- product invented would be matched against advisories that key on a
    -- real one, and a wrong match on this surface sends somebody to patch
    -- the wrong thing.
    purl           TEXT,

    first_seen     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata       JSONB       NOT NULL DEFAULT '{}',

    CONSTRAINT software_packages_identity
        UNIQUE (tenant_id, source, location, name, version, ecosystem)
);

COMMENT ON TABLE software_packages IS
    'Package-level inventory. `assets` is host-level and cannot answer '
    '"where does package P at version V run?".';
COMMENT ON COLUMN software_packages.source IS
    '''osquery'' = installed on a running host; ''sbom'' = declared by a '
    'repository. Not merged: the remediation differs.';
COMMENT ON COLUMN software_packages.asset_id IS
    'NULL for an SBOM package, which belongs to a repository rather than a '
    'host. Inventing a host would be a fabricated location.';
COMMENT ON COLUMN software_packages.purl IS
    'Only when the source supplies one. A synthesised purl would be matched '
    'against advisories keyed on a real one.';

-- The question this table exists for, in both of its forms: by name alone
-- ("anything running log4j?") and by name and version ("specifically 2.14").
CREATE INDEX IF NOT EXISTS idx_software_packages_lookup
    ON software_packages (tenant_id, lower(name), version);

-- "What is on this host?", which is the pivot from an alert.
CREATE INDEX IF NOT EXISTS idx_software_packages_location
    ON software_packages (tenant_id, location);

-- RLS, mirroring `alerts_tenant` from `002_rls.sql`.
--
-- Writes arrive from the ingest path, which — like fusion — holds no request
-- and binds no tenant GUC, so a `WITH CHECK` without the unbound arm would
-- refuse every insert. Migration 151 records that failure in full: the write
-- is best-effort, the exception is logged, and the surface then reads as
-- "this tenant has no software" rather than as an error.
ALTER TABLE software_packages ENABLE ROW LEVEL SECURITY;
ALTER TABLE software_packages FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS software_packages_tenant ON software_packages;
CREATE POLICY software_packages_tenant ON software_packages
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)
    WITH CHECK (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON software_packages TO aisoc_app';
    END IF;
END $$;

-- Rollback
-- ────────
--     DROP TABLE IF EXISTS software_packages;
--
-- Nothing else changes. The osquery pack keeps running and its rows stop
-- being stored, which is the pre-5.4 behaviour.
