-- 064: who agreed that this tenant's files may leave, and what left.
--
-- Two tables, because two different questions get asked later and neither
-- answers the other.
--
--   aisoc_sandbox_upload_policy   may files from tenant T go to provider P,
--                                 who agreed, and to which words
--   aisoc_sandbox_submissions     what was actually decided, per artefact
--
-- Why the consent is per (tenant, provider) and not per tenant
-- ------------------------------------------------------------
-- Consent is about where the file goes. An operator content to send a sample
-- to a sandbox running in their own rack has agreed to nothing about a hosted
-- service, and one flag would treat those as the same question. The primary
-- key is the pair for that reason.
--
-- Why the consent text version is stored
-- --------------------------------------
-- The first commercial provider wired here publishes submitted samples: a
-- stored report carries `visibility: "public"` and `tlp: "clear"`, so an
-- upload is a disclosure to the internet rather than to a vendor. The consent
-- text says that in those words. If the wording ever changes, what a tenant
-- previously agreed to did not, and a bare boolean cannot say which sentence
-- it was. `consent_text_version` travels onto the row so an audit can.
--
-- Why refusals are recorded and not only uploads
-- ----------------------------------------------
-- The common row here is a refusal, and it is the more useful one. "Nothing
-- was uploaded because the hash was already known" and "nothing was uploaded
-- because this tenant has not consented" are the two answers an operator
-- needs when asked what happened to an attachment, and a table holding only
-- successful uploads answers neither. `uploaded` is the single boolean that
-- means bytes left the deployment.

CREATE TABLE IF NOT EXISTS aisoc_sandbox_upload_policy (
    tenant_id            UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider             TEXT        NOT NULL,
    -- Off. Not defaulted on for any provider, local ones included: a local
    -- sandbox still writes the file to a system with its own retention.
    uploads_enabled      BOOLEAN     NOT NULL DEFAULT FALSE,
    consent_text_version TEXT,
    consented_by         UUID        REFERENCES users(id) ON DELETE SET NULL,
    consented_at         TIMESTAMPTZ,
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, provider)
);

COMMENT ON TABLE aisoc_sandbox_upload_policy IS
    'Per-tenant, per-provider consent to upload customer files for analysis. '
    'Absence of a row means no consent, which is why every read defaults to false '
    'rather than requiring a row to exist.';
COMMENT ON COLUMN aisoc_sandbox_upload_policy.consent_text_version IS
    'Which version of the disclosure text was shown when this was enabled. '
    'A boolean with no record of the sentence behind it cannot be audited.';

CREATE TABLE IF NOT EXISTS aisoc_sandbox_submissions (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider       TEXT        NOT NULL,
    -- 'file' | 'url' | 'hash'
    artifact_kind  TEXT        NOT NULL,
    sha256         TEXT,
    file_name      TEXT,
    -- The service.SandboxOutcome word: known | pending | not_seen |
    -- upload_refused | could_not_check.
    outcome        TEXT        NOT NULL,
    -- The policy.UploadRefusal word when the outcome was a refusal.
    refusal        TEXT,
    reason         TEXT        NOT NULL DEFAULT '',
    -- TRUE only when bytes left this deployment. The column the question
    -- "did any customer file go to a third party" is answered from.
    uploaded       BOOLEAN     NOT NULL DEFAULT FALSE,
    -- What the analysis is visible to, in the provider's own words.
    visibility     TEXT,
    provider_handle TEXT,
    requested_by   UUID        REFERENCES users(id) ON DELETE SET NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE aisoc_sandbox_submissions IS
    'Every file/URL analysis decision, allowed or refused. Refusals are the '
    'common row and the more useful one: it is what answers "what happened to '
    'this attachment" when nothing was uploaded.';
COMMENT ON COLUMN aisoc_sandbox_submissions.uploaded IS
    'TRUE only when file bytes were transmitted to the provider.';

CREATE INDEX IF NOT EXISTS idx_sandbox_submissions_tenant_created
    ON aisoc_sandbox_submissions (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sandbox_submissions_sha256
    ON aisoc_sandbox_submissions (tenant_id, sha256) WHERE sha256 IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_sandbox_submissions_uploaded
    ON aisoc_sandbox_submissions (tenant_id, created_at DESC) WHERE uploaded;

-- Row-level security. The `OR current_tenant_id() IS NULL` arm is the one that
-- lets the cross-tenant workers (retention purge, tenant deletion) read these
-- tables on a connection that binds no tenant; dropping it makes those
-- silently see nothing. FORCE so the owner does not walk past.
ALTER TABLE aisoc_sandbox_upload_policy ENABLE ROW LEVEL SECURITY;
ALTER TABLE aisoc_sandbox_upload_policy FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS aisoc_sandbox_upload_policy_tenant ON aisoc_sandbox_upload_policy;
CREATE POLICY aisoc_sandbox_upload_policy_tenant ON aisoc_sandbox_upload_policy
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

ALTER TABLE aisoc_sandbox_submissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE aisoc_sandbox_submissions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS aisoc_sandbox_submissions_tenant ON aisoc_sandbox_submissions;
CREATE POLICY aisoc_sandbox_submissions_tenant ON aisoc_sandbox_submissions
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

-- 061 set ALTER DEFAULT PRIVILEGES so new tables pick these up, but only for
-- tables created by the role that ran it. Granting explicitly means a chain
-- replayed by a different owner still leaves the runtime role able to work.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON aisoc_sandbox_upload_policy TO aisoc_app;
        GRANT SELECT, INSERT, UPDATE, DELETE ON aisoc_sandbox_submissions TO aisoc_app;
    END IF;
END
$$;
