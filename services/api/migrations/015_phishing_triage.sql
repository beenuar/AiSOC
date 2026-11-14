-- Migration 015: Email-security + phishing-triage workflow
-- Stores submitted email/URL artifacts and triage verdicts.

CREATE TABLE IF NOT EXISTS aisoc_phishing_submissions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID,
    submitted_by    TEXT,
    -- artifact
    artifact_kind   TEXT NOT NULL DEFAULT 'email'
                        CHECK (artifact_kind IN ('email','url','attachment','domain')),
    raw_content     TEXT,
    sender          TEXT,
    subject         TEXT,
    urls            TEXT[] DEFAULT ARRAY[]::TEXT[],
    attachments     JSONB DEFAULT '[]'::jsonb,
    -- triage
    verdict         TEXT DEFAULT 'pending'
                        CHECK (verdict IN ('pending','benign','phishing','spam','malware','unknown')),
    confidence      FLOAT,
    indicators      JSONB DEFAULT '[]'::jsonb,   -- IOCs extracted
    mitre_technique TEXT,
    -- case linkage
    case_id         UUID REFERENCES aisoc_cases(id) ON DELETE SET NULL,
    -- metadata
    submitted_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    triaged_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_aisoc_phishing_verdict  ON aisoc_phishing_submissions (verdict);
CREATE INDEX IF NOT EXISTS idx_aisoc_phishing_tenant   ON aisoc_phishing_submissions (tenant_id);
