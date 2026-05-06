-- Migration 013: Compliance evidence trails
-- Audit-grade evidence records linked to cases with hash-chain integrity.

CREATE TABLE IF NOT EXISTS aisoc_compliance_evidence (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id         UUID REFERENCES aisoc_cases(id) ON DELETE SET NULL,
    tenant_id       UUID,
    framework       TEXT NOT NULL,          -- SOC2, PCI-DSS, HIPAA, ISO27001, NIST-CSF …
    control_id      TEXT NOT NULL,          -- e.g. CC6.1, A.12.4.1
    control_title   TEXT,
    evidence_kind   TEXT NOT NULL DEFAULT 'alert'
                        CHECK (evidence_kind IN ('alert','log','screenshot','attestation','policy','runbook','other')),
    summary         TEXT NOT NULL,
    raw_payload     JSONB DEFAULT '{}'::jsonb,
    -- SHA-256 of (prev_hash || summary || raw_payload) for chain integrity
    payload_hash    TEXT,
    prev_hash       TEXT,
    -- lifecycle
    collected_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    reviewed_by     TEXT,
    reviewed_at     TIMESTAMPTZ,
    status          TEXT NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending','accepted','rejected')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_aisoc_compliance_framework ON aisoc_compliance_evidence (framework);
CREATE INDEX IF NOT EXISTS idx_aisoc_compliance_case      ON aisoc_compliance_evidence (case_id);
CREATE INDEX IF NOT EXISTS idx_aisoc_compliance_control   ON aisoc_compliance_evidence (control_id);
