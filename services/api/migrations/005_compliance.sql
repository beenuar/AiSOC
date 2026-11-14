-- Migration 005: SOC 2 / compliance evidence tables
-- Run after 004_audit_log.sql

-- SOC 2 control categories and evidence collection
CREATE TABLE IF NOT EXISTS compliance_controls (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    framework   TEXT NOT NULL,          -- 'soc2', 'iso27001', 'nist_csf', 'pci_dss', 'hipaa', 'dora'
    control_id  TEXT NOT NULL,          -- e.g. 'CC6.1', 'A.9.4.1'
    category    TEXT NOT NULL,
    title       TEXT NOT NULL,
    description TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (framework, control_id)
);

CREATE TABLE IF NOT EXISTS compliance_evidence (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    control_id      UUID NOT NULL REFERENCES compliance_controls(id),
    evidence_type   TEXT NOT NULL,   -- 'auto', 'manual', 'screenshot', 'document'
    title           TEXT NOT NULL,
    description     TEXT,
    status          TEXT NOT NULL DEFAULT 'collected', -- 'collected', 'review', 'approved', 'rejected'
    collected_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    collected_by    UUID REFERENCES users(id),
    metadata        JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_compliance_evidence_tenant ON compliance_evidence(tenant_id);
CREATE INDEX IF NOT EXISTS idx_compliance_evidence_control ON compliance_evidence(control_id);

-- RLS for evidence
ALTER TABLE compliance_evidence ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_policies
        WHERE schemaname = current_schema()
          AND tablename = 'compliance_evidence'
          AND policyname = 'compliance_evidence_tenant_isolation'
    ) THEN
        EXECUTE 'CREATE POLICY compliance_evidence_tenant_isolation ON compliance_evidence
            USING (tenant_id = current_setting(''app.current_tenant_id'', true)::uuid)';
    END IF;
END $$;

-- Seed SOC 2 Trust Services Criteria (CC controls)
INSERT INTO compliance_controls (framework, control_id, category, title, description) VALUES
  ('soc2', 'CC1.1', 'Control Environment', 'COSO Principle 1', 'The entity demonstrates a commitment to integrity and ethical values'),
  ('soc2', 'CC1.2', 'Control Environment', 'COSO Principle 2', 'The board of directors demonstrates independence from management'),
  ('soc2', 'CC2.1', 'Communication & Information', 'COSO Principle 13', 'The entity obtains or generates and uses relevant, quality information'),
  ('soc2', 'CC3.1', 'Risk Assessment', 'COSO Principle 6', 'The entity specifies objectives with sufficient clarity'),
  ('soc2', 'CC4.1', 'Monitoring Activities', 'COSO Principle 16', 'The entity selects, develops, and performs ongoing monitoring'),
  ('soc2', 'CC5.1', 'Control Activities', 'COSO Principle 10', 'The entity selects and develops control activities'),
  ('soc2', 'CC6.1', 'Logical Access Controls', 'Logical access security software', 'Protects against threats from sources outside the system'),
  ('soc2', 'CC6.2', 'Logical Access Controls', 'New internal access', 'Prior to issuing system credentials, the entity registers and authorizes new users'),
  ('soc2', 'CC6.3', 'Logical Access Controls', 'Remove access', 'The entity removes access to protected information assets'),
  ('soc2', 'CC6.6', 'Logical Access Controls', 'Logical access restrictions', 'Logical access security measures restrict access to information assets'),
  ('soc2', 'CC6.7', 'Logical Access Controls', 'Data transmission', 'The entity restricts the transmission, movement, and removal of information'),
  ('soc2', 'CC7.1', 'System Operations', 'Detection and monitoring', 'To meet its objectives, the entity uses detection and monitoring procedures'),
  ('soc2', 'CC7.2', 'System Operations', 'Monitor system components', 'The entity monitors system components for anomalies'),
  ('soc2', 'CC7.3', 'System Operations', 'Evaluate security events', 'The entity evaluates security events to determine whether they could impair objectives'),
  ('soc2', 'CC7.4', 'System Operations', 'Respond to security incidents', 'The entity responds to identified security incidents'),
  ('soc2', 'CC7.5', 'System Operations', 'Recover from incidents', 'The entity identifies, develops, and implements activities to recover from identified security incidents'),
  ('soc2', 'CC8.1', 'Change Management', 'Change management', 'The entity authorizes, designs, develops or acquires, configures, documents, tests, approves, and implements changes'),
  ('soc2', 'CC9.1', 'Risk Mitigation', 'Risk mitigation activities', 'The entity identifies, selects, and develops risk mitigation activities'),
  ('soc2', 'CC9.2', 'Risk Mitigation', 'Business disruption risk', 'The entity assesses and manages risks associated with vendors and business partners')
ON CONFLICT (framework, control_id) DO NOTHING;
