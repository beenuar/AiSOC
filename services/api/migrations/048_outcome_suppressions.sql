-- Wave 1 (close the loop): measured record of repeat alerts auto-suppressed
-- from prior outcome memory. The auto-triage worker inserts one row each time a
-- new alert matches a trusted prior benign/false-positive disposition and is
-- auto-resolved without re-triage, so the compounding alert-reduction metric is
-- measured from real events rather than estimated.
--
-- Tenant isolation is at the query layer (every read filters by tenant_id),
-- consistent with the /hunts + /cases pattern; no RLS on this analytics table.
-- Idempotent + transactional.
BEGIN;

CREATE TABLE IF NOT EXISTS aisoc_outcome_suppressions (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id     UUID NOT NULL,
    signature     TEXT NOT NULL,
    alert_id      UUID,
    disposition   TEXT NOT NULL,
    prior_author  TEXT NOT NULL DEFAULT 'ai',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_outcome_suppressions_tenant_time
    ON aisoc_outcome_suppressions (tenant_id, created_at DESC);

COMMIT;
