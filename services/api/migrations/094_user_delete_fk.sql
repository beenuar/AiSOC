-- 094: make a user row deletable.
--
-- Every FK referencing users already cascades (ownership rows) or SET NULLs
-- (attribution rows) EXCEPT compliance_evidence.collected_by, which RESTRICTs
-- (NO ACTION). That single edge would FK-fail any DELETE of a user who ever
-- collected compliance evidence. A compliance artifact must outlive its
-- collector, and the column is nullable, so the attribution survives as
-- "unknown collector" instead of blocking the row deletion — the same
-- retention model every other actor column already uses (audit_log.actor_id
-- SET NULL keeps the audit trail intact; only the name attribution goes).
--
-- Idempotent: re-running is a no-op once the constraint is recreated.

ALTER TABLE compliance_evidence
    DROP CONSTRAINT IF EXISTS compliance_evidence_collected_by_fkey;

ALTER TABLE compliance_evidence
    ADD CONSTRAINT compliance_evidence_collected_by_fkey
    FOREIGN KEY (collected_by) REFERENCES users(id) ON DELETE SET NULL;
