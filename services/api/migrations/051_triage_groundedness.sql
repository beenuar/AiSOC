-- Record how well each auto-triage verdict was supported by its evidence.
--
-- `app.confidence.groundedness` scores what fraction of the concrete
-- indicators a verdict's reasoning asserts — IPs, hashes, CVEs, MITRE
-- techniques, domains — actually appear in the evidence the agent was given.
-- v8.0 wired it into the triage path so an auto-closing verdict below the
-- floor is demoted to `needs_review` instead of closing.
--
-- The score itself was not persisted. It survived only inside a findings
-- string, which means it could not be aggregated, trended, or used to answer
-- the question a buyer evaluating an AI-SOC actually asks: how often is your
-- agent's reasoning supported by what it was shown, and how often does it
-- decline to decide?
--
-- Both columns are nullable rather than defaulted. NULL means "not scored",
-- which is a different fact from "scored zero" — pre-migration rows and
-- verdicts from the deterministic path were never assessed, and defaulting
-- them to 0.0 would read as every historical verdict being unsupported.

ALTER TABLE alerts
  -- Fraction in [0, 1]. NULL = not scored.
  ADD COLUMN IF NOT EXISTS triage_groundedness DOUBLE PRECISION,
  -- True when the groundedness gate demoted an auto-closing verdict to
  -- needs_review. Distinct from `disposition = 'needs_review'`, which is also
  -- reached by low confidence and by genuine escalation: this flags the subset
  -- where the agent had a confident answer that its evidence did not support.
  ADD COLUMN IF NOT EXISTS triage_ungrounded BOOLEAN;

-- The abstention and groundedness aggregates on /metrics/funnel scan by
-- tenant and window, so index the shape those queries use. Partial, because
-- the vast majority of rows are never scored and including them would make
-- the index mostly dead weight.
CREATE INDEX IF NOT EXISTS ix_alerts_tenant_groundedness
  ON alerts (tenant_id, created_at)
  WHERE triage_groundedness IS NOT NULL;

COMMENT ON COLUMN alerts.triage_groundedness IS
  'Fraction of indicators cited in the triage reasoning that appear in the evidence. NULL = not scored.';
COMMENT ON COLUMN alerts.triage_ungrounded IS
  'True when the groundedness gate demoted a confident auto-closing verdict to needs_review.';
