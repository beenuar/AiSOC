-- 112_phishing_message_analysis.sql — the headers a reported message carried,
-- and whether anything actually examined it.
--
-- Depth plan 7.2. The submissions table has held an `indicators` JSONB array
-- since migration 015 and that is the right home for *findings*. It is the
-- wrong home for two other things, and conflating them is what this migration
-- separates.
--
-- `headers` — the raw internet headers, as delivered
-- --------------------------------------------------
-- Stored because the analysis has to be re-runnable. A retriage that has to
-- re-fetch the message from a mailbox cannot run after a purge has removed
-- it, which is precisely the order a real phishing response happens in:
-- analyse, decide, purge, and *then* somebody asks why. The headers are the
-- evidence, so they are kept with the submission rather than with the
-- mailbox.
--
-- JSONB and not text, because the analysis reads it as a name → value map and
-- re-parsing an RFC 5322 block on every read would put a parser between the
-- evidence and the reader.
--
-- `analysis_run_id` — where the citations went
-- ---------------------------------------------
-- The ledger run this submission's analysis was written to. Nullable with no
-- foreign key, deliberately: `investigation_runs` is retained on a different
-- schedule from phishing submissions, so a cascade would delete evidence when
-- a run aged out, and a RESTRICT would make run retention fail. A dangling id
-- reads as "the citations have aged out", which is true and recoverable; a
-- deleted submission reads as "this was never analysed", which is not.
--
-- `analysed_at` / `artefacts_analysed` / `artefacts_unanalysed`
-- --------------------------------------------------------------
-- The two counts are stored separately and never summed, because the sum is
-- the number this product must not publish. Three URLs and two attachments on
-- a deployment with no provider configured is an analysis that examined
-- nothing, and a surface rendering "5 artefacts, 0 findings" has said the
-- opposite of what happened. A reader can compute the total; nothing can
-- recover the split from a total.
--
-- `analysed_at` is NULL until an analysis has run, which is distinct from an
-- analysis that ran and found nothing. The honest empty state for a column
-- nobody has written is an empty state, never a confident zero.
--
-- Reversible: DROP COLUMN.

ALTER TABLE aisoc_phishing_submissions
    ADD COLUMN IF NOT EXISTS headers JSONB NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE aisoc_phishing_submissions
    ADD COLUMN IF NOT EXISTS auth_results JSONB NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE aisoc_phishing_submissions
    ADD COLUMN IF NOT EXISTS analysis_run_id UUID;

ALTER TABLE aisoc_phishing_submissions
    ADD COLUMN IF NOT EXISTS analysed_at TIMESTAMPTZ;

ALTER TABLE aisoc_phishing_submissions
    ADD COLUMN IF NOT EXISTS artefacts_analysed INTEGER NOT NULL DEFAULT 0;

ALTER TABLE aisoc_phishing_submissions
    ADD COLUMN IF NOT EXISTS artefacts_unanalysed INTEGER NOT NULL DEFAULT 0;

COMMENT ON COLUMN aisoc_phishing_submissions.auth_results IS
    'SPF, DKIM and DMARC as {method: pass|fail|not_evaluated}. The third value is the point: a '
    'message with no Authentication-Results has not passed SPF, it has not been evaluated, and '
    'rendering that as a pass is the defect this column exists to make impossible.';

COMMENT ON COLUMN aisoc_phishing_submissions.artefacts_unanalysed IS
    'Counted separately from artefacts_analysed and never summed with it. The sum is the number '
    'this product must not publish: a surface that renders "5 artefacts, 0 findings" for five '
    'artefacts nothing examined has said the opposite of what happened.';

COMMENT ON COLUMN aisoc_phishing_submissions.analysed_at IS
    'NULL until an analysis has run. Distinct from an analysis that ran and found nothing: the '
    'honest empty state for a column nobody has written is empty, never a confident zero.';
