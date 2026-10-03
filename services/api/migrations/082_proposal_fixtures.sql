-- Persist a detection proposal's own fixtures.
--
-- Gap-closure wave 0.
--
-- `/decide` with `approve` answers HTTP 412 unless `eval_result` carries a
-- `candidate_rule` verdict, and the only thing that writes that key is
-- `POST /{id}/evaluate-rule`, which takes the positive and negative
-- fixtures as request body. They were never stored anywhere.
--
-- So the gate was unreachable twice over. The console had no client for the
-- route — that is the shallow half. The deeper half is that even calling it
-- directly required an operator to re-supply fixtures the proposal never
-- kept, which for an AI-drafted rule means re-deriving the very fixtures the
-- builder had already produced and discarded. A proposal that cannot prove
-- itself is a proposal that can never be approved.
--
-- Stored on the proposal rather than in a side table because they are part
-- of what is being proposed: "this rule, and here is what it must catch and
-- what it must ignore" is one artefact, and splitting it would let a
-- proposal travel without its proof.

ALTER TABLE detection_rule_proposals
    ADD COLUMN IF NOT EXISTS positive_fixtures JSONB NOT NULL DEFAULT '[]'::jsonb;

ALTER TABLE detection_rule_proposals
    ADD COLUMN IF NOT EXISTS negative_fixtures JSONB NOT NULL DEFAULT '[]'::jsonb;

COMMENT ON COLUMN detection_rule_proposals.positive_fixtures IS
    'Events the candidate rule MUST fire on. Supplied at proposal time and '
    'replayed by /evaluate-rule through the real engine before approval.';

COMMENT ON COLUMN detection_rule_proposals.negative_fixtures IS
    'Events the candidate rule must stay silent on. An empty list is allowed '
    'and means the proposal makes no claim about what it will not match.';
