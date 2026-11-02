-- 143_playbook_pause_timeout_outcome.sql — an approval deadline that passes
-- has to *do* something, and the playbook author decides what.
--
-- Wave-2 Phase 6.3. `expire_due` (migration 081) marks a waiting pause
-- `expired` and logs it. That is honest as far as it goes — the status
-- changes, so an operator can see that nobody decided — and it is the only
-- outcome available, which means every approval in the product behaves the
-- same way at its deadline: the containment does not happen, and nothing
-- else happens either.
--
-- For some steps that is right. For the step that isolates a host believed
-- to be exfiltrating, "nobody answered, so we did nothing" is a decision
-- nobody made on purpose, and it is the wrong one. For a step that sits
-- after an action already taken, the right answer at the deadline may be to
-- undo it rather than leave the estate half-changed.
--
-- So the step declares its own deadline behaviour and the pause carries it:
--
--   stay_paused   the existing behaviour, now chosen rather than implied
--   rollback      reverse what this run already did, through the platform
--                 rollback path, and record that the deadline caused it
--   contain       run one named, limited containment verb
--
-- `contain` is the one that needs a guard rail, and it has two. The verb is
-- named in the playbook, so a timeout cannot run something the author did
-- not write down; and it is dispatched through the ordinary governed path,
-- so it is graded by its own capability contract exactly like any other
-- action. A timeout is not a tier promotion: a verb the tenant's autonomy
-- tier would not auto-execute is still not auto-executed here, it queues.
--
-- The validation that the named verb exists and is a graded verb happens
-- when the playbook is saved, in `ask_timeout.validate_timeout_outcome`,
-- rather than at the deadline. A verb that does not resolve should fail
-- when somebody is reading the playbook, not three hours into an incident.

ALTER TABLE aisoc_playbook_pauses
    ADD COLUMN IF NOT EXISTS timeout_outcome TEXT NOT NULL DEFAULT 'stay_paused'
        CHECK (timeout_outcome IN ('stay_paused', 'rollback', 'contain'));

-- The capability to dispatch when `timeout_outcome = 'contain'`, with its
-- target and parameters. NULL for every other outcome, and the application
-- refuses a 'contain' row that leaves it NULL.
ALTER TABLE aisoc_playbook_pauses
    ADD COLUMN IF NOT EXISTS timeout_capability TEXT;

ALTER TABLE aisoc_playbook_pauses
    ADD COLUMN IF NOT EXISTS timeout_params JSONB NOT NULL DEFAULT '{}'::jsonb;

-- What actually happened at the deadline, written by the sweeper. Distinct
-- from `resolution`, which says why the pause ended: this says what the
-- platform did about it, and an operator reading an incident afterwards
-- needs both.
ALTER TABLE aisoc_playbook_pauses
    ADD COLUMN IF NOT EXISTS timeout_result JSONB;

-- A 'contain' outcome with no verb is unrunnable, and the deadline is the
-- worst time to discover it. Enforced in the database as well as in the
-- application because the two write paths (the engine and a future
-- operator edit) would otherwise each have to remember.
ALTER TABLE aisoc_playbook_pauses
    DROP CONSTRAINT IF EXISTS playbook_pause_timeout_contain_needs_a_verb;
ALTER TABLE aisoc_playbook_pauses
    ADD CONSTRAINT playbook_pause_timeout_contain_needs_a_verb
    CHECK (timeout_outcome <> 'contain' OR (timeout_capability IS NOT NULL AND timeout_capability <> ''));

COMMENT ON COLUMN aisoc_playbook_pauses.timeout_outcome IS
    'What happens when the approval deadline passes: stay_paused, rollback, or run one named limited containment verb. Declared by the playbook step, not by the deployment.';
COMMENT ON COLUMN aisoc_playbook_pauses.timeout_capability IS
    'The verb a contain outcome dispatches. Graded by its own capability contract through the ordinary governed path: a timeout is not a tier promotion.';
