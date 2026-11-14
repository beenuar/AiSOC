-- 104_playbook_verification.sql — make "ask the user, then their manager" a
-- state a run can sit in, rather than a message it sends and forgets.
--
-- Depth plan 5.4. `chatops_verify` posts an interactive prompt and returns
-- AWAITING_COMPLETION. That is honest about one prompt and is not a
-- workflow: nothing remembers who was asked, nothing escalates when the
-- person does not answer, and the signed reply lands on a callback that
-- writes a timeline event and ends there. A playbook therefore cannot
-- branch on the answer, which is the only reason to ask the question.
--
-- Three columns and one table, on the same reasoning migration 096 used for
-- `wait`: `aisoc_playbook_pauses` already stores the position, the context
-- and the step results a suspended run needs, and does so on disk because
-- surviving a restart is the requirement. A verification needs all of that
-- plus who is being asked and which stage it has reached.
--
-- Why a third `kind` rather than a second table
-- ---------------------------------------------
-- The sweeper, the resume path and the RLS policy would all have to be
-- written twice, and the second copy is where "a pause that never wakes"
-- comes back. A verification *is* a pause: it is waiting on a person, like
-- an approval, and on a clock, like a wait.
--
-- Why the stage is a column and not inferred
-- ------------------------------------------
-- The escalation to the manager reuses the same row: the deadline moves and
-- the stage advances. Inferring "we must be on the manager now" from a
-- non-null manager column would make a resolved manager with an unanswered
-- user prompt look like an escalation that already happened.
--
-- Reversible: DROP COLUMN IF EXISTS on each, DROP TABLE on the policy table,
-- and the CHECK reverts to the two-value form.

-- ── The pause grows a third kind ────────────────────────────────────────────

ALTER TABLE aisoc_playbook_pauses
    DROP CONSTRAINT IF EXISTS aisoc_playbook_pauses_kind_check;

ALTER TABLE aisoc_playbook_pauses
    ADD CONSTRAINT aisoc_playbook_pauses_kind_check
    CHECK (kind IN ('approval', 'wait', 'verification'));

-- Which half of the workflow this row is in. NULL for an approval and a
-- wait, which have no stages.
ALTER TABLE aisoc_playbook_pauses
    ADD COLUMN IF NOT EXISTS verification_stage TEXT
    CHECK (verification_stage IS NULL OR verification_stage IN ('user', 'manager'));

-- Who the alert is about. Kept beside the pause rather than dug out of
-- `run_context` at resume time, because the escalation needs it before the
-- run is rebuilt and a context key is not a contract.
ALTER TABLE aisoc_playbook_pauses
    ADD COLUMN IF NOT EXISTS verification_subject TEXT;

-- Who was asked second, resolved once at the point of escalation. NULL both
-- before the escalation and when no manager could be resolved at all —
-- which are different facts, and `verification_outcome` records the second
-- one as `no_manager` rather than leaving it to be inferred from a NULL.
ALTER TABLE aisoc_playbook_pauses
    ADD COLUMN IF NOT EXISTS verification_manager TEXT;

-- The answer, once there is one. Written by the callback before the run
-- resumes, so a replayed click reads an already-answered row.
ALTER TABLE aisoc_playbook_pauses
    ADD COLUMN IF NOT EXISTS verification_outcome TEXT
    CHECK (verification_outcome IS NULL OR verification_outcome IN (
        'acknowledged', 'denied', 'unsure', 'timed_out', 'no_manager'
    ));

COMMENT ON COLUMN aisoc_playbook_pauses.verification_stage IS
    'user = the affected person was asked; manager = it escalated to their manager.';
COMMENT ON COLUMN aisoc_playbook_pauses.verification_outcome IS
    'The signed answer, or timed_out / no_manager. A run branches on this.';

-- The sweeper's second query: verifications whose stage deadline has passed.
-- Partial for the reason the wait index is: resolved rows accumulate and a
-- full scan every tick costs history rather than work.
CREATE INDEX IF NOT EXISTS aisoc_playbook_pauses_verification_due_idx
    ON aisoc_playbook_pauses (resume_at)
    WHERE status = 'waiting' AND kind = 'verification' AND resume_at IS NOT NULL;

-- ── Who may be asked without a human saying so ──────────────────────────────
--
-- The contract's caution, as data. Two rules, and they are not the same
-- rule:
--
--   * A confirmed true positive is never asked. Messaging the account an
--     attacker is sitting on tells the attacker they are seen, and the
--     answer is worthless either way — the person whose credentials were
--     stolen will truthfully say "no, that wasn't me" and the person who is
--     the attacker will say whatever keeps the session alive.
--   * Everything else is asked only for alert classes this tenant opted
--     into. A verification prompt is a message to a colleague from a
--     security system; a product that sends those by default on day one is
--     uninstalled by the end of the week.
--
-- Default-deny: a tenant with no row here auto-sends nothing. A playbook an
-- analyst runs by hand is a human decision and is not governed by this
-- table.
CREATE TABLE IF NOT EXISTS aisoc_verification_policies (
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- The alert class, matched case-insensitively against the alert's
    -- `rule_id`, `category` or `alert_class`. One row per class rather than
    -- an array column so a grant can be revoked by deleting a row and the
    -- audit trail reads as a list of decisions.
    alert_class   TEXT NOT NULL,

    -- Who turned it on, for the review that follows the first complaint.
    enabled_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    enabled_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (tenant_id, alert_class)
);

COMMENT ON TABLE aisoc_verification_policies IS
    'Alert classes a tenant allows automatic user-verification prompts for. Absent = never auto-send.';

ALTER TABLE aisoc_verification_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE aisoc_verification_policies FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON aisoc_verification_policies;
CREATE POLICY tenant_isolation ON aisoc_verification_policies
    -- The unbound arm matches `aisoc_playbook_pauses` above and exists for
    -- the same reason: the agents service reads this from a Kafka consumer
    -- that binds no tenant, and without it every policy lookup would come
    -- back empty — which fails *closed* here, so the table would look
    -- installed and refuse every prompt.
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)
    WITH CHECK (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

-- ── The manager, from SCIM ──────────────────────────────────────────────────
--
-- SCIM's enterprise extension carries `manager.value`, and every IdP that
-- provisions users sends it when the directory has one. The column was
-- missing, so the platform held a provisioned directory and could not
-- answer "who does this person report to" — the one question an escalation
-- needs.
--
-- Stored as the provider's own reference (`manager.value` is an id in Okta
-- and Entra, an email in some others) rather than resolved to a local user
-- id, because the manager is frequently not an AiSOC user at all.
ALTER TABLE aisoc_scim_users
    ADD COLUMN IF NOT EXISTS manager_ref TEXT;

COMMENT ON COLUMN aisoc_scim_users.manager_ref IS
    'manager.value from the SCIM enterprise user extension; the provider''s own reference, not a local user id.';

CREATE INDEX IF NOT EXISTS aisoc_scim_users_manager_idx
    ON aisoc_scim_users (tenant_id, manager_ref)
    WHERE manager_ref IS NOT NULL;
