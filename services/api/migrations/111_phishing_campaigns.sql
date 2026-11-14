-- 111_phishing_campaigns.sql — reported-message intake, campaign grouping and
-- the per-recipient purge ledger.
--
-- Depth plan 7.1 (gap-closure Phase 10, parity 6.4). Phishing submissions have
-- existed since migration 015 and they record one artefact at a time: a body,
-- a sender, a subject, a list of URLs and a verdict. Nothing in that shape can
-- answer the two questions a phishing response actually turns on — **who else
-- got this**, and **is this the same message somebody reported an hour ago** —
-- so a campaign of twenty-five was twenty-five unrelated rows and the purge
-- had no list to work from.
--
-- Three additions, each answering one of those.
--
-- 1. Columns on the existing submissions table
-- --------------------------------------------
-- `internet_message_id` is the join key. It is the one identifier that
-- survives a message being delivered to many mailboxes, and it is what
-- Microsoft Graph filters on and what Gmail's `rfc822msgid:` operator
-- searches. Without it a purge cannot find the copies.
--
-- `recipients` is who received it, as reported. `reported_by` is who told us,
-- which is a different person and is the one an analyst thanks or asks a
-- follow-up question. `intake_source` records which of the three doors the
-- report came through, because "the M365 report mailbox has gone quiet" is a
-- diagnosis nobody can make from a table that does not distinguish them.
--
-- 2. `aisoc_phishing_campaigns`
-- -----------------------------
-- One row per group of submissions that are the same message. `grouping_key`
-- is a hash of whichever attribute grouped them and `grouping_basis` names
-- which one, so a reader can see *why* two reports were joined rather than
-- having to trust that they were. That matters because subject-similarity
-- grouping is a judgement and the other three are facts, and an analyst
-- about to purge across forty mailboxes is entitled to know which kind of
-- claim they are acting on.
--
-- `recipient_count` is stored rather than computed on read, because it is the
-- input to the approval tier: `capability_contracts.scaled_impact` turns it
-- into MODERATE, HIGH or SEVERE, and a count that changes between the
-- proposal being graded and the approver reading it would mean the two saw
-- different actions. It is recomputed from the recipient rows whenever one is
-- added, in the same transaction.
--
-- 3. `aisoc_phishing_campaign_recipients`
-- ---------------------------------------
-- One row per (campaign, mailbox). This is the purge ledger and it is a
-- table rather than a JSONB column for one reason: the purge is dispatched
-- **one request per mailbox**, each graded, audited and reversible on its
-- own, so each needs its own state and its own restore handle. A list inside
-- a document could record the outcome; it could not record twenty-five
-- outcomes that a rollback has to read back individually.
--
-- `purge_state` is a closed vocabulary and its default is `not_attempted`,
-- not `pending`. "Nobody has tried" and "a try is in flight" are different
-- facts and only one of them should make an operator wait.
--
-- `restore_message_id` and `restore_folder_id` are what the rollback needs and
-- cannot recover later: Microsoft's move gives the message a new id in the
-- destination folder, and the folder it came from is only knowable before the
-- move. Storing them is the difference between a declared rollback and a real
-- one.
--
-- Reversible: DROP TABLE IF EXISTS (children first), then DROP COLUMN.

ALTER TABLE aisoc_phishing_submissions
    ADD COLUMN IF NOT EXISTS internet_message_id TEXT;

ALTER TABLE aisoc_phishing_submissions
    ADD COLUMN IF NOT EXISTS recipients TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[];

ALTER TABLE aisoc_phishing_submissions
    ADD COLUMN IF NOT EXISTS reported_by TEXT;

-- `manual` is the honest default for every row that already exists: they came
-- through POST /phishing/submit, which is a person or a scripted caller, and
-- backfilling them as though they arrived from a report mailbox would invent
-- provenance.
ALTER TABLE aisoc_phishing_submissions
    ADD COLUMN IF NOT EXISTS intake_source TEXT NOT NULL DEFAULT 'manual';

ALTER TABLE aisoc_phishing_submissions
    ADD COLUMN IF NOT EXISTS campaign_id UUID;

CREATE INDEX IF NOT EXISTS aisoc_phishing_submissions_message_idx
    ON aisoc_phishing_submissions (tenant_id, internet_message_id)
    WHERE internet_message_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS aisoc_phishing_submissions_campaign_idx
    ON aisoc_phishing_submissions (campaign_id)
    WHERE campaign_id IS NOT NULL;


CREATE TABLE IF NOT EXISTS aisoc_phishing_campaigns (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Hash of the grouping attribute. Hashed rather than stored raw because
    -- the attribute may be a 998-character subject line and because it is
    -- only ever compared for equality.
    grouping_key        TEXT        NOT NULL,
    grouping_basis      TEXT        NOT NULL
                            CHECK (grouping_basis IN ('internet_message_id', 'attachment_hash', 'url', 'sender', 'subject')),

    sender              TEXT,
    subject             TEXT,

    report_count        INTEGER     NOT NULL DEFAULT 0,
    recipient_count     INTEGER     NOT NULL DEFAULT 0,

    -- `open` -> `purge_proposed` -> `purging` -> `purged` | `partially_purged`
    -- -> `restored`, or `dismissed` at any point. `partially_purged` exists
    -- because a fan-out across forty mailboxes routinely succeeds on most and
    -- fails on some, and collapsing that into `purged` publishes a claim the
    -- deployment cannot support.
    status              TEXT        NOT NULL DEFAULT 'open'
                            CHECK (status IN ('open', 'purge_proposed', 'purging', 'purged',
                                              'partially_purged', 'restored', 'dismissed')),

    first_reported_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_reported_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (tenant_id, grouping_key)
);

CREATE INDEX IF NOT EXISTS aisoc_phishing_campaigns_tenant_idx
    ON aisoc_phishing_campaigns (tenant_id, last_reported_at DESC);

COMMENT ON COLUMN aisoc_phishing_campaigns.grouping_basis IS
    'Which attribute joined these reports. Three of the five are facts about the message; '
    'subject similarity is a judgement. An analyst about to purge across forty mailboxes is '
    'entitled to know which kind of claim they are acting on.';


CREATE TABLE IF NOT EXISTS aisoc_phishing_campaign_recipients (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    campaign_id         UUID        NOT NULL REFERENCES aisoc_phishing_campaigns(id) ON DELETE CASCADE,
    tenant_id           UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    recipient           TEXT        NOT NULL,
    internet_message_id TEXT        NOT NULL DEFAULT '',

    -- Mirrors the step vocabulary in `playbook_step_dispatch.NOT_EXECUTED_STATES`
    -- plus the two terminal mailbox states. `not_attempted` is the default
    -- rather than `pending`: "nobody has tried" and "a try is in flight" are
    -- different facts and only one of them should make an operator wait.
    purge_state         TEXT        NOT NULL DEFAULT 'not_attempted'
                            CHECK (purge_state IN ('not_attempted', 'simulated', 'pending_approval',
                                                   'purged', 'not_found', 'failed', 'restored')),
    purge_detail        TEXT        NOT NULL DEFAULT '',

    -- What a rollback needs and cannot recover afterwards.
    restore_message_id  TEXT        NOT NULL DEFAULT '',
    restore_folder_id   TEXT        NOT NULL DEFAULT '',
    vendor              TEXT        NOT NULL DEFAULT '',

    last_action_at      TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (campaign_id, recipient)
);

CREATE INDEX IF NOT EXISTS aisoc_phishing_recipients_campaign_idx
    ON aisoc_phishing_campaign_recipients (campaign_id, purge_state);

COMMENT ON TABLE aisoc_phishing_campaign_recipients IS
    'The purge ledger: one row per mailbox, because the purge is dispatched one request per '
    'mailbox and each is graded, audited and reversible on its own. A JSONB list could record '
    'the outcome; it could not record twenty-five outcomes a rollback has to read back.';

-- Written out per table rather than looped with `format()`, so the policy is
-- visible to `grep` and to `scripts/check_tenant_query_predicates.py`, which
-- reads migrations to learn which tables carry one.
DO $$
BEGIN
    EXECUTE 'ALTER TABLE aisoc_phishing_campaigns ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE aisoc_phishing_campaigns FORCE ROW LEVEL SECURITY';
    EXECUTE 'DROP POLICY IF EXISTS tenant_isolation ON aisoc_phishing_campaigns';
    EXECUTE
        'CREATE POLICY tenant_isolation ON aisoc_phishing_campaigns '
        'USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL) '
        'WITH CHECK (tenant_id = current_tenant_id())';

    EXECUTE 'ALTER TABLE aisoc_phishing_campaign_recipients ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE aisoc_phishing_campaign_recipients FORCE ROW LEVEL SECURITY';
    EXECUTE 'DROP POLICY IF EXISTS tenant_isolation ON aisoc_phishing_campaign_recipients';
    EXECUTE
        'CREATE POLICY tenant_isolation ON aisoc_phishing_campaign_recipients '
        'USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL) '
        'WITH CHECK (tenant_id = current_tenant_id())';

    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON aisoc_phishing_campaigns TO aisoc_app';
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON aisoc_phishing_campaign_recipients TO aisoc_app';
    END IF;
END
$$;
