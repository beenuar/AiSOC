-- 107_case_war_rooms.sql — the chat channel a case runs in, and what has
-- already been said in it.
--
-- Depth plan 9.4. Nothing in the tree opened a channel: `grep -rn
-- 'conversations.create|channels.create|war_room'` across every service and
-- the console returned four hits, all of them prose — a playbook template
-- describing a "Notify war-room" step and an eval fixture quoting the phrase
-- in an expected answer. Both chat bots could only *answer*: `services/
-- slack-bot` gained one outbound route for an approval card and
-- `services/teams-bot` posts to a webhook somebody configured by hand.
--
-- Two tables
-- ----------
-- `aisoc_case_war_rooms` is the link: one case, one provider, one channel.
-- `aisoc_war_room_posts` is what has already been posted into it.
--
-- The second table is the whole design. "Post the timeline and verdicts as
-- they change" is a sync, and a sync with no record of what it has already
-- sent re-posts the entire case history on every tick — which is not a
-- cosmetic problem in a channel people are reading during an incident. The
-- key is a caller-supplied fingerprint of the *event*, unique per war room,
-- so a retry after a network failure is idempotent and two replicas running
-- the sweep cannot double-post.
--
-- Why `provider` is a closed set but `channel_id` is free text
-- -----------------------------------------------------------
-- There are two providers and each has exactly one client. A channel
-- identifier is whatever that vendor issues (`C0123ABCD` for Slack, a Graph
-- GUID for Teams) and parsing it would be this service pretending to know
-- something only the vendor does.
--
-- Why a war room is closed, never deleted
-- ---------------------------------------
-- The channel outlives the row either way. A deleted row means the next sync
-- opens a *second* channel for the same case, which is the failure mode an
-- analyst notices at the worst possible moment.
--
-- Reversible: DROP TABLE IF EXISTS, posts first.

CREATE TABLE IF NOT EXISTS aisoc_case_war_rooms (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    case_id         UUID        NOT NULL REFERENCES aisoc_cases(id) ON DELETE CASCADE,

    provider        TEXT        NOT NULL CHECK (provider IN ('slack', 'teams')),
    -- Whatever the vendor issued. Never parsed here.
    channel_id      TEXT        NOT NULL,
    channel_name    TEXT        NOT NULL DEFAULT '',
    -- Deep link an analyst clicks from the case. Empty when the provider did
    -- not return one, and the console renders the absence rather than
    -- constructing a URL that may not resolve.
    channel_url     TEXT        NOT NULL DEFAULT '',

    state           TEXT        NOT NULL DEFAULT 'open'
                    CHECK (state IN ('open', 'closed')),

    opened_by       TEXT        NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- When the sweep last succeeded. NULL means it has never run for this
    -- room, which is a different fact from "ran and had nothing to say", and
    -- the console renders them differently.
    last_synced_at  TIMESTAMPTZ,
    -- Why the last sync failed, when it did. Empty on success. Shown to the
    -- analyst, because a war room that has silently stopped mirroring is
    -- worse than one that was never opened.
    last_error      TEXT        NOT NULL DEFAULT '',

    -- One live room per case per provider. Partial, so a closed room does
    -- not block re-opening and the history of both survives.
    CONSTRAINT aisoc_case_war_rooms_channel_unique UNIQUE (tenant_id, provider, channel_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS aisoc_case_war_rooms_live_idx
    ON aisoc_case_war_rooms (case_id, provider)
    WHERE state = 'open';

-- The sweep's query: open rooms, oldest sync first.
CREATE INDEX IF NOT EXISTS aisoc_case_war_rooms_sweep_idx
    ON aisoc_case_war_rooms (last_synced_at NULLS FIRST)
    WHERE state = 'open';

CREATE TABLE IF NOT EXISTS aisoc_war_room_posts (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    war_room_id     UUID        NOT NULL REFERENCES aisoc_case_war_rooms(id) ON DELETE CASCADE,

    -- A fingerprint of the event this post represents, e.g.
    -- `status:closed@2026-10-11T08:00:00Z` or `verdict:true_positive:0.91`.
    -- Unique per room, which is what makes the sweep idempotent under a
    -- retry and safe with two replicas.
    event_key       TEXT        NOT NULL,
    -- What was said, kept so "what did the channel see" survives the channel
    -- being archived or the workspace being left.
    summary         TEXT        NOT NULL DEFAULT '',
    posted_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT aisoc_war_room_posts_unique UNIQUE (war_room_id, event_key)
);

CREATE INDEX IF NOT EXISTS aisoc_war_room_posts_room_idx
    ON aisoc_war_room_posts (war_room_id, posted_at DESC);

COMMENT ON TABLE aisoc_war_room_posts IS
    'What a war room has already been told. Without it the sweep re-posts the whole case '
    'history on every tick, which in a channel people are reading during an incident is '
    'not a cosmetic problem.';

-- Written out per table rather than looped with format(): a loop makes the
-- policy invisible to grep and to scripts/check_tenant_query_predicates.py.
DO $$
BEGIN
    EXECUTE 'ALTER TABLE aisoc_case_war_rooms ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE aisoc_case_war_rooms FORCE ROW LEVEL SECURITY';
    EXECUTE 'DROP POLICY IF EXISTS tenant_isolation ON aisoc_case_war_rooms';
    EXECUTE
        'CREATE POLICY tenant_isolation ON aisoc_case_war_rooms '
        'USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL) '
        'WITH CHECK (tenant_id = current_tenant_id())';

    EXECUTE 'ALTER TABLE aisoc_war_room_posts ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE aisoc_war_room_posts FORCE ROW LEVEL SECURITY';
    EXECUTE 'DROP POLICY IF EXISTS tenant_isolation ON aisoc_war_room_posts';
    EXECUTE
        'CREATE POLICY tenant_isolation ON aisoc_war_room_posts '
        'USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL) '
        'WITH CHECK (tenant_id = current_tenant_id())';

    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON aisoc_case_war_rooms TO aisoc_app';
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON aisoc_war_room_posts TO aisoc_app';
    END IF;
END
$$;
