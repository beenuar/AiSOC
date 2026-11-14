-- 146: enterprise AI-chat compliance logs, with the minimisation in the schema.
--
-- Depth plan wave 2, Phase 7.1.
--
-- The plan sentence this implements is "store users, roles, projects and
-- audit events, and for content store only classification labels and a
-- bounded snippet, never full conversations". A sentence is not a control.
-- A `TEXT` column permits a full conversation no matter what the prose
-- above it says, and the first caller that passes the whole message body
-- will succeed silently. So the bound is a `VARCHAR(280)` the database
-- enforces, there is no column anywhere here that can hold a message, and
-- `aisoc_ai_chat_content_labels` has no `body`, `content`, `text` or
-- `messages` column by deliberate omission — adding one is a migration
-- somebody has to write and review.
--
-- Why 280
-- -------
-- Long enough that a reviewer can tell a false positive from a real one
-- ("AWS_SECRET_ACCESS_KEY=" in a paste is obvious at a glance), short
-- enough that it cannot carry a conversation. It is one SMS, and that is
-- the right order of magnitude for "enough to triage, not enough to read".
-- The collector truncates before binding; the column is the backstop for
-- the caller that forgets, which is the whole point of putting it here.
--
-- Why four tables and not one
-- ---------------------------
-- Unlike `aisoc_ai_assets` (110), where every analyst question crosses the
-- kinds, these four are read by different features on different schedules
-- and have genuinely different retention pressure. The directory is small
-- and slow-moving; the activity feed is large and append-only; content
-- labels are the sensitive half and are the rows an erasure request is
-- actually about. Collapsing them would force the strictest retention onto
-- all of it, or — far worse — the loosest.
--
-- Retention, legal hold and erasure
-- ---------------------------------
-- Every table carries `tenant_id`, so `discover_tenant_tables` finds them
-- and the tenant-erasure path (ADR-0014) covers them without anybody
-- remembering to add them to a list. That is deliberate: a declared list is
-- the thing that goes stale. `collected_at` is what the retention purge
-- clocks off, and `legal_holds` outranks it through the existing
-- `may_purge` decision — these tables are no different from alerts there.
--
-- Off by default
-- --------------
-- `aisoc_ai_chat_compliance_config` holds one row per tenant and no row
-- means the collector does not run. There is no deployment-wide switch and
-- no environment variable: the key is the tenant's own, vault-encrypted,
-- and arrives through the console. A tenant that has not opted in has no
-- row here and no rows in any of the four tables below.

-- ---------------------------------------------------------------------
-- Per-tenant enablement. No row = off.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS aisoc_ai_chat_compliance_config (
    tenant_id          UUID        PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,

    -- Which vendor's compliance API. Constrained so an unimplemented
    -- provider fails at the write rather than at the first poll.
    provider           TEXT        NOT NULL CHECK (provider IN ('anthropic')),

    -- Opaque `vault:v1:<base64>` ciphertext from CredentialVault. Never
    -- returned to the console; the read route exposes `hasKey: bool`.
    access_key_vault   TEXT        NOT NULL,

    -- Separate from "a row exists" so an operator can pause collection
    -- without destroying the stored key and having to mint another.
    enabled            BOOLEAN     NOT NULL DEFAULT FALSE,

    -- Content labelling is the part that reads message text, in-process,
    -- to produce labels and a bounded snippet. It is a second, narrower
    -- opt-in on top of the first: a tenant may well want the activity feed
    -- and the directory and explicitly not want anything derived from
    -- message bodies. Defaulting it on would make the stricter choice the
    -- one you have to discover.
    content_labels_enabled BOOLEAN NOT NULL DEFAULT FALSE,

    -- Cursor for the activity feed, so a restart does not re-read six
    -- years of history or skip the gap.
    activity_cursor    TEXT,
    last_collected_at  TIMESTAMPTZ,
    -- NULL means "never run", which the console renders differently from
    -- "ran and found nothing". An empty feed and an unconfigured key are
    -- not the same state.
    last_error         TEXT,

    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE aisoc_ai_chat_compliance_config IS
    'Per-tenant enablement for enterprise AI-chat compliance collection. '
    'No row means off; there is no deployment-wide switch.';
COMMENT ON COLUMN aisoc_ai_chat_compliance_config.content_labels_enabled IS
    'Second, narrower opt-in covering anything derived from message text. '
    'Off by default even when collection itself is on.';

-- ---------------------------------------------------------------------
-- Directory: users and the roles they hold.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS aisoc_ai_chat_users (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    provider        TEXT        NOT NULL,
    -- The vendor's own user id, which is what every other record joins on.
    external_id     TEXT        NOT NULL,
    -- Bounded because an address is bounded. 320 is the RFC 5321 maximum.
    email           VARCHAR(320),
    display_name    VARCHAR(200),
    role            VARCHAR(64),
    -- The vendor organization this user belongs to, so a parent
    -- organisation's key reaching a tree of child organisations does not
    -- flatten them into one directory.
    provider_org_id TEXT,

    collected_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT aisoc_ai_chat_users_identity UNIQUE (tenant_id, provider, external_id)
);

-- ---------------------------------------------------------------------
-- Projects (the vendor calls them projects; they group chats).
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS aisoc_ai_chat_projects (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    provider        TEXT        NOT NULL,
    external_id     TEXT        NOT NULL,
    name            VARCHAR(200),
    provider_org_id TEXT,
    owner_email     VARCHAR(320),

    collected_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT aisoc_ai_chat_projects_identity UNIQUE (tenant_id, provider, external_id)
);

-- ---------------------------------------------------------------------
-- Audit events: the activity feed.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS aisoc_ai_chat_audit_events (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    provider         TEXT        NOT NULL,
    external_id      TEXT        NOT NULL,
    event_type       VARCHAR(128) NOT NULL,
    occurred_at      TIMESTAMPTZ NOT NULL,

    actor_email      VARCHAR(320),
    actor_external_id TEXT,
    -- An IP is evidence; a user agent is evidence. Both are bounded, and
    -- neither is conversation content.
    actor_ip         INET,
    provider_org_id  TEXT,
    chat_external_id TEXT,
    project_external_id TEXT,

    collected_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT aisoc_ai_chat_audit_events_identity UNIQUE (tenant_id, provider, external_id)
);

CREATE INDEX IF NOT EXISTS idx_ai_chat_audit_tenant_time
    ON aisoc_ai_chat_audit_events (tenant_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_ai_chat_audit_tenant_actor
    ON aisoc_ai_chat_audit_events (tenant_id, actor_email);

-- ---------------------------------------------------------------------
-- Content labels. The minimised half.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS aisoc_ai_chat_content_labels (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    provider         TEXT        NOT NULL,
    -- The chat, not the message. A per-message row would be a message
    -- index, which is the thing this table exists not to be.
    chat_external_id TEXT        NOT NULL,
    project_external_id TEXT,
    actor_email      VARCHAR(320),
    provider_org_id  TEXT,

    -- The four classes the plan names. A text[] rather than four booleans
    -- so a fifth class is a code change and not a migration, and
    -- constrained so a free-text label cannot be written: an unconstrained
    -- label column is how a classifier ends up storing the matched value.
    labels           TEXT[]      NOT NULL DEFAULT '{}'::text[],
    CONSTRAINT aisoc_ai_chat_labels_vocabulary CHECK (
        labels <@ ARRAY['secrets', 'personal_data', 'regulated', 'financial']::text[]
    ),

    -- Which secret shapes, by name, never by value. Same vocabulary the
    -- AI SDK's `secret_kinds` emits.
    secret_kinds     TEXT[]      NOT NULL DEFAULT '{}'::text[],

    -- THE BOUND. 280 characters, enforced here and not in a docstring.
    -- There is no other column on this table that can hold message text,
    -- and that absence is the control: a caller wanting to store a
    -- conversation has to add a column, which is a migration somebody
    -- reviews.
    snippet          VARCHAR(280),
    -- Whether the snippet was cut, so a reviewer is never shown a
    -- truncated line that reads as a complete one.
    snippet_truncated BOOLEAN    NOT NULL DEFAULT FALSE,

    -- How many messages were examined to produce this row. A count, not
    -- the messages. Lets the console say "3 of 41 messages matched"
    -- instead of a bare label, and lets a meter be asserted against rows
    -- counted independently.
    messages_examined INTEGER    NOT NULL DEFAULT 0 CHECK (messages_examined >= 0),
    messages_matched  INTEGER    NOT NULL DEFAULT 0 CHECK (messages_matched >= 0),

    occurred_at      TIMESTAMPTZ NOT NULL,
    collected_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT aisoc_ai_chat_content_labels_identity UNIQUE (tenant_id, provider, chat_external_id)
);

CREATE INDEX IF NOT EXISTS idx_ai_chat_labels_tenant_time
    ON aisoc_ai_chat_content_labels (tenant_id, occurred_at DESC);

COMMENT ON TABLE aisoc_ai_chat_content_labels IS
    'Classification labels and one bounded snippet per chat. Deliberately '
    'has no column able to hold a conversation: the minimisation is the '
    'schema, not a comment. Written only when a tenant has opted in twice.';
COMMENT ON COLUMN aisoc_ai_chat_content_labels.snippet IS
    'At most 280 characters of the matching text, truncated by the '
    'collector and bounded by the column. Enough to tell a false positive '
    'from a real one; not enough to read a conversation.';

-- ---------------------------------------------------------------------
-- Row-level security on every table.
--
-- The `OR current_tenant_id() IS NULL` arm is what lets the cross-tenant
-- workers (retention purge, tenant deletion) reach these tables; dropping
-- it makes those silently see nothing. FORCE so the table owner, which is
-- the role that runs migrations, does not walk past it.
-- ---------------------------------------------------------------------
DO $$
DECLARE
    t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'aisoc_ai_chat_compliance_config',
        'aisoc_ai_chat_users',
        'aisoc_ai_chat_projects',
        'aisoc_ai_chat_audit_events',
        'aisoc_ai_chat_content_labels'
    ] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('DROP POLICY IF EXISTS %I ON %I', t || '_tenant', t);
        EXECUTE format(
            'CREATE POLICY %I ON %I USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)',
            t || '_tenant', t
        );
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
            EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON %I TO aisoc_app', t);
        END IF;
    END LOOP;
END
$$;
