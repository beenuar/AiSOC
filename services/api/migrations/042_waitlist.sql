-- Migration 042: Managed-instance waitlist (T6.1 — `tryaisoc.com`).
--
-- Stores every public signup against ``/waitlist`` so the support team
-- can triage demand, contact prospects, and (once approved) promote
-- an entry into a real tenant via the tenant_provision pipeline in
-- migration 043.
--
-- Privacy
-- -------
-- Every column on this table mirrors a field the signup form already
-- collected in plaintext from a public marketing page. Nothing is
-- encrypted at rest. If we later add free-form support notes those
-- should land in a separate ``aisoc_waitlist_notes`` table so this
-- row-level history stays cheap to read and easy to audit.
--
-- Status ladder
-- -------------
-- ``new``        — fresh signup, no support contact yet.
-- ``contacted``  — support team has reached out (stamps ``contacted_at``).
-- ``onboarded``  — tenant has been provisioned (stamps ``onboarded_at``
--                  + ``provisioned_tenant_id``).
-- ``declined``   — terminal: not a fit, do-not-contact, etc.
--
-- Indexes
-- -------
--   - unique ``email`` — case-insensitive uniqueness is enforced at the
--     application layer (we ``.strip().lower()`` before write). The
--     unique index is a belt-and-suspenders catch for a stale row that
--     drifted out of the lowercase contract.
--   - ``status`` — admin list page filters by status; this is the only
--     other column you actually query by.
--   - ``provisioned_tenant_id`` partial — used by the audit query
--     "which tenants were born from a waitlist signup?".

BEGIN;

CREATE TABLE IF NOT EXISTS aisoc_waitlist_entries (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email                   VARCHAR(320) NOT NULL,
    company                 VARCHAR(255) NOT NULL,
    role                    VARCHAR(100) NOT NULL,
    soc_stack               JSONB NOT NULL DEFAULT '[]'::jsonb,
    motivation              TEXT NOT NULL,
    status                  VARCHAR(32) NOT NULL DEFAULT 'new',
    provisioned_tenant_id   UUID,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    contacted_at            TIMESTAMPTZ,
    onboarded_at            TIMESTAMPTZ,
    CONSTRAINT aisoc_waitlist_entries_email_unique UNIQUE (email),
    CONSTRAINT aisoc_waitlist_entries_status_check
        CHECK (status IN ('new', 'contacted', 'onboarded', 'declined')),
    CONSTRAINT aisoc_waitlist_entries_soc_stack_is_array
        CHECK (jsonb_typeof(soc_stack) = 'array')
);

CREATE INDEX IF NOT EXISTS aisoc_waitlist_entries_status_idx
    ON aisoc_waitlist_entries (status);

CREATE INDEX IF NOT EXISTS aisoc_waitlist_entries_provisioned_tenant_idx
    ON aisoc_waitlist_entries (provisioned_tenant_id)
    WHERE provisioned_tenant_id IS NOT NULL;

-- ============================================================
-- RLS: the waitlist is operator-level data, not tenant-scoped.
-- Rather than wire it into the tenant RLS machinery we keep RLS
-- disabled on this table and enforce access at the API layer
-- (admin-only on the read/PATCH endpoints; the public signup
-- endpoint is rate-limited per IP).
-- ============================================================
ALTER TABLE aisoc_waitlist_entries DISABLE ROW LEVEL SECURITY;

COMMIT;
