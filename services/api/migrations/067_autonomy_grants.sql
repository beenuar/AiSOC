-- 067: what a tenant earned, what it was measured on, and who overruled it.
--
-- Gap-closure Phase 2.3.
--
-- 066 records what the agent said and what the analysts said. This is the
-- thing decided from that: whether a tenant may let the agent auto-close an
-- alert class, or raise one response verb's autonomy tier, without a human in
-- the loop each time.
--
-- Why the evidence is stored on the row and not looked up
-- -------------------------------------------------------
-- The obvious design keeps a `granted` flag and recomputes the justification
-- on demand. It cannot answer the only question anybody asks of this table.
-- Six months after a disputed auto-closure, "why was this tenant allowed to
-- do that" has to be answered against the numbers as they stood on the day,
-- and by then the window has moved, decisions have aged out, the thresholds
-- may have been retuned and the model has probably changed. A recomputed
-- justification would describe a different world and would look authoritative
-- doing it.
--
-- So `evidence` is a snapshot: the counts, the rates derived from them, the
-- thresholds by value, the window as absolute timestamps, the models that
-- produced the verdicts, the first and last decision id so the underlying
-- rows can still be found, and a digest of the rule set that judged it. The
-- shape is `EvidenceSnapshot.as_dict()` in `autonomy_evidence_rules.py`.
--
-- Why `source` is a column and not a flag in the JSON
-- ---------------------------------------------------
-- An operator can overrule a refusal. That has to stay possible: a gate with
-- no override is a gate that gets worked around. What must not happen is an
-- override becoming indistinguishable from earned autonomy once it is a week
-- old, so it is a first-class column with a CHECK constraint, it is a
-- different audit action, and the refusals that were overruled travel in the
-- snapshot beside it. `source` is derived from the gate's own verdict and
-- never from a request field, so a caller cannot ask for an override to be
-- recorded as earned.
--
-- Why demotions update rather than delete
-- ---------------------------------------
-- A grant that was revoked is the most interesting row in this table. One
-- row per (tenant, scope, capability), carrying its current state and the
-- evidence for the last transition; the full history is the audit log, which
-- is hash-chained and cannot be rewritten.

CREATE TABLE IF NOT EXISTS aisoc_autonomy_grants (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- `alert_class` grants auto-closure for a class of alerts; `action_verb`
    -- raises one response verb's autonomy tier. Constrained because both
    -- halves of the system have to agree what a scope key means before they
    -- can agree a grant applies to something.
    scope_kind     TEXT        NOT NULL CHECK (scope_kind IN ('alert_class', 'action_verb')),
    scope_key      TEXT        NOT NULL,
    capability     TEXT        NOT NULL CHECK (capability IN ('auto_close', 'auto_execute')),

    -- shadow: measuring, not acting. granted: earned or overridden.
    -- demoted: held and lost. A revoked grant keeps its row, because it is
    -- the most interesting one in the table.
    state          TEXT        NOT NULL DEFAULT 'shadow'
                               CHECK (state IN ('shadow', 'granted', 'demoted')),
    -- Never inferred from a request field. `earned` means the evidence met
    -- every threshold on its own; `operator_override` means a human overruled
    -- a refusal, and the refusals are in `evidence`.
    source         TEXT        NOT NULL DEFAULT 'earned'
                               CHECK (source IN ('earned', 'operator_override')),

    -- `EvidenceSnapshot.as_dict()`. Not null on a granted or demoted row:
    -- a transition with no evidence is exactly the thing this table exists
    -- to make impossible.
    evidence       JSONB,

    granted_at     TIMESTAMPTZ,
    granted_by     UUID        REFERENCES users(id) ON DELETE SET NULL,
    demoted_at     TIMESTAMPTZ,
    -- The refusal words that caused the demotion, joined. Kept beside the
    -- snapshot so a reader scanning the table sees why without parsing JSON.
    demoted_reason TEXT,
    -- Free text an operator supplies when overruling. Required by the route
    -- rather than by the column, because an override with no stated reason is
    -- an override nobody can review, and the route is where a 422 is useful.
    override_reason TEXT,

    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (tenant_id, scope_kind, scope_key, capability)
);

COMMENT ON TABLE aisoc_autonomy_grants IS
    'Autonomy a tenant has earned, or that an operator granted over a refusal. '
    'One row per (tenant, scope, capability); the transition history is the '
    'hash-chained audit log, which cannot be rewritten.';
COMMENT ON COLUMN aisoc_autonomy_grants.evidence IS
    'EvidenceSnapshot.as_dict(): counts, rates, thresholds by value, the window '
    'as absolute timestamps, models, the first and last decision id, and a digest '
    'of the rules that judged it. Stored rather than recomputed because a window '
    'that has moved on describes a different world.';
COMMENT ON COLUMN aisoc_autonomy_grants.source IS
    'earned | operator_override. Derived from the gate verdict, never from a '
    'request field, so an override cannot be recorded as earned.';

CREATE INDEX IF NOT EXISTS idx_autonomy_grants_tenant
    ON aisoc_autonomy_grants (tenant_id, state);
-- The dispatch path asks one question: does this tenant hold this capability
-- for this scope. Partial, because a demoted row never answers it yes.
CREATE INDEX IF NOT EXISTS idx_autonomy_grants_lookup
    ON aisoc_autonomy_grants (tenant_id, capability, scope_kind, scope_key)
    WHERE state = 'granted';

-- Row-level security. The `OR current_tenant_id() IS NULL` arm is what lets
-- the cross-tenant workers (retention purge, tenant deletion) and the actions
-- service's unbound connection read this; dropping it makes those silently
-- see nothing, which here would mean every tenant losing their autonomy at
-- dispatch with no error anywhere. FORCE so the owner does not walk past.
ALTER TABLE aisoc_autonomy_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE aisoc_autonomy_grants FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS aisoc_autonomy_grants_tenant ON aisoc_autonomy_grants;
CREATE POLICY aisoc_autonomy_grants_tenant ON aisoc_autonomy_grants
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

-- 061 set ALTER DEFAULT PRIVILEGES so new tables pick these up, but only for
-- tables created by the role that ran it. Granting explicitly means a chain
-- replayed by a different owner still leaves the runtime role able to work.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisoc_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON aisoc_autonomy_grants TO aisoc_app;
    END IF;
END
$$;
