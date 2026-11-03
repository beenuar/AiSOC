-- GHSA-xhmc-69rh-h3rr, F10: separation of duties on MCP tool approvals
-- compared the *credential label*, not the person.
--
-- `aisoc_mcp_tool_approvals.requested_by` is written as
-- `current_user.api_key_prefix or current_user.email` -- whichever credential
-- authenticated the request. So one human holding an API key and a console
-- session appears under two different labels, and `decide_approval`'s
-- `requester == actor` comparison passed: they requested the call through
-- `ak_1a2b3c` and approved it as `them@corp.example`.
--
-- The person is already resolvable at both ends and was simply never stored.
-- `app/api/v1/deps.py` loads the key's owning `User` and sets
-- `CurrentUser.user_id` to that user's id, refusing the key outright when the
-- owner is deactivated -- so `user_id` is the human in both the key path and
-- the session path. This column records it.
--
-- Nullable on purpose. Rows written before this migration have no requester
-- identity and cannot be given one retroactively: a key prefix is not
-- reversible to a user here, and inventing a mapping would put a guess in the
-- column an auditor reads. `decide_approval` treats a NULL as
-- "unevaluated" -- it still applies the label comparison, records that the
-- identity check could not run, and does not refuse. Refusing would strand
-- every approval raised before this migration, and a control reporting itself
-- satisfied on requests it could not evaluate is the defect this column
-- exists to remove.

ALTER TABLE aisoc_mcp_tool_approvals
    ADD COLUMN IF NOT EXISTS requested_by_user_id UUID;

COMMENT ON COLUMN aisoc_mcp_tool_approvals.requested_by_user_id IS
    'The human who requested this tool call, resolved from the authenticated '
    'principal (an API key resolves to its owning user). Separation of duties '
    'compares this, never `requested_by`, which is a credential label. NULL on '
    'rows predating migration 158, which are recorded as unevaluated.';

-- Decisions are read back by requester for the separation-of-duties check on
-- a path that already filters by tenant.
CREATE INDEX IF NOT EXISTS idx_mcp_tool_approvals_requester
    ON aisoc_mcp_tool_approvals (tenant_id, requested_by_user_id)
    WHERE requested_by_user_id IS NOT NULL;
