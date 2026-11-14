"""Cross-cutting security primitives for the AiSOC backend.

Exports:
  - The prompt-injection defense layer used by the agent runtime to
    harden the LLM ↔ tool boundary.
  - The HMAC-SHA256 JWT module + tenant context plumbing used by every
    tenant-scoped API route and agent.
"""
from app.security.jwt import (  # noqa: F401
    JwtDecodeError,
    JwtError,
    JwtExpiredError,
    JwtMissingClaimError,
    JwtNotYetValidError,
    TenantClaims,
    claims_from_payload,
    decode_token,
    encode_token,
    issue_tenant_token,
)
from app.security.prompt_injection import (  # noqa: F401
    DefenseVerdict,
    InjectionSignal,
    ToolOutputDefender,
    defender,
)
from app.security.tenant import (  # noqa: F401
    TenantAccessDenied,
    TenantContext,
    apply_tenant_filter,
    ensure_row_visible,
    require_admin,
    require_tenant,
    viewable_tenants_or_active,
)
