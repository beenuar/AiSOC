"""Tenant-provisioning service module — T6.1 (`tryaisoc.com` managed beta).

Re-exports the small surface the API endpoint cares about so callers can
``from app.services.tenant_provision import provision_from_waitlist`` and
keep the import line short.

The split between :mod:`templates` (declarative seed content) and
:mod:`provisioner` (the orchestration that stitches it onto a fresh
tenant row) is intentional: templates is **pure data** with no DB
imports, so it stays trivially testable and so a future onboarding flow
can pre-render the templates into a CSV / docs page without spinning
up a database session.
"""

from __future__ import annotations

from app.services.tenant_provision.provisioner import (
    AdminInvite,
    InitialAdminUser,
    ProvisioningError,
    ProvisionResult,
    SlugCollisionError,
    WaitlistEntryNotFoundError,
    WaitlistEntryNotPromotableError,
    generate_credential_key,
    provision_from_waitlist,
)
from app.services.tenant_provision.templates import (
    DEFAULT_INITIAL_DETECTIONS,
    DEFAULT_INITIAL_PLAYBOOKS,
    DEFAULT_INITIAL_RBAC_ROLES,
    TenantTemplateBundle,
    get_default_template_bundle,
)

__all__ = [
    "AdminInvite",
    "DEFAULT_INITIAL_DETECTIONS",
    "DEFAULT_INITIAL_PLAYBOOKS",
    "DEFAULT_INITIAL_RBAC_ROLES",
    "InitialAdminUser",
    "ProvisionResult",
    "ProvisioningError",
    "SlugCollisionError",
    "TenantTemplateBundle",
    "WaitlistEntryNotFoundError",
    "WaitlistEntryNotPromotableError",
    "generate_credential_key",
    "get_default_template_bundle",
    "provision_from_waitlist",
]
