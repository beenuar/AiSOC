"""Effective-permissions resolver package (T3.2).

The resolver answers "what can principal X actually do, on which resources,
right now?" across the providers AiSOC connects to. It is the read-side of the
identity graph: ingest writes the structural ``:HAS_PERMISSION`` / ``:GRANTS``
/ ``:MEMBER_OF`` edges as policy snapshots arrive, and this package walks
those edges + applies provider-specific resolution rules (deny-overrides, SCP
intersection, scope inheritance) to produce a flat set of ``(resource,
actions)`` decisions per principal.

Public surface
--------------

* :class:`~app.services.effective_permissions.base.Resolver` — abstract
  per-provider entry point. Each provider implements ``resolve()``.
* :class:`~app.services.effective_permissions.base.ResolvedPermission` — one
  decision (principal, resource, allowed actions, deny actions, policy chain).
* :class:`~app.services.effective_permissions.base.ResolverResult` — the
  envelope returned to the API endpoint and UI: resolver metadata plus the
  ordered list of decisions.
* :func:`~app.services.effective_permissions.service.resolve_effective_permissions`
  — the dispatcher that picks the right provider and (best-effort) caches the
  result into Neo4j as ``(:Identity)-[:EFFECTIVE_PERMISSION]->(:Resource)``.

Provider coverage status (Phase 4.1)
-----------------------------------

==========  ==============================================================
Provider     Status (this slice)
==========  ==============================================================
aws          Full implementation — identity-based, resource-based, SCP,
             deny-overrides, ``Condition``-aware (StringEquals / StringLike),
             wildcard expansion against a synthesised action catalogue.
azure        Full implementation (Phase 4.1) — scope-inheriting RBAC walker
             over MG -> Sub -> RG -> Resource. Role definitions /
             assignments / deny assignments are honoured; ABAC conditions
             surface as ``notes``.
gcp          Full implementation (Phase 4.1) — hierarchy-inheriting binding
             walker over Org -> Folder -> Project -> Resource. Roles expand
             to permission lists; org-policy denied_permissions are
             subtracted. IAM conditions (CEL) surface as ``notes``.
okta         Full implementation (Phase 4.1) — group + admin-role expander.
             Surfaces app reads (``okta.app.{id}.read``) plus admin role
             privileges.
gws          Full implementation (Phase 4.1) — OU-scoped role expander.
             Role assignments at ``CUSTOMER`` or ``ORG_UNIT`` scope are
             matched against the resource's OU path.
==========  ==============================================================

The dispatcher in ``service.py`` is the only caller wiring; nothing in the
API layer hardcodes a provider name.
"""

from app.services.effective_permissions.base import (
    PolicyChainStep,
    ResolvedPermission,
    Resolver,
    ResolverError,
    ResolverResult,
)
from app.services.effective_permissions.service import (
    SUPPORTED_PROVIDERS,
    resolve_effective_permissions,
)

__all__ = [
    "PolicyChainStep",
    "ResolvedPermission",
    "Resolver",
    "ResolverError",
    "ResolverResult",
    "SUPPORTED_PROVIDERS",
    "resolve_effective_permissions",
]
