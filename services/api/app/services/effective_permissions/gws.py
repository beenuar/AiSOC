"""Google Workspace effective-permissions resolver — scaffold (T3.2).

Will resolve a user's admin role assignments (Super Admin, Help Desk Admin,
Custom Roles) into the underlying privilege set declared by each role, scoped
to the org units the role assignment is bound to.

The full implementation is deferred — the dispatcher recognises the provider
and the endpoint returns HTTP 501 with a ``coverage: scaffold`` envelope.
"""

from __future__ import annotations

from typing import Any

from app.services.effective_permissions.base import Resolver, ResolverResult


class GoogleWorkspaceResolver(Resolver):
    """Scaffolded Google Workspace resolver — see module docstring."""

    provider = "gws"
    coverage = "scaffold"

    def resolve(
        self,
        principal_id: str,
        *,
        snapshot: dict[str, Any] | None = None,
    ) -> ResolverResult:
        raise NotImplementedError(
            "GoogleWorkspaceResolver is scaffolded but not yet implemented. "
            "Resolve user -> admin role assignments, expand each role's "
            "privilege list, scope by the assigned org unit."
        )
