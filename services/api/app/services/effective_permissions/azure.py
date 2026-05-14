"""Azure RBAC effective-permissions resolver — scaffold (T3.2).

Will walk role assignments at the principal's scopes (management group →
subscription → resource group → resource) and intersect with the action set
declared by each role definition (built-in or custom). Deny assignments
short-circuit the result.

The full implementation is deferred — the dispatcher recognises the provider
and the endpoint returns HTTP 501 with a ``coverage: scaffold`` envelope so
the UI can render a "not yet implemented" placeholder without a 404.
"""

from __future__ import annotations

from typing import Any

from app.services.effective_permissions.base import Resolver, ResolverResult


class AzureRbacResolver(Resolver):
    """Scaffolded Azure RBAC resolver — see module docstring."""

    provider = "azure"
    coverage = "scaffold"

    def resolve(
        self,
        principal_id: str,
        *,
        snapshot: dict[str, Any] | None = None,
    ) -> ResolverResult:
        raise NotImplementedError(
            "AzureRbacResolver is scaffolded but not yet implemented. "
            "Walk role assignments at MG/Sub/RG/Resource scope, intersect "
            "with role definition actions, apply deny assignments."
        )
