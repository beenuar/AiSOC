"""GCP IAM effective-permissions resolver — scaffold (T3.2).

Will walk IAM allow policies at the resource hierarchy (organization → folder
→ project → resource) and intersect with role permission lists, then apply
organization policies (deny constraints, restricted services).

The full implementation is deferred — the dispatcher recognises the provider
and the endpoint returns HTTP 501 with a ``coverage: scaffold`` envelope.
"""

from __future__ import annotations

from typing import Any

from app.services.effective_permissions.base import Resolver, ResolverResult


class GcpIamResolver(Resolver):
    """Scaffolded GCP IAM resolver — see module docstring."""

    provider = "gcp"
    coverage = "scaffold"

    def resolve(
        self,
        principal_id: str,
        *,
        snapshot: dict[str, Any] | None = None,
    ) -> ResolverResult:
        raise NotImplementedError(
            "GcpIamResolver is scaffolded but not yet implemented. Walk IAM "
            "allow policies at Org/Folder/Project/Resource scope, expand "
            "role -> permissions, apply org-policy deny constraints."
        )
