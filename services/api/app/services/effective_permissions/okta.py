"""Okta effective-permissions resolver — scaffold (T3.2).

Will resolve a user's group memberships, then map each group to the apps it
is assigned to and to any admin roles it grants. Output is the union of app
access (``okta.app.read`` style) and admin-role privilege strings.

The full implementation is deferred — the dispatcher recognises the provider
and the endpoint returns HTTP 501 with a ``coverage: scaffold`` envelope.
"""

from __future__ import annotations

from typing import Any

from app.services.effective_permissions.base import Resolver, ResolverResult


class OktaResolver(Resolver):
    """Scaffolded Okta resolver — see module docstring."""

    provider = "okta"
    coverage = "scaffold"

    def resolve(
        self,
        principal_id: str,
        *,
        snapshot: dict[str, Any] | None = None,
    ) -> ResolverResult:
        raise NotImplementedError(
            "OktaResolver is scaffolded but not yet implemented. Resolve "
            "user -> groups, groups -> apps + admin roles, union the "
            "results into the effective privilege set."
        )
