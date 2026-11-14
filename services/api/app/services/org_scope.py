"""Resolve which tenants an operator principal may read across.

Every cross-tenant surface in the MSSP API takes its tenant list from here
and from nowhere else. That is the whole design: there is one place that
decides "which tenants", it is small enough to read in a sitting, and the
aggregate layer physically cannot run a query without its answer.

The rule that matters is the empty one. A member with no grants resolves to
an **empty** portfolio, never an unfiltered one. Every cross-tenant leak this
codebase has had took the same shape — a scope that was absent rather than
narrow, and a query that treated absent as "no filter". `get_entity_neighbors`
accepted a `tenant_id` and never bound it. `_events_of_interest` handed
API-authored SQL to a rewriter meant for untrusted SQL and checked nothing,
so every fresh tenant saw the same global funnel. `rewrite_for_tenant` itself
returned unscoped SQL and reported success when its parser moved a dict key.
So:

- resolution returns a frozenset, and an empty frozenset is a real answer;
- :class:`PortfolioScope.tenant_ids` is the only input the aggregates accept;
- the aggregates raise on an empty set rather than running unfiltered SQL.

Two axes, kept separate because they answer different questions:

    breadth    owner/admin reach the whole portfolio. operator/viewer reach
               only what `organization_member_tenants` grants them.
    authority  owner/admin/operator may act. viewer is read-only.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.organization import (
    ACTING_ROLES,
    ADMINISTERING_ROLES,
    PORTFOLIO_WIDE_ROLES,
    Organization,
    OrganizationMember,
    OrganizationMemberTenant,
    OrganizationTenant,
)

logger = logging.getLogger("aisoc.org_scope")


class PortfolioScopeError(RuntimeError):
    """A cross-tenant query was attempted without a resolved portfolio.

    Raised by :func:`require_scope`. This is a programming error, not a user
    error: it means an aggregate was about to run with no tenant filter.
    """


@dataclass(frozen=True)
class PortfolioScope:
    """The tenants one principal may read across, and what they may do.

    ``tenant_ids`` is authoritative and exhaustive. Nothing downstream is
    permitted to widen it, and no code path may substitute "all tenants" for
    an empty one.
    """

    org_id: uuid.UUID | None = None
    org_slug: str | None = None
    org_name: str | None = None
    org_role: str | None = None
    tenant_ids: frozenset[uuid.UUID] = field(default_factory=frozenset)
    # True when the member's reach is the entire portfolio rather than a set
    # of explicit grants. Surfaced so the console can say *why* a portfolio
    # looks small instead of leaving an operator guessing.
    portfolio_wide: bool = False

    @property
    def is_member(self) -> bool:
        return self.org_id is not None

    @property
    def is_empty(self) -> bool:
        return not self.tenant_ids

    @property
    def can_act(self) -> bool:
        return self.org_role in ACTING_ROLES

    @property
    def can_administer(self) -> bool:
        return self.org_role in ADMINISTERING_ROLES

    def covers(self, tenant_id: uuid.UUID) -> bool:
        return tenant_id in self.tenant_ids

    def ordered_ids(self) -> list[uuid.UUID]:
        """Deterministic ordering, so queries and their tests are stable."""
        return sorted(self.tenant_ids)


EMPTY_SCOPE = PortfolioScope()


async def resolve_portfolio_scope(db: AsyncSession, user_id: uuid.UUID) -> PortfolioScope:
    """Resolve the portfolio managed by the principal ``user_id``.

    Returns :data:`EMPTY_SCOPE` for a principal who belongs to no
    organisation. Returns a member scope with an empty ``tenant_ids`` for a
    member who has been granted nothing — which is a different situation
    (they are an operator, they just cannot see anything yet) and the API
    distinguishes the two.

    Takes the id rather than a principal object on purpose. This function
    previously accepted ``user: User`` and read ``user.id``, while its only
    production caller passes the authenticated ``CurrentUser``, which carries
    its identifier as ``user_id`` and has no ``id`` at all — so every
    ``/mssp/portfolio`` request raised ``AttributeError`` and returned 500,
    including the non-member case the route means to answer with 403. The
    service tests passed throughout because they handed it an ORM ``User``,
    which does have ``.id``. An identifier cannot be the wrong shape.
    """
    membership = (
        await db.execute(
            select(OrganizationMember, Organization)
            .join(Organization, Organization.id == OrganizationMember.org_id)
            .where(
                OrganizationMember.user_id == user_id,
                Organization.is_active.is_(True),
            )
            .order_by(Organization.created_at)
        )
    ).first()

    if membership is None:
        logger.debug("org_scope.not_a_member user=%s", user_id)
        return EMPTY_SCOPE

    member, org = membership
    role = str(member.org_role)

    portfolio_rows = (await db.execute(select(OrganizationTenant.tenant_id).where(OrganizationTenant.org_id == org.id))).scalars()
    portfolio = {uuid.UUID(str(t)) for t in portfolio_rows}

    if role in PORTFOLIO_WIDE_ROLES:
        tenant_ids = portfolio
        portfolio_wide = True
    else:
        granted_rows = (
            await db.execute(
                select(OrganizationMemberTenant.tenant_id).where(
                    OrganizationMemberTenant.org_id == org.id,
                    OrganizationMemberTenant.user_id == user_id,
                )
            )
        ).scalars()
        # Intersected with the portfolio even though the composite foreign
        # key already guarantees containment. Belt and braces: this is the
        # set that becomes a SQL predicate, and a stale grant surviving a
        # schema change must narrow the result, never widen it.
        tenant_ids = {uuid.UUID(str(t)) for t in granted_rows} & portfolio
        portfolio_wide = False

    if not tenant_ids:
        # Logged at warning, with ids, because "the console is empty" is
        # otherwise indistinguishable from "the platform is broken" — the
        # exact confusion a `debug`-level skip caused for tenant resolution.
        logger.warning(
            "org_scope.empty_portfolio user=%s org=%s role=%s portfolio_size=%d",
            user_id,
            org.id,
            role,
            len(portfolio),
        )

    return PortfolioScope(
        org_id=uuid.UUID(str(org.id)),
        org_slug=str(org.slug),
        org_name=str(org.name),
        org_role=role,
        tenant_ids=frozenset(tenant_ids),
        portfolio_wide=portfolio_wide,
    )


def require_scope(scope: PortfolioScope) -> list[uuid.UUID]:
    """Return the tenant list for a query, or refuse to build one.

    The aggregates call this instead of reading ``scope.tenant_ids``
    directly, so "I forgot to check for empty" produces an exception at the
    point of the mistake rather than a `WHERE tenant_id = ANY('{}')` that a
    later refactor could drop.
    """
    if scope.is_empty:
        raise PortfolioScopeError("refusing to build a cross-tenant query with an empty portfolio scope")
    return scope.ordered_ids()


def narrow(scope: PortfolioScope, tenant_ids: Sequence[uuid.UUID]) -> PortfolioScope:
    """Restrict a scope to a caller-supplied subset.

    Used by endpoints that accept a `tenant_id` filter. Intersection only —
    naming a tenant outside the portfolio narrows the result to nothing
    rather than reaching outside it, so a filter parameter can never become
    a selector for someone else's data.
    """
    requested = {uuid.UUID(str(t)) for t in tenant_ids}
    return PortfolioScope(
        org_id=scope.org_id,
        org_slug=scope.org_slug,
        org_name=scope.org_name,
        org_role=scope.org_role,
        tenant_ids=frozenset(requested & scope.tenant_ids),
        portfolio_wide=False,
    )
