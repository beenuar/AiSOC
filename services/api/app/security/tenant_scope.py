"""Intersect a client-supplied tenant with the authenticated principal's scope.

The API service already resolves an authenticated principal on almost every
route (``AuthUser`` → :class:`~app.api.v1.deps.CurrentUser`), so the tenant is
available without the caller naming it. Some routes still accept a
``tenant_id`` query parameter anyway — for a console that passes it explicitly,
or an MSSP operator narrowing to one managed customer — and that parameter is
where the isolation question lives.

This module is the one place that answers it. The rule is intersection:

* no ``tenant_id`` supplied → the principal's own tenant;
* a ``tenant_id`` the principal holds → that tenant;
* anything else → 403, never the requested tenant's rows.

Several routes already did this inline, correctly, with a hand-written
``if tenant_id != current_user.tenant_id: raise 403``. Correct, but invisible:
a structural gate cannot see it, a reviewer has to notice its absence rather
than its presence, and the next route to be written copies whichever neighbour
it happened to look at. Naming the operation makes the property checkable —
``scripts/check_route_tenant_scope.py`` fails the build when a route takes a
tenant identifier and never passes it through one of these.

Cross-tenant surfaces (the MSSP portfolio) are a different shape and keep
their own resolver, :mod:`app.services.org_scope`, which answers "which
tenants" rather than "which tenant". Both refuse on an empty scope rather than
widening to all — that is the invariant they share, and the one every
cross-tenant leak in this codebase has broken.
"""

from __future__ import annotations

import logging
import uuid

from fastapi import HTTPException, status

logger = logging.getLogger("aisoc.tenant_scope")


class TenantScopeError(Exception):
    """A read was attempted for a tenant the principal does not hold."""


def resolve_scoped_tenant(
    user: object,
    requested: uuid.UUID | str | None = None,
) -> uuid.UUID:
    """Return the tenant this request may read, or raise.

    ``user`` is any object carrying a ``tenant_id`` — in practice
    :class:`~app.api.v1.deps.CurrentUser`. Typed loosely so this module stays
    importable from anywhere without dragging in the dependency graph of
    ``app.api.v1.deps``.
    """
    own = getattr(user, "tenant_id", None)
    if own is None:
        raise TenantScopeError("authenticated principal carries no tenant")
    own_uuid = own if isinstance(own, uuid.UUID) else uuid.UUID(str(own))

    if requested is None:
        return own_uuid

    try:
        wanted = requested if isinstance(requested, uuid.UUID) else uuid.UUID(str(requested))
    except (ValueError, AttributeError, TypeError) as exc:
        raise TenantScopeError("requested tenant is not a UUID") from exc

    if wanted != own_uuid:
        # Warning, not debug: a caller reaching for a tenant they do not hold
        # is a security event. Values are interpolated as %s args rather than
        # formatted in, and they are UUIDs, so there is no newline to inject.
        logger.warning(
            "tenant_scope.refused user=%s own=%s requested=%s",
            getattr(user, "user_id", "unknown"),
            own_uuid,
            wanted,
        )
        raise TenantScopeError("requested tenant is outside the caller's authorised scope")
    return own_uuid


def scoped_tenant_or_403(
    user: object,
    requested: uuid.UUID | str | None = None,
) -> uuid.UUID:
    """:func:`resolve_scoped_tenant`, surfaced to HTTP as 403.

    Routes call this so a refusal reaches the client as a refusal rather than
    a 500, without every route repeating the same try/except.
    """
    try:
        return resolve_scoped_tenant(user, requested)
    except TenantScopeError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
