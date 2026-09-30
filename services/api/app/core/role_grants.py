"""The one place that decides whether a principal may confer authority.

Why this module exists
----------------------
``POST /api/v1/tenants/me/users`` took a ``role`` string from the request body
and wrote it to ``users.role`` — the column ``CurrentUser.require_permission``
reads on every guarded request. ``ROLE_PERMISSIONS`` gives ``platform_admin``
and ``admin`` the list ``["*"]``, and ``has_permission`` returns ``True`` for
every permission when that list contains ``"*"``. So a ``tenant_admin``, whose
whole point is that it is *scoped*, could create an account holding every
permission in the product and sign in as it (GHSA-pm3f-h6gc-rvgp).

The narrow repair is an allow-list on that one handler. It is the wrong
repair, because the defect is not "this handler forgot to validate": it is
that the server treated a client-supplied authority string as the
authorization decision itself. Four other routes did the same thing, and an
allow-list per route means the fifth one written next year is a new advisory.

So the property enforced here is about the *granter*, not the call site:

    no principal may confer authority it does not itself hold.

Escalation is then impossible by construction rather than by enumeration, and
a new route that writes a role gets the property by calling one function.

Where the wildcard fits
-----------------------
A subset check alone would still let a wildcard principal confer a wildcard
role, which is ordinarily unremarkable — administrators appoint
administrators. It is not unremarkable *here*, because every route that could
do it resolves its tenant from the caller's session, so a ``platform_admin``
minted through one is a principal with ``"*"`` over every tenant created
through a single tenant's door. :func:`never_grantable` therefore refuses the
wildcard roles to everyone, including a caller that already holds ``"*"``.
Minting one stays an out-of-band act with database credentials
(``app/scripts/bootstrap_admin.py``).

That set is *derived* from ``ROLE_PERMISSIONS`` rather than written down. A
third wildcard role added later is un-grantable the moment it is declared,
which is the only version of this rule that survives someone else editing the
map.

Relationship to the SCIM vocabulary
-----------------------------------
``app/services/scim/roles.py`` had already reached the same conclusion for
directory groups and kept its own copy of the list. Two lists that agree today
are two lists that disagree later, so it now imports :data:`GRANTABLE_ROLES`
and :data:`NEVER_GRANTABLE` from here and the vocabularies are the same object.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Final

from app.core.security import ROLE_PERMISSIONS

#: The permission string that means "every permission".
WILDCARD: Final[str] = "*"

#: Roles a request may confer, least authority first.
#:
#: The order is declared rather than derived because permission sets are only
#: *partially* ordered: ``threat_hunter`` holds ``rules:write`` and
#: ``soc_analyst`` does not, while ``soc_analyst`` holds ``playbooks:execute``
#: and ``threat_hunter`` does not. Neither contains the other, so no sort of
#: the map produces this list. Callers that need authority comparison should
#: use :func:`permissions_for` and compare sets; this order exists for the
#: places that must pick a single winner, such as SCIM group precedence.
GRANTABLE_ROLES: Final[tuple[str, ...]] = (
    "viewer",
    "soc_analyst",
    "threat_hunter",
    "soc_lead",
    "tenant_admin",
)

#: Roles no request may confer, whatever the caller holds, with the reason.
#:
#: Only the non-wildcard entries are listed. The wildcard ones are computed in
#: :func:`never_grantable` so that a role declared with ``["*"]`` tomorrow is
#: covered without anyone remembering to add it here.
_NEVER_GRANTABLE_EXPLICIT: Final[dict[str, str]] = {
    "api_service": "the identity an API key resolves to, not a role a person can hold",
}

_WILDCARD_REASON: Final[str] = (
    "holds '*' across every tenant; a tenant-scoped request must not be able to mint one. "
    "Use app/scripts/bootstrap_admin.py, which runs out of band with database credentials."
)


class RoleGrantDenied(Exception):
    """A grant was refused. ``unknown`` separates bad input from a real refusal.

    Carries the reason as text because every caller surfaces it to an operator
    who otherwise sees a bare 403 and has to read the source to learn which of
    their own permissions was missing.
    """

    def __init__(self, reason: str, *, unknown: bool = False) -> None:
        super().__init__(reason)
        self.reason = reason
        self.unknown = unknown


def wildcard_roles() -> frozenset[str]:
    """Roles whose declared permission list is the wildcard."""
    return frozenset(role for role, perms in ROLE_PERMISSIONS.items() if WILDCARD in perms)


def never_grantable() -> dict[str, str]:
    """Every role a request may not confer, mapped to why."""
    reasons = dict.fromkeys(wildcard_roles(), _WILDCARD_REASON)
    reasons.update(_NEVER_GRANTABLE_EXPLICIT)
    return reasons


def permissions_for(role: str) -> frozenset[str]:
    """The permissions a role confers. An unknown role confers nothing."""
    return frozenset(ROLE_PERMISSIONS.get(role, []))


def holds_wildcard(role: str) -> bool:
    """Whether a role confers every permission."""
    return WILDCARD in ROLE_PERMISSIONS.get(role, [])


def _granter_permissions(granter_role: str, granter_scopes: Sequence[str] | None) -> frozenset[str]:
    """What the caller actually holds.

    An API-key principal's authority is its ``scopes`` list, not the role of
    the user who minted it — ``CurrentUser.require_permission`` takes the
    scopes branch whenever ``scopes`` is not ``None``. Reading the role here
    would let a key with two read scopes, owned by a ``tenant_admin``, grant
    everything ``tenant_admin`` holds.
    """
    if granter_scopes is not None:
        return frozenset(granter_scopes)
    return permissions_for(granter_role)


def _covers(held: frozenset[str], wanted: str) -> bool:
    """Whether a held permission set covers one wanted permission.

    Mirrors ``has_permission`` and the API-key branch of
    ``CurrentUser.require_permission``, including the ``resource:*`` form. A
    subset check that did not understand ``alerts:*`` would refuse a grant the
    caller can in fact make, which is the kind of false refusal that gets a
    control removed.
    """
    if WILDCARD in held:
        return True
    if wanted in held:
        return True
    return f"{wanted.split(':')[0]}:{WILDCARD}" in held


def missing_permissions(held: frozenset[str], wanted: Iterable[str]) -> list[str]:
    """Which wanted permissions the held set does not cover, sorted."""
    return sorted({perm for perm in wanted if not _covers(held, perm)})


def authorize_role_grant(
    *,
    granter_role: str,
    requested_role: str,
    granter_scopes: Sequence[str] | None = None,
) -> str:
    """Return ``requested_role`` if this caller may confer it, else raise.

    Raises :class:`RoleGrantDenied`. ``unknown`` is set when the role is not in
    the enforced vocabulary at all, which callers map to 422 — a role outside
    ``ROLE_PERMISSIONS`` is not a smaller privilege, it is a string in a column
    that grants nothing while reading in a console as though it grants
    something.
    """
    if requested_role not in ROLE_PERMISSIONS:
        raise RoleGrantDenied(
            f"Unknown role {requested_role!r}. Assignable roles: {', '.join(GRANTABLE_ROLES)}",
            unknown=True,
        )

    blocked = never_grantable().get(requested_role)
    if blocked is not None:
        raise RoleGrantDenied(f"Role {requested_role!r} cannot be assigned through the API: {blocked}")

    held = _granter_permissions(granter_role, granter_scopes)
    missing = missing_permissions(held, permissions_for(requested_role))
    if missing:
        raise RoleGrantDenied(f"Cannot grant {requested_role!r}: it confers permissions you do not hold ({', '.join(missing)})")
    return requested_role


def authorize_permission_grant(
    *,
    granter_role: str,
    requested: Sequence[str],
    granter_scopes: Sequence[str] | None = None,
    subject: str = "permissions",
) -> list[str]:
    """Return ``requested`` if this caller may confer every one of them, else raise.

    The same property applied to a permission list rather than a role name,
    for API-key scopes and for database-backed RBAC roles. The wildcard is
    *not* special-cased away here, unlike :func:`authorize_role_grant`: a
    caller holding ``"*"`` may mint a ``"*"`` key, because that confers no
    authority the caller does not already have and does not create a principal
    outside the caller's own tenant. What it stops is the case that shipped —
    ``tenant_admin``, which is scoped on purpose, minting one.
    """
    held = _granter_permissions(granter_role, granter_scopes)
    missing = missing_permissions(held, requested)
    if missing:
        raise RoleGrantDenied(f"Cannot grant {subject} you do not hold: {', '.join(missing)}")
    return list(requested)


def authorize_role_change(
    *,
    granter_role: str,
    current_role: str,
    requested_role: str,
    granter_scopes: Sequence[str] | None = None,
) -> str:
    """Authorize re-roling an existing principal.

    Two checks, because changing a role is two acts. Conferring the new role
    is :func:`authorize_role_grant`. Taking away the old one matters
    separately: without this, a ``tenant_admin`` could not *create* a
    ``platform_admin`` but could demote the one that exists to ``viewer``,
    ending the only principal able to undo it. So a principal currently
    holding a never-grantable role is not re-roled from a tenant-scoped
    request at all.
    """
    blocked = never_grantable().get(current_role)
    if blocked is not None:
        raise RoleGrantDenied(f"This account holds {current_role!r}, which cannot be changed through the API: {blocked}")
    return authorize_role_grant(
        granter_role=granter_role,
        requested_role=requested_role,
        granter_scopes=granter_scopes,
    )


def vocabulary_problems() -> list[str]:
    """Disagreements between this module and the enforced permission map.

    Returned rather than raised so a gate and a test can report all of them at
    once. The last check is the ratchet that matters: a role added to
    ``ROLE_PERMISSIONS`` that is neither grantable nor recorded as refused is
    a role nobody decided about, and silence there defaults to "assignable"
    in every reviewer's head and to "refused" in this module's.
    """
    problems: list[str] = []
    refused = never_grantable()

    for role in GRANTABLE_ROLES:
        if role not in ROLE_PERMISSIONS:
            problems.append(f"GRANTABLE_ROLES names {role!r}, which ROLE_PERMISSIONS does not define")
        if role in refused:
            problems.append(f"{role!r} is both grantable and refused: {refused[role]}")
        if holds_wildcard(role):
            problems.append(f"{role!r} is grantable and holds the wildcard — a single request would confer everything")

    for role in _NEVER_GRANTABLE_EXPLICIT:
        if role not in ROLE_PERMISSIONS:
            problems.append(f"_NEVER_GRANTABLE_EXPLICIT names {role!r}, which ROLE_PERMISSIONS no longer defines")

    undecided = set(ROLE_PERMISSIONS) - set(GRANTABLE_ROLES) - set(refused)
    for role in sorted(undecided):
        problems.append(f"ROLE_PERMISSIONS defines {role!r} and this module neither makes it grantable nor records why it is not")

    return problems
