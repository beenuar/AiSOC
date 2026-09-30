"""Mapping directory groups onto the roles this platform actually enforces.

Where the enforced vocabulary lives
------------------------------------
``services/api/app/core/security.py`` declares ``ROLE_PERMISSIONS``, and
``CurrentUser.require_permission`` reads it through ``has_permission(role, …)``
on every guarded request. That map is the role vocabulary. A role outside it
is a string in a column: it grants nothing, and worse, it *reads* in a console
as though it grants something.

So a pushed group resolves to one of those keys or to nothing at all.
``check_scim_contract.py`` compares this module against that map in both
directions, so a role renamed there cannot leave a mapping here pointing at a
role that no longer exists.

Why an unrecognised group confers nothing
------------------------------------------
An identity provider pushes whatever the administrator selected, named
however that directory names things. The tempting default is to create a role
per pushed group, which manufactures roles nobody granted permissions to. The
default here is the opposite: a group whose name does not resolve is recorded,
audited and powerless. Unrecognised means no privilege rather than unknown
privilege.

Why precedence is explicit
---------------------------
A principal is routinely in several groups, and ``users.role`` is a single
column. Picking "the most recently added" would make a user's authority
depend on the order an identity provider happened to sync, which changes
between runs. :data:`ROLE_PRECEDENCE` is a total order, so the same set of
groups always produces the same role.
"""

from __future__ import annotations

import re
from typing import Final

from app.core.role_grants import GRANTABLE_ROLES, never_grantable
from app.core.security import ROLE_PERMISSIONS

#: The role a provisioned principal holds before any group confers one.
#: Least privilege: a user created by an IdP push but placed in no mapped
#: group can sign in and read, and can do nothing else.
DEFAULT_PROVISIONED_ROLE: Final[str] = "viewer"

#: Total order, least authority first. A principal's role is the last entry
#: in this list that any of their mapped groups confers.
#:
#: This *is* ``app.core.role_grants.GRANTABLE_ROLES``, not a copy of it. SCIM
#: reached the conclusion that wildcard roles must not be conferrable by a
#: client-supplied name first, and kept its own list; the tenant user API then
#: shipped without the same rule (GHSA-pm3f-h6gc-rvgp). Two lists that agree
#: today are two lists that disagree later, so there is now one.
ROLE_PRECEDENCE: Final[tuple[str, ...]] = GRANTABLE_ROLES

#: Roles no directory group may confer, with the reason.
#:
#: ``platform_admin`` and ``admin`` hold ``*`` across every tenant. Letting a
#: group name grant that would mean anyone who can create a group in the
#: customer's directory, which is a different and usually larger set of people
#: than the platform's administrators, could mint a platform administrator by
#: choosing a group name. ``api_service`` is the identity an API key resolves
#: to and is not a human role at all.
#:
#: Shared with every other grant path, and the wildcard members are derived
#: from ``ROLE_PERMISSIONS`` rather than named, so a third role declared with
#: ``["*"]`` is unreachable from a group the moment it is declared.
UNREACHABLE_BY_GROUP: Final[dict[str, str]] = never_grantable()

#: Group-name fragments that resolve to a role, most specific first.
#:
#: Matched against the group's display name reduced to lowercase words, so
#: ``AiSOC-SOC-Analysts``, ``aisoc soc analyst`` and ``SOC_Analysts`` all
#: reach the same role. Order matters: ``soc lead`` must be tested before
#: ``soc analyst`` would match a name containing both.
GROUP_NAME_RULES: Final[tuple[tuple[tuple[str, ...], str], ...]] = (
    (("tenant", "admin"), "tenant_admin"),
    (("soc", "lead"), "soc_lead"),
    (("soc", "manager"), "soc_lead"),
    (("incident", "commander"), "soc_lead"),
    (("threat", "hunter"), "threat_hunter"),
    (("threat", "hunting"), "threat_hunter"),
    (("hunter",), "threat_hunter"),
    (("soc", "analyst"), "soc_analyst"),
    (("triage",), "soc_analyst"),
    (("analyst",), "soc_analyst"),
    (("viewer",), "viewer"),
    (("read", "only"), "viewer"),
    (("auditor",), "viewer"),
)

_WORD = re.compile(r"[a-z0-9]+")


def assignable_roles() -> tuple[str, ...]:
    """Roles a directory group may confer, least authority first."""
    return ROLE_PRECEDENCE


def normalise_group_name(display_name: str) -> list[str]:
    """Reduce a group display name to lowercase word tokens."""
    return _WORD.findall(display_name.casefold())


def _match_tokens(display_name: str) -> set[str]:
    """Tokens a rule may match against, including depluralised forms.

    Directory groups are named for the people in them, so they are almost
    always plural: ``AiSOC-SOC-Analysts``, ``Threat Hunters``,
    ``Tenant Admins``. Matching on the exact token would resolve
    ``soc analyst`` and leave the plural spelling every real directory uses
    conferring nothing, which fails in the safe direction but fails on
    nearly every real group.

    Both forms are kept rather than replaced, so a name that is genuinely
    singular still matches.
    """
    tokens = set()
    for word in normalise_group_name(display_name):
        tokens.add(word)
        if len(word) > 3 and word.endswith("es"):
            tokens.add(word[:-2])
        if len(word) > 2 and word.endswith("s"):
            tokens.add(word[:-1])
    return tokens


def resolve_role(display_name: str) -> str | None:
    """The role a group name confers, or ``None`` when it confers nothing.

    Returning ``None`` is a normal outcome, not a failure. It means the
    group is recorded and membership is tracked while no privilege changes
    hands.
    """
    present = _match_tokens(display_name)
    if not present:
        return None
    for fragments, role in GROUP_NAME_RULES:
        if all(fragment in present for fragment in fragments):
            return role
    return None


def effective_role(mapped_roles: list[str | None]) -> str:
    """The single role a principal holds, given every group they are in.

    Unmapped groups contribute nothing. A principal in no mapped group falls
    back to :data:`DEFAULT_PROVISIONED_ROLE` rather than keeping whatever
    role they had, because otherwise removing somebody from the one group
    that granted their authority would leave that authority in place, which
    is the failure a deprovisioning test is written to catch.
    """
    rank = {role: index for index, role in enumerate(ROLE_PRECEDENCE)}
    best = DEFAULT_PROVISIONED_ROLE
    best_rank = rank.get(DEFAULT_PROVISIONED_ROLE, 0)
    for role in mapped_roles:
        if role is None:
            continue
        candidate = rank.get(role)
        if candidate is not None and candidate > best_rank:
            best, best_rank = role, candidate
    return best


def validate_vocabulary() -> list[str]:
    """Disagreements between this module and the enforced role map.

    Returned rather than raised so both the gate and a test can report every
    problem at once instead of the first one.
    """
    problems: list[str] = []
    enforced = set(ROLE_PERMISSIONS)

    for role in ROLE_PRECEDENCE:
        if role not in enforced:
            problems.append(f"ROLE_PRECEDENCE names {role!r}, which ROLE_PERMISSIONS does not define")
        if role in UNREACHABLE_BY_GROUP:
            problems.append(f"{role!r} is both assignable and listed as unreachable by group")

    for _fragments, role in GROUP_NAME_RULES:
        if role not in ROLE_PRECEDENCE:
            problems.append(f"GROUP_NAME_RULES maps to {role!r}, which is not in ROLE_PRECEDENCE")

    for role in UNREACHABLE_BY_GROUP:
        if role not in enforced:
            problems.append(f"UNREACHABLE_BY_GROUP names {role!r}, which ROLE_PERMISSIONS no longer defines")

    uncovered = enforced - set(ROLE_PRECEDENCE) - set(UNREACHABLE_BY_GROUP)
    for role in sorted(uncovered):
        problems.append(f"ROLE_PERMISSIONS defines {role!r} and this module neither makes it assignable nor records why it is not")

    if DEFAULT_PROVISIONED_ROLE not in ROLE_PRECEDENCE:
        problems.append(f"DEFAULT_PROVISIONED_ROLE {DEFAULT_PROVISIONED_ROLE!r} is not in ROLE_PRECEDENCE")

    return problems
