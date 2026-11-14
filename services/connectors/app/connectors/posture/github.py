"""Collect a GitHub organisation posture snapshot.

Returns the shape the GitHub resolver in
``services/api/app/services/effective_permissions/github.py`` consumes.

Why GitHub belongs in this set
------------------------------
It is where the source and the deployment credentials live, so "what can
this identity do" has a direct blast radius -- and unlike the three clouds,
its permission model is small enough to collect completely rather than
partially. An org member reaches a repository two ways: a direct
collaborator grant, or membership of a team that holds one. Both are
collected.

The modelling decision worth stating: GitHub's permission *levels* (read,
triage, write, maintain, admin) are ordered, and a principal holding two
grants on one repository gets the stronger. That ordering is applied here,
at collection time, because it is a property of GitHub rather than of this
product, and a resolver that re-derived it would be a second place for the
ladder to drift.
"""

from __future__ import annotations

from typing import Any

import structlog

from app.connectors.posture import Collected

logger = structlog.get_logger()

_BASE = "https://api.github.com"
_MAX_PAGES = 50
_PER_PAGE = 100

#: Weakest to strongest. A principal holding two grants on one repository
#: gets the stronger, which is GitHub's rule and not ours.
_LEVELS = ("pull", "triage", "push", "maintain", "admin")

#: The actions each level confers, named the way GitHub's own documentation
#: and audit log name them so a reader can match an answer against a log
#: line without a translation table.
_LEVEL_ACTIONS: dict[str, tuple[str, ...]] = {
    "pull": ("repo.read", "repo.clone"),
    "triage": ("repo.read", "repo.clone", "issues.manage"),
    "push": ("repo.read", "repo.clone", "issues.manage", "repo.push", "workflow.run"),
    "maintain": (
        "repo.read",
        "repo.clone",
        "issues.manage",
        "repo.push",
        "workflow.run",
        "repo.manage_settings",
    ),
    "admin": (
        "repo.read",
        "repo.clone",
        "issues.manage",
        "repo.push",
        "workflow.run",
        "repo.manage_settings",
        "repo.manage_access",
        "repo.delete",
        "secrets.write",
    ),
}


def strongest(*levels: str) -> str:
    """The strongest of the levels given, ignoring any GitHub does not define.

    An unrecognised level is dropped rather than ranked, because guessing
    where a new GitHub level sits in the ladder would either over- or
    under-state access, and both are wrong in a way nobody would notice.
    """
    known = [level for level in levels if level in _LEVELS]
    if not known:
        return ""
    return max(known, key=_LEVELS.index)


def _level_from_permissions(permissions: dict[str, Any] | None) -> str:
    """Read a level off GitHub's boolean permission block.

    The REST API returns ``{"admin": true, "push": true, ...}`` rather than
    a single level on several endpoints, and the booleans are cumulative, so
    the strongest true one is the level.
    """
    if not isinstance(permissions, dict):
        return ""
    for level in reversed(_LEVELS):
        if permissions.get(level) is True:
            return level
    return ""


async def _paged(
    client: Any,
    url: str,
    headers: dict[str, str],
    out: Collected,
    what: str,
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for page in range(1, _MAX_PAGES + 1):
        try:
            resp = await client.get(url, headers=headers, params={"per_page": _PER_PAGE, "page": page})
        except Exception as exc:  # noqa: BLE001
            out.note(f"{what}: request failed on page {page}: {exc}")
            return items
        if resp.status_code != 200:
            out.note(f"{what}: HTTP {resp.status_code} on page {page}")
            return items
        batch = resp.json()
        if not isinstance(batch, list) or not batch:
            return items
        items.extend(batch)
        if len(batch) < _PER_PAGE:
            return items
    out.note(f"{what}: stopped after {_MAX_PAGES} pages; the organisation is larger than one pass")
    return items


async def collect(client: Any, headers: dict[str, str], org: str) -> Collected:
    out = Collected(snapshot={})
    if not org:
        out.note("no organisation is configured on the connector, so nothing could be collected")
        out.snapshot = {"org": "", "principals": [], "teams": [], "repositories": [], "grants": []}
        return out

    members = await _paged(client, f"{_BASE}/orgs/{org}/members", headers, out, "organisation members")
    teams = await _paged(client, f"{_BASE}/orgs/{org}/teams", headers, out, "teams")
    repos = await _paged(client, f"{_BASE}/orgs/{org}/repos", headers, out, "repositories")

    # Org owners hold admin on every repository regardless of any team or
    # collaborator grant, so the role is read separately. Without it the
    # most privileged identities in the organisation would resolve to
    # whatever their team happened to grant.
    owners: set[str] = set()
    for member in members:
        login = member.get("login")
        if not login:
            continue
        try:
            resp = await client.get(f"{_BASE}/orgs/{org}/memberships/{login}", headers=headers)
            if resp.status_code == 200 and resp.json().get("role") == "admin":
                owners.add(login)
            elif resp.status_code != 200:
                out.note(
                    f"membership role for {login} returned HTTP {resp.status_code}; if they are an "
                    f"organisation owner their admin access over every repository is not reflected"
                )
        except Exception as exc:  # noqa: BLE001
            out.note(f"membership role for {login} could not be read: {exc}")

    team_members: dict[str, list[str]] = {}
    grants: list[dict[str, Any]] = []

    for team in teams:
        slug = team.get("slug")
        if not slug:
            continue
        logins = [
            m["login"]
            for m in await _paged(client, f"{_BASE}/orgs/{org}/teams/{slug}/members", headers, out, f"team {slug} members")
            if m.get("login")
        ]
        team_members[slug] = logins
        for repo in await _paged(client, f"{_BASE}/orgs/{org}/teams/{slug}/repos", headers, out, f"team {slug} repositories"):
            full_name = repo.get("full_name")
            level = _level_from_permissions(repo.get("permissions"))
            if not full_name or not level:
                continue
            grants.append(
                {
                    "id": f"team:{slug}:{full_name}",
                    "principal_id": f"team:{slug}",
                    "repository_id": full_name,
                    "level": level,
                    "via": f"team:{slug}",
                }
            )

    repositories: list[dict[str, Any]] = []
    for repo in repos:
        full_name = repo.get("full_name")
        if not full_name:
            continue
        repositories.append(
            {
                "id": full_name,
                "name": repo.get("name") or full_name,
                "private": bool(repo.get("private")),
                "archived": bool(repo.get("archived")),
            }
        )
        for collaborator in await _paged(
            client,
            f"{_BASE}/repos/{full_name}/collaborators",
            headers,
            out,
            f"collaborators on {full_name}",
        ):
            login = collaborator.get("login")
            level = _level_from_permissions(collaborator.get("permissions"))
            if not login or not level:
                continue
            grants.append(
                {
                    "id": f"user:{login}:{full_name}",
                    "principal_id": login,
                    "repository_id": full_name,
                    "level": level,
                    "via": None,
                }
            )

    for login in sorted(owners):
        for repo in repositories:
            grants.append(
                {
                    "id": f"owner:{login}:{repo['id']}",
                    "principal_id": login,
                    "repository_id": repo["id"],
                    "level": "admin",
                    "via": "organisation-owner",
                }
            )

    principals: list[dict[str, Any]] = [
        {
            "id": m["login"],
            "name": m["login"],
            "type": "user",
            "org_role": "admin" if m["login"] in owners else "member",
            "teams": sorted(slug for slug, logins in team_members.items() if m["login"] in logins),
        }
        for m in members
        if m.get("login")
    ]
    principals.extend(
        {
            "id": f"team:{slug}",
            "name": slug,
            "type": "team",
            "org_role": "team",
            "teams": [],
        }
        for slug in sorted(team_members)
    )

    if not principals:
        out.note(
            f"no members were returned for organisation {org!r}. On a live organisation this is far "
            f"more often a token without the read:org scope than an organisation with no members"
        )

    out.snapshot = {
        "org": org,
        "principals": principals,
        "teams": [{"id": f"team:{slug}", "slug": slug, "members": sorted(logins)} for slug, logins in sorted(team_members.items())],
        "repositories": repositories,
        "grants": grants,
        "level_actions": {level: list(actions) for level, actions in _LEVEL_ACTIONS.items()},
    }
    return out
