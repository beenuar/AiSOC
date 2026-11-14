"""GitHub organisation effective-permissions resolver (depth plan 2.5).

GitHub belongs in this set because it is where the source and the deployment
credentials live, so "what can this identity do" has a direct blast radius --
and unlike the three clouds its permission model is small enough to resolve
completely rather than partially.

Resolution model
----------------

A principal reaches a repository three ways, and the strongest wins:

1. **Organisation owner.** Admin on every repository in the organisation,
   regardless of any team or collaborator grant. Collected separately
   because an owner frequently holds no team grant at all, and a resolver
   that only read teams would report the most privileged identities in the
   organisation as having whatever their team happened to give them.
2. **Team membership.** A team holds a level on a repository and every
   member inherits it.
3. **Direct collaborator.** A grant made to the person on one repository.

Snapshot shape::

    {
      "org": "acme",
      "principals": [
        {"id": "alice", "type": "user", "org_role": "member|admin",
         "teams": ["platform"]},
        {"id": "team:platform", "type": "team", ...},
      ],
      "teams": [{"id": "team:platform", "slug": "platform", "members": ["alice"]}],
      "repositories": [{"id": "acme/api", "private": true, "archived": false}],
      "grants": [
        {"id": "...", "principal_id": "alice" | "team:platform",
         "repository_id": "acme/api", "level": "push",
         "via": null | "team:platform" | "organisation-owner"},
      ],
      "level_actions": {"push": ["repo.read", ...], ...}
    }

The level ladder is ordered by the *collector*, not here: it is a property
of GitHub rather than of this product, and re-deriving it in the resolver
would be a second place for the ladder to drift. This module reads
``level_actions`` out of the snapshot for the same reason.

There is no deny in GitHub's model -- access is granted, never subtracted --
so ``deny_actions`` is always empty, and that is a real property of the
provider rather than something unimplemented here. An archived repository is
the one case that *looks* like a deny: writes are refused regardless of the
grant. It is reported as a note on the decision's provenance rather than as
a denied action, because the grant genuinely exists and would take effect
the moment someone unarchives the repository -- which is a single click, and
is exactly the kind of latent access a reviewer is looking for.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.services.effective_permissions.base import (
    PolicyChainStep,
    ResolvedPermission,
    Resolver,
    ResolverError,
    ResolverResult,
)

#: Weakest to strongest. Mirrors the collector's ladder; the parity test in
#: ``services/connectors/tests/test_posture_collectors.py`` asserts the two
#: are equal rather than
#: trusting this comment.
LEVELS = ("pull", "triage", "push", "maintain", "admin")


def _strongest(*levels: str) -> str:
    known = [level for level in levels if level in LEVELS]
    if not known:
        return ""
    return max(known, key=LEVELS.index)


class GitHubResolver(Resolver):
    """Resolve what a GitHub principal can do to each repository."""

    provider = "github"
    coverage = "full"

    def __init__(self, snapshot: dict[str, Any] | None = None) -> None:
        self._snapshot = snapshot

    def resolve(
        self,
        principal_id: str,
        *,
        snapshot: dict[str, Any] | None = None,
    ) -> ResolverResult:
        snap = snapshot if snapshot is not None else self._snapshot
        if snap is None:
            raise ResolverError("GitHubResolver.resolve called without a snapshot")

        principals = {p["id"]: p for p in snap.get("principals", []) if p.get("id")}
        principal = principals.get(principal_id)
        if principal is None:
            raise ResolverError(f"principal {principal_id!r} not present in snapshot")

        level_actions: dict[str, list[str]] = snap.get("level_actions") or {}
        notes: list[str] = []
        if not level_actions:
            # Without the ladder the resolver cannot say what a level
            # confers. Refusing is correct: inventing a ladder here is how
            # the product would end up with two that disagree.
            raise ResolverError(
                "snapshot carries no level_actions map; the collector owns the GitHub permission "
                "ladder and a resolver that invented one would be a second source of truth"
            )

        teams = {t["id"]: t for t in snap.get("teams", []) if t.get("id")}
        repositories = {r["id"]: r for r in snap.get("repositories", []) if r.get("id")}

        # Every id this principal can be granted through: itself, plus the
        # teams it belongs to.
        identities = {principal_id}
        for slug in principal.get("teams") or []:
            identities.add(f"team:{slug}")
        for team_id, team in teams.items():
            if principal_id in (team.get("members") or []):
                identities.add(team_id)

        # repository -> (level, winning grant). A principal with two grants
        # on one repository gets the stronger, which is GitHub's rule.
        best: dict[str, tuple[str, dict[str, Any]]] = {}
        chains: dict[str, list[PolicyChainStep]] = {}
        for grant in snap.get("grants", []):
            if grant.get("principal_id") not in identities:
                continue
            repo_id = grant.get("repository_id")
            level = grant.get("level")
            if not repo_id or level not in LEVELS:
                continue
            chains.setdefault(repo_id, []).append(
                PolicyChainStep(
                    kind="grant",
                    id=str(grant.get("id") or f"{grant.get('principal_id')}:{repo_id}"),
                    name=f"{level} via {grant.get('via') or 'direct collaborator'}",
                    effect="allow",
                    via=grant.get("via"),
                )
            )
            current = best.get(repo_id)
            if current is None or LEVELS.index(level) > LEVELS.index(current[0]):
                best[repo_id] = (level, grant)

        decisions: list[ResolvedPermission] = []
        archived: list[str] = []
        for repo_id, (level, _grant) in sorted(best.items()):
            repo = repositories.get(repo_id, {})
            if repo.get("archived"):
                archived.append(repo_id)
            decisions.append(
                ResolvedPermission(
                    principal_id=principal_id,
                    resource_id=repo_id,
                    resource_kind="github:repository",
                    resource_arn=repo_id,
                    actions=tuple(sorted(level_actions.get(level, ()))),
                    # GitHub grants and never subtracts. Empty here is a
                    # property of the provider, not a gap in this resolver.
                    deny_actions=(),
                    policy_chain=tuple(chains.get(repo_id, ())),
                )
            )

        if archived:
            notes.append(
                f"{len(archived)} repository(ies) are archived, so writes are refused today despite "
                f"the grant: {', '.join(sorted(archived)[:5])}"
                + (" and others" if len(archived) > 5 else "")
                + ". The grant is real and takes effect the moment the repository is unarchived."
            )

        return ResolverResult(
            provider=self.provider,
            principal_id=principal_id,
            coverage=self.coverage,
            last_resolved=datetime.now(tz=UTC),
            decisions=decisions,
            notes=notes,
        )
