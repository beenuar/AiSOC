"""One person across six sources, with confidence and evidence.

Depth plan wave 2, Phase 3.1.

An alert names ``alice@example.com`` from Okta, ``ALICE`` from an EDR device
login, ``arn:aws:iam::1:user/alice`` from CloudTrail and ``alice-gh`` from a
code platform, and the platform treats them as four people. Stories cannot
cross a source, and a privilege answer about one does not reach an alert
about another.

The failure mode this is designed against
-----------------------------------------
Not "no links" — **wrong links**. Merging two people because their
local-parts match destroys the thing the feature exists to provide, and it
destroys it invisibly: the merged identity looks richer, not broken. The
canonical wrong merges are concrete and all three are refused here:

* ``alice@example.com`` and ``alice@contoso.com`` — routinely two people;
* ``admin`` on an endpoint and ``admin`` in a directory — two accounts;
* ``svc-deploy`` seen in two clouds — two service accounts, usually.

So every link carries a rule, a confidence and the evidence that produced
it, and **only links at or above** :data:`MERGE_THRESHOLD` are allowed to
merge. Everything weaker is returned and shown, because a weak link is
genuinely useful to an analyst reading a story and genuinely dangerous to
anything that acts on it. Those are different consumers, and the shape lets
them have different answers.

Where it is stored
------------------
Both the entity store in CORE (ADR-0010 put it there precisely so a CORE
install is not context-free) and the graph in ``full``, behind one read
interface — see :mod:`app.services.identity_resolution_store`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "LINK_RULES",
    "MERGE_THRESHOLD",
    "SOURCE_KINDS",
    "IdentityLink",
    "ResolutionResult",
    "resolve_links",
]

#: The six sources the plan names. A seventh added without a rule below
#: links nothing, so the two lists are kept adjacent on purpose.
SOURCE_KINDS: tuple[str, ...] = (
    "idp",
    "edr_device_user",
    "proxy_user",
    "cloud_principal",
    "code_platform",
    "workspace",
)

#: At or above this, a link may merge two identities into one cluster.
#: Below it the link is shown and nothing acts on it.
#:
#: 0.90 rather than something lower because of the asymmetry of the two
#: errors. A missed link costs an analyst one pivot they make by hand; a
#: wrong link silently attributes one person's alerts to another, and
#: nothing downstream can detect it.
MERGE_THRESHOLD = 0.90

#: Identifiers that are role names rather than people. A match on one of
#: these is not evidence of anything: every estate has an `admin`, and
#: merging on it would join every tenant's local administrator into one
#: identity and take the whole estate's alerts with it.
GENERIC_IDENTIFIERS: frozenset[str] = frozenset(
    {
        "admin",
        "administrator",
        "root",
        "guest",
        "support",
        "service",
        "svc",
        "system",
        "operator",
        "backup",
        "test",
        "deploy",
        "build",
        "ci",
        "runner",
        "bot",
        "jenkins",
        "terraform",
        "ansible",
    }
)

#: Prefixes that mark an identifier as a shared service account rather than
#: a person. Matched on the local part, so `svc-deploy@example.com` and a
#: bare `svc-deploy` are both caught.
_SERVICE_PREFIXES: tuple[str, ...] = ("svc-", "svc_", "service-", "sa-", "bot-", "ci-")

_ARN_USER_RE = re.compile(r"^arn:aws:iam::\d+:(?:user|role)/(?:.*/)?(?P<name>[^/]+)$")
_GCP_MEMBER_RE = re.compile(r"^(?:user|serviceAccount):(?P<name>.+)$")


@dataclass(frozen=True)
class IdentityLink:
    """One proposed link between two source-scoped identities."""

    left: str
    right: str
    confidence: float
    rule: str
    evidence: list[str] = field(default_factory=list)

    @property
    def merged(self) -> bool:
        """Whether this link is strong enough to merge on."""
        return self.confidence >= MERGE_THRESHOLD

    def as_dict(self) -> dict[str, Any]:
        return {
            "left": self.left,
            "right": self.right,
            "confidence": round(self.confidence, 4),
            "rule": self.rule,
            "evidence": list(self.evidence),
            "merged": self.merged,
            # Said in words as well as implied by the number, because the
            # number is a threshold comparison a reader has to know to make.
            "note": ("Strong enough to treat as one person." if self.merged else "Shown as a possible link only; nothing merges on it."),
        }


@dataclass(frozen=True)
class ResolutionResult:
    """Every link found, strong and weak."""

    links: list[IdentityLink] = field(default_factory=list)
    #: Identities that matched nothing. Returned rather than dropped so a
    #: surface can say "we could not place this account", which is a
    #: finding in itself on an estate that is supposed to be joined up.
    unlinked: list[str] = field(default_factory=list)

    def clusters_for_merge(self) -> list[set[str]]:
        """Connected components over **merge-strength links only**.

        Weak links are deliberately absent from the graph this walks. A
        chain of three weak links would otherwise merge two identities that
        no single rule was willing to join, which is how a transitive
        merge quietly becomes the broadest possible one.
        """
        parent: dict[str, str] = {}

        def find(x: str) -> str:
            parent.setdefault(x, x)
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(a: str, b: str) -> None:
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[ra] = rb

        strong = [link for link in self.links if link.merged]
        for link in strong:
            union(link.left, link.right)

        groups: dict[str, set[str]] = {}
        for node in parent:
            groups.setdefault(find(node), set()).add(node)
        return [members for members in groups.values() if len(members) > 1]

    def as_dict(self) -> dict[str, Any]:
        return {
            "links": [link.as_dict() for link in self.links],
            "merge_threshold": MERGE_THRESHOLD,
            "clusters": [sorted(c) for c in self.clusters_for_merge()],
            "unlinked": list(self.unlinked),
        }


def _key(record: dict[str, Any]) -> str:
    return f"{record.get('source', '')}:{record.get('id', '')}"


def _local_part(value: str) -> str:
    text = (value or "").strip().lower()
    if not text:
        return ""
    arn = _ARN_USER_RE.match(text)
    if arn:
        text = arn.group("name")
    member = _GCP_MEMBER_RE.match(text)
    if member:
        text = member.group("name")
    if "@" in text:
        text = text.split("@", 1)[0]
    if "\\" in text:
        # DOMAIN\user
        text = text.split("\\", 1)[1]
    return text.strip()


def _domain(value: str) -> str:
    text = (value or "").strip().lower()
    return text.split("@", 1)[1] if "@" in text else ""


def _is_generic(local: str) -> bool:
    if not local:
        return True
    if local in GENERIC_IDENTIFIERS:
        return True
    return any(local.startswith(prefix) for prefix in _SERVICE_PREFIXES)


#: Each rule is ``(name, confidence, description)``. The confidence is the
#: rule's, not the pair's: what varies between pairs is which rule fires,
#: and a rule whose confidence depends on the data is a rule nobody can
#: reason about.
LINK_RULES: dict[str, tuple[float, str]] = {
    "verified_email_match": (
        0.98,
        "both identities carry the same address and the provider marked it verified",
    ),
    "email_match": (
        0.92,
        "both identities carry the same email address",
    ),
    "upn_match": (
        0.92,
        "both identities carry the same user principal name",
    ),
    "employee_id_match": (
        0.97,
        "both identities carry the same directory employee id",
    ),
    "explicit_mapping": (
        0.99,
        "the tenant's directory import states this mapping",
    ),
    "local_part_same_domain": (
        0.80,
        "the local parts match and the email domains are the same",
    ),
    "local_part_only": (
        0.45,
        "only the local parts match; different or missing domains",
    ),
    "display_name_match": (
        0.40,
        "only the display names match, which two people routinely share",
    ),
}


def resolve_links(records: list[dict[str, Any]]) -> ResolutionResult:
    """Link source-scoped identities pairwise, strongest rule per pair.

    ``records`` are dicts with at least ``source`` and ``id``, optionally
    ``email``, ``email_verified``, ``upn``, ``employee_id``,
    ``display_name`` and ``maps_to`` (an explicit mapping from the tenant's
    own directory import).

    Pure. The store and the graph writer are elsewhere, so this can be
    tested against fixtures with no database — which matters because the
    thing under test is a judgement about people, and the cases worth
    writing are adversarial rather than infrastructural.
    """
    cleaned = [r for r in records if r.get("source") in SOURCE_KINDS and str(r.get("id") or "").strip()]
    links: list[IdentityLink] = []
    linked: set[str] = set()

    for i, left in enumerate(cleaned):
        for right in cleaned[i + 1 :]:
            if left.get("source") == right.get("source"):
                # Two accounts in one source are two accounts. Joining them
                # is a different problem (duplicate detection) with
                # different evidence, and conflating the two is how a
                # directory's own guest copy of a user merges with the user.
                continue
            link = _best_link(left, right)
            if link is None:
                continue
            links.append(link)
            if link.merged:
                linked.add(link.left)
                linked.add(link.right)

    unlinked = sorted({_key(r) for r in cleaned} - linked)
    return ResolutionResult(links=links, unlinked=unlinked)


def _best_link(left: dict[str, Any], right: dict[str, Any]) -> IdentityLink | None:
    """The strongest rule that fires for this pair, or ``None``."""
    lkey, rkey = _key(left), _key(right)

    explicit = {str(x).strip().lower() for x in (left.get("maps_to") or [])}
    if str(right.get("id") or "").strip().lower() in explicit or rkey.lower() in explicit:
        return _link(lkey, rkey, "explicit_mapping", [f"the directory import maps {lkey} to {rkey}"])

    lemp, remp = str(left.get("employee_id") or "").strip(), str(right.get("employee_id") or "").strip()
    if lemp and lemp == remp:
        return _link(lkey, rkey, "employee_id_match", [f"both carry employee id {lemp}"])

    lmail = str(left.get("email") or "").strip().lower()
    rmail = str(right.get("email") or "").strip().lower()
    if lmail and lmail == rmail:
        # A shared mailbox is not a person, and merging on one joins
        # everybody who can send as it.
        if _is_generic(_local_part(lmail)):
            return _link(
                lkey,
                rkey,
                "local_part_only",
                [f"both carry {lmail}, but it is a role address rather than a person"],
            )
        rule = "verified_email_match" if (left.get("email_verified") and right.get("email_verified")) else "email_match"
        return _link(lkey, rkey, rule, [f"both carry the address {lmail}"])

    lupn, rupn = str(left.get("upn") or "").strip().lower(), str(right.get("upn") or "").strip().lower()
    if lupn and lupn == rupn:
        return _link(lkey, rkey, "upn_match", [f"both carry the user principal name {lupn}"])

    llocal = _local_part(str(left.get("id") or "")) or _local_part(lmail)
    rlocal = _local_part(str(right.get("id") or "")) or _local_part(rmail)
    if llocal and llocal == rlocal:
        if _is_generic(llocal):
            # Not even a weak link. `admin` matching `admin` is not
            # evidence of anything, and returning it at 0.45 would fill a
            # review page with noise that reads as near-misses.
            return None
        ldom, rdom = _domain(lmail or str(left.get("id") or "")), _domain(rmail or str(right.get("id") or ""))
        if ldom and ldom == rdom:
            return _link(
                lkey,
                rkey,
                "local_part_same_domain",
                [f"local part {llocal!r} matches and both are in {ldom}"],
            )
        return _link(
            lkey,
            rkey,
            "local_part_only",
            [
                f"local part {llocal!r} matches",
                f"domains differ or are absent ({ldom or 'none'} vs {rdom or 'none'})",
            ],
        )

    lname = str(left.get("display_name") or "").strip().lower()
    rname = str(right.get("display_name") or "").strip().lower()
    if lname and lname == rname:
        return _link(lkey, rkey, "display_name_match", [f"both display as {lname!r}"])

    return None


def _link(left: str, right: str, rule: str, evidence: list[str]) -> IdentityLink:
    confidence, description = LINK_RULES[rule]
    return IdentityLink(
        left=left,
        right=right,
        confidence=confidence,
        rule=rule,
        evidence=[*evidence, description],
    )
