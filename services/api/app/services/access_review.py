"""Read-only access review: what was granted, through what, and was it used.

Depth plan wave 2, Phase 1.2.

1.1 made "what can this identity do" answerable from a versioned posture
snapshot, and recorded which of those actions a principal actually exercised
in a trailing window. Neither is a review. A reviewer asks comparative
questions — who holds admin they never use, which human has a long-lived
cloud key, which outside collaborator has admin on a repository, which admin
has gone dormant — and this module is where those are asked.

Read-only, and the rule is load-bearing
---------------------------------------
Nothing here changes vendor state, and nothing here is wired to anything
that can. Every finding names the object a human should go and change, and
stops. That is a deliberate scope limit from the plan, and it is also what
makes the module safe to run broadly: an access review that could act is one
nobody enables.

The honesty property this module exists to protect
--------------------------------------------------
``UsageOverlay.measured`` is ``False`` on any install with no event lake,
and a review that reads that as "used nothing" produces a finding against
**every permission in the estate**, with exactly the confidence of a correct
finding. So:

* usage-dependent findings are not emitted at all when usage was not
  measured, rather than emitted with a caveat nobody reads;
* :class:`ReviewResult` carries ``usage_measured`` and a reason, so a
  surface can say "nothing reviewed" instead of showing a short list;
* :func:`best_fit_role` returns ``None`` rather than a guess.

A review of zero principals is "nothing reviewed", never "no findings". The
second reads as a clean bill of health for an estate nobody looked at.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from app.services.identity_privilege import ESCALATION_ACTIONS, IdentityPrivilege, tier_at_least
from app.services.identity_privilege_store import UsageOverlay

__all__ = [
    "FINDING_KINDS",
    "AccessFinding",
    "FindingSpec",
    "ReviewResult",
    "best_fit_role",
    "review_principal",
    "summarise",
]

Severity = Literal["info", "low", "medium", "high", "critical"]

#: A principal with no activity for this long is dormant. Ninety days
#: matches the usage window's default for a reason: a dormancy claim shorter
#: than the window it is measured over is not a measurement, it is an
#: artefact of where the window happens to start.
DORMANT_AFTER_DAYS = 90

#: Action prefixes that write rather than read. Used only for the
#: unused-write finding, which is the one a reviewer acts on first: unused
#: *read* access is untidy, unused *write* access is the blast radius of a
#: credential nobody would miss.
_WRITE_PREFIXES: tuple[str, ...] = (
    "iam:Create",
    "iam:Put",
    "iam:Attach",
    "iam:Update",
    "iam:Delete",
    "s3:Put",
    "s3:Delete",
    "ec2:Run",
    "ec2:Terminate",
    "kms:Schedule",
    "secretsmanager:Put",
    "Microsoft.Authorization/",
    "microsoft.directory/",
    "resourcemanager.projects.setIamPolicy",
    "iam.roles.",
    "iam.serviceAccountKeys.create",
    "storage.objects.delete",
    "admin.users.",
    "admin.roles.",
    "okta.users.manage",
    "okta.groups.manage",
    "okta.roles.manage",
    "admin:org",
    "write:org",
    "repo:admin",
    "delete_repo",
)


@dataclass(frozen=True)
class FindingSpec:
    """What one kind of finding is, and what a person should do about it.

    ``object_hint`` and ``recommendation`` are required rather than
    optional. A read-only review whose findings do not name the object to
    change is a list of complaints: the reviewer still has to work out where
    to go, which is the part that makes reviews not happen.
    """

    kind: str
    title: str
    severity: Severity
    object_hint: str
    recommendation: str
    #: True when the finding cannot be computed without usage data. These
    #: are suppressed entirely on an install where usage was not measured.
    needs_usage: bool = False


FINDING_KINDS: dict[str, FindingSpec] = {
    "human_with_long_lived_key": FindingSpec(
        kind="human_with_long_lived_key",
        title="A person holds a long-lived cloud access key",
        severity="high",
        object_hint="the access key on the principal",
        recommendation=(
            "Replace the static key with federated or short-lived credentials, then delete the key. "
            "A human's long-lived key is the credential most likely to end up in a shell history, a "
            "CI variable or a laptop backup, and it does not expire on its own."
        ),
    ),
    "unused_write_access": FindingSpec(
        kind="unused_write_access",
        title="Write or administrative access that was never exercised",
        severity="medium",
        object_hint="the policy, role or group grant that carries the unused actions",
        recommendation=(
            "Remove the unused actions from the grant, or move the principal to a smaller role. "
            "Check the window first: quarterly work looks unused in a 30-day window."
        ),
        needs_usage=True,
    ),
    "outside_collaborator_admin": FindingSpec(
        kind="outside_collaborator_admin",
        title="An external identity holds administrative access",
        severity="high",
        object_hint="the collaborator or guest grant on the repository, organisation or tenant",
        recommendation=(
            "Downgrade the grant to the least role that covers the collaboration, or move the work "
            "into a dedicated repository. An outside collaborator with admin can change branch "
            "protection and add further collaborators."
        ),
    ),
    "dormant_admin": FindingSpec(
        kind="dormant_admin",
        title="An administrative principal has been dormant",
        severity="medium",
        object_hint="the principal and the admin role it holds",
        recommendation=(
            "Confirm the account is still needed. A dormant admin is an account whose compromise "
            "nobody would notice, because there is no normal activity for an anomaly to stand out "
            "against."
        ),
        needs_usage=True,
    ),
    "escalation_without_use": FindingSpec(
        kind="escalation_without_use",
        title="An identity can grant itself more access and never has",
        severity="high",
        object_hint="the policy granting the authorization-write actions",
        recommendation=(
            "Remove the authorization-write actions. An identity that can grant itself more access "
            "makes every other permission it holds a lower bound rather than a limit."
        ),
        needs_usage=True,
    ),
    "fork_reachable_workflow_secret": FindingSpec(
        kind="fork_reachable_workflow_secret",
        title="A workflow with a fork-reachable trigger can read secrets",
        severity="high",
        object_hint="the workflow file and its trigger block",
        recommendation=(
            "Split the privileged half into a separate `workflow_run` job, or drop the secret from "
            "the fork-reachable job. `pull_request_target` runs with the base repository's secrets "
            "against a fork's code."
        ),
    ),
    "org_member_without_mfa": FindingSpec(
        kind="org_member_without_mfa",
        title="An organisation member has no second factor",
        severity="high",
        object_hint="the member's account in the organisation",
        recommendation=(
            "Enrol the account, or enforce two-factor authentication at the organisation level. A "
            "single-factor member of an organisation that holds source code is a password away "
            "from a supply-chain change."
        ),
    ),
    "apps_script_project_drift": FindingSpec(
        kind="apps_script_project_drift",
        title="An Apps Script project differs from what the service creates",
        severity="medium",
        object_hint="the GCP project under the Apps Script folder",
        recommendation=(
            "Compare the project against a service-created one and remove the additions. Billing "
            "linked or extra services enabled on a `sys-` project is the shape of a human using "
            "the Apps Script folder as cover."
        ),
    ),
}


@dataclass(frozen=True)
class AccessFinding:
    """One finding, with the evidence that produced it."""

    kind: str
    principal_id: str
    provider: str
    severity: Severity
    title: str
    detail: str
    object_hint: str
    recommendation: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "principal_id": self.principal_id,
            "provider": self.provider,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "object_hint": self.object_hint,
            "recommendation": self.recommendation,
            "evidence": dict(self.evidence),
        }


@dataclass(frozen=True)
class ReviewResult:
    """One principal's review, and how much of it could be computed."""

    principal_id: str
    provider: str
    findings: list[AccessFinding] = field(default_factory=list)
    usage_measured: bool = False
    #: Why usage-dependent findings were skipped, when they were. Present so
    #: the surface can distinguish "reviewed, nothing found" from "could not
    #: review half of it".
    unmeasured_reason: str | None = None
    best_fit: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "principal_id": self.principal_id,
            "provider": self.provider,
            "findings": [f.as_dict() for f in self.findings],
            "usage_measured": self.usage_measured,
            "unmeasured_reason": self.unmeasured_reason,
            "best_fit_role": self.best_fit,
        }


def _is_write(action: str) -> bool:
    return any(action.startswith(prefix) for prefix in _WRITE_PREFIXES)


def _is_escalation(action: str) -> bool:
    return any(fnmatch.fnmatchcase(action, pattern) for pattern in ESCALATION_ACTIONS)


def review_principal(
    *,
    privilege: IdentityPrivilege,
    usage: UsageOverlay,
    granted_actions: set[str] | None = None,
    has_long_lived_key: bool | None = None,
    is_human: bool | None = None,
    now: datetime | None = None,
) -> ReviewResult:
    """Review one principal. Pure — no database, no vendor call.

    ``granted_actions`` defaults to the actions named in the privilege
    evidence, which is the subset that produced a tag. A caller with the
    full resolver result should pass it, because the evidence set is
    deliberately narrow and a right-sizing answer wants everything.
    """
    now = now or datetime.now(tz=UTC)
    granted = set(granted_actions or ())
    if not granted:
        for actions in privilege.evidence.values():
            granted.update(actions)

    findings: list[AccessFinding] = []

    def add(kind: str, detail: str, evidence: dict[str, Any]) -> None:
        spec = FINDING_KINDS[kind]
        findings.append(
            AccessFinding(
                kind=kind,
                principal_id=privilege.principal_id,
                provider=privilege.provider,
                severity=spec.severity,
                title=spec.title,
                detail=detail,
                object_hint=spec.object_hint,
                recommendation=spec.recommendation,
                evidence=evidence,
            )
        )

    # --- findings that do not need usage ---------------------------------

    if has_long_lived_key and is_human is not False:
        add(
            "human_with_long_lived_key",
            f"{privilege.principal_id} is a human principal holding a long-lived access key.",
            {"principal_kind": "human" if is_human else "unknown"},
        )

    if privilege.tags.third_party is True and tier_at_least(privilege.tier, "admin"):
        add(
            "outside_collaborator_admin",
            f"{privilege.principal_id} is external or vendor-owned and holds {privilege.tier} privilege.",
            {"tier": privilege.tier, "tags": privilege.tags.set_tags()},
        )

    # --- findings that need usage ----------------------------------------
    #
    # Suppressed wholesale rather than caveated. A caveat on a finding that
    # says "revoke this" is read by nobody, and the finding is wrong in the
    # direction that costs an outage.
    if not usage.measured:
        return ReviewResult(
            principal_id=privilege.principal_id,
            provider=privilege.provider,
            findings=findings,
            usage_measured=False,
            unmeasured_reason=(
                "Which permissions were actually exercised was not measured for this principal, so "
                "unused-access, dormancy and right-sizing findings were not computed. The event "
                "lake is a `full`-profile component; on a CORE install this is expected, and it is "
                "not the same as having found nothing."
            ),
            best_fit=None,
        )

    used = set(usage.used)
    unused_writes = sorted(a for a in granted - used if _is_write(a))
    if unused_writes:
        window = _window_text(usage)
        add(
            "unused_write_access",
            f"{len(unused_writes)} write or administrative action(s) granted to {privilege.principal_id} were not exercised {window}.",
            {"unused_actions": unused_writes[:50], "window": window, "granted": len(granted), "used": len(used)},
        )

    unused_escalation = sorted(a for a in granted - used if _is_escalation(a))
    if unused_escalation:
        add(
            "escalation_without_use",
            f"{privilege.principal_id} can grant access ({', '.join(unused_escalation[:5])}) and did not {_window_text(usage)}.",
            {"actions": unused_escalation[:20]},
        )

    last_seen = max((t for t in usage.used.values() if t is not None), default=None)
    dormant_cutoff = now - timedelta(days=DORMANT_AFTER_DAYS)
    if tier_at_least(privilege.tier, "admin") and (last_seen is None or last_seen < dormant_cutoff):
        add(
            "dormant_admin",
            f"{privilege.principal_id} holds {privilege.tier} privilege and was last active "
            f"{last_seen.date().isoformat() if last_seen else 'never in the window'}.",
            {"last_used_at": last_seen.isoformat() if last_seen else None, "tier": privilege.tier},
        )

    return ReviewResult(
        principal_id=privilege.principal_id,
        provider=privilege.provider,
        findings=findings,
        usage_measured=True,
        best_fit=best_fit_role(provider=privilege.provider, granted=granted, usage=usage),
    )


def _window_text(usage: UsageOverlay) -> str:
    if usage.window_start and usage.window_end:
        return f"between {usage.window_start.date().isoformat()} and {usage.window_end.date().isoformat()}"
    return "in the measured window"


#: Built-in roles per provider, smallest first, as ``(name, action globs)``.
#: Deliberately short and conservative: naming a role that does not cover an
#: action the principal actually used would be a recommendation to break
#: production, which is the one failure a right-sizing feature cannot have.
#: A principal whose used set exceeds every entry gets ``None``, and "we
#: could not find a smaller role" is a correct and useful answer.
_BUILTIN_ROLES: dict[str, tuple[tuple[str, tuple[str, ...]], ...]] = {
    "aws": (
        ("AmazonS3ReadOnlyAccess", ("s3:Get*", "s3:List*", "s3:Describe*")),
        ("ReadOnlyAccess", ("*:Get*", "*:List*", "*:Describe*", "*:BatchGet*")),
        ("AmazonS3FullAccess", ("s3:*",)),
        ("PowerUserAccess", ("*",)),
    ),
    "azure": (
        ("Reader", ("*/read",)),
        ("Contributor", ("*/read", "*/write", "*/delete", "*/action")),
    ),
    "gcp": (
        ("roles/viewer", ("*.get", "*.list", "*.getIamPolicy")),
        ("roles/editor", ("*.get", "*.list", "*.create", "*.update", "*.delete")),
    ),
    "github": (
        ("read", ("read:*", "repo:status")),
        ("write", ("read:*", "write:*", "repo")),
    ),
    "okta": (("READ_ONLY_ADMIN", ("okta.*.read",)),),
    "gws": (("_HELP_DESK_ADMIN", ("admin.users.update", "admin.users.read")),),
}


def best_fit_role(
    *,
    provider: str,
    granted: set[str],
    usage: UsageOverlay,
) -> str | None:
    """The smallest built-in role covering every action actually used.

    ``None`` whenever usage was not measured — a right-sizing recommendation
    computed from an unmeasured empty set recommends the smallest role in
    the table for every principal in the estate, which is both wrong and
    confidently phrased.

    Also ``None`` when no built-in covers the used set, which is the honest
    answer for a principal doing genuinely broad work: suggesting a role
    that does not cover something they used is a recommendation to cause an
    outage, and that is the one error this feature must not make.
    """
    if not usage.measured:
        return None
    used = set(usage.used)
    if not used:
        return None

    for name, globs in _BUILTIN_ROLES.get(provider, ()):
        if all(any(fnmatch.fnmatchcase(action, g) for g in globs) for action in used):
            # Only a recommendation if it is actually smaller than what is
            # held. A role that covers the used set *and* everything granted
            # changes nothing.
            if not all(any(fnmatch.fnmatchcase(action, g) for g in globs) for action in granted):
                return name
            return None
    return None


def summarise(results: list[ReviewResult]) -> dict[str, Any]:
    """Portfolio summary with an honest empty state.

    ``state`` is the field that matters. Zero findings over zero principals
    is ``nothing_reviewed``; zero findings over a real inventory is
    ``no_findings``. Rendering both as "0 findings" presents an estate
    nobody looked at as an estate with nothing wrong, which is the single
    most reassuring thing this page could get wrong.
    """
    if not results:
        return {
            "state": "nothing_reviewed",
            "reviewed_principals": 0,
            "findings": 0,
            "by_kind": {},
            "by_severity": {},
            "usage_measured_for": 0,
            "note": (
                "No principals were reviewed. This is not a clean bill of health: connect a cloud "
                "or identity provider and collect its posture to review anything."
            ),
        }

    findings = [f for r in results for f in r.findings]
    by_kind: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for finding in findings:
        by_kind[finding.kind] = by_kind.get(finding.kind, 0) + 1
        by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1

    measured = sum(1 for r in results if r.usage_measured)
    summary: dict[str, Any] = {
        "state": "no_findings" if not findings else "findings",
        "reviewed_principals": len(results),
        "findings": len(findings),
        "by_kind": by_kind,
        "by_severity": by_severity,
        "usage_measured_for": measured,
    }
    if measured < len(results):
        summary["note"] = (
            f"Usage was measured for {measured} of {len(results)} principals. Unused-access, "
            f"dormancy and right-sizing findings were not computed for the rest, so this is a "
            f"partial review."
        )
    return summary
