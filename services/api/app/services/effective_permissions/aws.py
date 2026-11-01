"""AWS IAM effective-permissions resolver (T3.2 — full implementation).

Resolution model
----------------

The resolver consumes a *snapshot* JSON document of shape::

    {
      "account_id": "123456789012",
      "principals": [
        {"id": "...", "arn": "...", "type": "user|role",
         "groups": ["...", ...], "attached_policies": ["..."],
         "inline_policies": ["..."],
         # policy id, resolved in "policies" below like any other
         "permissions_boundary": "p4"},
        ...
      ],
      "groups": [
        {"id": "g1", "name": "...", "attached_policies": ["..."], "inline_policies": ["..."]},
        ...
      ],
      "policies": [
        {"id": "p1", "name": "...", "document": {...IAM JSON...}, "kind": "identity|resource|scp"},
        ...
      ],
      "resources": [
        {"id": "r1", "arn": "...", "kind": "s3:bucket",
         "resource_policy_id": "p9", "service_actions": ["s3:GetObject", ...]},
        ...
      ],
      "scps": ["p17", "p18"],
      "action_catalogue": {"s3": ["s3:GetObject", "s3:PutObject", ...], ...}
    }

The model captures the five sources of allow/deny that govern an IAM call:

1. **Identity-based policies** attached to the user, the user's groups, or
   the role's inline policies. Any explicit ``Allow`` here is necessary
   (unless the resource is the principal's own resource policy targeting it).
2. **Resource-based policies** attached to the resource. An explicit
   ``Allow`` from a resource policy grants access even if no identity-based
   policy mentions the action — but only when the principal is named in the
   resource policy's ``Principal`` element.
3. **Service Control Policies (SCPs)** at the organisation level. They
   *cannot* grant — they only narrow. The resolver intersects the candidate
   action set with the union of SCP-allowed actions.
4. **Permissions boundaries** attached to the principal. A boundary is a
   managed policy that *caps* what identity-based policies may grant: the
   effective identity permission is the intersection of the two, and a
   boundary never grants anything by itself.

   The part that changes the answer on real estates, and is easy to get
   wrong: a boundary does **not** cap a resource-based policy that names the
   principal directly. A bucket policy granting this role ``s3:GetObject``
   works whether or not the boundary mentions S3. Intersecting the whole
   candidate set with the boundary would therefore *under*-report a real,
   reachable permission — and under-reporting on a containment decision
   reads as "this identity cannot touch the data" when it can.

   A ``Deny`` written inside a boundary document is an ordinary explicit
   deny and wins over everything, resource policies included.

5. **Explicit deny** anywhere — always wins.

For each ``(principal, resource)`` pair the algorithm is:

* Collect all statements that match the principal + resource ARN (with
  wildcard expansion against the resource's ``service_actions`` catalogue).
* Partition by effect into ``allow_actions`` and ``deny_actions``.
* Cap the identity-derived allows by the permissions boundary, if any.
* Compute the SCP-allowed action set (union over SCP allow statements that
  match the resource ARN).
* The final ``actions`` =
  ``((identity_allow ∩ boundary) ∪ resource_allow) − deny_actions ∩ scp_allowed``.
* The ``deny_actions`` list returned to the UI is every action some policy
  *tried* to grant that something higher-priority removed — an explicit
  deny, an SCP that excluded it, or a boundary that capped it away. A
  boundary-capped action is reported even though it never entered the
  candidate set, because the whole value of a boundary to a reviewer is
  seeing what it stopped, and an action that silently never appears is
  indistinguishable from one nobody ever granted.

6. **Session policies** passed on ``AssumeRole``. Like a permissions
   boundary they only cap, never grant, and like a boundary they do not cap a
   resource-based policy that names the session principal directly. They are
   the reason an assumed-role chain's reach is routinely far smaller than the
   role's, which matters because an assumed-role chain is what most cloud
   investigations are looking at.

``NotAction`` and ``NotResource`` invert the set a statement applies to, so
ignoring them does not return a vaguer answer — it returns the complement of
the right one. ``Allow NotAction s3:DeleteObject`` grants everything *except*
delete; read as an absent ``Action`` it grants nothing.

Condition operators are evaluated by
:mod:`app.services.effective_permissions.iam_conditions`, which returns a
three-valued result. An **undecidable** condition — a modelled operator whose
context key the snapshot does not carry, or one of the two operators that
module still does not model — is resolved per effect rather than globally:
an undecidable ``Allow`` does not grant, and an undecidable ``Deny`` still
denies. Both choices refuse to over-report access, which is the only
direction that is safe on a containment decision. Actions withheld that way
are reported in ``deny_actions`` and the reason lands in ``notes``, because
an action that silently never appears is indistinguishable from one nobody
ever granted.

A boundary attached to the principal but absent from the snapshot is flagged
in ``notes`` too: the cap cannot be applied and would otherwise over-permit
in exactly the case the boundary exists to prevent. The synthesised simulator
fixture exercises every feature the resolver models so the test gate is
meaningful.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from app.services.effective_permissions.base import (
    PolicyChainStep,
    ResolvedPermission,
    Resolver,
    ResolverError,
    ResolverResult,
)
from app.services.effective_permissions.iam_conditions import (
    evaluate_block,
    unmodelled_operators_in,
)


def _as_list(value: Any) -> list[Any]:
    """IAM JSON accepts a string *or* a list anywhere — normalise to a list."""

    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _principal_matches(statement_principal: Any, principal_arn: str) -> bool:
    """Return ``True`` if a resource-policy ``Principal`` element matches.

    Handles ``"*"``, ``{"AWS": "<arn or list>"}``, and the abbreviated
    ``{"AWS": "*"}`` form. Federated / service principals are out of scope
    for the structural simulator and ignored.
    """

    if statement_principal == "*":
        return True
    if not isinstance(statement_principal, dict):
        return False
    aws = statement_principal.get("AWS")
    for entry in _as_list(aws):
        if entry == "*" or entry == principal_arn:
            return True
        if isinstance(entry, str) and fnmatch.fnmatchcase(principal_arn, entry):
            return True
    return False


def _resource_matches(statement_resource: Any, resource_arn: str) -> bool:
    """Match an IAM ``Resource`` element against a concrete resource ARN."""

    for pattern in _as_list(statement_resource):
        if pattern == "*":
            return True
        if isinstance(pattern, str) and fnmatch.fnmatchcase(resource_arn, pattern):
            return True
    return False


def _statement_covers_resource(statement: dict[str, Any], resource_arn: str) -> bool:
    """Does this statement apply to ``resource_arn``?

    ``NotResource`` is the complement of ``Resource`` and the two are mutually
    exclusive in a valid statement. A statement carrying neither applies to
    everything, which is why ``Resource`` defaults to ``"*"`` — and why the
    ``NotResource`` arm has to be checked *first*: reading
    ``statement.get("Resource", "*")`` on a ``NotResource`` statement turns
    an exclusion into a universal grant.
    """

    if "NotResource" in statement:
        return not _resource_matches(statement["NotResource"], resource_arn)
    return _resource_matches(statement.get("Resource", "*"), resource_arn)


def _statement_actions(statement: dict[str, Any], catalogue: list[str]) -> set[str]:
    """The action set a statement applies to, honouring ``NotAction``.

    ``NotAction`` is the complement against the service catalogue, so the
    answer is only as complete as the catalogue is — an action the catalogue
    does not list cannot be reported either way. That is a real limit and the
    honest one: inventing actions to complement against would report access
    to API calls that may not exist.
    """

    if "NotAction" in statement:
        excluded = _expand_actions(_as_list(statement["NotAction"]), catalogue)
        return set(catalogue) - excluded
    return _expand_actions(_as_list(statement.get("Action")), catalogue)


@dataclass(frozen=True)
class _PolicyEvaluation:
    """What one policy said about one resource.

    ``undecided`` is the set this type exists for. Returning
    ``(allow, deny)`` forced every undecidable condition into one of the two,
    and whichever it picked was wrong half the time: folded into ``deny`` it
    claimed a policy denied something it did not mention, dropped entirely it
    silently narrowed the answer with nothing recording that it had.
    """

    allow: set[str]
    deny: set[str]
    undecided: set[str]
    notes: set[str]


def _expand_actions(actions: list[str], catalogue: list[str]) -> set[str]:
    """Expand wildcards (``s3:*``, ``s3:Get*``) against a service catalogue.

    The catalogue is the authoritative list of actions the resolver knows the
    target service supports — synthesised from CloudTrail event ontology in
    production, hard-coded per service in the test fixture.
    """

    expanded: set[str] = set()
    for action in actions:
        if "*" not in action:
            expanded.add(action)
            continue
        for known in catalogue:
            if fnmatch.fnmatchcase(known, action):
                expanded.add(known)
    return expanded


class AwsIamResolver(Resolver):
    """Production AWS IAM resolver — see module docstring for the model."""

    provider = "aws"
    coverage = "full"

    def __init__(self, snapshot: dict[str, Any] | None = None) -> None:
        """Bind an optional in-memory snapshot.

        Production callers will leave this ``None`` and pass the snapshot at
        :meth:`resolve` time (typically loaded from S3 / Neo4j by the
        dispatcher). Tests bind the snapshot at construction so they can
        share one resolver across many ``resolve()`` calls.
        """

        self._snapshot = snapshot

    def resolve(
        self,
        principal_id: str,
        *,
        snapshot: dict[str, Any] | None = None,
    ) -> ResolverResult:
        snap = snapshot if snapshot is not None else self._snapshot
        if snap is None:
            raise ResolverError("AwsIamResolver.resolve called without a snapshot")

        principals_by_id = {p["id"]: p for p in snap.get("principals", [])}
        principals_by_arn = {p["arn"]: p for p in snap.get("principals", []) if "arn" in p}
        principal = principals_by_id.get(principal_id) or principals_by_arn.get(principal_id)
        if principal is None:
            raise ResolverError(f"principal {principal_id!r} not present in snapshot")

        policies_by_id = {p["id"]: p for p in snap.get("policies", [])}
        groups_by_id = {g["id"]: g for g in snap.get("groups", [])}
        scp_ids = list(snap.get("scps", []))
        action_catalogue: dict[str, list[str]] = snap.get("action_catalogue", {})

        identity_policy_refs = self._collect_identity_policies(principal, groups_by_id)

        notes: list[str] = []
        boundary_id = principal.get("permissions_boundary")
        if boundary_id and boundary_id not in policies_by_id:
            # The principal is capped by a policy the snapshot does not
            # contain, so the cap cannot be applied. Reporting the
            # uncapped answer silently would over-permit in exactly the
            # case the boundary exists to prevent.
            notes.append(
                f"permissions boundary {boundary_id!r} is attached to the principal but absent from "
                f"the snapshot — the cap could not be applied and these actions may over-permit"
            )

        decisions: list[ResolvedPermission] = []
        for resource in snap.get("resources", []):
            decision, resource_notes = self._resolve_resource(
                principal=principal,
                resource=resource,
                identity_policy_refs=identity_policy_refs,
                policies_by_id=policies_by_id,
                scp_ids=scp_ids,
                action_catalogue=action_catalogue,
            )
            # Deduplicated and sorted: one unmodelled operator on a policy
            # attached to forty buckets is one gap, not forty notes.
            for note in sorted(resource_notes):
                if note not in notes:
                    notes.append(note)
            if decision is not None:
                decisions.append(decision)

        return ResolverResult(
            provider=self.provider,
            principal_id=principal_id,
            coverage=self.coverage,
            last_resolved=datetime.now(tz=UTC),
            decisions=decisions,
            notes=notes,
        )

    def _collect_identity_policies(
        self,
        principal: dict[str, Any],
        groups_by_id: dict[str, dict[str, Any]],
    ) -> list[tuple[str, str | None]]:
        """Return ``[(policy_id, via_group_id), ...]`` for the principal.

        ``via_group_id`` is ``None`` for directly-attached policies and the
        group id for policies inherited via group membership. The order is
        ``inline → attached → group-inline → group-attached`` which the UI
        renders top-down in the provenance pane.
        """

        refs: list[tuple[str, str | None]] = []
        for policy_id in principal.get("inline_policies", []):
            refs.append((policy_id, None))
        for policy_id in principal.get("attached_policies", []):
            refs.append((policy_id, None))
        for group_id in principal.get("groups", []):
            group = groups_by_id.get(group_id)
            if group is None:
                continue
            for policy_id in group.get("inline_policies", []):
                refs.append((policy_id, group_id))
            for policy_id in group.get("attached_policies", []):
                refs.append((policy_id, group_id))
        return refs

    def _resolve_resource(
        self,
        *,
        principal: dict[str, Any],
        resource: dict[str, Any],
        identity_policy_refs: list[tuple[str, str | None]],
        policies_by_id: dict[str, dict[str, Any]],
        scp_ids: list[str],
        action_catalogue: dict[str, list[str]],
    ) -> tuple[ResolvedPermission | None, set[str]]:
        resource_arn = resource["arn"]
        resource_service = resource.get("service") or resource_arn.split(":")[2]
        service_catalogue = resource.get("service_actions") or action_catalogue.get(resource_service, [])
        context = resource.get("context", {})

        chain: list[PolicyChainStep] = []
        identity_allow: set[str] = set()
        identity_deny: set[str] = set()
        undecided: set[str] = set()
        notes: set[str] = set()

        for policy_id, via_group_id in identity_policy_refs:
            policy = policies_by_id.get(policy_id)
            if policy is None:
                continue
            evaluation = self._evaluate_policy(
                policy=policy,
                principal_arn=principal["arn"],
                resource_arn=resource_arn,
                context=context,
                catalogue=service_catalogue,
                principal_match_required=False,
            )
            notes |= evaluation.notes
            undecided |= evaluation.undecided
            if evaluation.allow or evaluation.deny:
                identity_allow |= evaluation.allow
                identity_deny |= evaluation.deny
                chain.append(
                    PolicyChainStep(
                        kind="policy",
                        id=policy_id,
                        name=policy.get("name", policy_id),
                        effect="deny" if evaluation.deny and not evaluation.allow else "allow",
                        via=via_group_id,
                    )
                )

        resource_policy_id = resource.get("resource_policy_id")
        resource_allow: set[str] = set()
        resource_deny: set[str] = set()
        if resource_policy_id:
            resource_policy = policies_by_id.get(resource_policy_id)
            if resource_policy is not None:
                evaluation = self._evaluate_policy(
                    policy=resource_policy,
                    principal_arn=principal["arn"],
                    resource_arn=resource_arn,
                    context=context,
                    catalogue=service_catalogue,
                    principal_match_required=True,
                )
                notes |= evaluation.notes
                undecided |= evaluation.undecided
                resource_allow, resource_deny = evaluation.allow, evaluation.deny
                if resource_allow or resource_deny:
                    chain.append(
                        PolicyChainStep(
                            kind="policy",
                            id=resource_policy_id,
                            name=resource_policy.get("name", resource_policy_id),
                            effect="deny" if resource_deny and not resource_allow else "allow",
                        )
                    )

        # Permissions boundary. A boundary is a managed policy attached to a
        # principal that caps what its *identity* policies can grant: the
        # effective identity permission is the intersection of the two, and a
        # boundary never grants anything on its own.
        #
        # The exception is the part that is easy to get wrong and changes the
        # answer on real estates: AWS does **not** apply the boundary to a
        # resource-based policy that names the principal directly. A bucket
        # policy granting this role `s3:GetObject` works whether or not the
        # boundary mentions S3, so intersecting the whole candidate set with
        # the boundary would under-report a real, reachable permission -- and
        # under-reporting on a containment decision reads as "this identity
        # cannot touch the data" when it can.
        boundary_allowed: set[str] | None = None
        # Kept separate from identity_deny and resource_deny rather than
        # folded into either. Both of those flow into one `candidate_deny`
        # union below, so adding a boundary deny to either would have the
        # same effect and adding it to both is dead code that reads as
        # though it covers two arms.
        boundary_deny: set[str] = set()
        boundary_allow: set[str] = set()
        boundary_id = principal.get("permissions_boundary")
        boundary = policies_by_id.get(boundary_id) if boundary_id else None
        if boundary is not None:
            boundary_eval = self._evaluate_policy(
                policy=boundary,
                principal_arn=principal["arn"],
                resource_arn=resource_arn,
                context=context,
                catalogue=service_catalogue,
                principal_match_required=False,
            )
            notes |= boundary_eval.notes
            boundary_allow, boundary_deny = boundary_eval.allow, boundary_eval.deny
            boundary_allowed = boundary_allow

        identity_capped = identity_allow
        boundary_blocked: set[str] = set()
        # Both, not just `boundary_allowed`. The two are equivalent by
        # construction -- `boundary_allowed` is assigned only inside the
        # `boundary is not None` branch above -- but that invariant lives
        # fifteen lines away and nothing enforces it, so a later edit that
        # assigns `boundary_allowed` anywhere else turns the `boundary.get`
        # below into an AttributeError on a path an analyst reaches.
        if boundary_allowed is not None and boundary is not None and boundary_id:
            identity_capped = identity_allow & boundary_allowed
            boundary_blocked = identity_allow - boundary_allowed
            if boundary_allow or boundary_blocked:
                chain.append(
                    PolicyChainStep(
                        kind="permissions-boundary",
                        id=boundary_id,
                        name=boundary.get("name", boundary_id),
                        # A cap reads as a deny in the provenance pane,
                        # because what an analyst needs to see is the hop
                        # that removed an action somebody granted.
                        effect="deny" if boundary_blocked else "allow",
                    )
                )

        # Session policies. Passed on `AssumeRole`, they cap the session the
        # same way a boundary caps the principal: the intersection of the
        # role's identity permissions and the session policy. Two properties
        # are worth stating because getting either wrong changes an answer:
        #
        #  * several session policies are ANDed, not ORed, so the cap is the
        #    *intersection* of them all. Unioning would widen the cap with
        #    each extra policy, which is backwards;
        #  * like a boundary, a session policy does not cap a resource-based
        #    policy that names the session principal directly, so the cap is
        #    applied to the identity arm only.
        #
        # This is the arm that matters most in practice: most cloud
        # investigations are looking at an assumed-role chain, and a role's
        # reach is routinely far wider than the session's.
        session_policy_ids = [pid for pid in _as_list(principal.get("session_policies")) if pid]
        session_blocked: set[str] = set()
        if session_policy_ids:
            session_allowed: set[str] | None = None
            for session_policy_id in session_policy_ids:
                session_policy = policies_by_id.get(session_policy_id)
                if session_policy is None:
                    notes.add(
                        f"session policy {session_policy_id!r} is attached to the session but absent "
                        f"from the snapshot — the cap could not be applied and these actions may over-permit"
                    )
                    continue
                session_eval = self._evaluate_policy(
                    policy=session_policy,
                    principal_arn=principal["arn"],
                    resource_arn=resource_arn,
                    context=context,
                    catalogue=service_catalogue,
                    principal_match_required=False,
                )
                notes |= session_eval.notes
                session_allowed = (
                    set(session_eval.allow) if session_allowed is None else session_allowed & session_eval.allow
                )
                if session_eval.deny:
                    identity_deny |= session_eval.deny
            if session_allowed is not None:
                session_blocked = identity_capped - session_allowed
                identity_capped = identity_capped & session_allowed
                if session_blocked or session_allowed:
                    chain.append(
                        PolicyChainStep(
                            kind="session-policy",
                            id=",".join(session_policy_ids),
                            name=f"session policy ({len(session_policy_ids)})",
                            effect="deny" if session_blocked else "allow",
                        )
                    )

        candidate_allow = identity_capped | resource_allow
        # A Deny written inside a boundary document is an ordinary explicit
        # deny, not a cap, so it joins the deny set and outranks the
        # resource-policy arm as well as the identity arm.
        candidate_deny = identity_deny | resource_deny | boundary_deny

        # Track the *pre-SCP* allow set so shadowed-denies surfaces actions
        # that some upstream policy tried to grant but were blocked at the
        # org boundary. The UI renders these in red so SOC analysts see the
        # gap between intent (identity policy says Allow *) and reality
        # (SCP cuts iam:CreateRole away).
        pre_scp_allow = set(candidate_allow)
        scp_allowed: set[str] | None = None
        if scp_ids:
            scp_allowed = set()
            for scp_id in scp_ids:
                scp = policies_by_id.get(scp_id)
                if scp is None:
                    continue
                scp_eval = self._evaluate_policy(
                    policy=scp,
                    principal_arn=principal["arn"],
                    resource_arn=resource_arn,
                    context=context,
                    catalogue=service_catalogue,
                    principal_match_required=False,
                )
                notes |= scp_eval.notes
                allow_set, deny_set = scp_eval.allow, scp_eval.deny
                if allow_set:
                    scp_allowed |= allow_set
                    chain.append(
                        PolicyChainStep(
                            kind="scp",
                            id=scp_id,
                            name=scp.get("name", scp_id),
                            effect="allow",
                        )
                    )
                if deny_set:
                    candidate_deny |= deny_set
                    chain.append(
                        PolicyChainStep(
                            kind="scp",
                            id=scp_id,
                            name=scp.get("name", scp_id),
                            effect="deny",
                        )
                    )

        if scp_allowed is not None:
            scp_blocked = pre_scp_allow - scp_allowed
            candidate_allow = candidate_allow & scp_allowed
        else:
            scp_blocked = set()

        final_actions = candidate_allow - candidate_deny
        # shadowed = (1) actions both sides tried to allow + an explicit deny
        # blocked, (2) actions an identity/resource policy granted that
        # the SCP excluded from the org allow-set, or (3) actions an identity
        # policy granted that the permissions boundary caps away.
        #
        # (3) is reported even though the action never entered candidate_allow:
        # the whole value of a boundary to a reviewer is seeing *what it
        # stopped*, and an action that silently never appears is
        # indistinguishable from one nobody ever granted.
        #
        # (4) is the undecidable set: an Allow this resolver withheld because
        # its condition could not be evaluated against the snapshot's request
        # context. Reporting it beside the other three is what keeps "we did
        # not grant this" distinguishable from "nobody granted this".
        shadowed_denies = (
            (pre_scp_allow & candidate_deny) | scp_blocked | boundary_blocked | session_blocked | undecided
        ) - final_actions

        if undecided:
            notes.add(
                f"{len(undecided)} action(s) on {resource_arn} were withheld because a policy condition "
                f"could not be evaluated against the snapshot's request context; they are listed in "
                f"deny_actions rather than dropped"
            )

        if not final_actions and not shadowed_denies:
            return None, notes

        return (
            ResolvedPermission(
                principal_id=principal["id"],
                resource_id=resource["id"],
                resource_kind=resource.get("kind"),
                resource_arn=resource_arn,
                actions=tuple(sorted(final_actions)),
                deny_actions=tuple(sorted(shadowed_denies)),
                policy_chain=tuple(chain),
            ),
            notes,
        )

    def _evaluate_policy(
        self,
        *,
        policy: dict[str, Any],
        principal_arn: str,
        resource_arn: str,
        context: dict[str, Any],
        catalogue: list[str],
        principal_match_required: bool,
    ) -> _PolicyEvaluation:
        """Evaluate one policy into allow / deny / withheld-as-undecidable.

        The third set is what makes the three-valued condition result usable.
        An ``Allow`` whose condition cannot be decided is **not** granted —
        but it is also not the same as one nobody wrote, so it is reported
        separately and surfaces to the reader rather than vanishing.
        """

        document = policy.get("document") or {}
        statements = _as_list(document.get("Statement"))
        allow: set[str] = set()
        deny: set[str] = set()
        undecided: set[str] = set()
        notes: set[str] = set()

        for statement in statements:
            if not isinstance(statement, dict):
                continue
            if principal_match_required and not _principal_matches(statement.get("Principal"), principal_arn):
                continue
            if not _statement_covers_resource(statement, resource_arn):
                continue

            condition = statement.get("Condition")
            notes |= unmodelled_operators_in(condition)
            satisfied = evaluate_block(condition, context)
            if satisfied is False:
                continue

            effect = statement.get("Effect", "Allow")
            actions = _statement_actions(statement, catalogue)
            if satisfied is None:
                # Undecidable. An Allow is withheld (never over-report what
                # an identity can reach); a Deny still denies (never
                # over-report it either). Both arms fail toward less access.
                if effect == "Allow":
                    undecided |= actions
                elif effect == "Deny":
                    deny |= actions
                continue

            if effect == "Allow":
                allow |= actions
            elif effect == "Deny":
                deny |= actions

        return _PolicyEvaluation(allow=allow, deny=deny, undecided=undecided, notes=notes)
