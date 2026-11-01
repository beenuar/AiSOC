"""Depth 2 Phase 1.1 reproduction: the posture exists and nothing consumes it.

Depth 2.5 built versioned posture snapshots and six resolvers that answer
"what can this principal do" from one. Depth 2.6 — carried into wave 2 as
1.1 — is the half that was never built: nothing asks the resolver on an
analyst's behalf, no alert carries a privilege tier, and the AWS resolver's
own docstring lists four IAM semantics it does not model.

Each test below fails on the pre-change tree for one stated reason. They are
kept after the fix as the guard, because every one of them is the "built but
unwired" shape this repository keeps rediscovering: a resolver with no
caller is indistinguishable from a resolver that does not exist, and a
passing unit test on the resolver cannot tell the difference.
"""

from __future__ import annotations

from typing import Any

import pytest

from app.services.effective_permissions.aws import AwsIamResolver


def _snapshot(statement: dict[str, Any], *, principal_extra: dict[str, Any] | None = None) -> dict[str, Any]:
    """One principal, one bucket, one identity policy carrying ``statement``."""
    principal: dict[str, Any] = {
        "id": "u1",
        "arn": "arn:aws:iam::123456789012:user/alice",
        "type": "user",
        "attached_policies": ["p1"],
    }
    principal.update(principal_extra or {})
    return {
        "account_id": "123456789012",
        "principals": [principal],
        "policies": [{"id": "p1", "name": "p1", "kind": "identity", "document": {"Statement": [statement]}}],
        "resources": [
            {
                "id": "r1",
                "arn": "arn:aws:s3:::data",
                "kind": "s3:bucket",
                "service_actions": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
            }
        ],
    }


def _actions(snapshot: dict[str, Any]) -> set[str]:
    result = AwsIamResolver().resolve("u1", snapshot=snapshot)
    return {action for decision in result.decisions for action in decision.actions}


class TestAwsSemanticsTheResolverDoesNotModel:
    """Each fixture changes the answer, which is the point of modelling it.

    A resolver that ignores ``NotAction`` does not return a slightly vaguer
    answer — it returns the opposite one, because ``NotAction`` inverts the
    set the statement applies to. Silently broader is how a containment
    decision reads "this identity cannot touch the data" when it can.
    """

    def test_not_action_inverts_the_action_set(self) -> None:
        """``Allow NotAction s3:DeleteObject`` grants Get and Put, not Delete."""
        actions = _actions(_snapshot({"Effect": "Allow", "NotAction": "s3:DeleteObject", "Resource": "*"}))
        assert actions == {"s3:GetObject", "s3:PutObject"}

    def test_not_action_on_a_deny_denies_everything_else(self) -> None:
        """The deny arm matters more: it is what an SCP uses to pin a region."""
        snapshot = _snapshot({"Effect": "Allow", "Action": "s3:*", "Resource": "*"})
        snapshot["policies"].append(
            {
                "id": "p2",
                "name": "p2",
                "kind": "identity",
                "document": {"Statement": [{"Effect": "Deny", "NotAction": "s3:GetObject", "Resource": "*"}]},
            }
        )
        snapshot["principals"][0]["attached_policies"].append("p2")
        assert _actions(snapshot) == {"s3:GetObject"}

    def test_not_resource_excludes_only_the_named_resource(self) -> None:
        """``NotResource`` on the one bucket in the snapshot matches nothing."""
        actions = _actions(
            _snapshot({"Effect": "Allow", "Action": "s3:*", "NotResource": "arn:aws:s3:::data"})
        )
        assert actions == set()

    @pytest.mark.parametrize(
        ("condition", "context", "expected"),
        [
            ({"Bool": {"aws:SecureTransport": "true"}}, {"aws:SecureTransport": "true"}, True),
            ({"Bool": {"aws:SecureTransport": "true"}}, {"aws:SecureTransport": "false"}, False),
            ({"StringNotEquals": {"aws:PrincipalTag/team": "ops"}}, {"aws:PrincipalTag/team": "dev"}, True),
            ({"StringNotEquals": {"aws:PrincipalTag/team": "ops"}}, {"aws:PrincipalTag/team": "ops"}, False),
            ({"NumericLessThan": {"s3:max-keys": "10"}}, {"s3:max-keys": "5"}, True),
            ({"NumericLessThan": {"s3:max-keys": "10"}}, {"s3:max-keys": "50"}, False),
            ({"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}}, {"aws:SourceIp": "203.0.113.7"}, True),
            ({"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}}, {"aws:SourceIp": "198.51.100.7"}, False),
            ({"ArnLike": {"aws:PrincipalArn": "arn:aws:iam::*:user/*"}}, {"aws:PrincipalArn": "arn:aws:iam::1:user/a"}, True),
            ({"DateGreaterThan": {"aws:CurrentTime": "2020-01-01T00:00:00Z"}}, {"aws:CurrentTime": "2026-01-01T00:00:00Z"}, True),
            ({"DateGreaterThan": {"aws:CurrentTime": "2030-01-01T00:00:00Z"}}, {"aws:CurrentTime": "2026-01-01T00:00:00Z"}, False),
        ],
    )
    def test_condition_operators_beyond_string_equals(
        self, condition: dict[str, Any], context: dict[str, Any], expected: bool
    ) -> None:
        """Today every operator outside StringEquals/StringLike denies outright.

        That is the conservative direction, which sounds safe and is not: it
        makes ``Bool aws:SecureTransport true`` — on a policy the request
        satisfies — read as "this identity cannot read the bucket", so an
        access review under-reports real access.
        """
        snapshot = _snapshot({"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*", "Condition": condition})
        snapshot["resources"][0]["context"] = context
        assert ("s3:GetObject" in _actions(snapshot)) is expected

    def test_session_policy_caps_an_assumed_role(self) -> None:
        """A session policy is the cap that an assumed-role chain actually runs under.

        ``sts:AssumeRole`` with a session policy is how every federated and
        cross-account hop narrows itself, so ignoring it over-reports the
        role's reach on exactly the principals an investigation cares about.
        """
        snapshot = _snapshot({"Effect": "Allow", "Action": "s3:*", "Resource": "*"})
        snapshot["principals"][0]["session_policies"] = ["sp1"]
        snapshot["policies"].append(
            {
                "id": "sp1",
                "name": "sp1",
                "kind": "session",
                "document": {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]},
            }
        )
        assert _actions(snapshot) == {"s3:GetObject"}


class TestNothingConsumesThePosture:
    """The wiring half of 1.1 — a tool nobody is offered is not a tool."""

    def test_investigate_query_exposes_the_typed_pivot(self) -> None:
        """``POST /investigate/query`` picks from ``investigation_tools.TOOLS``."""
        from app.services import investigation_tools

        assert "identity_effective_permissions" in investigation_tools.TOOLS

    def test_privilege_facts_are_derived_from_a_point_in_time_snapshot(self) -> None:
        """Fusion needs a tier for the moment the identity acted, not now."""
        from app.services.identity_privilege import derive_privilege

        result = AwsIamResolver().resolve(
            "u1",
            snapshot=_snapshot({"Effect": "Allow", "Action": "iam:AttachUserPolicy", "Resource": "*"}),
        )
        facts = derive_privilege(result)
        assert facts.tier in {"standard", "elevated", "admin", "domain_admin"}
        assert facts.tags.can_escalate is True

    def test_absent_posture_is_unknown_and_not_a_default_tier(self) -> None:
        """"No snapshot covers this time" must never render as ``standard``.

        A default tier is the confident-zero defect: a reader cannot tell a
        measured standard account from one the platform knows nothing about,
        and the second is the one worth escalating.
        """
        from app.services.identity_privilege import UNKNOWN_PRIVILEGE

        assert UNKNOWN_PRIVILEGE.tier == "unknown"
        assert UNKNOWN_PRIVILEGE.tags.can_escalate is None


class TestBlastRadiusUsesPermissionsNotHops:
    def test_a_permission_scoped_blast_radius_exists(self) -> None:
        """N-hop reachability over any relationship answers a different question.

        "Everything within three hops" includes the alert that mentioned the
        host, the IOC seen on it and the technique tagged on that: a list an
        analyst cannot act on. What the identity's effective permissions
        reach is the containment question.
        """
        from app.services import graph_service

        assert hasattr(graph_service, "get_permission_blast_radius")
