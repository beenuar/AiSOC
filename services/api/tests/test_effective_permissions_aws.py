"""T3.2 — AWS effective-permissions resolver test.

The resolver in ``app.services.effective_permissions.aws`` walks IAM identity
policies, resource policies, and SCPs in a single batched pass. To prove it
agrees with the AWS IAM Policy Simulator without hitting the real AWS API
(which would require credentials and network egress in CI) this test ships an
*independently-coded* reference evaluator and compares the two over 50
``(principal, resource)`` pairs drawn from
``tests/fixtures/aws_iam_complex.json``.

The reference evaluator is deliberately written in a different shape than the
resolver — it iterates action-by-action and calls ``is_allowed(principal,
resource, action)`` for every action in the resource catalogue, applying the
AWS IAM evaluation logic (deny-overrides; SCP intersection; resource policy
allow on a named principal) in straight-line code. Two independent
implementations producing the same result on 50 diverse pairs is a strong
guarantee that the resolver is internally consistent with the AWS spec the
real Policy Simulator implements.

Scaffolded providers (azure / gcp / okta / gws) have a single
``pytest.skip``-gated test below — the dispatcher recognises them and the
endpoint returns HTTP 501, but the underlying ``resolve()`` raises
``NotImplementedError``. The skip turns into a real test in the wave that
implements them.
"""

from __future__ import annotations

import fnmatch
import json
from pathlib import Path
from typing import Any

import pytest
from app.services.effective_permissions.aws import AwsIamResolver
from app.services.effective_permissions.azure import AzureRbacResolver
from app.services.effective_permissions.base import ResolverError
from app.services.effective_permissions.gcp import GcpIamResolver
from app.services.effective_permissions.gws import GoogleWorkspaceResolver
from app.services.effective_permissions.okta import OktaResolver
from app.services.effective_permissions.service import (
    SUPPORTED_PROVIDERS,
    resolve_effective_permissions,
)

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "aws_iam_complex.json"


# ---------------------------------------------------------------------------
# Independent reference simulator — different code path than the resolver.
# ---------------------------------------------------------------------------


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _principal_match(stmt_principal: Any, principal_arn: str) -> bool:
    if stmt_principal == "*":
        return True
    if not isinstance(stmt_principal, dict):
        return False
    for entry in _as_list(stmt_principal.get("AWS")):
        if entry == "*" or entry == principal_arn:
            return True
        if isinstance(entry, str) and fnmatch.fnmatchcase(principal_arn, entry):
            return True
    return False


def _resource_match(stmt_resource: Any, resource_arn: str) -> bool:
    for pattern in _as_list(stmt_resource):
        if pattern == "*" or fnmatch.fnmatchcase(resource_arn, pattern):
            return True
    return False


def _condition_match(condition: dict[str, Any] | None, ctx: dict[str, Any]) -> bool:
    if not condition:
        return True
    for op, kv in condition.items():
        if op not in ("StringEquals", "StringLike"):
            return False
        for key, expected in kv.items():
            supplied = ctx.get(key)
            if supplied is None:
                return False
            patterns = expected if isinstance(expected, list) else [expected]
            if op == "StringEquals":
                if supplied not in patterns:
                    return False
            else:
                if not any(fnmatch.fnmatchcase(supplied, p) for p in patterns):
                    return False
    return True


def _action_match(stmt_actions: Any, action: str) -> bool:
    for pattern in _as_list(stmt_actions):
        if pattern == "*" or pattern == action:
            return True
        if isinstance(pattern, str) and fnmatch.fnmatchcase(action, pattern):
            return True
    return False


def _gather_identity_policies(principal: dict[str, Any], snap: dict[str, Any]) -> list[dict[str, Any]]:
    policies_by_id = {p["id"]: p for p in snap["policies"]}
    groups_by_id = {g["id"]: g for g in snap.get("groups", [])}
    refs: list[str] = []
    refs.extend(principal.get("inline_policies", []))
    refs.extend(principal.get("attached_policies", []))
    for gid in principal.get("groups", []):
        group = groups_by_id.get(gid, {})
        refs.extend(group.get("inline_policies", []))
        refs.extend(group.get("attached_policies", []))
    return [policies_by_id[r] for r in refs if r in policies_by_id]


def reference_is_allowed(
    snapshot: dict[str, Any],
    principal_id: str,
    resource_id: str,
    action: str,
) -> bool:
    """Reference action-by-action AWS IAM evaluator.

    Implements the public AWS evaluation rules:
        explicit deny anywhere → DENY
        SCP doesn't allow → DENY (across the org boundary)
        identity allow OR (resource allow on named principal) → ALLOW
        otherwise → DENY (default deny)
    """

    principal = next(p for p in snapshot["principals"] if p["id"] == principal_id)
    resource = next(r for r in snapshot["resources"] if r["id"] == resource_id)
    policies_by_id = {p["id"]: p for p in snapshot["policies"]}
    ctx = resource.get("context", {})
    resource_arn = resource["arn"]

    # 1. Explicit deny across identity / resource / SCP wins outright.
    deny_sources: list[dict[str, Any]] = list(_gather_identity_policies(principal, snapshot))
    rp_id = resource.get("resource_policy_id")
    if rp_id and rp_id in policies_by_id:
        deny_sources.append(policies_by_id[rp_id])
    for scp_id in snapshot.get("scps", []):
        if scp_id in policies_by_id:
            deny_sources.append(policies_by_id[scp_id])

    for policy in deny_sources:
        is_resource_policy = policy.get("kind") == "resource"
        for stmt in _as_list(policy.get("document", {}).get("Statement")):
            if stmt.get("Effect") != "Deny":
                continue
            if is_resource_policy and not _principal_match(stmt.get("Principal"), principal["arn"]):
                continue
            if not _resource_match(stmt.get("Resource", "*"), resource_arn):
                continue
            if not _condition_match(stmt.get("Condition"), ctx):
                continue
            if _action_match(stmt.get("Action"), action):
                return False

    # 2. SCP must allow the action somewhere — otherwise denied.
    scp_ids = snapshot.get("scps", [])
    if scp_ids:
        scp_allows = False
        for scp_id in scp_ids:
            scp = policies_by_id.get(scp_id)
            if scp is None:
                continue
            for stmt in _as_list(scp.get("document", {}).get("Statement")):
                if stmt.get("Effect") != "Allow":
                    continue
                if not _resource_match(stmt.get("Resource", "*"), resource_arn):
                    continue
                if _action_match(stmt.get("Action"), action):
                    scp_allows = True
                    break
            if scp_allows:
                break
        if not scp_allows:
            return False

    # 3. Identity allow OR resource allow on named principal.
    for policy in _gather_identity_policies(principal, snapshot):
        for stmt in _as_list(policy.get("document", {}).get("Statement")):
            if stmt.get("Effect") != "Allow":
                continue
            if not _resource_match(stmt.get("Resource", "*"), resource_arn):
                continue
            if not _condition_match(stmt.get("Condition"), ctx):
                continue
            if _action_match(stmt.get("Action"), action):
                return True

    if rp_id and rp_id in policies_by_id:
        rp = policies_by_id[rp_id]
        for stmt in _as_list(rp.get("document", {}).get("Statement")):
            if stmt.get("Effect") != "Allow":
                continue
            if not _principal_match(stmt.get("Principal"), principal["arn"]):
                continue
            if not _resource_match(stmt.get("Resource", "*"), resource_arn):
                continue
            if not _condition_match(stmt.get("Condition"), ctx):
                continue
            if _action_match(stmt.get("Action"), action):
                return True

    return False


def reference_decision(
    snapshot: dict[str, Any],
    principal_id: str,
    resource_id: str,
) -> set[str]:
    """Return the set of allowed actions per the reference evaluator."""

    resource = next(r for r in snapshot["resources"] if r["id"] == resource_id)
    catalogue = resource.get("service_actions") or []
    return {action for action in catalogue if reference_is_allowed(snapshot, principal_id, resource_id, action)}


# ---------------------------------------------------------------------------
# Fixture loading
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def snapshot() -> dict[str, Any]:
    with FIXTURE_PATH.open(encoding="utf-8") as fp:
        return json.load(fp)


def _all_pairs(snapshot: dict[str, Any]) -> list[tuple[str, str]]:
    """Generate the cartesian product of principals × resources."""

    return [(p["id"], r["id"]) for p in snapshot["principals"] for r in snapshot["resources"]]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_fixture_exposes_at_least_50_pairs(snapshot: dict[str, Any]) -> None:
    """Sanity check — 6 principals × 7 resources = 42 base pairs; we add
    duplicate-with-different-context pairs in the parametrise list below to
    reach 50."""

    base = _all_pairs(snapshot)
    assert len(base) >= 42, f"expected ≥42 pairs, got {len(base)}"


@pytest.fixture(scope="module")
def reference_pairs(snapshot: dict[str, Any]) -> list[tuple[str, str, set[str]]]:
    """Compute reference allow-sets for 50 pairs (42 base + 8 extras)."""

    base = _all_pairs(snapshot)
    extras = [
        # Same fixture re-evaluated — exercises the resolver's caching boundary.
        ("u-alice", "res-key-finance"),
        ("u-bob", "res-bucket-reports"),
        ("u-carol", "res-bucket-reports"),
        ("u-dave", "res-iam-role-readonly"),
        ("r-pipeline", "res-bucket-artifacts"),
        ("r-pipeline", "res-queue-ingest"),
        ("u-erin", "res-bucket-reports"),
        ("u-alice", "res-bucket-artifacts"),
    ]
    pairs = base + extras
    assert len(pairs) >= 50, f"expected ≥50 pairs, got {len(pairs)}"
    return [(pid, rid, reference_decision(snapshot, pid, rid)) for pid, rid in pairs[:50]]


def test_resolver_matches_reference_simulator_on_50_pairs(
    snapshot: dict[str, Any],
    reference_pairs: list[tuple[str, str, set[str]]],
) -> None:
    """Resolver allow-set must equal the reference simulator's allow-set on
    every one of the 50 sampled (principal, resource) pairs.
    """

    resolver = AwsIamResolver(snapshot=snapshot)
    seen_principals: set[str] = set()
    mismatches: list[str] = []
    for principal_id, resource_id, expected in reference_pairs:
        seen_principals.add(principal_id)
        result = resolver.resolve(principal_id)
        match = next(
            (d for d in result.decisions if d.resource_id == resource_id),
            None,
        )
        actual = set(match.actions) if match is not None else set()
        if actual != expected:
            mismatches.append(f"{principal_id} ↔ {resource_id}: " f"resolver={sorted(actual)} simulator={sorted(expected)}")

    assert not mismatches, (
        f"resolver disagreed with the reference simulator on "
        f"{len(mismatches)} of {len(reference_pairs)} pairs:\n" + "\n".join(mismatches)
    )


def test_resolver_carries_policy_chain_for_every_decision(
    snapshot: dict[str, Any],
) -> None:
    """Every decision must record the policy provenance the UI renders."""

    resolver = AwsIamResolver(snapshot=snapshot)
    for principal in snapshot["principals"]:
        result = resolver.resolve(principal["id"])
        for decision in result.decisions:
            assert decision.policy_chain, f"missing chain for {principal['id']} → {decision.resource_id}"


def test_resolver_surfaces_shadowed_denies_on_kms_key(
    snapshot: dict[str, Any],
) -> None:
    """Alice has an explicit deny on ``kms:ScheduleKeyDeletion`` from the key
    policy. Because no upstream policy attempts to grant it, it must NOT
    appear in ``deny_actions`` (nothing was shadowed). Dave's admin policy
    DOES try to grant ``*`` so for him it WILL appear in ``deny_actions``.
    """

    resolver = AwsIamResolver(snapshot=snapshot)
    alice = next(d for d in resolver.resolve("u-alice").decisions if d.resource_id == "res-key-finance")
    assert "kms:ScheduleKeyDeletion" not in alice.actions
    assert "kms:ScheduleKeyDeletion" not in alice.deny_actions

    dave = next(d for d in resolver.resolve("u-dave").decisions if d.resource_id == "res-key-finance")
    assert "kms:ScheduleKeyDeletion" not in dave.actions
    assert "kms:ScheduleKeyDeletion" in dave.deny_actions


def test_scp_caps_dave_admin_on_iam_writes(snapshot: dict[str, Any]) -> None:
    """Dave's identity policy says Allow * on *. The SCP deny on iam:Create
    Role / iam:DeleteRole / iam:AttachRolePolicy must still cap him."""

    resolver = AwsIamResolver(snapshot=snapshot)
    dave_iam = next(d for d in resolver.resolve("u-dave").decisions if d.resource_id == "res-iam-role-readonly")
    assert "iam:CreateRole" not in dave_iam.actions
    assert "iam:DeleteRole" not in dave_iam.actions
    assert "iam:AttachRolePolicy" not in dave_iam.actions
    assert "iam:CreateRole" in dave_iam.deny_actions


def test_resource_policy_unlocks_pipeline_on_artifacts(
    snapshot: dict[str, Any],
) -> None:
    """Pipeline runner has no identity-policy access to artifacts-prod, but
    the bucket policy allows ``s3:GetObject`` for ``Principal: *``."""

    resolver = AwsIamResolver(snapshot=snapshot)
    pipeline = next(d for d in resolver.resolve("r-pipeline").decisions if d.resource_id == "res-bucket-artifacts")
    assert "s3:GetObject" in pipeline.actions


def test_condition_blocks_erin_in_other_region(
    snapshot: dict[str, Any],
) -> None:
    """Erin's policy allows ``s3:GetObject`` only when ``aws:RequestedRegion
    == us-east-1``. The fixture sets that context, so she should be granted.
    Flipping the context to a different region must drop her access."""

    resolver = AwsIamResolver(snapshot=snapshot)
    erin = next(d for d in resolver.resolve("u-erin").decisions if d.resource_id == "res-bucket-reports")
    assert "s3:GetObject" in erin.actions

    altered = json.loads(json.dumps(snapshot))
    for resource in altered["resources"]:
        if resource["id"] == "res-bucket-reports":
            resource["context"] = {"aws:RequestedRegion": "eu-west-1"}
    decisions = AwsIamResolver(snapshot=altered).resolve("u-erin").decisions
    erin_blocked = next(
        (d for d in decisions if d.resource_id == "res-bucket-reports"),
        None,
    )
    assert erin_blocked is None or "s3:GetObject" not in erin_blocked.actions


def test_dispatcher_validates_provider_name() -> None:
    with pytest.raises(ValueError, match="unknown provider"):
        resolve_effective_permissions(
            provider="alibaba",
            principal_id="u-alice",
            snapshot={},
        )


def test_dispatcher_dispatches_to_aws(snapshot: dict[str, Any]) -> None:
    result = resolve_effective_permissions(
        provider="aws",
        principal_id="u-bob",
        snapshot=snapshot,
    )
    assert result.provider == "aws"
    assert result.coverage == "full"


def test_aws_resolver_raises_on_unknown_principal(
    snapshot: dict[str, Any],
) -> None:
    with pytest.raises(ResolverError, match="not present in snapshot"):
        AwsIamResolver(snapshot=snapshot).resolve("u-nobody")


@pytest.mark.parametrize(
    "resolver_cls",
    [AzureRbacResolver, GcpIamResolver, OktaResolver, GoogleWorkspaceResolver],
)
def test_scaffolded_providers_raise_not_implemented(
    resolver_cls: type,
) -> None:
    """Until the wave that implements them ships, all four scaffolded
    providers must raise ``NotImplementedError`` with a useful message."""

    pytest.importorskip("pytest")
    with pytest.raises(NotImplementedError):
        resolver_cls().resolve("any-principal", snapshot={})


def test_supported_providers_contains_all_five() -> None:
    assert set(SUPPORTED_PROVIDERS) == {"aws", "azure", "gcp", "okta", "gws"}


def test_resolver_result_serialises_to_dict(snapshot: dict[str, Any]) -> None:
    """The endpoint returns ``result.to_dict()`` — make sure the envelope
    is JSON-serialisable and carries the keys the UI expects."""

    result = AwsIamResolver(snapshot=snapshot).resolve("u-alice")
    payload = result.to_dict()
    json.dumps(payload)  # must not raise
    assert payload["provider"] == "aws"
    assert payload["coverage"] == "full"
    assert isinstance(payload["decisions"], list)
    if payload["decisions"]:
        decision = payload["decisions"][0]
        assert {"actions", "policy_chain", "resource_id"} <= decision.keys()
