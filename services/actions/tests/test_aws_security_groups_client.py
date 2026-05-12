"""Regression tests for the AWS Security Groups client wiring.

These tests pin the public surface of ``app.clients.aws_security_groups`` so
that the bug fixed in GH #82 cannot silently come back. The actions service
fails to start at import time if any of the following regress:

* ``AWSSecurityGroupsClient`` is removed or renamed (the network executor
  imports it by that exact name).
* The legacy ``AWSSGClient`` alias is dropped (older callers and external
  plugins still import it).
* The constructor stops accepting the keyword arguments that
  ``app.executors.network`` passes (``access_key_id``, ``secret_access_key``,
  ``region``, ``role_arn``, ``session_name``) or stops allowing a
  ``region``-only construction for the rollback path.
* ``block_ip`` / ``unblock_ip`` stop accepting the executor's
  ``sg_id=`` / ``ip=`` / ``port=`` / ``protocol=`` keyword pattern.

The tests intentionally avoid importing ``boto3``: in the absence of boto3
the client must degrade to a structured "unavailable" stub instead of
crashing, which keeps the actions container booting in minimal images.
"""

from __future__ import annotations

import asyncio
import inspect

import pytest
from app.clients.aws_security_groups import AWSSecurityGroupsClient, AWSSGClient


def test_canonical_name_is_exported():
    """The class the network executor imports must exist under this name."""
    assert AWSSecurityGroupsClient.__name__ == "AWSSecurityGroupsClient"


def test_legacy_alias_points_at_canonical_class():
    """``AWSSGClient`` is kept as a backwards-compat alias and must not drift."""
    assert AWSSGClient is AWSSecurityGroupsClient


def test_constructor_accepts_executor_kwargs():
    """Pin the kwargs ``app.executors.network._aws_client`` actually passes.

    Reproduces the call site verbatim — if any of these are renamed or made
    positional, instantiation in the executor breaks at runtime.
    """
    client = AWSSecurityGroupsClient(
        access_key_id="AKIA-test",
        secret_access_key="secret-test",
        region="us-west-2",
        role_arn="arn:aws:iam::123456789012:role/aisoc",
        session_name="aisoc-action",
    )
    # Constructor must complete and stash the inputs without contacting AWS.
    assert client._region == "us-west-2"
    assert client._role_arn == "arn:aws:iam::123456789012:role/aisoc"


def test_constructor_accepts_region_only_for_rollback_path():
    """``BlockIPExecutor.rollback`` constructs the client with only a region.

    That path must not require credentials (boto3's default credential chain
    handles them in cluster), or the rollback after a successful block_ip
    silently fails.
    """
    client = AWSSecurityGroupsClient(region="eu-west-1")
    assert client._region == "eu-west-1"
    assert client._access_key_id is None
    assert client._secret_access_key is None


def test_legacy_constructor_aliases_still_work():
    """Older callers used ``assume_role_arn`` / ``sg_id`` keyword names.

    Keep those accepted so external plugin code that imports the client
    keeps working across the rename.
    """
    client = AWSSecurityGroupsClient(
        region="us-east-1",
        sg_id="sg-deadbeef",
        assume_role_arn="arn:aws:iam::000000000000:role/legacy",
    )
    assert client._sg_id == "sg-deadbeef"
    assert client._role_arn == "arn:aws:iam::000000000000:role/legacy"


def test_block_ip_signature_matches_executor_call_site():
    """The executor calls ``aws.block_ip(sg_id=..., ip=..., port=..., protocol=...)``.

    All four parameter names must be accepted as keyword arguments. We
    inspect the signature instead of calling AWS so the test runs offline.
    """
    sig = inspect.signature(AWSSecurityGroupsClient.block_ip)
    params = sig.parameters
    for kw in ("ip", "sg_id", "port", "protocol"):
        assert kw in params, f"block_ip is missing required keyword: {kw}"


def test_unblock_ip_signature_matches_executor_call_site():
    """Same contract as block_ip — used by both AllowIPExecutor and rollback."""
    sig = inspect.signature(AWSSecurityGroupsClient.unblock_ip)
    params = sig.parameters
    for kw in ("ip", "sg_id", "port", "protocol"):
        assert kw in params, f"unblock_ip is missing required keyword: {kw}"


def test_resolve_sg_id_requires_a_value():
    """Calling block_ip / unblock_ip without an SG id at construct *or*
    call time must raise — silently no-oping would be a security bug.
    """
    client = AWSSecurityGroupsClient(region="us-east-1")
    with pytest.raises(ValueError, match="security_group_id is required"):
        client._resolve_sg_id(None)


def test_port_range_translation_is_aws_correct():
    """``-1`` and ``None`` must collapse to ``(-1, -1)`` so the IpPermissions
    block sent to ``authorize_security_group_ingress`` means "all ports"
    rather than "port 0" or a malformed range.
    """
    assert AWSSecurityGroupsClient._port_range(-1) == (-1, -1)
    assert AWSSecurityGroupsClient._port_range(None) == (-1, -1)
    assert AWSSecurityGroupsClient._port_range(443) == (443, 443)


def test_block_ip_returns_unavailable_stub_when_boto3_missing(monkeypatch):
    """In a slim image without boto3 the actions service must still boot
    and the executor must get a structured failure object back rather than
    an ImportError. Pin that contract here.
    """

    monkeypatch.setattr(AWSSecurityGroupsClient, "_boto3_available", staticmethod(lambda: False))

    client = AWSSecurityGroupsClient(region="us-east-1", security_group_id="sg-abc")
    result = asyncio.run(client.block_ip("198.51.100.7"))

    assert result["success"] is False
    assert result["action"] == "block_ip"
    assert result["ip"] == "198.51.100.7"
    assert "boto3" in result["note"]


def test_describe_rules_returns_empty_list_when_boto3_missing(monkeypatch):
    """``describe_rules`` is read-only — when boto3 is missing it should
    degrade to an empty list rather than crash, so callers can branch on
    "no rules visible" instead of catching ImportError.
    """

    monkeypatch.setattr(AWSSecurityGroupsClient, "_boto3_available", staticmethod(lambda: False))

    client = AWSSecurityGroupsClient(region="us-east-1", security_group_id="sg-abc")
    rules = asyncio.run(client.describe_rules())
    assert rules == []


def test_executor_module_imports_cleanly():
    """The original GH #82 symptom: ``from app.executors.network import ...``
    raised ImportError because ``AWSSecurityGroupsClient`` did not exist.

    This single import call is the cheapest possible regression check —
    if it fails, the actions service won't start.
    """
    from app.executors.network import (  # noqa: F401
        AllowIPExecutor,
        BlockDomainExecutor,
        BlockIPExecutor,
    )


def test_executor_registry_imports_cleanly():
    """The actual import chain that crashed in production was

        app.services.executor_registry
            -> app.executors.network
                -> app.clients.aws_security_groups (ImportError: AWSSecurityGroupsClient)

    We only want to catch *this* regression, not unrelated import errors from
    other dependencies that may not be installed in every environment, so we
    skip cleanly on unrelated ImportError / ModuleNotFoundError and only
    fail loudly if the failure mentions the AWS SG client.
    """
    try:
        from app.services import executor_registry  # noqa: F401
    except (ImportError, ModuleNotFoundError) as exc:
        msg = str(exc)
        if "aws_security_groups" in msg or "AWSSecurityGroupsClient" in msg:
            raise AssertionError(f"GH #82 regression: registry import broken by AWS SG client: {exc}") from exc
        pytest.skip(f"unrelated dependency not available in this env: {exc}")
