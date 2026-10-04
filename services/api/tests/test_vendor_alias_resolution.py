"""The three vendors that were never offered to an investigation now are.

Fix pass item 1.3. See `plans/aisoc_fix_pass_plan.plan.md`.

What was wrong
--------------
`vendor_reads.available_reads` decided which vendor tools to bind by looking an
executor's vendor id up against the tenant's saved connectors:

    by_type.get(vendor_id)

A read executor is named for the product -- `defender`, `entra`, `aws` -- and a
connector for the integration a tenant configures -- `azure_defender`,
`azure_entra`, `aws_cloudtrail`. For four of the seven the two strings happen to
be identical. For the other three the lookup returned `None` on every tenant,
so the tool was never bound and a model investigating a Defender host, an Entra
identity or a CloudTrail event was told the tenant had no integration for it.

Three of the five vendors added in gap-closure 4.2 had therefore never once
been reachable.

Why nothing failed
------------------
The lookup that misses is the same expression as the lookup that hits, and the
three vendors were simply absent from a list nobody counted.

What this file asserts
----------------------
The resolution itself, in both directions: a tenant that saved
`azure_defender` is offered the `defender` executor, and a tenant that saved
nothing is offered nothing. The negative half matters as much, because a
resolver that returned the first connector it found for every vendor would
satisfy the positive half.

`scripts/check_vendor_catalog_ids.py` owns the naming question -- that every
executor id resolves to a type a tenant can save. This owns the behavioural
one.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from app.services.agent_tools import vendor_aliases


def _connector(connector_type: str) -> SimpleNamespace:
    return SimpleNamespace(connector_type=connector_type, name=f"{connector_type}-1")


class TestTheThreeThatNeverMatched:
    @pytest.mark.parametrize(
        ("vendor_id", "saved_type"),
        [
            ("defender", "azure_defender"),
            ("entra", "azure_entra"),
            ("aws", "aws_cloudtrail"),
        ],
    )
    def test_a_tenant_that_saved_the_integration_is_offered_the_vendor(self, vendor_id: str, saved_type: str) -> None:
        """Pre-fix each of these resolved to None on every tenant."""
        by_type = {saved_type: _connector(saved_type)}

        resolved = vendor_aliases.resolve(vendor_id, by_type)

        assert resolved is not None, f"a tenant with {saved_type!r} saved was not offered the {vendor_id!r} read executor"
        assert resolved.connector_type == saved_type


class TestTheFourThatAlreadyMatched:
    @pytest.mark.parametrize("vendor_id", ["crowdstrike", "okta", "sentinelone", "google_workspace"])
    def test_an_unaliased_vendor_still_resolves_to_itself(self, vendor_id: str) -> None:
        """The alias map is a list of exceptions, not a second catalog.

        A vendor with no entry must keep resolving by its own name, or the fix
        would break the four that were working.
        """
        by_type = {vendor_id: _connector(vendor_id)}

        resolved = vendor_aliases.resolve(vendor_id, by_type)

        assert resolved is not None and resolved.connector_type == vendor_id


class TestTheNegativeControls:
    """What stops the assertions above passing over a resolver that matches anything."""

    def test_a_tenant_with_nothing_connected_is_offered_nothing(self) -> None:
        assert vendor_aliases.resolve("defender", {}) is None

    def test_an_unrelated_connector_does_not_satisfy_a_vendor(self) -> None:
        """A tenant with Okta has not got Defender.

        A resolver that fell back to "any connector" would bind a tool that
        answers `no_integration`, which costs a turn of a bounded loop and
        which some models narrate as though it returned something.
        """
        assert vendor_aliases.resolve("defender", {"okta": _connector("okta")}) is None

    def test_preference_order_is_honoured(self) -> None:
        """`aws` reads a cloud audit trail, so CloudTrail wins over GuardDuty.

        A tenant with both gets the one that answers the question the
        capability asks, rather than whichever the dictionary happened to
        iterate first.
        """
        by_type = {
            "aws_guardduty": _connector("aws_guardduty"),
            "aws_cloudtrail": _connector("aws_cloudtrail"),
        }

        resolved = vendor_aliases.resolve("aws", by_type)

        assert resolved is not None and resolved.connector_type == "aws_cloudtrail"
