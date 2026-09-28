"""A reference-only rule must be refused by the endpoint, not only by the UI.

4,388 of the 7,155 catalogue entries are rules the detection engine does not
load. Installing one flips a per-tenant flag over a rule that can never match
— a no-op wearing the costume of an action, which is why the console renders
"Cannot install" and offers no button for them.

That was the *only* thing stopping it. Measured against a running stack, a
POST straight at ``/api/v1/marketplace/install`` for
``chronicle-detection-rules-a-scheduled-task-was-created`` — badged
REFERENCE ONLY in the console a moment earlier — answered **HTTP 200** and
recorded the install. The control was styled as prevented rather than
prevented, and anything not going through that particular button (a script,
the docs' curl example, a second console) walked straight past it.

Asserted in both directions: an executable entry must still install, or a
route that refuses everything would pass the first half of this file.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Any

import pytest
from app.api.v1.endpoints import marketplace
from fastapi import HTTPException


class _Principal:
    """The authenticated caller, reduced to the three fields install reads."""

    def __init__(self) -> None:
        self.tenant_id = uuid.UUID("00000000-0000-0000-0000-000000000001")
        self.user_id = uuid.uuid4()
        self.email = "operator@example.com"


def _index() -> dict[str, Any]:
    return marketplace._load_index()


def _first(predicate) -> dict[str, Any]:
    for item in _index().get("items") or []:
        if predicate(item):
            return item
    pytest.skip("catalogue has no entry of this kind")


def _install(item: dict[str, Any]):
    return asyncio.run(
        marketplace.install_marketplace_item(
            marketplace.InstallRequest(type=item["type"], id=item["id"]),
            _Principal(),
        )
    )


@pytest.fixture(autouse=True)
def _clean_install_store():
    marketplace._installed.clear()
    yield
    marketplace._installed.clear()


class TestReferenceOnlyIsRefused:
    def test_the_catalogue_still_contains_reference_only_entries(self) -> None:
        """Without this the rest of the file could pass against an empty set."""
        count = sum(1 for i in _index()["items"] if i.get("executable") is False)
        assert count > 0, "no reference-only entries — this suite proves nothing"

    def test_installing_one_is_refused(self) -> None:
        item = _first(lambda i: i.get("executable") is False)
        with pytest.raises(HTTPException) as caught:
            _install(item)
        assert caught.value.status_code == 409
        assert "reference-only" in str(caught.value.detail).lower()

    def test_the_refusal_says_why(self) -> None:
        item = _first(lambda i: i.get("executable") is False and i.get("quarantine_reason"))
        with pytest.raises(HTTPException) as caught:
            _install(item)
        assert item["quarantine_reason"] in str(caught.value.detail)

    def test_nothing_is_recorded_when_it_is_refused(self) -> None:
        # A refusal that still wrote the marker would leave the console
        # showing "Installed" for a rule that cannot fire.
        item = _first(lambda i: i.get("executable") is False)
        with pytest.raises(HTTPException):
            _install(item)
        assert marketplace._installed == {}


class TestExecutableStillInstalls:
    def test_an_executable_rule_installs(self) -> None:
        # The other direction. Refusing everything would satisfy the class
        # above and break the marketplace.
        item = _first(lambda i: i["type"] == "detection" and i.get("executable") is True)
        result = _install(item)
        assert result.id == item["id"]
        assert result.already_installed is False
        assert len(marketplace._installed) == 1

    def test_an_entry_with_no_executable_field_installs(self) -> None:
        # Playbooks and plugins are not engine rules and carry no
        # `executable`. `is False` rather than falsiness is what keeps them
        # installable, so pin it.
        item = _first(lambda i: i["type"] == "playbook" and "executable" not in i)
        result = _install(item)
        assert result.id == item["id"]
