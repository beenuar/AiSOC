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
from collections.abc import Callable
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


def _first(predicate: Callable[[dict[str, Any]], bool]) -> dict[str, Any]:
    # One exit, because `pytest.skip` raises and a trailing call to it reads
    # to a static analyser as a path that falls off the end without returning.
    items: list[dict[str, Any]] = _index().get("items") or []
    match: dict[str, Any] | None = next((item for item in items if predicate(item)), None)
    if match is None:
        # `pytest.skip()` raises, but it is not typed `NoReturn`, so a type
        # checker reads the line below as returning `None`. Raising the very
        # exception it raises says the same thing in a way both tools follow.
        raise pytest.skip.Exception("catalogue has no entry of this kind")
    return match


def _install(item: dict[str, Any], db: _FakeDB | None = None):
    """Drive the real handler. Pass a `db` to inspect what it wrote."""
    return asyncio.run(
        marketplace.install_marketplace_item(
            marketplace.InstallRequest(type=item["type"], id=item["id"]),
            _Principal(),
            db if db is not None else _FakeDB(),
        )
    )


class _FakeDB:
    """Records what reached the database.

    Install state moved out of a process-local dict into
    `marketplace_installs`, so a refusal is no longer "the dict stayed
    empty" — it is "no INSERT was issued". This double exists to assert
    that, which is a stronger claim than the dict version made: the old
    test could not distinguish a refusal from a write that silently
    failed.
    """

    def __init__(self) -> None:
        self.statements: list[str] = []
        self.committed = 0

    async def execute(self, statement, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        self.statements.append(str(statement))
        return _FakeRows()

    async def scalar(self, statement, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        self.statements.append(str(statement))
        return None

    async def commit(self) -> None:
        self.committed += 1

    @property
    def inserts(self) -> list[str]:
        return [s for s in self.statements if "INSERT INTO marketplace_installs" in s]


class _FakeRows:
    def all(self) -> list:
        return []

    @property
    def rowcount(self) -> int:
        return 0


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
        item = _first(lambda i: i.get("executable") is False and bool(i.get("quarantine_reason")))
        with pytest.raises(HTTPException) as caught:
            _install(item)
        assert item["quarantine_reason"] in str(caught.value.detail)

    def test_nothing_is_recorded_when_it_is_refused(self) -> None:
        # A refusal that still wrote the marker would leave the console
        # showing "Installed" for a rule that cannot fire.
        item = _first(lambda i: i.get("executable") is False)
        db = _FakeDB()
        with pytest.raises(HTTPException):
            _install(item, db)
        assert db.inserts == [], "a refused install still wrote to marketplace_installs"


class TestExecutableStillInstalls:
    def test_an_executable_rule_installs(self) -> None:
        # The other direction. Refusing everything would satisfy the class
        # above and break the marketplace.
        item = _first(lambda i: bool(i["type"] == "detection") and i.get("executable") is True)
        db = _FakeDB()
        result = _install(item, db)
        assert result.id == item["id"]
        assert result.already_installed is False
        assert len(db.inserts) == 1, "an accepted install did not reach marketplace_installs"

    def test_an_entry_with_no_executable_field_installs(self) -> None:
        # Playbooks and plugins are not engine rules and carry no
        # `executable`. `is False` rather than falsiness is what keeps them
        # installable, so pin it.
        item = _first(lambda i: bool(i["type"] == "playbook") and "executable" not in i)
        result = _install(item)
        assert result.id == item["id"]
