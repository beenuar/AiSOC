"""The portfolio scope resolver has to accept the principal the route hands it.

`test_mssp_portfolio_isolation.py` proves the aggregation is tenant-scoped and
`test_mssp_portfolio_contract.py` proves every figure survives serialisation.
Neither could see the defect that made the whole surface unreachable, because
both call `resolve_portfolio_scope` with an ORM `User` fetched from the test
database, and the one production caller passes the authenticated
`CurrentUser`. `CurrentUser` carries its identifier as `user_id` and has no
`id` at all, so `GET /mssp/portfolio` raised `AttributeError` and returned 500
to every caller — including the non-member, whom the route means to answer
with a deliberate 403. The route was annotated `current_user: User`, so type
checking believed the attribute was there.

The lesson is the one the audit keeps relearning: a passing test on the wrong
object is indistinguishable from a working feature. So this test drives the
real dependency with the real principal type, and needs no database to do it
— the non-member path returns before any row is read.
"""

from __future__ import annotations

import uuid

import pytest
from app.api.v1.deps import CurrentUser
from app.api.v1.endpoints.mssp import _scope
from app.services.org_scope import resolve_portfolio_scope
from fastapi import HTTPException


class _NoRows:
    """The single result shape `resolve_portfolio_scope` reads on this path."""

    def first(self):
        return None

    def scalars(self):
        return []


class _StubSession:
    """Answers `execute` with "no membership" and records that it was asked.

    A stub rather than a mock because the assertion is about the *principal*
    reaching the query at all. If the id is read off the wrong attribute the
    call never gets here, which is exactly the failure being pinned.
    """

    def __init__(self) -> None:
        self.executed = 0

    async def execute(self, *_args, **_kwargs):
        self.executed += 1
        return _NoRows()


def _principal() -> CurrentUser:
    return CurrentUser(
        user_id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        role="admin",
        email="operator@example.com",
    )


def test_the_authenticated_principal_exposes_no_id_attribute() -> None:
    """Pins the premise. If `CurrentUser` ever grows an `id`, the call sites
    below stop being load-bearing and this test says so rather than passing
    for a reason that no longer holds."""
    assert not hasattr(_principal(), "id")
    assert isinstance(_principal().user_id, uuid.UUID)


@pytest.mark.asyncio
async def test_resolving_a_scope_accepts_the_principals_identifier() -> None:
    """The resolver takes an id, so it cannot be handed the wrong shape."""
    db = _StubSession()
    scope = await resolve_portfolio_scope(db, _principal().user_id)
    assert db.executed == 1, "the membership query never ran"
    assert not scope.is_member
    assert scope.is_empty


@pytest.mark.asyncio
async def test_a_non_member_is_refused_with_403_not_a_500() -> None:
    """The observed defect, stated as an assertion.

    Before the fix this raised `AttributeError` out of the dependency and
    FastAPI turned it into `500 Internal Server Error`, so an operator who
    manages nothing could not tell "this surface is not yours" from "this
    product is broken".
    """
    with pytest.raises(HTTPException) as caught:
        await _scope(db=_StubSession(), current_user=_principal())

    assert caught.value.status_code == 403
    assert "organisation" in str(caught.value.detail).lower()
