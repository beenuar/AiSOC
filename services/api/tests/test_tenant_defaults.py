"""A tenant can be created without naming every column the schema fills in.

Issue #1693. `tenants.mssp_role` has been `NOT NULL DEFAULT 'standalone'`
since migration 012, and the ORM declared it `nullable=True` with no default.
Those two statements look compatible and are not:

    a column the ORM believes is nullable is named in the INSERT with an
    explicit NULL, and a column named in an INSERT does not receive the
    column DEFAULT.

So the database default could never fire and `pnpm aisoc:demo` failed its
seed step on a brand-new database with `NotNullViolationError`. It was not a
seed bug — the seed is simply the first thing to insert a tenant.

These assert the ORM's own view, which is where the defect lived. The
statement SQLAlchemy builds is decided by the mapper, so a compiled INSERT
answers the question without a database; the end-to-end proof that the row
lands with `standalone` runs in the live suite, and `check_orm_nullability.py`
guards the whole class.
"""

from __future__ import annotations

import uuid

from app.models.tenant import Tenant


def _column():
    return Tenant.__table__.c.mssp_role


def test_the_model_agrees_with_the_schema_that_null_is_refused() -> None:
    assert _column().nullable is False, (
        "the migrations declare mssp_role NOT NULL; a nullable mapping makes SQLAlchemy send an explicit NULL and the insert fails"
    )


def test_a_default_exists_so_an_omitted_value_is_filled_in() -> None:
    col = _column()
    assert col.default is not None or col.server_default is not None, (
        "without a default the ORM still has nothing to put in a NOT NULL column"
    )


def test_constructing_a_tenant_without_the_field_yields_standalone() -> None:
    """What the demo seed does, and what used to raise."""
    tenant = Tenant(
        id=uuid.uuid4(),
        name="AiSOC Demo Tenant",
        slug="demo",
        plan="enterprise",
        is_active=True,
        settings={"demo": True},
        limits={"alerts_per_day": 1_000_000},
    )
    # The ORM default is applied at flush, so read it off the column rather
    # than the unflushed instance — asserting `tenant.mssp_role` here would
    # pass on a model with no default at all, which is the bug.
    default = _column().default
    assert default is not None
    assert default.arg == "standalone"
    assert tenant.slug == "demo"


def test_an_explicit_role_is_not_overwritten_by_the_default() -> None:
    """Positive control for the MSSP paths, which set this field themselves."""
    tenant = Tenant(id=uuid.uuid4(), name="Child", slug="child", mssp_role="child")
    assert tenant.mssp_role == "child"
