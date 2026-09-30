"""The API-token minter creates nothing and never mints for the demo tenant.

`make smoke` drives one real event through the pipeline and then asks the API
whether it became an alert. That read used to succeed with no credential,
because an uncredentialed request resolved to a demo administrator in a
development-class environment and every documented way to start the stack
produced one. So the golden pipeline was reading the API as an anonymous
administrator, without anybody having decided that.

This command is how the harness gets a real credential instead. Two properties
matter more than the happy path:

* it mints for an account that already exists and refuses otherwise, because a
  minting command that could create its own administrator would be a second
  bootstrap path with none of the checks the first one has;
* it never mints for the demo tenant, because that tenant is what the
  development auth shim hands an anonymous caller — a real token scoped to it
  would make the bypass reachable from outside the bypass.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from app.api.v1.dev_auth import DEMO_TENANT_ID
from app.core.security import decode_token
from app.scripts import mint_api_token
from app.scripts.bootstrap_admin import DEFAULT_TENANT_ID


class _User:
    """Enough of the ORM row for the resolver, which reads four fields."""

    def __init__(self, *, email: str, role: str, tenant_id: uuid.UUID, created_at: datetime | None = None):
        self.id = uuid.uuid4()
        self.email = email
        self.role = role
        self.tenant_id = tenant_id
        self.is_active = True
        self.created_at = created_at or datetime.now(UTC)


class _Result:
    def __init__(self, rows: list[_User]):
        self._rows = rows

    def scalar_one_or_none(self) -> _User | None:
        return self._rows[0] if self._rows else None

    def scalars(self) -> list[_User]:
        return self._rows


class _Session:
    """Returns a fixed row set, and records that nothing was written."""

    def __init__(self, rows: list[_User]):
        self._rows = rows
        self.added: list[object] = []
        self.commits = 0

    async def execute(self, _statement) -> _Result:  # noqa: ANN001
        return _Result(list(self._rows))

    def add(self, obj: object) -> None:
        self.added.append(obj)

    async def commit(self) -> None:
        self.commits += 1


@pytest.mark.asyncio
async def test_it_refuses_when_no_account_exists() -> None:
    session = _Session([])
    with pytest.raises(SystemExit) as exit_info:
        await mint_api_token._resolve_user(session, None, DEFAULT_TENANT_ID)
    message = str(exit_info.value)
    assert "no active account" in message
    assert "bootstrap_admin" in message, "the refusal has to say what to run"


@pytest.mark.asyncio
async def test_it_creates_nothing() -> None:
    """A minting command that could create an administrator would be a second
    bootstrap path with none of the checks the first one has."""
    session = _Session([_User(email="a@example.com", role="admin", tenant_id=DEFAULT_TENANT_ID)])
    await mint_api_token._resolve_user(session, None, DEFAULT_TENANT_ID)
    assert session.added == []
    assert session.commits == 0


@pytest.mark.asyncio
async def test_it_refuses_the_demo_tenant_outright() -> None:
    """Asking for it by UUID is refused before any account is looked up.

    That tenant is what the development auth shim hands an anonymous caller,
    so a real token scoped to it would make the bypass reachable from outside
    the bypass.
    """
    session = _Session([])
    with pytest.raises(SystemExit) as exit_info:
        await mint_api_token._resolve_tenant(session, str(DEMO_TENANT_ID))
    assert "demo tenant" in str(exit_info.value)


@pytest.mark.asyncio
async def test_it_defaults_to_the_tenant_bootstrap_admin_uses() -> None:
    """The path with no `--tenant`, which had no test at first.

    Every assertion here passed while `DEFAULT_TENANT_ID` was not even
    imported, because each one supplied a tenant explicitly and so never
    reached this branch. Ruff found the undefined name; the suite did not.
    """

    class _TenantRow:
        id = DEFAULT_TENANT_ID

    session = _Session([_TenantRow()])
    assert await mint_api_token._resolve_tenant(session, None) == DEFAULT_TENANT_ID


@pytest.mark.asyncio
async def test_it_refuses_when_there_is_no_tenant_at_all() -> None:
    session = _Session([])
    with pytest.raises(SystemExit) as exit_info:
        await mint_api_token._resolve_tenant(session, None)
    assert "no tenant to mint inside" in str(exit_info.value)


@pytest.mark.asyncio
async def test_a_non_uuid_tenant_is_rejected() -> None:
    session = _Session([])
    with pytest.raises(SystemExit) as exit_info:
        await mint_api_token._resolve_tenant(session, "default")
    assert "must be a UUID" in str(exit_info.value)


@pytest.mark.asyncio
async def test_it_refuses_an_address_that_does_not_exist() -> None:
    session = _Session([])
    with pytest.raises(SystemExit) as exit_info:
        await mint_api_token._resolve_user(session, "nobody@example.com", DEFAULT_TENANT_ID)
    assert "nobody@example.com" in str(exit_info.value)


@pytest.mark.asyncio
async def test_it_prefers_the_most_privileged_account() -> None:
    """Not merely the oldest. The read the harness performs needs
    `alerts:read`, and a viewer created first would not carry it."""
    viewer = _User(
        email="viewer@example.com",
        role="viewer",
        tenant_id=DEFAULT_TENANT_ID,
        created_at=datetime.now(UTC) - timedelta(days=30),
    )
    admin = _User(email="admin@example.com", role="admin", tenant_id=DEFAULT_TENANT_ID)
    session = _Session([viewer, admin])
    assert (await mint_api_token._resolve_user(session, None, DEFAULT_TENANT_ID)).email == "admin@example.com"


def test_the_token_carries_the_claims_the_api_verifies() -> None:
    """`get_current_user` reads `sub` and requires `type == "access"`.

    Asserted against the real `decode_token`, so a change to the signing
    algorithm or the secret resolution fails here rather than at the first
    401 in an end-to-end run.
    """
    user_id = uuid.uuid4()
    from app.core.security import create_access_token

    token = create_access_token({"sub": str(user_id), "type": "access"}, expires_delta=timedelta(minutes=30))
    payload = decode_token(token)
    assert payload["sub"] == str(user_id)
    assert payload["type"] == "access"
    assert payload["exp"] > datetime.now(UTC).timestamp()


def test_the_default_ttl_is_short() -> None:
    """This is pasted into an environment variable by a test harness, not a
    session somebody keeps."""
    assert mint_api_token.DEFAULT_TTL_MINUTES <= 60
