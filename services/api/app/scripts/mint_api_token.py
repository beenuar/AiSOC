"""Mint a short-lived bearer token for an existing administrator.

    docker compose run --rm api python -m app.scripts.mint_api_token
    # or, from the repo root:
    make api-token

Prints an access token for the account ``bootstrap_admin`` created, so a
script can read ``/api/v1/alerts`` the way the console does.

Why this exists
---------------
``make smoke`` drives one real event through the pipeline and then asks the
API whether it became an alert. That read used to succeed with no credential
at all, because the API resolved an uncredentialed request to a demo
administrator in a development-class environment, and every documented way to
start the stack produced one. Closing that turned the last stage of the golden
pipeline into a 401.

The harness therefore needs a credential, and it should obtain one the way a
person would rather than being handed a bypass. This is the sibling of
``mint_ingest_token``: a shipped command, so the step that calls it also
covers a path an operator can follow.

What it will not do
-------------------
Create an account, change a password, or grant a role. It mints a token for a
principal that already exists, and fails with an actionable message when none
does. A minting command that could create its own administrator would be a
second bootstrap path with none of the checks the first one has.

It never mints for the demo tenant. That tenant is what the development auth
shim hands an anonymous caller, so a *real* token scoped to it would make the
bypass reachable from outside the bypass.

This is not a dev-mode shortcut and does not consult ``AISOC_DEV_MODE``.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import uuid
from datetime import timedelta

from sqlalchemy import select

from app.api.v1.dev_auth import DEMO_TENANT_ID
from app.core.security import create_access_token
from app.db.database import AsyncSessionLocal
from app.models.tenant import Tenant, User
from app.scripts.bootstrap_admin import DEFAULT_TENANT_ID

#: Short by design. This is a credential printed to a terminal and pasted into
#: an environment variable by a test harness, not a session someone keeps.
DEFAULT_TTL_MINUTES = 30

#: Roles a token may be minted for, most privileged first. The read the golden
#: pipeline performs needs `alerts:read`, which every one of these carries.
_PREFERRED_ROLES = ("admin", "platform_admin", "tenant_admin", "soc_lead")


async def _resolve_tenant(session, tenant_ref: str | None) -> uuid.UUID:
    """Which tenant to mint inside. Never the demo one.

    Every user query below carries this as a predicate. `users` has no
    row-level security — excluded by design, because the login lookup has to
    find an account before a tenant is known — so a predicate is the only
    control there is, and `scripts/check_tenant_query_predicates.py` enforces
    it. The first draft of this command selected "the most privileged active
    account anywhere", which is both unscoped and a vague target on a
    multi-tenant deployment; the gate caught it.
    """
    if tenant_ref:
        try:
            wanted = uuid.UUID(tenant_ref)
        except ValueError:
            raise SystemExit(f"--tenant must be a UUID, got {tenant_ref!r}") from None
        if wanted == DEMO_TENANT_ID:
            raise SystemExit(
                "that is the demo tenant, which the development auth shim already hands to "
                "anonymous callers. Refusing to mint a real token for it."
            )
        return wanted

    # The tenant `bootstrap_admin` uses, and the one it falls back to when
    # that row is absent: the oldest that is not the demo tenant.
    result = await session.execute(select(Tenant).where(Tenant.id == DEFAULT_TENANT_ID))
    if result.scalar_one_or_none() is not None:
        return DEFAULT_TENANT_ID

    result = await session.execute(select(Tenant).where(Tenant.id != DEMO_TENANT_ID).order_by(Tenant.created_at).limit(1))
    tenant = result.scalar_one_or_none()
    if tenant is None:
        raise SystemExit("no tenant to mint inside.\nCreate one with: docker compose run --rm api python -m app.scripts.bootstrap_admin")
    return tenant.id


async def _resolve_user(session, email: str | None, tenant_id: uuid.UUID) -> User:
    """The account to mint for inside `tenant_id`: the one named, else the
    best-privileged one."""
    if email:
        result = await session.execute(
            select(User).where(
                User.email == email,
                User.tenant_id == tenant_id,
                User.is_active == True,  # noqa: E712
            )
        )
        user = result.scalar_one_or_none()
        if user is None:
            raise SystemExit(
                f"no active account with the address {email!r} in tenant {tenant_id}.\n"
                "Create one with: docker compose run --rm api python -m app.scripts.bootstrap_admin"
            )
        return user

    result = await session.execute(
        select(User).where(
            User.tenant_id == tenant_id,
            User.is_active == True,  # noqa: E712
        )
    )
    users = list(result.scalars())
    if not users:
        raise SystemExit(
            f"no active account in tenant {tenant_id} to mint for.\n"
            "Create one with: docker compose run --rm api python -m app.scripts.bootstrap_admin"
        )

    def rank(candidate: User) -> tuple[int, str]:
        role = (candidate.role or "").strip()
        position = _PREFERRED_ROLES.index(role) if role in _PREFERRED_ROLES else len(_PREFERRED_ROLES)
        return (position, str(candidate.created_at))

    return sorted(users, key=rank)[0]


async def mint(*, email: str | None, tenant_ref: str | None, ttl_minutes: int) -> tuple[str, User]:
    async with AsyncSessionLocal() as session:
        tenant_id = await _resolve_tenant(session, tenant_ref)
        user = await _resolve_user(session, email, tenant_id)
        token = create_access_token(
            {"sub": str(user.id), "type": "access"},
            expires_delta=timedelta(minutes=ttl_minutes),
        )
        return token, user


def _print_human(token: str, user: User, *, ttl_minutes: int) -> None:
    print()
    print("  Access token minted.")
    print()
    print(f"    account   {user.email}  ({user.role})")
    print(f"    tenant    {user.tenant_id}")
    print(f"    expires   in {ttl_minutes} minutes")
    print()
    print(f"    {token}")
    print()
    print("  Use it as a bearer token:")
    print()
    print(f'    curl -H "Authorization: Bearer $TOKEN" {"http://localhost:8000"}/api/v1/alerts')
    print()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mint_api_token",
        description="Mint a short-lived bearer token for an existing administrator.",
    )
    parser.add_argument(
        "--email",
        default=None,
        help="the account to mint for; defaults to the most privileged active one",
    )
    parser.add_argument(
        "--tenant",
        default=None,
        help="tenant UUID to mint inside; defaults to the tenant bootstrap_admin uses",
    )
    parser.add_argument(
        "--ttl-minutes",
        type=int,
        default=DEFAULT_TTL_MINUTES,
        help=f"how long the token is valid (default {DEFAULT_TTL_MINUTES})",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help='print only the token, for AISOC_API_TOKEN="$(... --quiet)"',
    )
    return parser


async def _run(args: argparse.Namespace) -> int:
    if args.ttl_minutes < 1:
        print("--ttl-minutes must be at least 1", file=sys.stderr)
        return 2
    token, user = await mint(email=args.email, tenant_ref=args.tenant, ttl_minutes=args.ttl_minutes)
    if args.quiet:
        # Nothing but the token on stdout, so a shell can capture it with
        # AISOC_API_TOKEN="$(... --quiet)" without parsing.
        print(token)
    else:
        _print_human(token, user, ttl_minutes=args.ttl_minutes)
    return 0


def main() -> int:
    return asyncio.run(_run(build_parser().parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
