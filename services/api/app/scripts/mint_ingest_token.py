"""Mint the credential that ``POST /v1/ingest/batch`` requires.

    docker compose run --rm api python -m app.scripts.mint_ingest_token
    # or, from the repo root:
    make ingest-token

Run it once after ``make up`` if you want to push telemetry with curl, a
script, or anything else that is not a configured connector. It prints a
token and the URL to send to. Re-running returns the *same* token rather
than minting a second one, so it is safe to call from a script; pass
``--rotate`` to replace it.

Why this exists
---------------
``/v1/ingest/batch`` used to accept anything. It read an ``X-Tenant-ID``
header, trusted it, and wrote events for whatever tenant the caller named,
so anyone who could reach the port could write alerts into any tenant. It
now requires a credential that carries its own tenant, and this command is
how a fresh deployment gets one — the same role ``bootstrap_admin`` plays
for the console login.

It writes the same ``tenant_inbox_tokens`` row that
``POST /api/v1/inbox/tokens`` writes, using the ``connector-push`` template.
The API route is the path the console uses and is preferred when you have a
session; this command exists for the case the route cannot serve, which is
a fresh stack where nobody has logged in yet.

This is not a dev-mode shortcut and does not consult ``AISOC_DEV_MODE``. It
mints a real credential and is the supported path in every environment.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import secrets
import sys
import uuid
from datetime import UTC, datetime

from sqlalchemy import select, update

from app.core.config import settings
from app.db.database import AsyncSessionLocal
from app.models.inbox import TenantInboxToken
from app.models.tenant import Tenant

# Matches the tenant seeded by migration 001, the same constant
# ``bootstrap_admin`` adopts, so a token minted here belongs to the tenant
# the rest of a fresh install's rows belong to.
DEFAULT_TENANT_ID = uuid.UUID("00000000-0000-0000-0000-000000000001")

# Must equal ingestauth.PushTemplateID in services/ingest. A token minted
# with any other template is refused by /v1/ingest, deliberately:
# see the note in services/api/app/api/v1/endpoints/inbox.py.
PUSH_TEMPLATE_ID = "connector-push"

DEFAULT_LABEL = "Direct ingest API"


class MintError(RuntimeError):
    """A condition the operator has to resolve, reported without a traceback."""


def _generate_token() -> str:
    """Same shape as ``_generate_inbox_token`` in the mint endpoint."""
    return f"aitnb_{secrets.token_urlsafe(32)}"


def _ingest_url() -> str:
    base = (getattr(settings, "INGEST_PUBLIC_URL", "") or "").rstrip("/")
    return f"{base}/v1/ingest/batch" if base else "http://localhost:8081/v1/ingest/batch"


async def _resolve_tenant(session, tenant_ref: str | None) -> Tenant:
    """Find the tenant to mint for.

    With no ``--tenant`` the canonical seeded tenant wins, then the only
    tenant if there is exactly one. We refuse to guess when several exist:
    a token silently minted for the wrong tenant would send telemetry
    somewhere the operator is not looking, which is worse than an error.
    """
    if tenant_ref:
        try:
            wanted = uuid.UUID(tenant_ref)
        except ValueError:
            result = await session.execute(select(Tenant).where(Tenant.slug == tenant_ref))
            tenant = result.scalar_one_or_none()
            if tenant is None:
                raise MintError(f"no tenant with id or slug {tenant_ref!r}") from None
            return tenant
        result = await session.execute(select(Tenant).where(Tenant.id == wanted))
        tenant = result.scalar_one_or_none()
        if tenant is None:
            raise MintError(f"no tenant with id {tenant_ref!r}")
        return tenant

    result = await session.execute(select(Tenant).where(Tenant.id == DEFAULT_TENANT_ID))
    tenant = result.scalar_one_or_none()
    if tenant is not None:
        return tenant

    result = await session.execute(select(Tenant).order_by(Tenant.created_at))
    tenants = list(result.scalars().all())
    if not tenants:
        raise MintError("no tenants exist yet — run 'make bootstrap' first")
    if len(tenants) > 1:
        names = ", ".join(f"{t.slug} ({t.id})" for t in tenants)
        raise MintError(f"several tenants exist; name one with --tenant: {names}")
    return tenants[0]


async def mint(*, tenant_ref: str | None, rotate: bool, label: str) -> tuple[str, Tenant, bool]:
    """Return ``(token, tenant, is_new)``.

    Reusing an existing active token is what makes this safe to call from
    ``make smoke`` on every run: a command that minted a fresh credential
    each time would leave a trail of live tokens nobody revokes.
    """
    async with AsyncSessionLocal() as session:
        tenant = await _resolve_tenant(session, tenant_ref)

        result = await session.execute(
            select(TenantInboxToken)
            .where(
                TenantInboxToken.tenant_id == tenant.id,
                TenantInboxToken.template_id == PUSH_TEMPLATE_ID,
                TenantInboxToken.revoked_at.is_(None),
            )
            .order_by(TenantInboxToken.created_at.desc())
        )
        existing = result.scalars().first()

        if existing is not None and not rotate:
            return existing.token, tenant, False

        if existing is not None:
            await session.execute(
                update(TenantInboxToken).where(TenantInboxToken.token == existing.token).values(revoked_at=datetime.now(UTC))
            )

        token = _generate_token()
        session.add(
            TenantInboxToken(
                token=token,
                tenant_id=tenant.id,
                template_id=PUSH_TEMPLATE_ID,
                label=label,
                hmac_secret=None,
                created_at=datetime.now(UTC),
            )
        )
        await session.commit()
        return token, tenant, True


def _print_human(token: str, tenant: Tenant, *, is_new: bool) -> None:
    bar = "─" * 72
    print(f"\n{bar}")
    print("  Ingest credential for tenant " + f"{tenant.slug} ({tenant.id})")
    print(bar)
    print(f"  Token   {token}")
    print(bar)
    if is_new:
        print("  Minted now. It is stored in tenant_inbox_tokens and can be")
        print("  rotated with --rotate or revoked from Settings -> Connectors.")
    else:
        print("  This tenant already had a push token; reusing it.")
        print("  Replace it with --rotate.")
    print()
    print("  Push an event:")
    print(f"    curl -X POST {_ingest_url()} \\")
    print("      -H 'Content-Type: application/json' \\")
    print('      -H "Authorization: Bearer $AISOC_INGEST_TOKEN" \\')
    print('      -d \'{"connector_id":"edr-1","connector_type":"crowdstrike",')
    print('           "source_format":"json","events":[{"severity":"high",')
    print('           "title":"Encoded PowerShell from Office"}]}\'')
    print()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m app.scripts.mint_ingest_token",
        description="Mint the credential POST /v1/ingest/batch requires.",
    )
    parser.add_argument(
        "--tenant",
        default=os.environ.get("AISOC_TENANT_ID") or None,
        help="tenant id or slug (default: the canonical seeded tenant, or the only one)",
    )
    parser.add_argument(
        "--rotate",
        action="store_true",
        help="revoke the existing push token and mint a replacement",
    )
    parser.add_argument(
        "--label",
        default=DEFAULT_LABEL,
        help=f"operator-facing label (default: {DEFAULT_LABEL!r})",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="print only the token, for use in scripts",
    )
    return parser


async def _run(args: argparse.Namespace) -> int:
    token, tenant, is_new = await mint(tenant_ref=args.tenant, rotate=args.rotate, label=args.label)
    if args.quiet:
        # Only the token, and nothing else on stdout, so a caller can do
        # AISOC_INGEST_TOKEN="$(... --quiet)" without parsing.
        print(token)
    else:
        _print_human(token, tenant, is_new=is_new)
    return 0


def main() -> int:
    args = build_parser().parse_args()
    try:
        return asyncio.run(_run(args))
    except MintError as exc:
        print(f"\nmint_ingest_token failed: {exc}\n", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover - module entrypoint
    raise SystemExit(main())
