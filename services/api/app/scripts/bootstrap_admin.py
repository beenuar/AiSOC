"""Create the first administrator for a fresh deployment.

    docker compose run --rm api python -m app.scripts.bootstrap_admin
    # or, from the repo root:
    make bootstrap

Run it once after ``make up``. It creates the default tenant if it is missing,
creates an administrator, and prints the password exactly once. Nothing writes
the password to disk — if it scrolls away, re-run with ``--reset-password``.

Why this exists rather than a seeded row in ``001_init.sql``: a password hash
committed to a public repository is a default credential on every deployment
that ever clones it. The migration used to carry one, and because nobody could
say what plaintext it came from, the only account a new install had was an
account nobody could log into. The fix is not a better-known default — it is
that the deployment mints its own secret at first run and tells the operator
what it is.

Three properties the acceptance test depends on:

* **The address passes the API's own validator.** ``LoginRequest.email`` is a
  pydantic ``EmailStr``, which rejects the RFC 6761 special-use domains
  (``.local``, ``.test``, ``.invalid``, ``.localhost``) *before* the password is
  ever compared — a 422, not a 401. The seeded ``admin@aisoc.local`` could
  therefore never authenticate whatever its password was. This script validates
  with the same library the route does and refuses to create an account that
  cannot sign in, so the failure surfaces here with an explanation instead of at
  a login form with a schema error.
* **The operator knows the password**, because it was generated here and
  printed, or supplied by them.
* **Re-running is safe.** An existing administrator is reported and left alone;
  the password is only touched under an explicit ``--reset-password``.

This is not a dev-mode shortcut and does not consult ``AISOC_DEV_MODE``. It
creates a real account with a real secret and is the supported path in every
environment.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import secrets
import string
import sys
import uuid

from email_validator import EmailNotValidError, validate_email
from sqlalchemy import func, select

from app.core.security import get_password_hash
from app.db.database import AsyncSessionLocal
from app.models.tenant import Tenant, User

# Matches the tenant seeded by migration 001. Reused so a bootstrap on an
# already-migrated database adopts that tenant rather than creating a second
# one that none of the seeded rows belong to.
DEFAULT_TENANT_ID = uuid.UUID("00000000-0000-0000-0000-000000000001")

# `.internal` is reserved by ICANN for private use and — unlike `.local`,
# `.test` and `.invalid` — is not on the email validator's special-use list, so
# it both reads as "this address is internal to your deployment" and passes
# validation. `test_bootstrap_admin.py` asserts that against the real validator,
# so if a future release adds `.internal` to that list CI goes red here rather
# than the next self-hoster discovering it at a login form.
DEFAULT_ADMIN_EMAIL = "admin@aisoc.internal"
DEFAULT_ADMIN_USERNAME = "admin"

# Unambiguous alphabet: no O/0, l/1/I. The password is read off a terminal and
# typed into a browser, and a character the operator cannot transcribe is the
# same defect as a password nobody knows.
_ALPHABET = (
    "".join(c for c in string.ascii_uppercase if c not in "OI")
    + "".join(c for c in string.ascii_lowercase if c not in "l")
    + "".join(c for c in string.digits if c not in "01")
)
_GENERATED_PASSWORD_LENGTH = 24

# Long enough that a generated one cannot be mistaken for a placeholder and
# short enough to type. bcrypt caps input at 72 bytes; `get_password_hash`
# truncates, so anything beyond that is silently not part of the secret.
MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 72


class BootstrapError(RuntimeError):
    """A condition the operator has to resolve, reported without a traceback."""


def generate_password() -> str:
    return "".join(secrets.choice(_ALPHABET) for _ in range(_GENERATED_PASSWORD_LENGTH))


def validate_admin_email(email: str) -> str:
    """Return the normalised address, or raise if the API could not accept it.

    ``check_deliverability=False`` keeps this offline: an air-gapped install
    must be able to bootstrap, and a DNS lookup here would make the first-run
    path depend on egress. Syntax and the special-use domain list are what
    ``EmailStr`` enforces on the login route, and both are checked locally.
    """
    try:
        return validate_email(email, check_deliverability=False).normalized
    except EmailNotValidError as exc:
        raise BootstrapError(
            f"{email!r} cannot be used to sign in: {exc}\n"
            "  The login route validates with the same library, so an account created with this\n"
            "  address would be rejected before its password was checked. Reserved domains\n"
            "  (.local, .test, .invalid, .localhost) are the usual cause; try a routable domain\n"
            f"  or the default {DEFAULT_ADMIN_EMAIL}."
        ) from exc


def validate_password(password: str) -> str:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise BootstrapError(f"password is {len(password)} characters; the minimum is {MIN_PASSWORD_LENGTH}.")
    if len(password.encode("utf-8")) > MAX_PASSWORD_LENGTH:
        raise BootstrapError(
            f"password is longer than {MAX_PASSWORD_LENGTH} bytes, which bcrypt truncates — "
            "the part past the limit would not be part of the secret."
        )
    return password


def resolve_password(args: argparse.Namespace) -> tuple[str, bool]:
    """Return ``(password, was_generated)``.

    Precedence is explicit-over-implicit: ``--password-stdin`` (so a secret
    never lands in shell history or `ps` output), then ``AISOC_ADMIN_PASSWORD``,
    then a fresh random one.
    """
    if args.password_stdin:
        password = sys.stdin.readline().rstrip("\n")
        if not password:
            raise BootstrapError("--password-stdin was given but stdin was empty.")
        return validate_password(password), False

    from_env = os.environ.get("AISOC_ADMIN_PASSWORD", "")
    if from_env:
        return validate_password(from_env), False

    return generate_password(), True


async def _ensure_tenant(session) -> Tenant:
    """Adopt the migration-seeded tenant, else any existing one, else create it."""
    result = await session.execute(select(Tenant).where(Tenant.id == DEFAULT_TENANT_ID))
    tenant = result.scalar_one_or_none()
    if tenant is not None:
        return tenant

    # A deployment that was provisioned some other way already has a tenant;
    # attaching the administrator to a brand-new one would make them an admin
    # of nothing, with every existing alert invisible.
    result = await session.execute(select(Tenant).order_by(Tenant.created_at).limit(1))
    tenant = result.scalar_one_or_none()
    if tenant is not None:
        return tenant

    tenant = Tenant(
        id=DEFAULT_TENANT_ID,
        name="Default",
        slug="default",
        plan="enterprise",
        is_active=True,
    )
    session.add(tenant)
    await session.flush()
    return tenant


async def bootstrap(
    *,
    email: str,
    password: str,
    username: str,
    reset_password: bool,
) -> tuple[str, bool]:
    """Create or adopt the administrator.

    Returns ``(email, credential_is_new)``. ``credential_is_new`` is False when
    an account already existed and was left untouched, which is what tells the
    caller not to print a password the operator cannot use.
    """
    email = validate_admin_email(email)
    validate_password(password)

    async with AsyncSessionLocal() as session:
        tenant = await _ensure_tenant(session)

        # Case-insensitive: Postgres `UNIQUE` on `email` is case-sensitive, so
        # `Admin@…` and `admin@…` are two rows, and a second bootstrap would
        # hand out a password for an account the operator does not realise is a
        # duplicate.
        result = await session.execute(select(User).where(func.lower(User.email) == email.lower()))
        user = result.scalar_one_or_none()

        if user is not None:
            if not reset_password:
                return email, False
            user.hashed_password = get_password_hash(password)
            user.is_active = True
            user.is_verified = True
            user.role = "admin"
            await session.commit()
            return email, True

        # An administrator under a different address still counts — re-running
        # after a rename should not quietly mint a second one.
        result = await session.execute(select(User).where(User.role == "admin", User.is_active.is_(True)).limit(1))
        existing_admin = result.scalar_one_or_none()
        if existing_admin is not None and not reset_password:
            return existing_admin.email, False

        session.add(
            User(
                tenant_id=tenant.id,
                email=email,
                username=username,
                hashed_password=get_password_hash(password),
                role="admin",
                is_active=True,
                is_verified=True,
                preferences={},
            )
        )
        await session.commit()
        return email, True


def _print_credentials(email: str, password: str, *, generated: bool) -> None:
    """Report the new account, disclosing the password only if we invented it.

    A password the operator supplied through ``AISOC_ADMIN_PASSWORD`` or
    ``--password-stdin`` is never echoed: they already have it, and printing it
    back would put a secret on a terminal and into any scrollback or CI log for
    no gain. A generated one is printed because it exists nowhere else — that
    single line is the whole point of this command, and it is why the password
    is never written to disk.

    CodeQL flags the generated branch as ``py/clear-text-logging-sensitive-data``
    and is correct that it discloses a secret. It is dismissed as accepted risk
    rather than suppressed: without it nobody can sign in, which is the defect
    this script exists to fix. The exposure is as narrow as the design allows —
    stdout rather than a logger, only the generated password, and
    ``golden-pipeline.yml`` redacts the line before it reaches a CI log. The
    alternative worth building later is an out-of-band channel (a one-shot
    token redeemed in the console); until that exists, a terminal the operator
    is already looking at is the smallest surface available.
    """
    console = os.environ.get("AISOC_CONSOLE_URL", "http://localhost:3000")
    bar = "─" * 64
    print(f"\n{bar}")
    print("  Administrator created. Sign in at " + console)
    print(bar)
    print(f"  Email     {email}")
    if generated:
        print(f"  Password  {password}")
        print(bar)
        print("  This password was generated now and is not stored anywhere.")
        print("  Copy it before closing this terminal. Lost it? Re-run with")
        print("  --reset-password to mint a new one.")
    else:
        print("  Password  (the one you supplied — not echoed)")
        print(bar)
    print()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m app.scripts.bootstrap_admin",
        description="Create the first administrator for this deployment.",
    )
    parser.add_argument(
        "--email",
        default=os.environ.get("AISOC_ADMIN_EMAIL", DEFAULT_ADMIN_EMAIL),
        help=f"administrator address (default: {DEFAULT_ADMIN_EMAIL}, or AISOC_ADMIN_EMAIL)",
    )
    parser.add_argument(
        "--username",
        default=os.environ.get("AISOC_ADMIN_USERNAME", DEFAULT_ADMIN_USERNAME),
        help=f"display name (default: {DEFAULT_ADMIN_USERNAME})",
    )
    parser.add_argument(
        "--password-stdin",
        action="store_true",
        help="read the password from stdin instead of generating one",
    )
    parser.add_argument(
        "--reset-password",
        action="store_true",
        help="replace the password of an existing administrator",
    )
    return parser


async def _run(args: argparse.Namespace) -> int:
    password, generated = resolve_password(args)
    email, credential_is_new = await bootstrap(
        email=args.email,
        password=password,
        username=args.username,
        reset_password=args.reset_password,
    )

    if not credential_is_new:
        console = os.environ.get("AISOC_CONSOLE_URL", "http://localhost:3000")
        print(f"\nAn administrator already exists: {email}")
        print(f"Sign in at {console}.")
        print("Forgotten the password? Re-run this command with --reset-password.\n")
        return 0

    _print_credentials(email, password, generated=generated)
    return 0


def main() -> int:
    args = build_parser().parse_args()
    try:
        return asyncio.run(_run(args))
    except BootstrapError as exc:
        print(f"\nbootstrap failed: {exc}\n", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover - module entrypoint
    raise SystemExit(main())
