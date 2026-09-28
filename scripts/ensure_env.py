#!/usr/bin/env python3
"""Create `.env` and fill its generated secrets with real values.

The problem this solves
-----------------------
``README.md`` documents three commands: ``git clone``, ``cp .env.example .env``,
``make up``. The middle one used to break the deployment.

``.env.example`` shipped
``AISOC_CREDENTIAL_KEY=replace-me-with-a-freshly-generated-fernet-key``.
``docker-compose.yml`` interpolates that straight into the API container, and
``app.security.credential_vault`` takes its friendly ephemeral-development-key
path only when the key is **empty** — a non-empty invalid key reaches
``Fernet()`` and raises, which the connector endpoints turn into HTTP 500
``credential vault unavailable``. Nothing failed at boot, so the operator met
the failure minutes later at the connector wizard, with no line connecting it
back to the ``cp``. Skipping the documented ``cp`` produced a *working* vault
and following the README produced a broken one.

The fix chosen, and why
-----------------------
Generate real values at setup time rather than teaching the vault to tolerate a
placeholder. Tolerating it would mean a deployment whose connector credentials
silently do not survive a restart — a worse failure than the loud one, because
it is invisible until a customer's saved credential stops decrypting. The
placeholder is a *setup* defect and setup is where it is fixed.

Two layers, because either alone still leaves a hole:

1. This script, run by ``make up`` / ``make env`` / ``install.sh``, writes a
   freshly generated value for each secret below whenever the current one is
   empty or a placeholder. The documented quick start therefore ends with a
   vault that works *and* persists.
2. ``.env.example`` now ships these three **empty** rather than as prose. An
   operator who hand-copies the template and never runs the generator gets the
   documented development path (an ephemeral key, logged as a warning) instead
   of a hard 500. Empty is a value the vault already understands; the
   placeholder was not.

Secrets are written, never printed: the output says which names were filled.
"""

from __future__ import annotations

import argparse
import base64
import os
import re
import secrets
import sys
from collections.abc import Callable
from pathlib import Path

# `scripts/` is on sys.path when this file is run as a program, but not when a
# test loads it by path with importlib. gate_toolkit sits beside it either way.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from check_env_placeholders import is_placeholder, parse_env
from gate_toolkit import repo_root, self_test_if_requested

# `--check` is a verdict, so it answers `--self-test` like every other verdict
# in this tree: over a repository with no content there is neither a `.env` nor
# a template to copy one from, and the only honest answer is to refuse.
self_test_if_requested(__file__)


def _fernet_key() -> str:
    """A 32-byte urlsafe-base64 key, the format `cryptography.fernet` requires.

    Generated from the standard library rather than by importing
    ``cryptography``: this runs on the *host*, before any container is built,
    and requiring a pip install to create a config file would put a dependency
    in front of ``make up``. The format is fully specified — 32 random bytes,
    urlsafe base64 — so there is nothing for the library to add.
    """
    return base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")


#: ``name -> (generator, why it exists)``. The comment is written into `.env`
#: above a key that had to be appended, so an operator reading the file later
#: can tell a generated secret from one they set.
GENERATED: dict[str, tuple[Callable[[], str], str]] = {
    "AISOC_CREDENTIAL_KEY": (
        _fernet_key,
        "Fernet key for the connector credential vault. Rotate via AISOC_CREDENTIAL_KEY_ROTATION_FROM.",
    ),
    "SECRET_KEY": (
        lambda: secrets.token_hex(32),
        "HS256 signing key for console sessions. Shared by the API and the connectors service.",
    ),
    "AISOC_SERVICE_TOKEN": (
        lambda: secrets.token_urlsafe(32),
        "Shared bearer for service-to-service calls (API -> connectors, ueba, honeytokens, purple-team).",
    ),
    # Distinct from AISOC_SERVICE_TOKEN: the actions service reaches vendor
    # APIs and can isolate a host or disable an account, so it does not share
    # a credential with the read-mostly services above.
    #
    # It was absent here while docker-compose.yml said it "must match" on the
    # api and actions services, so no install had one, and the guard that
    # reads it exempted itself whenever it was empty and AISOC_DEV_MODE was
    # set — which it is by default. Generating it is what lets that guard
    # fail closed without breaking the documented path.
    "AISOC_ACTIONS_SERVICE_TOKEN": (
        lambda: secrets.token_urlsafe(32),
        "Shared bearer for the actions service (API -> actions). Gates every response action.",
    ),
    # The HS256 key the API signs realtime tickets with and the realtime edge
    # verifies them against. Both sides previously fell back to a constant
    # committed to this repository whenever this was unset — which no manifest
    # ever set — so anyone who could reach the edge could mint a ticket for any
    # tenant by signing with a published value.
    "AISOC_REALTIME_JWT_SECRET": (
        lambda: secrets.token_urlsafe(32),
        "HS256 key for realtime WebSocket/SSE tickets. Shared by the API (mints) and realtime (verifies).",
    ),
    # Service-to-service bearer for realtime's /internal/* fan-out routes.
    # Their guard treated an unset value as authorized, and nothing set it, so
    # the routes accepted an arbitrary tenant_id from any caller that could
    # reach the port.
    "REALTIME_INTERNAL_TOKEN": (
        lambda: secrets.token_urlsafe(32),
        "Bearer for realtime's /internal/* fan-out (API/agents -> realtime). Sent as x-internal-token.",
    ),
    # The datastore passwords. `.env.example` shipped these as
    # `aisoc_dev_secret` / `aisoc_app_dev_secret` / `redis_dev_secret` /
    # `clickhouse_dev_secret`, and `docker-compose.prod.yml` guarded each one
    # with `${VAR:?… the development default is a published literal}`.
    # Compose's `:?` rejects an unset or empty variable and cannot look at a
    # value, so every one of those guards accepted the exact literal its own
    # message named. `preflight-secrets` in that file refuses the value at
    # boot; generating them here means a fresh install never holds one.
    #
    # Hex rather than urlsafe base64: these travel inside DSNs
    # (`redis://:$REDIS_PASSWORD@…`) and a `/` or `+` in the userinfo would
    # have to be percent-encoded by every consumer that builds one.
    "POSTGRES_PASSWORD": (
        lambda: secrets.token_hex(24),
        "Postgres owner role. Owns every table and applies the migration chain; no service connects as it.",
    ),
    "AISOC_APP_DB_PASSWORD": (
        lambda: secrets.token_hex(24),
        "Postgres runtime role (aisoc_app). DML only, so the row-level-security policies apply to it.",
    ),
    "REDIS_PASSWORD": (
        lambda: secrets.token_hex(24),
        "Redis AUTH password. Referenced by REDIS_URL rather than repeated inside it.",
    ),
    "CLICKHOUSE_PASSWORD": (
        lambda: secrets.token_hex(24),
        "ClickHouse event-lake password. Referenced by CLICKHOUSE_URL rather than repeated inside it.",
    ),
}


def _assignment(key: str) -> re.Pattern[str]:
    return re.compile(rf"^(\s*(?:export\s+)?{re.escape(key)}\s*=)(.*)$", re.MULTILINE)


def needs_filling(text: str, key: str) -> bool:
    """True when ``key`` is absent, empty, or still a placeholder in ``text``."""
    for _lineno, name, value in parse_env(text):
        if name != key:
            continue
        stripped = value.strip()
        return not stripped or is_placeholder(stripped)
    return True


def fill(text: str, key: str, value: str, why: str) -> str:
    """Return ``text`` with ``key`` set to ``value``, appending it if absent."""
    pattern = _assignment(key)
    if pattern.search(text):
        return pattern.sub(lambda m: f"{m.group(1)}{value}", text, count=1)
    suffix = "" if text.endswith("\n") else "\n"
    return f"{text}{suffix}\n# {why}\n# Generated by scripts/ensure_env.py — keep it secret, keep it out of git.\n{key}={value}\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Create .env and generate its secrets.")
    parser.add_argument("--env", type=Path, default=None, help="path to .env (default: repository root)")
    parser.add_argument("--example", type=Path, default=None, help="path to .env.example")
    parser.add_argument(
        "--check",
        action="store_true",
        help="report what would change and exit non-zero if anything would; write nothing",
    )
    args = parser.parse_args(argv)

    root = repo_root()
    env_path = args.env or root / ".env"
    example_path = args.example or root / ".env.example"

    created = False
    if not env_path.exists():
        if not example_path.is_file():
            print(f"ensure_env: ERROR — neither {env_path} nor {example_path} exists", file=sys.stderr)
            return 1
        if args.check:
            print(f"ensure_env: {env_path} does not exist (would be created from {example_path.name})")
            return 1
        env_path.write_text(example_path.read_text(encoding="utf-8"), encoding="utf-8")
        created = True

    text = env_path.read_text(encoding="utf-8")
    pending = [key for key in GENERATED if needs_filling(text, key)]

    if args.check:
        if pending:
            print("ensure_env: these are unset or still placeholders: " + ", ".join(pending))
            return 1
        print("ensure_env: OK — every generated secret has a real value")
        return 0

    for key in pending:
        generator, why = GENERATED[key]
        text = fill(text, key, generator(), why)

    if pending or created:
        env_path.write_text(text, encoding="utf-8")
        # 0600: this file now holds real secrets. The template it came from is
        # world-readable and nothing narrowed the mode after the copy.
        env_path.chmod(0o600)

    if created:
        print(f"ensure_env: created {env_path.name} from {example_path.name}")
    if pending:
        print("ensure_env: generated " + ", ".join(pending))
    elif not created:
        print("ensure_env: .env already has a real value for every generated secret — unchanged")
    return 0


if __name__ == "__main__":
    sys.exit(main())
