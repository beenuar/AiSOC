#!/usr/bin/env python3
"""Refuse a secret whose value is published in this repository.

The hole this closes
--------------------
``docker-compose.prod.yml`` states, in its own header, that "nothing starts on
a default credential", and implements that with::

    POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?set POSTGRES_PASSWORD — the development default is a published literal}

Compose's ``:?`` operator rejects an **unset or empty** variable. It cannot
look at a value. ``.env.example`` ships ``POSTGRES_PASSWORD=aisoc_dev_secret``
and ``docker-compose.yml`` defaults the same variable to the same literal, so
the one input the message names is the one input the guard accepts. Measured
before the fix::

    $ printf 'POSTGRES_PASSWORD=aisoc_dev_secret\\n' > .env
    $ docker compose config
    POSTGRES_PASSWORD: aisoc_dev_secret        # no error

Every ``${VAR:?}`` in that file has the same shape, so the property the file
claims held for none of them.

Why a value check has to run
----------------------------
There is no Compose expression that compares a value, so the check cannot live
in the interpolation. It runs as the ``preflight-secrets`` service, which every
other service depends on with ``condition: service_completed_successfully`` —
a non-zero exit there stops the stack before the first datastore starts, which
is the same moment and the same shape of failure as the ``:?`` guard the file
already documents.

Where the list of published values comes from
---------------------------------------------
Derived from the tree, never hand-written. A hand-maintained list of "secrets
we published" is a list that stops matching the day someone adds a new default,
and the gate that reads it keeps printing OK. So this reads:

* every ``${VAR:-literal}`` fallback in the compose files, for secret-shaped
  variable names — that is where a published default actually lives;
* every non-empty value in ``.env.example`` for a secret-shaped name, plus any
  password embedded in a URL there (``redis://:redis_dev_secret@…``);
* ``INSECURE_SECRET_KEY_DEFAULTS`` from the API settings module, read by AST
  rather than imported so this file keeps running on a bare interpreter.

The comparison is on **values**, not on variable names. Setting
``NEO4J_PASSWORD`` to the literal published for ``POSTGRES_PASSWORD`` is the
same disclosure, and naming the variable it was published for is the useful
half of the error message.

Modes
-----
``--check-env``   inspect this process's environment. What the preflight
                  container runs; the production stack's guarded variables are
                  interpolated into it by Compose.
``--check``       verdict over the repository: every ``${VAR:?}`` guard in the
                  production compose file must be a variable the preflight
                  service actually receives, and the preflight must be wired
                  ahead of every service. A guard added without extending the
                  preflight is the way this would rot, so it is the thing
                  asserted.
"""

from __future__ import annotations

import argparse
import ast
import os
import re
import sys
from collections.abc import Iterable, Mapping
from pathlib import Path
from urllib.parse import urlsplit

# `scripts/` is on sys.path when this file is run as a program, but not when a
# test loads it by path with importlib. gate_toolkit sits beside it either way.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_if_requested

self_test_if_requested(__file__)

#: The Compose service that runs ``--check-env`` ahead of everything else.
PREFLIGHT_SERVICE = "preflight-secrets"

#: Variable names whose value is a credential. Matched on the name, and used
#: only to decide *what to harvest as published* and *what to inspect in an
#: environment* — never to decide whether a value is safe.
SECRET_NAME_RE = re.compile(
    r"(PASSWORD|PASSWD|SECRET|TOKEN|_KEY$|_KEY_|APIKEY|API_KEY|CREDENTIAL|PRIVATE)",
    re.IGNORECASE,
)

#: Variables that carry a credential inside a URL rather than on their own.
URL_NAME_RE = re.compile(r"(_URL$|_DSN$|_URI$)", re.IGNORECASE)

#: ``${NAME:-default}`` with a non-empty default.
COMPOSE_DEFAULT_RE = re.compile(r"\$\{([A-Z0-9_]+):-([^}]+)\}")

#: ``${NAME:?message}`` — the guard this module exists because of.
COMPOSE_REQUIRED_RE = re.compile(r"\$\{([A-Z0-9_]+):\?")

#: Values that are not credentials even though they sit on a secret-shaped
#: name, so harvesting them would make the checker refuse a correct
#: deployment. Each is a mode switch or a file path, not a shared secret.
NOT_A_CREDENTIAL = frozenset(
    {
        "true",
        "false",
        "0",
        "1",
        "none",
        "disabled",
        "enabled",
        "auto",
        "latest",
    }
)

#: A published value shorter than this is a word, not a key, and matching on it
#: would refuse real passwords that happen to contain it. ``admin`` is below the
#: bar and is listed explicitly because Grafana really does ship it.
MIN_HARVEST_LEN = 6
ALWAYS_HARVEST = frozenset({"admin", "aisoc", "changeme", "password", "secret"})


def _dotenv_pairs(text: str) -> Iterable[tuple[str, str]]:
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        name, sep, value = line.partition("=")
        if not sep:
            continue
        name = name.removeprefix("export ").strip()
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            continue
        yield name, value.strip().strip('"').strip("'")


def _url_password(value: str) -> str | None:
    """The password embedded in ``scheme://user:password@host``, if any."""
    if "://" not in value:
        return None
    try:
        parsed = urlsplit(value)
    except ValueError:
        return None
    password = parsed.password
    if not password or "${" in password:
        return None
    return password


def _harvestable(value: str) -> bool:
    candidate = value.strip()
    if not candidate or "${" in candidate:
        return False
    if candidate.lower() in NOT_A_CREDENTIAL:
        return False
    if candidate.lower() in ALWAYS_HARVEST:
        return True
    return len(candidate) >= MIN_HARVEST_LEN


def _insecure_secret_key_defaults(root: Path) -> set[str]:
    """``INSECURE_SECRET_KEY_DEFAULTS`` from the API settings, read by AST.

    Imported would mean pydantic on the path. This runs in a preflight
    container built for something else, and on a host before any install.
    """
    config = root / "services" / "api" / "app" / "core" / "config.py"
    if not config.exists():
        return set()
    try:
        tree = ast.parse(config.read_text(encoding="utf-8"))
    except SyntaxError:
        return set()
    for node in ast.walk(tree):
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            target = node.target.id
        elif isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            target = node.targets[0].id
        else:
            continue
        if target != "INSECURE_SECRET_KEY_DEFAULTS" or node.value is None:
            continue
        return {
            literal.value.strip()
            for literal in ast.walk(node.value)
            if isinstance(literal, ast.Constant) and isinstance(literal.value, str) and literal.value.strip()
        }
    return set()


def compose_files(root: Path) -> list[Path]:
    paths = [root / "docker-compose.yml", root / "docker-compose.prod.yml"]
    paths += sorted((root / "infra" / "compose").glob("docker-compose*.yml"))
    return [p for p in paths if p.exists()]


def published_literals(root: Path | None = None) -> dict[str, str]:
    """``value -> where it is published``, derived from the tree.

    Raises when it harvests nothing: an empty set of published values makes
    every check below pass, and "scanned nothing" must not print the same word
    as "found nothing".
    """
    root = root or repo_root()
    found: dict[str, str] = {}

    for path in compose_files(root):
        rel = path.relative_to(root)
        for name, default in COMPOSE_DEFAULT_RE.findall(path.read_text(encoding="utf-8")):
            # A URL-shaped variable publishes only the credential inside it.
            # Harvesting the whole value would put `http://api:8000` on the
            # refused list and make the preflight reject a correct stack.
            value = _url_password(default) if URL_NAME_RE.search(name) else (default if SECRET_NAME_RE.search(name) else None)
            if value and _harvestable(value):
                found.setdefault(value, f"{rel} default for {name}")

    example = root / ".env.example"
    if example.exists():
        for name, value in _dotenv_pairs(example.read_text(encoding="utf-8")):
            harvested = _url_password(value) if URL_NAME_RE.search(name) else (value if SECRET_NAME_RE.search(name) else None)
            if harvested and _harvestable(harvested):
                found.setdefault(harvested, f".env.example {name}")

    for value in _insecure_secret_key_defaults(root):
        if _harvestable(value):
            found.setdefault(value, "INSECURE_SECRET_KEY_DEFAULTS in services/api/app/core/config.py")

    if not found:
        raise SystemExit(
            "check_published_secrets: harvested no published values from "
            f"{root}. Refusing to report a clean environment against an empty list."
        )
    return found


def offending(env: Mapping[str, str], published: Mapping[str, str]) -> list[tuple[str, str]]:
    """``(variable, where the value is published)`` for each hit in ``env``."""
    hits: list[tuple[str, str]] = []
    for name, value in sorted(env.items()):
        if not value:
            continue
        candidates = [value.strip()]
        embedded = _url_password(value)
        if embedded:
            candidates.append(embedded)
        if not (SECRET_NAME_RE.search(name) or URL_NAME_RE.search(name)):
            continue
        for candidate in candidates:
            where = published.get(candidate)
            if where:
                hits.append((name, where))
                break
    return hits


def _compose_services(path: Path) -> dict:
    """`services:` from a compose file, with the merge tags understood."""
    import yaml  # noqa: PLC0415 — only the repo-side verdict needs a YAML parser

    class _Loader(yaml.SafeLoader):
        pass

    def _strip(loader, node):  # noqa: ANN001, ANN202 - loader plumbing
        if isinstance(node, yaml.SequenceNode):
            return loader.construct_sequence(node, deep=True)
        if isinstance(node, yaml.MappingNode):
            return loader.construct_mapping(node, deep=True)
        return loader.construct_scalar(node)

    for tag in ("!reset", "!override"):
        _Loader.add_constructor(tag, _strip)

    return (yaml.load(path.read_text(encoding="utf-8"), Loader=_Loader) or {}).get("services") or {}  # noqa: S506


def guarded_variables(prod: Path) -> set[str]:
    """Every ``${VAR:?}`` the production compose file actually interpolates.

    Read off the parsed values rather than the raw text. The header comment
    in that file spells `${VAR:?}` out to explain the hole this module closes,
    and a text scan harvests `VAR` from the prose — the same mistake
    ``test_no_dev_secret_literal_reaches_a_service`` in the gate records
    having made once already.
    """
    found: set[str] = set()
    for service in _compose_services(prod).values():
        environment = (service or {}).get("environment") or {}
        values = environment.values() if isinstance(environment, dict) else environment
        for value in values:
            found |= set(COMPOSE_REQUIRED_RE.findall(str(value)))
    return found


def _check_env() -> int:
    published = published_literals()
    hits = offending(os.environ, published)
    if not hits:
        print(f"OK: no secret holds one of the {len(published)} values published in this repository.")
        return 0
    print("Refusing to start: these hold a value published in this repository.", file=sys.stderr)
    for name, where in hits:
        print(f"  - {name} is set to the literal published as {where}", file=sys.stderr)
    print(
        "\nGenerate replacements with `make env`, or set them yourself; `openssl rand -hex 32` is fine for any of them.",
        file=sys.stderr,
    )
    return 1


def _check_repo() -> int:
    root = repo_root()
    prod = root / "docker-compose.prod.yml"
    if not prod.exists():
        print("FAIL: docker-compose.prod.yml is missing.", file=sys.stderr)
        return 1

    guarded = guarded_variables(prod)
    if not guarded:
        print("FAIL: found no `${VAR:?}` guards to cover.", file=sys.stderr)
        return 1

    services = _compose_services(prod)
    preflight = services.get(PREFLIGHT_SERVICE)
    if not preflight:
        print(f"FAIL: `{PREFLIGHT_SERVICE}` is not defined in docker-compose.prod.yml.", file=sys.stderr)
        return 1

    received = set((preflight.get("environment") or {}).keys())
    missing = sorted(guarded - received)
    if missing:
        print(
            "FAIL: these are guarded with `${VAR:?}` but never reach the preflight, "
            "so a published value in them would not be caught: " + ", ".join(missing),
            file=sys.stderr,
        )
        return 1

    ungated = sorted(
        name
        for name, service in services.items()
        if name != PREFLIGHT_SERVICE and PREFLIGHT_SERVICE not in ((service or {}).get("depends_on") or {})
    )
    if ungated:
        print(
            f"FAIL: these start without waiting for `{PREFLIGHT_SERVICE}`: " + ", ".join(ungated),
            file=sys.stderr,
        )
        return 1

    published = published_literals(root)
    sample = next(iter(published))
    if not offending({"POSTGRES_PASSWORD": sample}, published):
        print("FAIL: the checker does not flag a value it harvested as published.", file=sys.stderr)
        return 1

    print(
        f"OK: {len(guarded)} guarded variables all reach `{PREFLIGHT_SERVICE}`, "
        f"{len(services) - 1} services wait for it, and {len(published)} published values are refused."
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check-env", action="store_true", help="inspect this process's environment")
    parser.add_argument("--check", action="store_true", help="verdict over the repository")
    parser.add_argument(
        "--list-guarded",
        action="store_true",
        help="print every `${VAR:?}` variable in the production compose file, one per line",
    )
    args = parser.parse_args(argv)
    if args.check_env:
        return _check_env()
    if args.check:
        return _check_repo()
    if args.list_guarded:
        # For the compose-smoke step that has to supply a value for every
        # guarded variable. Hand-listing them meant the next `${VAR:?}` added
        # to that file broke the smoke run — which is what happened the first
        # time one was, and is a list maintained in two places by definition.
        for name in sorted(guarded_variables(repo_root() / "docker-compose.prod.yml")):
            print(name)
        return 0
    parser.error("choose --check-env, --check or --list-guarded")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
