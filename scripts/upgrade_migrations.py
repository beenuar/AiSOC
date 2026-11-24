#!/usr/bin/env python3
"""Apply migrations only when the API image carries this checkout's SQL.

The startup schema guard reads the checkout, while the migration runner reads
the API image. A successful pull of a moving tag can still fetch an older
image, whose runner reports zero pending migrations without seeing new SQL.

Hash the checkout's files and verify them inside the same one-off container
that runs the real migration runner. Passing the verifier as Python source
keeps this usable with images that predate this helper; comparing and running
in one container avoids a tag changing between separate probe and run steps.
Neither this host helper nor its verifier needs third-party dependencies.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shlex
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_if_requested  # noqa: E402

self_test_if_requested(__file__)


def migration_manifest(directory: Path) -> dict[str, str]:
    """Read every SQL file, refusing missing, empty or unreadable trees."""
    try:
        files = sorted(path for path in directory.iterdir() if path.suffix == ".sql")
        if not files:
            raise ValueError(f"no .sql migrations under {directory}")
        manifest = {}
        for path in files:
            if not path.is_file():
                raise ValueError(f"not a regular migration file: {path}")
            # The runner reads UTF-8 text with universal newline translation.
            # Hash the text it executes so CRLF checkouts match Linux images.
            manifest[path.name] = hashlib.sha256(path.read_text(encoding="utf-8").encode("utf-8")).hexdigest()
        return manifest
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"cannot read migrations under {directory} ({type(exc).__name__})") from exc


# Only the standard library is used before the manifests match. Resolving the
# runner's spec locates its sibling migrations directory without importing the
# runner (and its settings) or opening a database connection. This is the same
# relative directory as run_migrations.MIGRATIONS_DIR in existing images.
CONTAINER_RUNNER = r"""
import hashlib
import importlib.util
import json
import runpy
import sys
from pathlib import Path

def refuse(message):
    print("upgrade_migrations: " + message, file=sys.stderr, flush=True)
    raise SystemExit(2)

try:
    expected = json.loads(sys.argv[1])
except (IndexError, TypeError, ValueError):
    refuse("invalid checkout migration manifest; refusing to migrate")
if not isinstance(expected, dict) or not expected:
    refuse("empty or invalid checkout migration manifest; refusing to migrate")
for name, digest in expected.items():
    if (
        not isinstance(name, str) or Path(name).name != name
        or Path(name).suffix != ".sql" or not isinstance(digest, str)
        or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest)
    ):
        refuse("invalid checkout migration manifest; refusing to migrate")

try:
    spec = importlib.util.find_spec("app.scripts.run_migrations")
    if spec is None or spec.origin is None:
        refuse("API image has no migration runner; refusing to migrate")
    directory = Path(spec.origin).resolve().parents[2] / "migrations"
    files = sorted(path for path in directory.iterdir() if path.suffix == ".sql")
    if not files:
        refuse("API image has no SQL migrations; refusing to migrate")
    actual = {}
    for path in files:
        if not path.is_file():
            refuse("API image migration is not a regular file: " + repr(path.name))
        actual[path.name] = hashlib.sha256(path.read_text(encoding="utf-8").encode("utf-8")).hexdigest()
except (ImportError, OSError, ValueError, IndexError) as exc:
    refuse("cannot read API image migrations (" + type(exc).__name__ + "); refusing to migrate")

differences = (
    ("missing from API image", sorted(expected.keys() - actual.keys())),
    ("extra in API image", sorted(actual.keys() - expected.keys())),
    ("changed SQL in API image", sorted(name for name in expected.keys() & actual.keys() if expected[name] != actual[name])),
)
if any(names for _, names in differences):
    print("upgrade_migrations: API image migrations do not match this checkout.", file=sys.stderr)
    for label, names in differences:
        if names:
            print("  " + label + " (" + str(len(names)) + "):", file=sys.stderr)
            for name in names[:10]:
                print("    " + repr(name), file=sys.stderr)
            if len(names) > 10:
                print("    ... and " + str(len(names) - 10) + " more", file=sys.stderr)
    refuse(
        "no migrations were applied. Use images and a checkout from the same release, "
        "or build from this checkout before retrying make upgrade."
    )

print("upgrade_migrations: verified " + str(len(actual)) + " migration files; applying with the matching API image.", flush=True)
sys.argv = ["app.scripts.run_migrations"]
runpy.run_module("app.scripts.run_migrations", run_name="__main__", alter_sys=True)
"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify the API image's migration files against this checkout before applying them.")
    parser.add_argument("--compose", default="docker compose", help="compose invocation, including this deployment's overlays/options")
    parser.add_argument("--migrations-dir", type=Path, default=None, help="default: <repo>/services/api/migrations")
    args = parser.parse_args(argv)

    directory = args.migrations_dir or repo_root(start=Path.cwd()) / "services" / "api" / "migrations"
    try:
        expected = migration_manifest(directory)
        compose = shlex.split(args.compose)
        if not compose:
            raise ValueError("the compose invocation is empty")
    except ValueError as exc:
        print(f"upgrade_migrations: {exc}; refusing to migrate", file=sys.stderr)
        return 2

    print(f"upgrade_migrations: checking {len(expected)} checkout migration files against the API image", flush=True)
    try:
        result = subprocess.run(
            [
                *compose,
                "run",
                "--rm",
                "--no-deps",
                "-T",
                "-e",
                "AISOC_MIGRATIONS_STRICT=1",
                "api",
                "python",
                "-c",
                CONTAINER_RUNNER,
                json.dumps(expected, sort_keys=True),
            ],
            check=False,
        )
    except OSError as exc:
        print(f"upgrade_migrations: could not run compose ({type(exc).__name__}); refusing to migrate", file=sys.stderr)
        return 2
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
