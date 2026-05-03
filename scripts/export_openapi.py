#!/usr/bin/env python3
"""
Export the AiSOC FastAPI OpenAPI schema to docs/openapi.yaml.

Usage
-----
  python scripts/export_openapi.py [--check]

  --check   Diff mode: exit 1 if docs/openapi.yaml differs from what the app
            currently generates.  Used by CI to keep the committed schema in sync.

The script imports the FastAPI application directly (no running server needed)
and calls ``app.openapi()`` to get the schema, then serialises it to YAML.

MIT License — Cyble Open-Source AiSOC
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

# ── Ensure the api service is importable ─────────────────────────────────────
REPO_ROOT = Path(__file__).resolve().parents[1]
API_SRC = REPO_ROOT / "services" / "api"
if str(API_SRC) not in sys.path:
    sys.path.insert(0, str(API_SRC))

# Set minimal env vars so settings validation doesn't fail
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("SECRET_KEY", "export-openapi-dummy-secret-key-32bytes!")
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://x:x@localhost/x")

try:
    import yaml  # PyYAML
except ImportError:
    print("ERROR: PyYAML is required. Install with: pip install pyyaml", file=sys.stderr)
    sys.exit(1)

from app.main import app  # noqa: E402  (after sys.path manipulation)


def get_schema() -> dict:
    return app.openapi()


def write_yaml(schema: dict, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open("w", encoding="utf-8") as fh:
        yaml.dump(schema, fh, allow_unicode=True, sort_keys=False, default_flow_style=False)
    print(f"✅  OpenAPI schema written to {dest.relative_to(REPO_ROOT)}")


def check_yaml(schema: dict, dest: Path) -> bool:
    """Return True if file matches generated schema."""
    if not dest.exists():
        print(f"❌  {dest.relative_to(REPO_ROOT)} does not exist. Run: python scripts/export_openapi.py", file=sys.stderr)
        return False

    with dest.open("r", encoding="utf-8") as fh:
        existing = yaml.safe_load(fh)

    if existing != schema:
        print(
            f"❌  {dest.relative_to(REPO_ROOT)} is out of date.\n"
            "    Run: python scripts/export_openapi.py  then commit the result.",
            file=sys.stderr,
        )
        return False

    print(f"✅  {dest.relative_to(REPO_ROOT)} is up to date.")
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description="Export or verify AiSOC OpenAPI schema.")
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit with code 1 if docs/openapi.yaml differs from the current schema.",
    )
    parser.add_argument(
        "--output",
        default=str(REPO_ROOT / "docs" / "openapi.yaml"),
        help="Destination path (default: docs/openapi.yaml)",
    )
    args = parser.parse_args()

    dest = Path(args.output)
    schema = get_schema()

    if args.check:
        ok = check_yaml(schema, dest)
        sys.exit(0 if ok else 1)
    else:
        write_yaml(schema, dest)


if __name__ == "__main__":
    main()
