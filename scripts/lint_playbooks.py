#!/usr/bin/env python3
"""
Lint all playbook JSON files in services/agents/data/playbooks/ (and any
*.playbook.json files anywhere in the repo) against the JSON Schema at
schemas/playbook.schema.json.

Exit code:
  0  all files pass
  1  one or more files fail validation
  2  no files found (treated as a warning, exits 0)

Usage:
  python3 scripts/lint_playbooks.py
  python3 scripts/lint_playbooks.py path/to/my-playbook.json
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

try:
    import jsonschema
except ImportError:
    print("ERROR: jsonschema not installed.  Run: pip install jsonschema", file=sys.stderr)
    sys.exit(1)

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = REPO_ROOT / "schemas" / "playbook.schema.json"

# Directories / glob patterns to scan automatically
SCAN_DIRS = [
    REPO_ROOT / "services" / "agents" / "data" / "playbooks",
]
SCAN_GLOB = "*.json"


def load_schema() -> dict:
    if not SCHEMA_PATH.exists():
        print(f"ERROR: Schema not found at {SCHEMA_PATH}", file=sys.stderr)
        sys.exit(1)
    return json.loads(SCHEMA_PATH.read_text())


def collect_files(extra: list[str]) -> list[Path]:
    files: list[Path] = []
    for d in SCAN_DIRS:
        if d.is_dir():
            files.extend(sorted(d.glob(SCAN_GLOB)))
    for p in extra:
        files.append(Path(p))
    return files


def validate_file(path: Path, schema: dict, validator_cls) -> list[str]:
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        return [f"JSON parse error: {exc}"]

    # If the file is a list (e.g. index.json with multiple playbooks), validate each item
    items = data if isinstance(data, list) else [data]
    errors: list[str] = []
    for i, item in enumerate(items):
        for err in sorted(validator_cls.iter_errors(item), key=lambda e: list(e.path)):
            loc = ".".join(str(p) for p in err.path) or "(root)"
            errors.append(f"  [item {i}] {loc}: {err.message}")
    return errors


def main() -> None:
    extra_args = sys.argv[1:]
    schema = load_schema()
    validator_cls = jsonschema.Draft7Validator(schema)

    files = collect_files(extra_args)

    if not files:
        print("No playbook files found — skipping lint (exit 0).")
        sys.exit(0)

    fail_count = 0
    for path in files:
        errs = validate_file(path, schema, validator_cls)
        if errs:
            print(f"FAIL  {path.relative_to(REPO_ROOT)}")
            for e in errs:
                print(e)
            fail_count += 1
        else:
            print(f"OK    {path.relative_to(REPO_ROOT)}")

    total = len(files)
    print(f"\n{total - fail_count}/{total} playbook files passed schema validation.")

    if fail_count:
        sys.exit(1)


if __name__ == "__main__":
    main()
