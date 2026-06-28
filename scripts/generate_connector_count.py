#!/usr/bin/env python3
"""Generate the single source of truth for AiSOC's first-party connector count.

Why this exists
---------------
Before this script, five different surfaces in the repo each carried their own
hard-coded "N connectors" claim:

  * ``README.md`` (52)
  * ``apps/docs/docs/connectors/index.md`` (50)
  * ``apps/web/src/components/landing/sections/Hero.tsx`` (69)
  * ``apps/web/src/components/landing/sections/FeatureGrid.tsx`` (69)
  * ``apps/web/src/components/landing/sections/ConnectorsMarquee.tsx`` (69)

The registry of record is ``services/connectors/app/connectors/__init__.py`` —
``_CONNECTOR_CLASSES`` is the tuple that backs ``CONNECTOR_REGISTRY``. This
script reads that tuple via the Python AST (so the script has no runtime
dependency on the ``connectors`` package itself) and writes:

  * ``apps/web/src/data/connector-count.json`` — machine-readable count.
  * ``apps/web/src/data/connectorCount.ts``    — TypeScript constants
    (``CONNECTOR_COUNT`` + ``CONNECTOR_CATEGORIES``) imported by every
    landing / pricing / FAQ surface.

Usage
-----

    python3 scripts/generate_connector_count.py             # write outputs
    python3 scripts/generate_connector_count.py --check     # fail if drift

The ``--check`` mode is wired into ``.github/workflows/ci.yml`` so any time
someone adds a connector class without regenerating the count, CI catches it.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
REGISTRY_FILE = REPO_ROOT / "services" / "connectors" / "app" / "connectors" / "__init__.py"
CONNECTORS_DIR = REPO_ROOT / "services" / "connectors" / "app" / "connectors"
JSON_OUT = REPO_ROOT / "apps" / "web" / "src" / "data" / "connector-count.json"
TS_OUT = REPO_ROOT / "apps" / "web" / "src" / "data" / "connectorCount.ts"

# Files that quote a connector count in prose. We rewrite the number in place,
# and CI verifies no other surface diverges. Each entry is a regex that MUST
# match exactly one number per file, in the form ``\b<count>\b`` plus a
# disambiguating prefix/suffix so we never rewrite an unrelated integer.
COUNT_BEARING_FILES: tuple[tuple[Path, tuple[re.Pattern[str], ...]], ...] = (
    (
        REPO_ROOT / "README.md",
        (
            re.compile(r"(?P<pre>declares \*\*)(?P<n>\d+)(?P<post> first-party connectors)"),
            re.compile(r"(?P<pre>corrected \*\*)(?P<n>\d+)(?P<post>-connector count\*\*)"),
            re.compile(r"(?P<pre>a )(?P<n>\d+)(?P<post>-connector click-and-connect catalog)"),
        ),
    ),
    (
        REPO_ROOT / "apps" / "docs" / "docs" / "connectors" / "index.md",
        (
            re.compile(r"(?P<pre>with \*\*)(?P<n>\d+) connectors(?P<post>\*\*)"),
        ),
    ),
    (
        REPO_ROOT / "apps" / "docs" / "docs" / "connectors" / "endpoint-decision-matrix.md",
        (
            re.compile(r"(?P<pre>the full )(?P<n>\d+)(?P<post>-connector catalog)"),
        ),
    ),
    (
        REPO_ROOT / "apps" / "docs" / "docs" / "connectors" / "api-coverage.md",
        (
            re.compile(r"(?P<pre>## Coverage table — )(?P<n>\d+)(?P<post> connectors)"),
        ),
    ),
    (
        REPO_ROOT / "apps" / "docs" / "docs" / "architecture.md",
        (
            re.compile(r"(?P<pre>now )(?P<n>\d+) connectors(?P<post>\*\*)"),
        ),
    ),
    (
        REPO_ROOT / "apps" / "docs" / "docs" / "intro.md",
        (
            re.compile(r"(?P<pre>a \*\*)(?P<n>\d+)(?P<post>-connector\*\* catalog)"),
        ),
    ),
    (
        REPO_ROOT / "ROADMAP.md",
        (
            re.compile(r"(?P<pre>declares \*\*)(?P<n>\d+)(?P<post> first-party connectors)"),
        ),
    ),
    (
        REPO_ROOT / "docs" / "architecture" / "SYSTEM_DESIGN.md",
        (
            re.compile(r"(?P<pre>│  )(?P<n>\d+)(?P<post> connector classes│)"),
            re.compile(r"(?P<pre>\| Python 3\.11 \| )(?P<n>\d+)(?P<post> connector classes,)"),
            re.compile(r"(?P<pre>with \*\*)(?P<n>\d+)(?P<post> registered connector classes\*\*)"),
        ),
    ),
)


def parse_registry_count() -> int:
    """Parse ``_CONNECTOR_CLASSES`` length via AST (no runtime imports)."""
    source = REGISTRY_FILE.read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in tree.body:
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if node.target.id == "_CONNECTOR_CLASSES" and isinstance(node.value, ast.Tuple):
                return len(node.value.elts)
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "_CONNECTOR_CLASSES":
                    if isinstance(node.value, ast.Tuple):
                        return len(node.value.elts)
    raise RuntimeError(
        f"could not find _CONNECTOR_CLASSES tuple in {REGISTRY_FILE.relative_to(REPO_ROOT)}"
    )


_CATEGORY_PATTERN = re.compile(r'^\s*connector_category\s*=\s*"([a-z][a-z0-9_-]*)"', re.MULTILINE)


def parse_category_counts() -> dict[str, int]:
    """Count ``connector_category = "..."`` declarations across registered files."""
    counts: Counter[str] = Counter()
    for py in sorted(CONNECTORS_DIR.glob("*.py")):
        if py.name in {"__init__.py", "base.py"}:
            continue
        text = py.read_text(encoding="utf-8")
        match = _CATEGORY_PATTERN.search(text)
        if match:
            counts[match.group(1)] += 1
    return dict(sorted(counts.items()))


def build_payload() -> dict[str, object]:
    """Produce the on-disk payload."""
    count = parse_registry_count()
    categories = parse_category_counts()
    return {
        "count": count,
        "categories": categories,
        "generatedFrom": "services/connectors/app/connectors/__init__.py",
        "regenerateWith": "python3 scripts/generate_connector_count.py",
    }


def render_typescript(payload: dict[str, object]) -> str:
    """Render the TS constants module imported by the landing/pricing UI."""
    return (
        "// AUTO-GENERATED by scripts/generate_connector_count.py.\n"
        "// Do not edit by hand. Run the script (or `make connector-count`) instead.\n"
        "//\n"
        "// This module is the single source of truth for every prose claim of the\n"
        "// form \"N connectors\" or \"All N connectors\" across the marketing site,\n"
        "// docs portal, and pricing surfaces. The count itself comes from the\n"
        "// _CONNECTOR_CLASSES tuple in services/connectors/app/connectors/__init__.py.\n"
        "\n"
        "import data from './connector-count.json';\n"
        "\n"
        "export const CONNECTOR_COUNT: number = data.count;\n"
        "export const CONNECTOR_CATEGORIES: Readonly<Record<string, number>> ="
        " data.categories;\n"
        "\n"
        "// Human-readable label used in marquees / chips.\n"
        "export const CONNECTOR_COUNT_LABEL = `${CONNECTOR_COUNT} connectors`;\n"
    )


def write_outputs(payload: dict[str, object]) -> None:
    JSON_OUT.parent.mkdir(parents=True, exist_ok=True)
    JSON_OUT.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    TS_OUT.write_text(render_typescript(payload), encoding="utf-8")


def reconcile_prose(count: int, *, check_only: bool) -> list[str]:
    """Rewrite or verify every COUNT_BEARING_FILES entry.

    Returns a list of human-readable drift messages. Empty list means clean.
    """
    drift: list[str] = []
    for path, patterns in COUNT_BEARING_FILES:
        if not path.exists():
            drift.append(f"missing file {path.relative_to(REPO_ROOT)}")
            continue
        before = path.read_text(encoding="utf-8")
        after = before
        for pattern in patterns:
            matches = list(pattern.finditer(after))
            if not matches:
                drift.append(
                    f"{path.relative_to(REPO_ROOT)}: pattern {pattern.pattern!r} did not match"
                )
                continue
            for match in matches:
                if match.group("n") != str(count):
                    after = (
                        after[: match.start("n")]
                        + str(count)
                        + after[match.end("n") :]
                    )
        if after != before:
            if check_only:
                drift.append(
                    f"{path.relative_to(REPO_ROOT)}: connector count drift (expected {count})"
                )
            else:
                path.write_text(after, encoding="utf-8")
    return drift


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail (exit 1) on any drift instead of rewriting files.",
    )
    args = parser.parse_args(argv)

    payload = build_payload()
    count = int(payload["count"])  # type: ignore[arg-type]

    drift: list[str] = []

    if args.check:
        json_existing = (
            json.loads(JSON_OUT.read_text(encoding="utf-8"))
            if JSON_OUT.exists()
            else None
        )
        if json_existing != payload:
            drift.append(
                f"{JSON_OUT.relative_to(REPO_ROOT)}: regenerate with"
                " `python3 scripts/generate_connector_count.py`"
            )
        ts_existing = TS_OUT.read_text(encoding="utf-8") if TS_OUT.exists() else ""
        if ts_existing != render_typescript(payload):
            drift.append(
                f"{TS_OUT.relative_to(REPO_ROOT)}: regenerate with"
                " `python3 scripts/generate_connector_count.py`"
            )
    else:
        write_outputs(payload)

    drift.extend(reconcile_prose(count, check_only=args.check))

    if drift:
        print(
            f"connector-count drift detected (registry={count}):", file=sys.stderr
        )
        for line in drift:
            print(f"  - {line}", file=sys.stderr)
        return 1

    print(
        f"connector-count OK — {count} registered, {len(payload['categories'])}"  # type: ignore[arg-type]
        " categories"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
