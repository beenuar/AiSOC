#!/usr/bin/env python3
"""The marketplace index must ship wherever it is read, and be the same file.

Three copies of `marketplace/index.json` exist, because three build contexts
need it and none of them can see the other two:

  * `marketplace/index.json` — the generated original, read from a checkout.
  * `apps/web/public/marketplace/index.json` — served statically by the
    console, which is what the marketplace page actually browses.
  * `services/api/app/data/marketplace/index.json` — inside the API's Docker
    build context, which is `services/api`; the repository-root directory is
    invisible to its `COPY . .`.

That third copy did not exist, so the published API image shipped no index at
all and `GET /v1/marketplace` plus `POST /v1/marketplace/install` answered
**503 on every containerised deployment**. Reported in discussion #374 and
true of every release since the endpoint was written. Nothing failed in CI,
because nothing compared what the image contains against what the code reads.

This gate asserts the three are byte-identical and that every item carries the
content digest install depends on — the API image has no `detections/`,
`playbooks/` or `plugins/` tree to hash at runtime, so an index without
digests would 404 on install even with all three copies in place.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_if_requested  # noqa: E402

self_test_if_requested(__file__)

REPO_ROOT = repo_root()

#: Every location the index must exist, and why. Keep in step with
#: `write_index()` in scripts/build_marketplace.py.
COPIES: tuple[tuple[str, str], ...] = (
    ("marketplace/index.json", "the generated original"),
    ("apps/web/public/marketplace/index.json", "served statically by the console"),
    ("services/api/app/data/marketplace/index.json", "inside the API's Docker build context"),
)


class ScanError(RuntimeError):
    """The scan could not run, which is not the same as a clean result."""


def scan() -> list[str]:
    errors: list[str] = []

    present: dict[str, str] = {}
    for relative, why in COPIES:
        path = REPO_ROOT / relative
        if not path.is_file():
            errors.append(
                f"{relative} is missing ({why}). Run `pnpm marketplace:sync`. Without it that consumer reads no catalogue at all."
            )
            continue
        present[relative] = hashlib.sha256(path.read_bytes()).hexdigest()

    if len(set(present.values())) > 1:
        detail = ", ".join(f"{name}={digest[:12]}" for name, digest in sorted(present.items()))
        errors.append(
            f"the copies disagree ({detail}). One consumer is showing a different catalogue than another. Run `pnpm marketplace:sync`."
        )

    original = REPO_ROOT / COPIES[0][0]
    if original.is_file():
        try:
            document = json.loads(original.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ScanError(f"{COPIES[0][0]} is not readable as JSON: {exc}") from exc

        items = document.get("items") or []
        if not items:
            raise ScanError(f"{COPIES[0][0]} lists no items; the format this gate reads has changed")

        # Install resolves a digest from the index when the content trees are
        # absent, which is the case in every image. An item without one fails
        # the install it is offered for.
        unhashed = [item.get("id", "<no id>") for item in items if not item.get("sha256")]
        if unhashed:
            errors.append(
                f"{len(unhashed)} item(s) carry no sha256, so installing them from a container "
                f"would 404 on a file the image does not ship: {unhashed[:5]}"
            )

    return errors


def main() -> int:
    try:
        errors = scan()
    except ScanError as exc:
        print(f"check_marketplace_index_parity: FAILED to run the scan: {exc}", file=sys.stderr)
        return 2

    if errors:
        print("MARKETPLACE INDEX PARITY GATE FAILED:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    items = len(json.loads((REPO_ROOT / COPIES[0][0]).read_text(encoding="utf-8"))["items"])
    print(f"check_marketplace_index_parity: OK — {len(COPIES)} identical copies, {items} items all carrying a digest")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
