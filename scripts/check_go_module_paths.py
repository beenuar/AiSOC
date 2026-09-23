#!/usr/bin/env python3
"""Every published Go module must declare a path `go get` can resolve.

Both published SDKs declared `github.com/beenuar/aisoc/<name>`:

  * wrong case — the repository is `AiSOC`, and Go module paths are
    case-sensitive against the VCS path;
  * missing the `packages/` prefix — the directory the module lives in.

So `go get github.com/beenuar/aisoc/sdk-go` resolved to nothing, and neither
SDK was installable by anyone outside this repository. Nothing caught it
because every in-repo consumer used a `replace` directive or a relative
import, which is exactly the shape that hides a broken published path: the
tree builds perfectly and the artifact does not exist.

This is a path check, not a network check. It runs offline and deterministically
and asserts the declared module path matches where the directory actually is.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

#: The canonical repository path, matching the GitHub org and repo casing.
REPO_PATH = "github.com/beenuar/AiSOC"

#: Directories whose modules are published for external consumption. A module
#: under services/ is internal to a deployable image and is not `go get`-able
#: by design, so only these are checked.
PUBLISHED_ROOTS = ("packages",)

_MODULE_RE = re.compile(r"^module\s+(\S+)", re.MULTILINE)


def declared_path(go_mod: Path) -> str | None:
    match = _MODULE_RE.search(go_mod.read_text(encoding="utf-8"))
    return match.group(1) if match else None


def expected_path(go_mod: Path) -> str:
    return f"{REPO_PATH}/{go_mod.parent.relative_to(ROOT).as_posix()}"


def main() -> int:
    problems: list[str] = []
    checked = 0

    for root in PUBLISHED_ROOTS:
        for go_mod in sorted((ROOT / root).rglob("go.mod")):
            if "node_modules" in go_mod.parts:
                continue
            checked += 1
            declared = declared_path(go_mod)
            expected = expected_path(go_mod)
            rel = go_mod.relative_to(ROOT)

            if declared is None:
                problems.append(f"{rel}: no `module` directive")
            elif declared != expected:
                problems.append(
                    f"{rel}: declares `{declared}` but lives at `{expected}`. "
                    "`go get` resolves the module path against the VCS path, and it is "
                    "case-sensitive, so this module is not installable."
                )

    if problems:
        print("GO MODULE PATH GATE FAILED:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1

    print(f"OK: {checked} published Go module path(s) resolve against {REPO_PATH}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
