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
import subprocess
import sys
from pathlib import Path

# `scripts/` is on sys.path when this file is run as a program, but not when a
# test loads it by path with importlib. gate_toolkit sits beside it either way.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import self_test_if_requested

self_test_if_requested(__file__)


def _repo_root() -> Path:
    """The repository, per git — not per this file's location.

    Resolving two levels up from `__file__` means a copy of this script run
    from anywhere else scans whatever happens to sit above it and prints a
    confident OK about a tree it never opened.
    """
    out = subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=False,
        cwd=Path(__file__).resolve().parent,
    )
    if out.returncode == 0 and out.stdout.strip():
        return Path(out.stdout.strip()).resolve()
    return Path(__file__).resolve().parent.parent


ROOT = _repo_root()

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

    # "Found nothing" and "opened nothing" print the same word otherwise. The
    # published roots are a hand-written tuple, so a module moving out of
    # `packages/` takes its coverage with it silently — and the failure this
    # gate exists to catch is precisely one nobody in-tree can observe,
    # because every in-repo consumer uses a `replace` directive.
    if not checked:
        print(
            f"GO MODULE PATH GATE FAILED: found no go.mod under {', '.join(PUBLISHED_ROOTS)}/ "
            f"in {ROOT}. Zero modules checked is not zero modules broken — either "
            f"PUBLISHED_ROOTS no longer describes where the published SDKs live, or the "
            f"walk is looking at the wrong tree.",
            file=sys.stderr,
        )
        return 1

    if problems:
        print("GO MODULE PATH GATE FAILED:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1

    print(f"OK: {checked} published Go module path(s) resolve against {REPO_PATH}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
