#!/usr/bin/env python3
"""Gate: one Go version across the repo, and CI installs it.

Six ``go.mod`` files declared five different versions — 1.21, 1.22, 1.24,
1.25.0 and 1.26 — while the CI Go matrix installed 1.25. That is not
untidiness: ``services/osquery-extensions`` declared 1.26, so it could not be
built by the toolchain CI provides, and a contributor following the repo
would install whichever version they happened to read first.

Nothing checked, because nothing compared the two. This does.

Run:  python3 scripts/check_toolchain_versions.py
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = REPO_ROOT / ".github" / "workflows"


def go_modules() -> dict[Path, str]:
    """Every go.mod and the version it declares."""
    found: dict[Path, str] = {}
    for path in sorted(REPO_ROOT.rglob("go.mod")):
        # Vendored and cached trees are not ours to align.
        if any(part in ("vendor", "node_modules", ".git") for part in path.parts):
            continue
        match = re.search(r"^go (\S+)$", path.read_text(encoding="utf-8"), re.M)
        if match:
            found[path.relative_to(REPO_ROOT)] = match.group(1)
    return found


def workflow_go_versions() -> dict[str, set[str]]:
    """Every ``go-version:`` a workflow asks setup-go to install."""
    found: dict[str, set[str]] = {}
    for path in sorted(WORKFLOWS.glob("*.yml")):
        versions = set(re.findall(r"go-version:\s*['\"]?([0-9][0-9.x]*)['\"]?", path.read_text(encoding="utf-8")))
        if versions:
            found[path.name] = versions
    return found


def dockerfile_go_images() -> dict[str, str]:
    """Every ``FROM golang:X.Y`` base image in the repo.

    Added because the first version of this gate checked go.mod against the
    CI workflows and stopped there. Bumping the modules to 1.26 then broke
    the compose build: three Dockerfiles still pinned golang:1.21, 1.24 and
    1.25, and ``go mod download`` failed inside the image against a module
    requiring a newer toolchain. A gate that covers two of the three places
    a version is written finds the drift it was not looking for.
    """
    found: dict[str, str] = {}
    for path in sorted(REPO_ROOT.rglob("Dockerfile*")):
        if any(part in ("node_modules", ".git", "plans") for part in path.parts):
            continue
        match = re.search(r"FROM\s+golang:(\d+\.\d+(?:\.\d+)?)", path.read_text(encoding="utf-8"))
        if match:
            found[str(path.relative_to(REPO_ROOT))] = match.group(1)
    return found


def _minor(version: str) -> tuple[int, int]:
    parts = version.split(".")
    return (int(parts[0]), int(parts[1]) if len(parts) > 1 else 0)


def main(argv: list[str] | None = None) -> int:
    argparse.ArgumentParser(description=__doc__).parse_args(argv)
    errors: list[str] = []

    modules = go_modules()
    if not modules:
        print("toolchain: no go.mod files found", file=sys.stderr)
        return 2

    declared = set(modules.values())
    if len(declared) > 1:
        detail = "\n".join(f"      {p}: {v}" for p, v in sorted(modules.items()))
        errors.append(f"go.mod files declare {len(declared)} different Go versions " f"({', '.join(sorted(declared))}):\n{detail}")

    target = max(declared, key=_minor)
    target_minor = _minor(target)

    for workflow, versions in workflow_go_versions().items():
        for version in versions:
            if version.endswith("x"):
                continue
            if _minor(version) < target_minor:
                errors.append(
                    f".github/workflows/{workflow} installs Go {version}, but a module "
                    f"declares {target}. That module cannot be built by the toolchain "
                    f"CI provides."
                )

    for dockerfile, version in dockerfile_go_images().items():
        if _minor(version) < target_minor:
            errors.append(
                f"{dockerfile} builds on golang:{version}, but a module declares " f"{target}. `go mod download` fails inside the image."
            )

    if errors:
        print("TOOLCHAIN VERSION GATE FAILED:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    images = dockerfile_go_images()
    print(f"toolchain: OK — {len(modules)} Go modules on {target}; CI and " f"{len(images)} Dockerfile(s) install it")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
