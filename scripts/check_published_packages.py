#!/usr/bin/env python3
"""Ask the registries what was published, rather than the workflow.

Why this exists
---------------
On the v12.2.0 release run all 59 jobs reported success, eight of them named
`npm — publish …` or `PyPI — publish …`, and all eight packages returned 404.
Only the final upload step is credential-gated, so each job built the
artefact, reached the upload, skipped it, and exited 0. The signal said nine
packages shipped and nothing had.

The credential gate is correct — the blocker is an account action, not code —
so the answer is not to publish but to stop inferring publication from a green
job. "The job ran" and "the registry holds the package" are different facts
and only the first was ever checked. This checks the second.

What it enforces
----------------
`.github/release-packages.yml` declares every package `release.yml` uploads
and whether each is expected to be on its registry. Three directions, because
a gate that only runs one way passes while drift accumulates in the other —
the recurring defect in this tree:

  manifest <-> workflow    Both ways. A package the npm/PyPI matrices build
                           and the manifest does not declare is a package
                           nothing will ever check; a package declared with no
                           matrix entry is a claim with no pipeline behind it.

  published: true  -> registry resolves, at the version in the tree. This is
                      the direction a release run cannot check itself: a job
                      that claims a publish and uploaded nothing fails here.

  published: false -> registry 404s. So the knowingly-absent set shrinks in a
                      commit when a credential arrives, instead of quietly
                      ceasing to be true. A stale `false` is as wrong as a
                      stale `true`; it is just wrong in the flattering
                      direction.

It also holds the prose to the same answer: `README.md`'s maturity row and
each package README's install command. Those used to be checked by a second
hardcoded package list in `tests/test_package_install_claims.py`, which could
disagree with this one. That test now imports this module, so there is one
list, one registry query, and one verdict.

Offline it skips rather than fails, because a contributor on a plane must not
be told the README is wrong when the truth is that the network is absent. The
structural checks above run first and do not need a network, so an offline run
still catches manifest/workflow drift.

Usage
-----
    python3 scripts/check_published_packages.py
    python3 scripts/check_published_packages.py --require-network
    python3 scripts/check_published_packages.py --summary "$GITHUB_STEP_SUMMARY"
    python3 scripts/check_published_packages.py --self-test
"""

from __future__ import annotations

import argparse
import json
import sys
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

import yaml

# `scripts/` is on sys.path when this file is run as a program, but not when a
# test loads it by path with importlib. gate_toolkit sits beside it either way.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_if_requested

self_test_if_requested(__file__)

ROOT = repo_root()
README = ROOT / "README.md"
MANIFEST = ROOT / ".github" / "release-packages.yml"
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"

#: The phrase README.md's maturity table uses while nothing is published.
UNPUBLISHED_CLAIM = "Ready, unpublished"

#: Wording that tells a reader, in the present tense, that the install command
#: beside it will not resolve yet. Any one satisfies the gate — the point is
#: that the reader is warned, not that a particular sentence is used.
DISCLAIMERS = (
    "not yet on pypi",
    "not yet on npm",
    "ready, unpublished",
    "will not resolve",
    "does **not** resolve",
    "does not resolve",
)

#: The job ids whose matrices name what gets uploaded. Ids, not display names:
#: the display names now change with the credential state, which is the whole
#: point of the change that introduced this file.
MATRIX_JOBS = {"npm-publish": "npm", "pypi-publish": "pypi"}

_TIMEOUT = 10


class Offline(RuntimeError):
    """The registry could not be reached, which is not the same as absent."""


@dataclass(frozen=True)
class Package:
    name: str
    registry: str
    directory: str
    published: bool
    reason: str
    install: str | None

    @property
    def slug(self) -> str:
        return f"{self.registry}:{self.name}"

    def readme(self, root: Path) -> Path:
        return root / self.directory / "README.md"

    def version(self, root: Path) -> str:
        """The version the release would upload, read from the package itself.

        Never copied into the manifest: a version in two places is a version
        that disagrees with itself.
        """
        directory = root / self.directory
        if self.registry == "npm":
            data = json.loads((directory / "package.json").read_text(encoding="utf-8"))
            return str(data["version"])
        data = tomllib.loads((directory / "pyproject.toml").read_text(encoding="utf-8"))
        project = data.get("project") or data.get("tool", {}).get("poetry", {})
        return str(project["version"])


def load_manifest(root: Path = ROOT) -> list[Package]:
    """Every declared package, or a hard error — never an empty list.

    A gate that walks zero packages finds zero violations, and the clean
    result is indistinguishable from a wrong root or a deleted manifest.
    """
    path = root / ".github" / "release-packages.yml"
    if not path.is_file():
        raise SystemExit(f"{path} is missing; there is nothing to check publication against.")
    declared = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    entries = declared.get("packages") or []
    if not entries:
        raise SystemExit(f"{path} declares no packages; refusing to report a clean tree.")
    packages = []
    for entry in entries:
        packages.append(
            Package(
                name=str(entry["name"]),
                registry=str(entry["registry"]),
                directory=str(entry["directory"]),
                published=bool(entry["published"]),
                reason=" ".join(str(entry.get("reason", "")).split()),
                install=entry.get("install"),
            )
        )
    return packages


def workflow_matrix(root: Path = ROOT) -> set[tuple[str, str, str]]:
    """(registry, package, directory) for every upload `release.yml` declares."""
    workflow = yaml.safe_load((root / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8"))
    jobs = workflow.get("jobs") or {}
    found: set[tuple[str, str, str]] = set()
    for job_id, registry in MATRIX_JOBS.items():
        job = jobs.get(job_id)
        if job is None:
            raise SystemExit(f"release.yml no longer has a `{job_id}` job; this gate is checking a workflow that moved.")
        for entry in job["strategy"]["matrix"]["include"]:
            found.add((registry, str(entry["pkg"]), str(entry["dir"])))
    return found


def _registry_url(registry: str, name: str) -> str:
    if registry == "npm":
        return f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@')}"
    return f"https://pypi.org/pypi/{name}/json"


def registry_versions(registry: str, name: str) -> set[str] | None:
    """Every version on the registry, or None when the distribution is absent.

    Raises Offline for anything that is not a clean answer. "Unreachable" and
    "not published" must never collapse into the same result: one of them is
    a finding and the other is a contributor's train going into a tunnel.
    """
    request = urllib.request.Request(_registry_url(registry, name), headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=_TIMEOUT) as response:  # noqa: S310 — fixed https hosts
            payload = json.load(response)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise Offline(f"{registry}:{name} returned {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        raise Offline(f"{registry}:{name} unreachable: {exc}") from exc
    versions = payload.get("versions") if registry == "npm" else payload.get("releases")
    return set(versions or {})


def is_published(registry: str, name: str) -> bool:
    """Whether the distribution exists at all. Used by the README-claim tests."""
    return registry_versions(registry, name) is not None


# --------------------------------------------------------------------------
# Checks
# --------------------------------------------------------------------------


def _check_manifest_matches_workflow(packages: list[Package], root: Path) -> list[str]:
    declared = {(p.registry, p.name, p.directory) for p in packages}
    built = workflow_matrix(root)
    failures = []
    for registry, name, directory in sorted(built - declared):
        failures.append(
            f"release.yml uploads {registry}:{name} from {directory}, and "
            f".github/release-packages.yml does not declare it — so nothing checks whether it published."
        )
    for registry, name, directory in sorted(declared - built):
        failures.append(
            f".github/release-packages.yml declares {registry}:{name} from {directory}, and "
            f"release.yml's {registry} matrix does not build it — the declaration has no pipeline behind it."
        )
    return failures


def _check_directories_exist(packages: list[Package], root: Path) -> list[str]:
    failures = []
    for package in packages:
        try:
            package.version(root)
        except (OSError, KeyError, ValueError) as exc:
            failures.append(f"{package.slug}: cannot read a version from {package.directory} ({exc}).")
    return failures


def _check_registry_state(packages: list[Package], observed: dict[str, set[str] | None], root: Path) -> list[str]:
    failures = []
    for package in packages:
        versions = observed[package.slug]
        if package.published and versions is None:
            failures.append(
                f"{package.slug} is declared published and the registry returns 404. A release job reported success and uploaded nothing."
            )
        elif package.published and package.version(root) not in versions:
            failures.append(
                f"{package.slug} is declared published, but version {package.version(root)} — the version in the tree — "
                f"is not on the registry (it holds {len(versions)} other version(s)). The last release did not upload it."
            )
        elif not package.published and versions is not None:
            failures.append(
                f"{package.slug} is declared unpublished and the registry resolves it. "
                f"Set `published: true` and drop the reason: the knowingly-absent set must shrink in a commit."
            )
    return failures


def _check_prose(packages: list[Package], observed: dict[str, set[str] | None], root: Path) -> list[str]:
    """README.md's maturity row and each package README's install command."""
    failures = []
    live = [p.slug for p in packages if observed[p.slug] is not None]
    readme = (root / "README.md").read_text(encoding="utf-8")
    claims_unpublished = UNPUBLISHED_CLAIM.lower() in readme.lower()

    if live and claims_unpublished:
        failures.append(
            f"README.md still says {UNPUBLISHED_CLAIM!r}, but these are live: {', '.join(live)}. "
            f"Update the maturity table: the claim was true and is not any more."
        )
    if not live and not claims_unpublished:
        failures.append(
            f"Nothing is on npm or PyPI, and README.md no longer says {UNPUBLISHED_CLAIM!r}. A reader following it will hit a 404."
        )

    for package in packages:
        if not package.install or observed[package.slug] is not None:
            continue  # nothing advertised, or it resolves and needs no caveat
        path = package.readme(root)
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        if package.install not in text:
            continue
        if not any(d in text.lower() for d in DISCLAIMERS):
            failures.append(
                f"{path.relative_to(root)} shows `{package.install}` and {package.slug} is not on its registry (404). "
                f"Say so in the present tense next to the command."
            )
    return failures


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------


def summary_markdown(packages: list[Package], observed: dict[str, set[str] | None], root: Path) -> str:
    """The table a reader sees on the run page without opening a log."""
    uploaded = [p for p in packages if observed[p.slug] is not None]
    skipped = [p for p in packages if observed[p.slug] is None]

    lines = ["## Package publication", ""]
    lines.append(
        f"**{len(uploaded)} of {len(packages)} packages are on their registry.** "
        f"Asked of npm and PyPI directly, not inferred from a job status."
    )
    lines.append("")
    lines.append("| Package | Registry | Version in tree | On the registry | Outcome |")
    lines.append("| --- | --- | --- | --- | --- |")
    for package in packages:
        versions = observed[package.slug]
        version = package.version(root)
        if versions is None:
            state, outcome = "no — 404", "packed, **not uploaded**"
        elif version in versions:
            state, outcome = f"yes — {version}", "published"
        else:
            state, outcome = f"yes, but not {version}", "**this version was not uploaded**"
        lines.append(f"| `{package.name}` | {package.registry} | {version} | {state} | {outcome} |")

    if skipped:
        lines.append("")
        lines.append("### Why these were packed and not uploaded")
        lines.append("")
        for package in skipped:
            lines.append(f"- **`{package.name}`** ({package.registry}) — {package.reason}")
        lines.append("")
        lines.append(
            "Each of these was built, validated and packed, so the packaging cannot rot unnoticed. "
            "None of them was uploaded. Declared in `.github/release-packages.yml`."
        )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--require-network",
        action="store_true",
        help="fail instead of skipping when a registry cannot be reached",
    )
    parser.add_argument(
        "--summary",
        metavar="PATH",
        help="append a markdown publication table to PATH (use $GITHUB_STEP_SUMMARY)",
    )
    args = parser.parse_args(argv)

    packages = load_manifest(ROOT)
    print(f"Root: {ROOT}")
    print(f"Declared packages: {len(packages)} ({sum(p.published for p in packages)} expected published)")

    # Structural first: these need no network, so an offline run still catches
    # a manifest that has drifted from the workflow it describes.
    failures = _check_manifest_matches_workflow(packages, ROOT) + _check_directories_exist(packages, ROOT)
    if failures:
        _report(failures)
        return 1

    observed: dict[str, set[str] | None] = {}
    for package in packages:
        try:
            observed[package.slug] = registry_versions(package.registry, package.name)
        except Offline as exc:
            if args.require_network:
                print(f"ERROR: {exc}", file=sys.stderr)
                return 1
            print(f"SKIP: {exc} — structural checks passed; registry state not established.")
            return 0

    failures = _check_registry_state(packages, observed, ROOT) + _check_prose(packages, observed, ROOT)

    if args.summary:
        with open(args.summary, "a", encoding="utf-8") as handle:
            handle.write(summary_markdown(packages, observed, ROOT))

    if failures:
        _report(failures)
        return 1

    live = sum(1 for p in packages if observed[p.slug] is not None)
    print(f"OK: registry state matches the manifest ({live}/{len(packages)} published).")
    return 0


def _report(failures: list[str]) -> None:
    print("PUBLISHED-PACKAGES GATE FAILED:", file=sys.stderr)
    for failure in failures:
        print(f"  - {failure}", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
