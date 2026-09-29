"""A package README must not imply an install command that cannot resolve.

None of the eight first-party packages has ever been uploaded. The release
workflow's publish jobs reported **success** anyway, because only the final
upload step is credential-gated and the repository's sole secret is
`FLY_API_TOKEN` — so each job ran, skipped the upload, and went green. Asking
the registries is the only way to know: all eight return 404.

That is a deliberate, documented state and not a defect. The defect is what
the READMEs said about it. Four of them offered the install command under the
heading `v8.0+ (once <package> lands on PyPI)`, and v8.0 shipped four major
versions ago — so by v12 the label read as "this should already work" rather
than "not yet". A reader runs it, gets `No matching distribution found`, and
concludes the project is broken.

This gate holds the two together: for every package that is *not* on its
registry, the README that advertises it must say so in the present tense. If
a package is later published, the gate stops requiring the disclaimer for it
rather than needing to be edited — so publishing cannot leave a stale "not
yet" behind either.

The package list, the registry query and the accepted wording all come from
`scripts/check_published_packages.py`, which reads
`.github/release-packages.yml`. This file used to carry its own copy of all
three, covering five of the eight packages — two descriptions of the same
fact, free to drift, and drifted: `aisoc`, `@aisoc/mcp` and `aisoc-detections`
were never checked here at all, and `packages/aisoc-lite/README.md` was
advertising `npx aisoc triage --demo` with no caveat as a result.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
_GATE = REPO / "scripts" / "check_published_packages.py"


def _load_gate():
    spec = importlib.util.spec_from_file_location("check_published_packages", _GATE)
    module = importlib.util.module_from_spec(spec)
    # Registered before execution: `@dataclass` resolves annotations through
    # `sys.modules[cls.__module__]`, and a module that is only ever a local
    # variable is not there, so the decorator raises during import.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


gate = _load_gate()

#: Every package the release workflow uploads, straight from the manifest.
PACKAGES = gate.load_manifest(REPO)

#: Only the ones whose README advertises a command a reader could run.
ADVERTISED = [p for p in PACKAGES if p.install]

#: A label naming a release that has already shipped. It reads as availability
#: rather than as a caveat, which is precisely how these went stale.
STALE_LABEL = re.compile(r"v\d+\.\d+\+?\s*\(once\b", re.I)


def _published(package) -> bool:
    try:
        return gate.is_published(package.registry, package.name)
    except gate.Offline as exc:
        pytest.skip(f"{exc}; cannot establish publication")


@pytest.mark.parametrize("package", ADVERTISED, ids=[p.name for p in ADVERTISED])
def test_an_unpublished_package_says_so(package) -> None:
    readme = package.readme(REPO)
    assert readme.is_file(), f"{package.directory} has no README but the manifest advertises `{package.install}`"
    text = readme.read_text(encoding="utf-8")

    if package.install not in text:
        return  # it does not advertise the command, so there is nothing to qualify

    if _published(package):
        return  # the command resolves; no disclaimer needed, and none required

    lowered = text.lower()
    assert any(d in lowered for d in gate.DISCLAIMERS), (
        f"{readme.relative_to(REPO)} shows `{package.install}` but {package.name} is not on "
        f"{package.registry} (404). Say so in the present tense next to the command."
    )


@pytest.mark.parametrize("package", PACKAGES, ids=[p.name for p in PACKAGES])
def test_no_readme_defers_to_a_release_that_already_shipped(package) -> None:
    """`v8.0+ (once ... lands on PyPI)` on a v12 tree is not a caveat.

    Checked separately from the disclaimer because the two fail differently:
    a missing disclaimer says nothing, while a stale one says something false
    with more confidence than saying nothing would.
    """
    readme = package.readme(REPO)
    if not readme.is_file():
        return
    found = STALE_LABEL.search(readme.read_text(encoding="utf-8"))
    assert not found, (
        f"{readme.relative_to(REPO)} defers publication to {found.group(0)!r}, a release that has shipped. "
        f"The tree is at v{(REPO / 'VERSION').read_text().strip()}."
    )


def test_every_package_the_release_uploads_is_covered_here() -> None:
    """The list is derived, so a new package cannot slip past unnoticed.

    The direction that actually broke. A hardcoded list in this file agreed
    with itself for as long as nobody added a package to `release.yml`, and
    three were already missing from it when this was written.
    """
    declared = {(p.registry, p.name, p.directory) for p in PACKAGES}
    assert declared == gate.workflow_matrix(REPO), (
        "the manifest and release.yml's publish matrices disagree; scripts/check_published_packages.py names the difference"
    )
