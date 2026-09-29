"""A package README must not imply an install command that cannot resolve.

None of the eight first-party packages has ever been uploaded. The release
workflow's publish jobs report **success** anyway, because only the final
upload step is credential-gated and the repository's sole secret is
`FLY_API_TOKEN` — so the job runs, skips the upload, and goes green. Asking
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
"""

from __future__ import annotations

import json
import pathlib
import re
import urllib.error
import urllib.request

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]

#: (README, registry, distribution name, the install command it advertises).
PACKAGES: tuple[tuple[str, str, str, str], ...] = (
    ("packages/sdk-py/README.md", "pypi", "aisoc-sdk", "pip install aisoc-sdk"),
    ("packages/aisoc-cli/README.md", "pypi", "aisoc-cli", "pip install aisoc-cli"),
    ("packages/plugin-sdk-py/README.md", "pypi", "aisoc-plugin-sdk", "pip install aisoc-plugin-sdk"),
    ("packages/aisoc-sandbox/README.md", "pypi", "aisoc-sandbox", "pip install aisoc-sandbox"),
    ("packages/sdk-ts/README.md", "npm", "@aisoc/sdk", "npm install @aisoc/sdk"),
)

#: Wording that tells a reader, in the present tense, that the command above
#: will not resolve yet. Any one of these satisfies the gate — the point is
#: that the reader is warned, not that a particular sentence is used.
DISCLAIMERS = ("not yet on pypi", "not yet on npm", "ready, unpublished", "will not resolve")

#: A label naming a release that has already shipped. It reads as availability
#: rather than as a caveat, which is precisely how these went stale.
STALE_LABEL = re.compile(r"v\d+\.\d+\+?\s*\(once\b", re.I)


def _published(registry: str, name: str) -> bool:
    url = f"https://pypi.org/pypi/{name}/json" if registry == "pypi" else f"https://registry.npmjs.org/{name.replace('/', '%2f')}"
    try:
        with urllib.request.urlopen(url, timeout=20) as response:  # noqa: S310 - fixed https hosts
            return response.status == 200 and bool(json.loads(response.read() or b"{}"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return False
        pytest.skip(f"{registry} answered {exc.code} for {name}; cannot establish publication")
    except OSError as exc:
        pytest.skip(f"no network to {registry} ({exc}); cannot establish publication")
    return False


@pytest.mark.parametrize("relative,registry,name,command", PACKAGES, ids=[p[2] for p in PACKAGES])
def test_an_unpublished_package_says_so(relative: str, registry: str, name: str, command: str) -> None:
    readme = REPO / relative
    assert readme.is_file(), f"{relative} is gone but still listed here"
    text = readme.read_text(encoding="utf-8")

    if command not in text:
        return  # it does not advertise the command, so there is nothing to qualify

    if _published(registry, name):
        return  # the command resolves; no disclaimer needed, and none required

    lowered = text.lower()
    assert any(d in lowered for d in DISCLAIMERS), (
        f"{relative} shows `{command}` but {name} is not on {registry} (404). Say so in the present tense next to the command."
    )


@pytest.mark.parametrize("relative", [p[0] for p in PACKAGES], ids=[p[2] for p in PACKAGES])
def test_no_readme_defers_to_a_release_that_already_shipped(relative: str) -> None:
    """`v8.0+ (once ... lands on PyPI)` on a v12 tree is not a caveat.

    Checked separately from the disclaimer because the two fail differently:
    a missing disclaimer says nothing, while a stale one says something false
    with more confidence than saying nothing would.
    """
    text = (REPO / relative).read_text(encoding="utf-8")
    found = STALE_LABEL.search(text)
    assert not found, (
        f"{relative} defers publication to {found.group(0)!r}, a release that has shipped. "
        f"The tree is at v{(REPO / 'VERSION').read_text().strip()}."
    )
