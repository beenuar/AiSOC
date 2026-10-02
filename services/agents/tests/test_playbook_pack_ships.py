"""The playbook pack must be inside the package, not beside the repo.

`playbooks/packs/v1/` holds 62 production playbooks, and the agents image
shipped **zero** of them. `services/agents/Dockerfile` has a build
context of `services/agents` and copies only `app/`; a build context
cannot reach outside itself, so the loader resolved a path that does not
exist in a container.

Nothing said so. The loader's pack branch is guarded by
`if self._pack_root.exists()`, which makes an absent pack indistinguishable
from an empty one — a deployment's playbook library was 62 entries
shorter than the repository's with no error anywhere.

These tests fail if that regresses.
"""

from __future__ import annotations

from pathlib import Path

from app.playbook.store import _DEFAULT_PACK_ROOT, PlaybookStore

#: The count at the time of writing. Asserted as a floor rather than an
#: equality so adding a playbook does not fail the build, while removing
#: the pack — the actual failure mode — still does.
EXPECTED_AT_LEAST = 62


def test_the_pack_resolves_inside_the_installed_package() -> None:
    """A path outside `app/` is a path no container has."""
    resolved = Path(_DEFAULT_PACK_ROOT).resolve()
    assert "app/playbook/packs" in resolved.as_posix(), (
        f"the pack root is {resolved}, which is outside the package. The agents image "
        "copies only app/, so a pack resolved anywhere else ships as zero playbooks."
    )


def test_the_pack_is_not_empty() -> None:
    found = list(Path(_DEFAULT_PACK_ROOT).rglob("*.playbook.json"))
    assert len(found) >= EXPECTED_AT_LEAST, f"found {len(found)} pack playbooks, expected at least {EXPECTED_AT_LEAST}"


def test_the_store_actually_loads_them() -> None:
    """Resolving the path and parsing the files are different claims."""
    store = PlaybookStore.default()
    assert len(store._playbooks) >= EXPECTED_AT_LEAST, (
        f"the store loaded {len(store._playbooks)} playbooks; a pack that resolves but does not parse is still a pack nobody can run"
    )
