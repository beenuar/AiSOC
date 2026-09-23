"""The built wheel must carry the scaffold templates.

`aisoc plugin new` reads them through `importlib.resources.files("aisoc_cli")`,
so a wheel without them installs cleanly and then fails on first use — the
worst shape of packaging bug, because `pip install` reports success.

This exists because the opposite mistake shipped: `pyproject.toml` declared
`packages = ["src/aisoc_cli"]` *and* a `force-include` mapping the same
templates directory to the same wheel path, so hatchling tried to add each
file twice and refused to build at all:

    ValueError: A second file is being added to the wheel archive at the same
    path: aisoc_cli/templates/connector/README.md.tmpl

Nothing built this wheel except a release tag, so it was invisible until the
release ran, and it would have blocked the first real publish. Removing the
redundant mapping is only safe if something checks the templates still arrive.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_ROOT = PACKAGE_ROOT / "src" / "aisoc_cli" / "templates"

#: The five plugin types `aisoc plugin new --type` accepts.
EXPECTED_TYPES = {"connector", "detection", "enricher", "responder", "widget"}


def _source_templates() -> set[str]:
    return {str(p.relative_to(TEMPLATE_ROOT)) for p in TEMPLATE_ROOT.rglob("*.tmpl")}


def test_the_source_tree_has_a_template_for_every_plugin_type() -> None:
    present = {p.name for p in TEMPLATE_ROOT.iterdir() if p.is_dir()}
    assert EXPECTED_TYPES <= present, f"missing template dirs: {sorted(EXPECTED_TYPES - present)}"


@pytest.mark.skipif(importlib.util.find_spec("build") is None, reason="python -m build is required to build the wheel")
def test_templates_reach_the_wheel(tmp_path: Path) -> None:
    """Build the real wheel and look inside it.

    Slower than inspecting config, and the only check that would have caught
    either the duplicate-path failure or a silently dropped template. A test
    that reads `pyproject.toml` would have declared both fine.
    """
    try:
        subprocess.run(
            [sys.executable, "-m", "build", "--wheel", "--outdir", str(tmp_path)],
            cwd=PACKAGE_ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=600,
        )
    except subprocess.CalledProcessError as exc:  # pragma: no cover - real failure
        pytest.fail(f"wheel build failed:\n{exc.stdout}\n{exc.stderr}")

    wheels = sorted(tmp_path.glob("*.whl"))
    assert wheels, "no wheel was produced"

    in_wheel = {
        name[len("aisoc_cli/templates/") :] for name in zipfile.ZipFile(wheels[-1]).namelist() if name.startswith("aisoc_cli/templates/") and name.endswith(".tmpl")
    }
    missing = _source_templates() - in_wheel
    assert not missing, f"{len(missing)} template(s) are in the source tree but not the wheel: {sorted(missing)[:5]}"

    # And no duplicates, which is the failure that blocked the build.
    names = [n for n in zipfile.ZipFile(wheels[-1]).namelist() if n.startswith("aisoc_cli/")]
    assert len(names) == len(set(names)), "the wheel contains duplicate entries"
