"""The gate that keeps the rule catalogue readable has to be able to fail.

`scripts/sync_packaged_detection_rulesets.py --check` is the only thing
standing between the API image and the state issue #1273 reported: a console
that lists no detection rules while the engine loads and fires 2,586. A gate
whose clean verdict has never been shown to be falsifiable is worth nothing,
and the failure it must catch is a *packaging* one — a file absent from a
Docker build context — which no handler test can see.

So every case below runs the real program against a fabricated tree through
`AISOC_REPO_ROOT`, and asserts it exits non-zero. One of them is the positive
control: an untouched tree must still pass, or "fails on everything" would
read identically to "fails on the right things".

The sixth case is the one that is easy to leave out. A one-directional check
compares the packaged copy against the source and never the reverse, so a
file that exists *only* on the packaged side — a rule the engine does not
load — passes silently. Listing rules that do not fire is worse than listing
none, which is the whole reason this gate exists.
"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
GATE = REPO / "scripts" / "sync_packaged_detection_rulesets.py"
FUSION_DATA = pathlib.Path("services/fusion/app/data")
PACKAGED = pathlib.Path("services/api/app/data/detections")
WINDOWED_SOURCE = pathlib.Path("services/fusion/app/services/windowed_detection.py")

ARTEFACTS = (
    "detection_ruleset.json",
    "detection_ruleset_imported.json",
    "windowed_ruleset.json",
)
GENERATED = "windowed_builtin_rules.json"


def _tree(tmp_path: pathlib.Path) -> pathlib.Path:
    """A minimal checkout holding only what the gate reads."""
    root = tmp_path / "tree"
    (root / FUSION_DATA).mkdir(parents=True)
    (root / PACKAGED).mkdir(parents=True)
    (root / WINDOWED_SOURCE.parent).mkdir(parents=True, exist_ok=True)

    for name in ARTEFACTS:
        shutil.copy2(REPO / FUSION_DATA / name, root / FUSION_DATA / name)
        shutil.copy2(REPO / PACKAGED / name, root / PACKAGED / name)
    shutil.copy2(REPO / PACKAGED / GENERATED, root / PACKAGED / GENERATED)
    shutil.copy2(REPO / WINDOWED_SOURCE, root / WINDOWED_SOURCE)
    return root


def _check(root: pathlib.Path) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "AISOC_REPO_ROOT": str(root)}
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, str(GATE), "--check"],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )


class TestThePositiveControl:
    """An untouched tree passes, so the failures below mean something."""

    def test_a_synced_tree_is_clean(self, tmp_path: pathlib.Path) -> None:
        result = _check(_tree(tmp_path))
        assert result.returncode == 0, result.stderr
        assert "2586 rules" in result.stdout


class TestTheGateCatchesItsOwnAbsence:
    @pytest.mark.parametrize("name", [*ARTEFACTS, GENERATED])
    def test_a_missing_packaged_copy_fails(self, tmp_path: pathlib.Path, name: str) -> None:
        """The exact state the API image shipped in: the file is not there."""
        root = _tree(tmp_path)
        (root / PACKAGED / name).unlink()

        result = _check(root)
        assert result.returncode != 0
        assert name in result.stderr
        assert "build context" in result.stderr

    def test_a_stale_packaged_copy_fails(self, tmp_path: pathlib.Path) -> None:
        """Regenerating the corpus without re-syncing is the likely drift."""
        root = _tree(tmp_path)
        target = root / PACKAGED / "detection_ruleset.json"
        payload = json.loads(target.read_text(encoding="utf-8"))
        payload["rules"] = payload["rules"][:-1]
        payload["count"] = len(payload["rules"])
        target.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

        result = _check(root)
        assert result.returncode != 0
        assert "different corpora" in result.stderr

    def test_a_stale_export_of_the_python_resident_rules_fails(self, tmp_path: pathlib.Path) -> None:
        """A fourth hardcoded windowed rule must not go unnoticed.

        `_BUILTIN_RULES` is the one input with no committed source artefact,
        so nothing but this comparison would catch a rule added there.
        """
        root = _tree(tmp_path)
        source = root / WINDOWED_SOURCE
        text = source.read_text(encoding="utf-8")
        addition = (
            "    WindowRule(\n"
            '        id="wd-invented-for-this-test",\n'
            '        name="Invented",\n'
            '        severity="low",\n'
            '        category="network",\n'
            '        mitre=["T1046"],\n'
            '        match_when={"event_type": "network"},\n'
            '        group_by="src_ip",\n'
            "        threshold=3,\n"
            "        window_seconds=60,\n"
            "    ),\n)"
        )
        marker = "        window_seconds=120,\n    ),\n)"
        assert marker in text, "the _BUILTIN_RULES literal changed shape; update this control"
        source.write_text(text.replace(marker, "        window_seconds=120,\n    ),\n" + addition), encoding="utf-8")

        result = _check(root)
        assert result.returncode != 0
        assert GENERATED in result.stderr

    def test_a_packaged_file_with_no_source_fails(self, tmp_path: pathlib.Path) -> None:
        """The direction a one-directional gate misses.

        An artefact only the API carries describes rules the engine never
        loads. The catalogue would offer them, an operator would disable one,
        and nothing would change.
        """
        root = _tree(tmp_path)
        (root / PACKAGED / "detection_ruleset_invented.json").write_text(json.dumps({"count": 0, "rules": []}), encoding="utf-8")

        result = _check(root)
        assert result.returncode != 0
        assert "no counterpart" in result.stderr

    def test_an_unreadable_source_refuses_rather_than_passing(self, tmp_path: pathlib.Path) -> None:
        """Scanning nothing and finding nothing must not print the same word."""
        root = _tree(tmp_path)
        (root / FUSION_DATA / "detection_ruleset.json").unlink()

        result = _check(root)
        assert result.returncode == 2
        assert "nothing to package" in result.stderr
