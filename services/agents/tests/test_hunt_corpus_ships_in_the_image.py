"""The hunt corpus resolves in the layout the agents image actually has.

Why this is a separate module from ``test_hunt_corpus.py``
---------------------------------------------------------
That suite grades the hunts. It passes whether or not any of them reach a
container, because it runs where every test runs: a source checkout, with
``hunts/`` sitting at the repository root. The image is built with ``context:
./services/agents`` and copies ``app/`` and nothing else, so the repository
root is not in it — and for every release the scheduler logged
``hunt.corpus.missing`` and then ``corpus_loaded count=0`` while this suite
was green.

So the thing to test is the resolution, in the layout that failed: a tree
holding only what ``COPY app/ ./app/`` brings in. The test builds exactly that
tree and runs the real loader in it, in a subprocess, because an in-process
import would resolve against this checkout no matter what directory it was
pointed at.

``services/agents/Dockerfile`` carries the same assertion so a real build
fails rather than shipping an empty corpus; this is the copy that runs on
every pull request, where no image is built.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from app.hunt.loader import PACKAGED_CORPUS_DIRNAME, HuntCorpus

_AGENTS_ROOT = Path(__file__).resolve().parents[1]
_APP = _AGENTS_ROOT / "app"
_PACKAGED = _APP / "hunt" / PACKAGED_CORPUS_DIRNAME
_REPO_HUNTS = _AGENTS_ROOT.parents[1] / "hunts"

#: What the loader reads, and therefore what "shipped" means here.
_GLOB = "*.yaml"

_PROBE = (
    "import sys;"
    "from app.hunt.loader import HuntCorpus;"
    "c = HuntCorpus();"
    "n = c.reload();"
    "print(f'{n}|{c.directory}');"
    "sys.exit(0 if n > 0 else 1)"
)


class PackagedHuntCorpusTest(unittest.TestCase):
    def test_packaged_copy_is_inside_the_build_context(self) -> None:
        """The copy that ships is under ``services/agents``, which the image sees."""
        self.assertTrue(_PACKAGED.is_dir(), f"{_PACKAGED} does not exist; run scripts/sync_packaged_hunt_corpus.py")
        self.assertEqual(
            _AGENTS_ROOT,
            _PACKAGED.parents[2],
            "the packaged corpus moved outside services/agents and is no longer in the image's build context",
        )
        self.assertGreater(len(list(_PACKAGED.glob(_GLOB))), 0, "the packaged corpus directory holds no hunts")

    def test_packaged_copy_matches_the_source(self) -> None:
        """Both directions. A packaged-only hunt runs in the image and in no test."""
        source = {p.name: p.read_bytes() for p in _REPO_HUNTS.glob(_GLOB)}
        packaged = {p.name: p.read_bytes() for p in _PACKAGED.glob(_GLOB)}
        self.assertTrue(source, f"{_REPO_HUNTS} holds no hunts; this test would otherwise compare two empty sets")
        self.assertEqual(
            sorted(source),
            sorted(packaged),
            "hunts/ and the packaged copy hold different files — run scripts/sync_packaged_hunt_corpus.py",
        )
        for name, body in source.items():
            self.assertEqual(body, packaged[name], f"{name} differs between hunts/ and the packaged copy")

    def test_image_layout_loads_a_non_empty_corpus(self) -> None:
        """A tree holding only ``app/`` — what the image is — still finds hunts.

        This is the assertion that was missing. Under the previous resolver
        this tree produced ``count=0``, and nothing in CI could see it.
        """
        with tempfile.TemporaryDirectory() as raw:
            image = Path(raw)
            shutil.copytree(_APP, image / "app", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
            self.assertFalse(
                (image / "hunts").exists(),
                "the simulated image tree has a repository-root hunts/, so it is not simulating the image",
            )

            result = subprocess.run(
                [sys.executable, "-c", _PROBE],
                cwd=image,
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertEqual(
            0,
            result.returncode,
            f"the agents image layout loads zero hunts.\nstdout: {result.stdout}\nstderr: {result.stderr[-2000:]}",
        )
        count, directory = result.stdout.strip().rsplit("|", 1)
        self.assertGreater(int(count), 0)
        self.assertTrue(
            directory.endswith(f"app/hunt/{PACKAGED_CORPUS_DIRNAME}"),
            f"the image layout resolved {directory!r}, which is not the packaged copy",
        )

    def test_source_checkout_still_prefers_the_repository_corpus(self) -> None:
        """Hot reload for a hunt author is the reason the walk comes first.

        Stated as a test because the two are byte-identical, so nothing else
        would notice if this silently flipped and ``hunts/`` stopped being read.
        """
        self.assertEqual(_REPO_HUNTS.resolve(), HuntCorpus().directory.resolve())


if __name__ == "__main__":
    unittest.main()
