#!/usr/bin/env python3
"""Ship the hunt library inside the agents image, and keep it identical.

Why this exists
---------------
``docker-compose.yml`` builds the agents service with ``context:
./services/agents``, and ``services/agents/Dockerfile`` copies ``app/`` and
nothing else. The 68-hunt library lives at ``hunts/`` in the repository root,
which is *outside* that build context, so no ``COPY`` could ever have reached
it. Measured against a running stack: ``docker exec aisoc-agents ls
/app/hunts`` answers "No such file or directory", the boot log reads
``hunt.corpus.missing`` and then ``hunt.scheduler.corpus_loaded count=0``, and
the README maturity table calls the library Stable.

The reason it looked fine is the part worth remembering.
``app/hunt/loader.py`` walks its parents for a sibling ``hunts/`` and then
falls back to "the conventional host layout" — a source checkout. Every test
and every CI gate runs in a source checkout, so all of them find the corpus
and none of them describe the image.

This is the same build-context class as the compiled detection corpus
(``scripts/sync_packaged_detection_rulesets.py``, #1273) and as
``marketplace/index.json`` before it, and it is solved the same way rather
than with a second mechanism: a copy committed inside the build context, with
a gate holding the two byte-identical.

Direction
---------
``hunts/`` is the source of truth; ``services/agents/app/hunt/corpus/`` is
derived. ``--check`` compares in **both** directions — a file added under the
packaged directory and not to the source fails too, because a one-directional
gate passes while drift accumulates in the direction things actually change.

The other half of the claim
---------------------------
Byte-identity proves the files agree. It does not prove the image *loads*
them: a rename of the packaged directory, or a ``COPY`` that stops covering
it, would leave two identical trees and a container with zero hunts. So this
also asserts that ``services/agents/Dockerfile`` carries the build-time
assertion that fails the image build when the corpus loads nothing, and that
``loader.py`` still names this directory. Those three together are what make
"the image ships the hunt library" a checked claim rather than a hopeful one.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_if_requested  # noqa: E402

self_test_if_requested(__file__)

REPO = repo_root()
SOURCE = REPO / "hunts"
PACKAGED = REPO / "services" / "agents" / "app" / "hunt" / "corpus"
LOADER = REPO / "services" / "agents" / "app" / "hunt" / "loader.py"
DOCKERFILE = REPO / "services" / "agents" / "Dockerfile"

#: What the loader reads. ``HuntCorpus.reload()`` globs ``*.yaml`` and nothing
#: else, so copying ``*.yml`` as well would package files the engine never
#: opens — the same "catalogue lists what the engine does not load" defect
#: this change exists to close, one directory over.
SUFFIX = "*.yaml"

#: The constant in ``loader.py`` that has to point here. Named rather than
#: pattern-matched so a rename on either side is a failure and not a silent
#: fallback to the source-checkout path, which exists on every machine that
#: runs this gate and on no deployment.
LOADER_CONSTANT = "PACKAGED_CORPUS_DIRNAME"

#: The marker the Dockerfile assertion carries. The assertion itself is a
#: ``RUN python -c`` that loads the corpus and exits non-zero on zero hunts;
#: this gate only has to know that it is still there.
DOCKERFILE_MARKER = "hunt.corpus.packaged-assert"


class SyncError(RuntimeError):
    """The sync could not run, which is not the same as a clean result."""


def _payloads() -> dict[str, bytes]:
    """What the packaged directory must contain, keyed by file name."""
    if not SOURCE.is_dir():
        raise SyncError(f"{SOURCE.relative_to(REPO)} is missing; there is nothing to package and nothing to compare")

    out: dict[str, bytes] = {}
    for path in sorted(SOURCE.glob(SUFFIX)):
        body = path.read_bytes()
        if not body.strip():
            raise SyncError(f"{path.relative_to(REPO)} is empty")
        out[path.name] = body

    if not out:
        raise SyncError(
            f"{SOURCE.relative_to(REPO)} holds no {SUFFIX} files. Finding nothing and reading nothing print the "
            "same word, so this refuses rather than reporting a clean sync of an empty corpus."
        )
    return out


def _loader_names_the_directory() -> str | None:
    """The directory name ``loader.py`` declares, read statically.

    ``ast`` rather than an import: ``loader.py`` pulls in pydantic and PyYAML,
    and this gate runs on a bare interpreter alongside the others.
    """
    if not LOADER.is_file():
        raise SyncError(f"{LOADER.relative_to(REPO)} is missing; the loader this gate is about does not exist")

    tree = ast.parse(LOADER.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        targets: list[ast.expr] = []
        if isinstance(node, ast.Assign):
            targets = list(node.targets)
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
        else:
            continue
        for target in targets:
            if isinstance(target, ast.Name) and target.id == LOADER_CONSTANT and node.value is not None:
                try:
                    value = ast.literal_eval(node.value)
                except ValueError:
                    return None
                return value if isinstance(value, str) else None
    return None


def write() -> int:
    payloads = _payloads()
    PACKAGED.mkdir(parents=True, exist_ok=True)

    # Written before the strays are removed so an interrupted run leaves a
    # superset rather than a gap: `--check` fails loudly on an extra file and
    # silently-correct-looking on a missing one is the worse of the two.
    for name, body in payloads.items():
        (PACKAGED / name).write_bytes(body)
    for stray in sorted(PACKAGED.iterdir()):
        if stray.is_file() and stray.name not in payloads:
            stray.unlink()

    print(f"sync_packaged_hunt_corpus: wrote {len(payloads)} hunt(s) to {PACKAGED.relative_to(REPO)}")
    return 0


def check() -> int:
    payloads = _payloads()
    errors: list[str] = []

    if not PACKAGED.is_dir():
        # One line rather than one per hunt. Sixty-eight copies of the same
        # sentence buries the two findings underneath it, which is how a gate
        # that is technically correct still fails to say what is wrong.
        errors.append(
            f"{PACKAGED.relative_to(REPO)} does not exist, so none of the {len(payloads)} hunts in "
            f"{SOURCE.relative_to(REPO)} are inside the agents build context and the scheduler loads zero of them "
            "in every container. Run `python3 scripts/sync_packaged_hunt_corpus.py`."
        )
    else:
        missing: list[str] = []
        for name, expected in payloads.items():
            destination = PACKAGED / name
            if not destination.is_file():
                missing.append(name)
                continue
            actual = destination.read_bytes()
            if actual != expected:
                errors.append(
                    f"{name}: the packaged copy ({hashlib.sha256(actual).hexdigest()[:12]}) and the source "
                    f"({hashlib.sha256(expected).hexdigest()[:12]}) are different hunts. Run "
                    "`python3 scripts/sync_packaged_hunt_corpus.py`."
                )
        if missing:
            errors.append(
                f"{len(missing)} hunt(s) in {SOURCE.relative_to(REPO)} have no packaged copy and therefore run in no "
                f"container: {', '.join(missing[:5])}{'…' if len(missing) > 5 else ''}. Run "
                "`python3 scripts/sync_packaged_hunt_corpus.py`."
            )

    # The other direction. A hunt that exists only on the packaged side runs in
    # every container and in no test, which is the harder failure to find.
    if PACKAGED.is_dir():
        for stray in sorted(PACKAGED.iterdir()):
            if stray.is_file() and stray.name not in payloads:
                errors.append(
                    f"{stray.relative_to(REPO)} has no counterpart in {SOURCE.relative_to(REPO)}; it would run in "
                    "the image and in nothing else"
                )

    declared = _loader_names_the_directory()
    if declared is None:
        errors.append(
            f"{LOADER.relative_to(REPO)} no longer declares {LOADER_CONSTANT}. Without it the loader falls back to "
            "the source-checkout layout, which exists on every machine running this gate and on no deployment."
        )
    elif declared != PACKAGED.name:
        errors.append(
            f"{LOADER.relative_to(REPO)} points {LOADER_CONSTANT} at {declared!r} while this gate packages "
            f"{PACKAGED.name!r}; the image would ship a directory nothing reads"
        )

    if not DOCKERFILE.is_file():
        errors.append(f"{DOCKERFILE.relative_to(REPO)} is missing")
    elif DOCKERFILE_MARKER not in DOCKERFILE.read_text(encoding="utf-8"):
        errors.append(
            f"{DOCKERFILE.relative_to(REPO)} no longer carries the {DOCKERFILE_MARKER} assertion. Identical files "
            "prove the two trees agree, not that the image loads them; that assertion is what fails the build when "
            "the corpus resolves to zero hunts."
        )

    if errors:
        print("PACKAGED HUNT CORPUS SYNC FAILED:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    print(f"sync_packaged_hunt_corpus: OK — {len(payloads)} identical hunt(s) in {PACKAGED.relative_to(REPO)}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if the packaged copies are missing, stale or extra")
    args = parser.parse_args(argv)
    try:
        return check() if args.check else write()
    except SyncError as exc:
        print(f"sync_packaged_hunt_corpus: FAILED to run: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
