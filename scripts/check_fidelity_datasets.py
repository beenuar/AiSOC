#!/usr/bin/env python3
"""Gate: every fidelity dataset is obtainable, and unmeasured floors say so.

Two of the four fidelity datasets shipped a downloader and two did not.
`ait_lds_loader.py` and `mitre_engenuity_loader.py` could parse the full
corpora from the day they landed, and there was no way to obtain either —
so the only numbers anyone could produce came from a ten-line micro
fixture. A micro fixture proves the loader parses. It says nothing about
how the classifier behaves at scale, which is the entire question a
fidelity benchmark exists to answer.

The asymmetry was invisible because each half looked complete on its own:
the loaders had tests, the fixtures had thresholds, and nothing compared
the set of loaders against the set of downloaders.

This checks three things:

  1. Every dataset with a loader has a downloader.
  2. Every downloader requires explicit licence acceptance. These are
     third-party corpora under attribution terms, and a script that
     fetches one without the operator reading them agrees to terms on
     their behalf.
  3. A threshold block marked `measured: false` is not presented
     anywhere as an observed result.

Run:  python3 scripts/check_fidelity_datasets.py
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from gate_toolkit import repo_root, self_test_if_requested

self_test_if_requested(__file__)

try:
    import yaml
except ImportError:  # pragma: no cover
    print("PyYAML is required: pip install pyyaml", file=sys.stderr)
    raise SystemExit(2) from None

REPO_ROOT = repo_root()
FIDELITY = REPO_ROOT / "services" / "agents" / "tests" / "fidelity"
DOWNLOADS = REPO_ROOT / "scripts" / "datasets"
THRESHOLDS = FIDELITY / "expected_results.yaml"
BENCHMARK_DOCS = (
    REPO_ROOT / "apps" / "docs" / "docs" / "benchmark.md",
    REPO_ROOT / "apps" / "docs" / "docs" / "benchmark-fidelity.md",
)


def loaders() -> set[str]:
    """Dataset names that have a loader module."""
    return {path.stem.removesuffix("_loader") for path in FIDELITY.glob("*_loader.py")}


def downloaders() -> set[str]:
    return {path.stem.removeprefix("download_") for path in DOWNLOADS.glob("download_*.py")}


def check_every_loader_can_be_fed() -> list[str]:
    missing = sorted(loaders() - downloaders())
    return [
        f"{name}: has a loader ({name}_loader.py) and no downloader. The full "
        f"corpus cannot be obtained, so any published number for it comes from "
        f"a micro fixture — which proves the loader parses and nothing else."
        for name in missing
    ]


def check_downloaders_require_licence_acceptance() -> list[str]:
    errors: list[str] = []
    for path in sorted(DOWNLOADS.glob("download_*.py")):
        source = path.read_text(encoding="utf-8")
        if "--accept-license" not in source:
            errors.append(
                f"{path.name}: does not require --accept-license. These are "
                f"third-party corpora under attribution terms; fetching one "
                f"without the operator reading them agrees on their behalf."
            )
        if "Citation" not in source and "citation" not in source:
            errors.append(
                f"{path.name}: carries no citation. Attribution is a licence " f"condition for every dataset here, not a courtesy."
            )
    return errors


def check_unmeasured_floors_are_not_published() -> list[str]:
    """A floor nobody has run must not appear as an observed number."""
    if not THRESHOLDS.exists():
        return [f"{THRESHOLDS.relative_to(REPO_ROOT)} is missing"]

    data = yaml.safe_load(THRESHOLDS.read_text(encoding="utf-8")) or {}
    unmeasured = {name for name, entry in data.items() if isinstance(entry, dict) and entry.get("measured") is False}
    if not unmeasured:
        return []

    errors: list[str] = []
    for name in sorted(unmeasured):
        entry = data[name]
        notes = str(entry.get("notes") or "").strip()
        # Must *lead* with the marker. Matching it anywhere passed a note
        # whose third paragraph happened to use the word in passing — a
        # caveat a reader reaches after two paragraphs is not a caveat.
        if not notes.upper().startswith("UNMEASURED"):
            errors.append(
                f"{name}: marked measured:false but its notes do not open "
                f"with UNMEASURED. A reader looking at the floor cannot tell "
                f"it from an observed result."
            )

        # And it must not be quoted as a result in the published docs.
        dataset = str(entry.get("dataset") or name)
        for doc in BENCHMARK_DOCS:
            if not doc.exists():
                continue
            text = doc.read_text(encoding="utf-8")
            pattern = re.compile(
                rf"{re.escape(dataset)}[^\n]*\bfull\b[^\n]*\d+(?:\.\d+)?\s*%",
                re.IGNORECASE,
            )
            if pattern.search(text):
                errors.append(
                    f"{name}: {doc.name} quotes a full-corpus percentage for "
                    f"{dataset}, but the threshold block says it was never "
                    f"measured."
                )
    return errors


def main(argv: list[str] | None = None) -> int:
    argparse.ArgumentParser(description=__doc__).parse_args(argv)

    if not FIDELITY.is_dir():
        print("fidelity-datasets: harness directory not found", file=sys.stderr)
        return 2

    errors = check_every_loader_can_be_fed() + check_downloaders_require_licence_acceptance() + check_unmeasured_floors_are_not_published()

    if errors:
        print("FIDELITY DATASET GATE FAILED:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    found = sorted(loaders())
    data = yaml.safe_load(THRESHOLDS.read_text(encoding="utf-8")) or {}
    unmeasured = [name for name, entry in data.items() if isinstance(entry, dict) and entry.get("measured") is False]
    print(f"fidelity-datasets: OK — {len(found)} dataset(s) with a loader " f"({', '.join(found)}), each with a licence-gated downloader")
    if unmeasured:
        print(f"  {len(unmeasured)} full-corpus floor(s) not yet measured: " f"{', '.join(sorted(unmeasured))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
