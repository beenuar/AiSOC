"""Detection-import orchestrator.

Runs every importer in ``tools.detection_import`` against its pinned upstream
commit and writes converted rules into the appropriate ``detections/<source>-
imports/`` directory.

Pinned commits live in this file, *deliberately* — bumping them is a code
review event so we know exactly which upstream snapshot we ship. To upgrade
an importer:

1. Update the ``*_COMMIT`` constant below.
2. Run ``python3 -m tools.detection_import.import_orchestrator``.
3. Run ``python3 scripts/validate_detections.py``.
4. Run ``pnpm marketplace:build && pnpm marketplace:check``.
5. Commit the ``detections/<source>-imports/`` diff together with the
   commit bump.

Run with no args to import everything. Pass ``--source sigmahq`` (or any
subset) to import a single source. Use ``--list`` to print the registered
sources.
"""

from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Callable
from dataclasses import dataclass

from tools.detection_import import (
    car_importer,
    chronicle_importer,
    sigma_importer,
    splunk_importer,
)
from tools.detection_import.common import ImportedRule

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pinned upstream commits.
#
# These are the *exact* SHAs we ship rules from. Update these in a dedicated
# PR so reviewers can see the upstream diff that lands.
# ---------------------------------------------------------------------------
# SHAs were verified against the upstream remotes on 2026-05-04. Bump them
# in a dedicated PR so reviewers can read the upstream diff alongside the
# imported-rule diff.
SIGMA_COMMIT = "df5c6a6ecc149e05cb4dea306012668fb2ae5a12"  # SigmaHQ/sigma master
CAR_COMMIT = "1b922fe1527d956e222a99473472e594f10f610b"  # mitre-attack/car master
SPLUNK_COMMIT = "4d4c7ee091459bcf9649202c27336f681d8a2304"  # splunk/security_content develop
CHRONICLE_COMMIT = "74dd490c3043fc2ce406dea00265b115b826509f"  # chronicle/detection-rules main


@dataclass
class Source:
    """One registered upstream source."""

    name: str
    commit: str
    runner: Callable[[str], list[ImportedRule]]


SOURCES: list[Source] = [
    Source(
        name="sigmahq",
        commit=SIGMA_COMMIT,
        runner=lambda commit: sigma_importer.import_rules(commit),
    ),
    Source(
        name="car",
        commit=CAR_COMMIT,
        runner=lambda commit: car_importer.import_rules(commit),
    ),
    Source(
        name="splunk",
        commit=SPLUNK_COMMIT,
        runner=lambda commit: splunk_importer.import_rules(commit),
    ),
    Source(
        name="chronicle",
        commit=CHRONICLE_COMMIT,
        runner=lambda commit: chronicle_importer.import_rules(commit),
    ),
]


def run(selected: list[str] | None = None) -> dict[str, int]:
    """Run the requested importers and return ``{source: count}``.

    ``selected`` may be ``None`` (run all) or a list of source names to
    include. Unknown names raise ``ValueError`` so typos fail loudly.
    """
    if selected is not None:
        known = {s.name for s in SOURCES}
        unknown = [name for name in selected if name not in known]
        if unknown:
            raise ValueError(
                f"Unknown source(s): {', '.join(unknown)}. "
                f"Known: {', '.join(sorted(known))}"
            )

    results: dict[str, int] = {}
    for source in SOURCES:
        if selected is not None and source.name not in selected:
            continue
        logger.info("→ Importing %s @ %s", source.name, source.commit[:12])
        try:
            rules = source.runner(source.commit)
        except Exception:
            logger.exception("Importer %s failed; continuing", source.name)
            results[source.name] = 0
            continue
        results[source.name] = len(rules)
        logger.info("  %s: %d rules", source.name, len(rules))
    return results


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run AiSOC detection-rule importers.",
    )
    parser.add_argument(
        "--source",
        action="append",
        dest="sources",
        help=(
            "Only run the named source. Repeatable. "
            "Defaults to running every source."
        ),
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List registered sources and pinned commits, then exit.",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Verbose (DEBUG) logging.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s :: %(message)s",
    )

    if args.list:
        for source in SOURCES:
            print(f"{source.name:<10}  {source.commit}")
        return 0

    results = run(args.sources)
    total = sum(results.values())
    print()
    print("Import summary")
    print("--------------")
    for name, count in results.items():
        print(f"  {name:<10}  {count} rules")
    print(f"  {'TOTAL':<10}  {total} rules")
    return 0


if __name__ == "__main__":
    sys.exit(main())
