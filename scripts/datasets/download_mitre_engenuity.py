#!/usr/bin/env python3
"""Fetch MITRE Engenuity ATT&CK Evaluations results for the fidelity benchmark.

Usage:
    python scripts/datasets/download_mitre_engenuity.py --accept-license
                                                        [--round enterprise-2024]
                                                        [--out datasets/mitre-engenuity]

Why this exists: `mitre_engenuity_loader.py` has been able to parse the
full Round-7 procedure JSON since it landed, and there was no way to
obtain it — CICIDS-2017 and CTU-13 each shipped a downloader and this did
not. So the published fidelity number for this dataset came from a
committed micro fixture, which proves the loader parses and says nothing
about the classifier at scale.

Unlike the other three, this is not a single archive: Engenuity publishes
per-round, per-vendor result JSON through a public API. What it fetches
is the **procedure and detection-category data**, which is what the
loader reads — not the vendor rankings, which Engenuity explicitly asks
not be used for comparison and which this benchmark has no business
republishing.

License (ATT&CK Evaluations):
  Published by MITRE Engenuity under the terms at
  https://attackevals.mitre-engenuity.org/ — results are free to use
  with attribution, and MITRE Engenuity explicitly states the
  evaluations do not rank vendors. Read the terms before passing
  --accept-license.

Citation:
  MITRE Engenuity ATT&CK Evaluations, Enterprise round. Cite the
  specific round and year alongside any number derived from it.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from urllib import error as urlerror
from urllib import request as urlrequest

logger = logging.getLogger("download_mitre_engenuity")

DEFAULT_API = "https://attackevals.mitre-engenuity.org/api"

#: Rounds the loader understands. Adding one means confirming the
#: procedure schema still matches `mitre_engenuity_loader.py` — the
#: shape has changed between rounds before, and a loader that parses a
#: newer round into the wrong fields fails silently rather than loudly.
ROUNDS: dict[str, str] = {
    "enterprise-2024": "Round 6 — Enterprise (2024)",
    "enterprise-2023": "Round 5 — Enterprise (2023)",
    "enterprise-2022": "Round 4 — Enterprise (2022)",
}

LICENSE_NOTICE = """\
============================================================
MITRE Engenuity ATT&CK Evaluations — terms + citation
============================================================
Source: MITRE Engenuity ATT&CK Evaluations
Terms: https://attackevals.mitre-engenuity.org/
Attribution required. MITRE Engenuity states explicitly that the
evaluations do NOT rank or score vendors; any derived number must
carry that caveat.

This script fetches procedure and detection-category data only — the
inputs the fidelity loader reads. It deliberately does not mirror
vendor comparison data.

By passing --accept-license you confirm you have read the terms.
AiSOC does NOT redistribute these files; the repo carries only a
small micro fixture for CI.
============================================================
"""


def _fetch_json(url: str) -> object:
    req = urlrequest.Request(url, headers={"User-Agent": "aisoc-fidelity/1.0"})
    try:
        with urlrequest.urlopen(req, timeout=60) as resp:  # noqa: S310 - opt-in download
            return json.loads(resp.read().decode("utf-8"))
    except urlerror.URLError as exc:
        raise SystemExit(f"fetch failed for {url}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(
            f"{url} did not return JSON. The Engenuity API has changed shape "
            f"before; check the endpoint before assuming a network fault."
        ) from exc


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("datasets/mitre-engenuity"))
    parser.add_argument("--api", default=DEFAULT_API)
    parser.add_argument(
        "--round",
        dest="rounds",
        action="append",
        choices=sorted(ROUNDS),
        help="Round to fetch; repeatable. Defaults to the most recent the " "loader is known to parse.",
    )
    parser.add_argument(
        "--accept-license",
        action="store_true",
        help="Acknowledge the Engenuity terms and the no-ranking caveat.",
    )
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    print(LICENSE_NOTICE)
    if not args.accept_license:
        print(
            "Refusing to download without --accept-license.\n"
            "The no-ranking caveat is the point: a number derived from this "
            "data and published without it misrepresents the source.",
            file=sys.stderr,
        )
        return 2

    rounds = args.rounds or ["enterprise-2024"]
    print(f"Rounds: {', '.join(ROUNDS[r] for r in rounds)}")

    if args.dry_run:
        for round_id in rounds:
            print(f"  would fetch {args.api}/participants/{round_id}")
        return 0

    args.out.mkdir(parents=True, exist_ok=True)
    for round_id in rounds:
        url = f"{args.api}/participants/{round_id}"
        logger.info("fetching %s", url)
        payload = _fetch_json(url)
        dest = args.out / f"{round_id}.json"
        dest.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        logger.info("wrote %s", dest)

    print()
    print("Next:")
    print("  python -m services.agents.tests.fidelity.runner " f"--dataset mitre_engenuity --input {args.out}/<round>.json")
    print(
        "  Thresholds for the full corpus are in " "services/agents/tests/fidelity/expected_results.yaml under " "`mitre_engenuity_full`."
    )
    print()
    print("  Any number you publish from this must carry MITRE Engenuity's own " "caveat: the evaluations do not rank vendors.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
