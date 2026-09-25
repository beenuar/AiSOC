#!/usr/bin/env python3
"""Download the AIT Log Data Set V2 for the AiSOC fidelity benchmark.

Usage:
    python scripts/datasets/download_ait_lds.py --accept-license
                                                [--out datasets/ait-lds]
                                                [--scenario fox]

Why this exists: `services/agents/tests/fidelity/ait_lds_loader.py` has
been able to parse the full corpus since it landed, and there was no way
to obtain it. CICIDS-2017 and CTU-13 each shipped a downloader; AIT-LDS
and MITRE Engenuity did not, so their fidelity numbers came only from a
committed micro fixture — which is enough to prove the loader parses and
nothing about how the classifier behaves at scale.

That asymmetry is the gap this closes. It does not by itself produce a
full-corpus number: running it is a local, opt-in step, and the harness
says so rather than implying CI measured something it did not.

We do not redistribute AIT-LDS. The repo carries a small `access.log`
micro fixture for CI; this fetches the real thing on request.

License (AIT Log Data Set V2):
  Published by the Austrian Institute of Technology under
  CC BY 4.0. Attribution is required; commercial use is permitted
  under the licence terms. Read them at
  https://zenodo.org/records/5789064 before passing --accept-license.

Citation:
  Landauer, M., Skopik, F., Frank, M., Hotwagner, W., Wurzenberger, M.,
  & Rauber, A. (2023). Maintainable Log Datasets for Evaluation of
  Intrusion Detection Systems. IEEE Transactions on Dependable and
  Secure Computing.
"""

from __future__ import annotations

import argparse
import hashlib
import logging
import sys
from pathlib import Path
from urllib import error as urlerror
from urllib import request as urlrequest

logger = logging.getLogger("download_ait_lds")

#: Zenodo record for AIT-LDS V2. Override with --mirror if the record
#: is superseded; Zenodo assigns a new id per version rather than
#: mutating the old one, so a stale default fails loudly with a 404
#: instead of silently fetching different data.
DEFAULT_MIRROR = "https://zenodo.org/records/5789064/files"

#: One archive per scenario. Hashes are `None` because we have not
#: pinned them — the same honesty convention `download_cicids.py` uses:
#: an unpinned hash means "we have not verified this", and the script
#: says so rather than implying a check it cannot perform.
SCENARIOS: dict[str, dict[str, object]] = {
    "fox": {"file": "fox.zip", "sha256": None, "approx_gb": 3.2},
    "harrison": {"file": "harrison.zip", "sha256": None, "approx_gb": 2.8},
    "russellmitchell": {"file": "russellmitchell.zip", "sha256": None, "approx_gb": 1.4},
    "santos": {"file": "santos.zip", "sha256": None, "approx_gb": 2.1},
    "shaw": {"file": "shaw.zip", "sha256": None, "approx_gb": 1.9},
    "wardbeck": {"file": "wardbeck.zip", "sha256": None, "approx_gb": 2.4},
    "wheeler": {"file": "wheeler.zip", "sha256": None, "approx_gb": 2.2},
    "wilson": {"file": "wilson.zip", "sha256": None, "approx_gb": 2.6},
}

LICENSE_NOTICE = """\
============================================================
AIT Log Data Set V2 — license + citation
============================================================
Dataset: AIT Log Data Set V2
Publisher: Austrian Institute of Technology (AIT)
Licence: CC BY 4.0 — attribution required
Terms: https://zenodo.org/records/5789064
Citation:
  Landauer, M., Skopik, F., Frank, M., Hotwagner, W.,
  Wurzenberger, M., & Rauber, A. (2023). Maintainable Log Datasets
  for Evaluation of Intrusion Detection Systems. IEEE TDSC.

By passing --accept-license you confirm you have read and agreed to
the upstream terms. AiSOC does NOT redistribute these files; the repo
carries only a small micro fixture for CI.
============================================================
"""


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _download(url: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    logger.info("downloading %s -> %s", url, dest)
    req = urlrequest.Request(url, headers={"User-Agent": "aisoc-fidelity/1.0"})
    try:
        with urlrequest.urlopen(req, timeout=120) as resp:  # noqa: S310 - opt-in download
            with dest.open("wb") as fh:
                while True:
                    chunk = resp.read(1 << 20)
                    if not chunk:
                        break
                    fh.write(chunk)
    except urlerror.URLError as exc:
        raise SystemExit(f"download failed for {url}: {exc}") from exc


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("datasets/ait-lds"))
    parser.add_argument("--mirror", default=DEFAULT_MIRROR)
    parser.add_argument(
        "--scenario",
        action="append",
        choices=sorted(SCENARIOS),
        help="Scenario to fetch; repeatable. Defaults to `fox`, which is enough to exercise the loader end to end without pulling ~19 GB.",
    )
    parser.add_argument("--all", action="store_true", help="Fetch every scenario.")
    parser.add_argument("--no-verify", action="store_true")
    parser.add_argument(
        "--accept-license",
        action="store_true",
        help="Acknowledge the AIT-LDS licence and citation. Required.",
    )
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    print(LICENSE_NOTICE)
    if not args.accept_license:
        print(
            "Refusing to download without --accept-license.\n"
            "This is not a formality: CC BY 4.0 requires attribution, and a\n"
            "dataset fetched without the licence being read is one whose terms\n"
            "nobody has agreed to.",
            file=sys.stderr,
        )
        return 2

    scenarios = sorted(SCENARIOS) if args.all else (args.scenario or ["fox"])
    total_gb = sum(float(SCENARIOS[s]["approx_gb"]) for s in scenarios)
    print(f"Scenarios: {', '.join(scenarios)}  (~{total_gb:.1f} GB)")

    if args.dry_run:
        for scenario in scenarios:
            print(f"  would fetch {args.mirror}/{SCENARIOS[scenario]['file']}")
        return 0

    for scenario in scenarios:
        entry = SCENARIOS[scenario]
        dest = args.out / str(entry["file"])
        if dest.exists():
            logger.info("%s already present; skipping", dest)
            continue
        _download(f"{args.mirror}/{entry['file']}", dest)

        expected = entry["sha256"]
        if expected and not args.no_verify:
            actual = _sha256(dest)
            if actual != expected:
                dest.unlink(missing_ok=True)
                raise SystemExit(f"checksum mismatch for {entry['file']}: expected {expected}, got {actual}. The file has been removed.")
        elif not expected:
            # Said out loud rather than passed over: an unverified download
            # is a different thing from a verified one, and the difference
            # should be visible to whoever runs this.
            logger.warning(
                "%s has no pinned SHA-256 — downloaded unverified. Pin it in this script in the same PR that re-runs the harness.",
                entry["file"],
            )

    print()
    print("Next:")
    print(
        "  python -m services.agents.tests.fidelity.runner "
        f"--dataset ait_lds --input {args.out}/<scenario>/gather/<host>/logs/apache2/access.log"
    )
    print("  Thresholds for the full corpus are in services/agents/tests/fidelity/expected_results.yaml under `ait_lds_full`.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
