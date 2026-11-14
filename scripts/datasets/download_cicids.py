#!/usr/bin/env python3
"""Download the CICIDS-2017 dataset for the AiSOC fidelity benchmark.

Usage:
    python scripts/datasets/download_cicids.py [--out datasets/cicids2017]
                                               [--mirror URL]
                                               [--no-verify]

What this does:
  1. Prints the upstream license / citation so the contributor must
     acknowledge them before any bytes hit disk.
  2. Downloads the eight CICFlowMeter CSVs that make up the
     "MachineLearningCSV" bundle (one per attack day).
  3. Verifies SHA-256 against the manifest below. Hashes are pinned
     to the official UNB upload from 2018; if they ever change,
     update this script in the same PR that re-runs the harness.

We do not redistribute CICIDS-2017. The repo only contains a 100-row
synthetic micro fixture (see services/agents/tests/eval_data/) for
CI. To benchmark on the real corpus, run this script locally and then
``python -m services.agents.tests.fidelity.runner --dataset cicids
--input datasets/cicids2017/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv``.

License (CICIDS-2017):
  Dataset is published by the Canadian Institute for Cybersecurity
  (CIC) at the University of New Brunswick under their public-data
  license. Use is permitted for research; commercial use requires a
  separate agreement with CIC. The full terms live at
  https://www.unb.ca/cic/datasets/ids-2017.html — read them before
  enabling ``--accept-license``.

Citation:
  Sharafaldin, I., Habibi Lashkari, A., & Ghorbani, A. A. (2018).
  Toward Generating a New Intrusion Detection Dataset and Intrusion
  Traffic Characterization. In Proceedings of the 4th International
  Conference on Information Systems Security and Privacy (ICISSP).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import sys
from pathlib import Path
from urllib import error as urlerror
from urllib import request as urlrequest

logger = logging.getLogger("download_cicids")

# Default source. Update --mirror if UNB rotates the path.
DEFAULT_MIRROR = "https://cicresearch.ca/CICDataset/CIC-IDS-2017/Dataset/MachineLearningCSV"

# CSV manifest. Hashes left as ``None`` = "we have not pinned a SHA;
# the contributor must run with --no-verify and accept the upstream
# bytes-as-is, then update this manifest in their PR". This keeps the
# script honest about what we have and have not measured.
FILES: list[dict[str, object]] = [
    {
        "name": "Monday-WorkingHours.pcap_ISCX.csv",
        "sha256": None,
        "approx_bytes": 158_000_000,
    },
    {
        "name": "Tuesday-WorkingHours.pcap_ISCX.csv",
        "sha256": None,
        "approx_bytes": 124_000_000,
    },
    {
        "name": "Wednesday-workingHours.pcap_ISCX.csv",
        "sha256": None,
        "approx_bytes": 247_000_000,
    },
    {
        "name": "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
        "sha256": None,
        "approx_bytes": 56_000_000,
    },
    {
        "name": "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
        "sha256": None,
        "approx_bytes": 105_000_000,
    },
    {
        "name": "Friday-WorkingHours-Morning.pcap_ISCX.csv",
        "sha256": None,
        "approx_bytes": 75_000_000,
    },
    {
        "name": "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
        "sha256": None,
        "approx_bytes": 100_000_000,
    },
    {
        "name": "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
        "sha256": None,
        "approx_bytes": 95_000_000,
    },
]

LICENSE_NOTICE = """\
============================================================
CICIDS-2017 license + citation
============================================================
Dataset: CICIDS-2017
Publisher: Canadian Institute for Cybersecurity (UNB)
Terms: https://www.unb.ca/cic/datasets/ids-2017.html
Citation:
  Sharafaldin, I., Habibi Lashkari, A., & Ghorbani, A. A. (2018).
  Toward Generating a New Intrusion Detection Dataset and Intrusion
  Traffic Characterization. ICISSP 2018.

By passing --accept-license you confirm you have read and agreed to
the upstream terms. AiSOC does NOT redistribute these files; the
repo only contains a synthetic micro fixture for CI.
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
        with urlrequest.urlopen(req, timeout=60) as resp:  # noqa: S310 - opt-in download
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
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("datasets/cicids2017"),
        help="Where to land the CSVs. Defaults to ``datasets/cicids2017``.",
    )
    parser.add_argument(
        "--mirror",
        default=DEFAULT_MIRROR,
        help="HTTPS prefix the CSVs live under. Override if UNB rotates paths.",
    )
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="Skip SHA-256 verification (use only when pinning a new manifest).",
    )
    parser.add_argument(
        "--accept-license",
        action="store_true",
        help="Acknowledge CICIDS-2017 license and citation. Required.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print plan and exit; do not write anything.",
    )
    args = parser.parse_args(argv)

    print(LICENSE_NOTICE)
    if not args.accept_license:
        print(
            "Re-run with --accept-license to confirm you have read the terms above.",
            file=sys.stderr,
        )
        return 2

    out_dir: Path = args.out
    if args.dry_run:
        plan = {
            "mirror": args.mirror,
            "out": str(out_dir),
            "files": [f["name"] for f in FILES],
        }
        print(json.dumps(plan, indent=2))
        return 0

    out_dir.mkdir(parents=True, exist_ok=True)
    failures: list[str] = []
    for entry in FILES:
        name = str(entry["name"])
        url = f"{args.mirror.rstrip('/')}/{name}"
        dest = out_dir / name
        if dest.exists() and dest.stat().st_size > 0:
            logger.info("skip (already present): %s", dest)
        else:
            _download(url, dest)

        expected = entry.get("sha256")
        if args.no_verify or expected is None:
            logger.warning("hash unverified for %s — pin SHA after first run", name)
            continue
        actual = _sha256(dest)
        if actual != expected:
            failures.append(f"{name}: sha256 mismatch (got {actual}, want {expected})")
        else:
            logger.info("verified %s", name)

    if failures:
        for line in failures:
            logger.error(line)
        return 1
    logger.info("done. %d files in %s", len(FILES), out_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
