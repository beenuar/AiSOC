#!/usr/bin/env python3
"""Download the CTU-13 botnet dataset for the AiSOC fidelity benchmark.

Usage:
    python scripts/datasets/download_ctu13.py [--out datasets/ctu13]
                                              [--mirror URL]
                                              [--scenarios 1,2,9]

What this does:
  1. Prints the upstream license / citation so the contributor must
     acknowledge them before any bytes hit disk.
  2. Downloads the .binetflow file for each requested CTU-13
     scenario (1..13). Each file is the Argus-format flow export
     for one botnet capture.
  3. Verifies SHA-256 against the manifest below where pins exist.
     Stratosphere Lab does occasionally re-encode files, so the
     ``--no-verify`` flag is supported but emits a noisy warning.

We do not redistribute CTU-13. The repo only contains a 100-row
synthetic CICIDS micro fixture for CI; CTU-13 is exercised entirely
via unit tests against the loader's pure functions.

License (CTU-13):
  Dataset is released by Stratosphere Lab at the Czech Technical
  University under the CC BY-NC-SA 4.0 license. Use is permitted for
  research/non-commercial purposes with attribution and share-alike.
  Read the upstream README at
  https://www.stratosphereips.org/datasets-ctu13 before running this
  script with ``--accept-license``.

Citation:
  Garcia, S., Grill, M., Stiborek, J., & Zunino, A. (2014). An
  empirical comparison of botnet detection methods. Computers &
  Security, 45, 100-123.
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

logger = logging.getLogger("download_ctu13")

DEFAULT_MIRROR = (
    "https://mcfp.felk.cvut.cz/publicDatasets/CTU-13-Dataset"
)

# CTU-13 ships 13 scenarios. Filenames at the upstream mirror follow
# the pattern ``{n}/capture{n}.binetflow``. SHA-256 entries are left
# as ``None`` until a contributor pins them in a follow-up PR (per
# the same convention used by download_cicids.py).
SCENARIOS: dict[int, dict[str, object]] = {
    n: {"sha256": None, "approx_bytes": 0} for n in range(1, 14)
}

LICENSE_NOTICE = """\
============================================================
CTU-13 license + citation
============================================================
Dataset: CTU-13
Publisher: Stratosphere Lab, Czech Technical University
Terms: CC BY-NC-SA 4.0 — https://www.stratosphereips.org/datasets-ctu13
Citation:
  Garcia, S., Grill, M., Stiborek, J., & Zunino, A. (2014). An
  empirical comparison of botnet detection methods. Computers &
  Security, 45, 100-123.

By passing --accept-license you confirm you have read and agreed to
the upstream terms. AiSOC does NOT redistribute these files; the
repo only contains synthetic CICIDS test fixtures for CI.
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


def _parse_scenarios(text: str) -> list[int]:
    out: list[int] = []
    for chunk in text.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            lo, hi = chunk.split("-", 1)
            out.extend(range(int(lo), int(hi) + 1))
        else:
            out.append(int(chunk))
    deduped: list[int] = []
    for n in out:
        if n in SCENARIOS and n not in deduped:
            deduped.append(n)
    return deduped


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("datasets/ctu13"),
        help="Where to land the binetflow files. Defaults to ``datasets/ctu13``.",
    )
    parser.add_argument(
        "--mirror",
        default=DEFAULT_MIRROR,
        help="HTTPS prefix for the CTU-13 mirror.",
    )
    parser.add_argument(
        "--scenarios",
        default="1-13",
        help="Comma/range list of scenarios to fetch (e.g. ``1,2,9`` or ``1-3``).",
    )
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="Skip SHA-256 verification (use only when pinning a new manifest).",
    )
    parser.add_argument(
        "--accept-license",
        action="store_true",
        help="Acknowledge CTU-13 CC BY-NC-SA 4.0 license. Required.",
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

    scenarios = _parse_scenarios(args.scenarios)
    if not scenarios:
        print("no valid scenarios in --scenarios", file=sys.stderr)
        return 2

    out_dir: Path = args.out
    if args.dry_run:
        plan = {
            "mirror": args.mirror,
            "out": str(out_dir),
            "scenarios": scenarios,
        }
        print(json.dumps(plan, indent=2))
        return 0

    out_dir.mkdir(parents=True, exist_ok=True)
    failures: list[str] = []
    for scenario in scenarios:
        name = f"capture{scenario}.binetflow"
        url = f"{args.mirror.rstrip('/')}/{scenario}/{name}"
        dest = out_dir / name
        if dest.exists() and dest.stat().st_size > 0:
            logger.info("skip (already present): %s", dest)
        else:
            _download(url, dest)

        expected = SCENARIOS[scenario].get("sha256")
        if args.no_verify or expected is None:
            logger.warning("hash unverified for scenario %d — pin SHA after first run", scenario)
            continue
        actual = _sha256(dest)
        if actual != expected:
            failures.append(f"scenario {scenario}: sha256 mismatch (got {actual}, want {expected})")
        else:
            logger.info("verified scenario %d", scenario)

    if failures:
        for line in failures:
            logger.error(line)
        return 1
    logger.info("done. %d scenarios in %s", len(scenarios), out_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
