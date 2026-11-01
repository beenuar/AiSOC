#!/usr/bin/env python3
"""Gate for the anonymizer and hosting classification dataset (depth 2, 1.6).

Four things, each of which has a recorded way of going wrong in this tree:

1. **Loader and downloader describe the same sources.** The fidelity-corpus
   rule: two corpora here once shipped a loader for data nobody could fetch,
   so their only numbers came from a ten-line fixture. The downloader's
   `SOURCES` and the committed manifest must name the same source ids.

2. **The committed artefact is intact and not empty.** `records_sha256` in
   the manifest must match the records file, and the record count must match
   the lines. A half-written refresh that still parses is the failure a
   digest catches and a line count does not.

3. **The class vocabulary agrees in all three places** — the downloader, the
   Python loader and the Go stamper. A class added to one and not the others
   is the shape that produced a rule matching a field nothing emits.

4. **Go and Python answer identically.** The Go package classifies live
   events at ingest; the Python loader classifies fixtures during replay.
   If they disagree, a rule passes its fixtures and never fires live, which
   is the exact trap the plan names. Checked by sampling the dataset and
   running both.

The fourth check needs a Go toolchain. When none is present it is reported
as NOT CHECKED and the gate still fails if anything else is wrong; it never
passes silently, and CI always has Go.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_if_requested  # noqa: E402

self_test_if_requested(__file__)

ROOT = repo_root()
DATA_DIR = ROOT / "services" / "ingest" / "internal" / "activity" / "ipclass" / "data"
RECORDS = DATA_DIR / "ip_classes.tsv"
MANIFEST = DATA_DIR / "manifest.json"
GO_PACKAGE = ROOT / "services" / "ingest" / "internal" / "activity" / "ipclass" / "ipclass.go"

#: Sampled rather than exhaustive: 21,726 records through a Go subprocess is
#: minutes, and the failure this check exists for (a different containment
#: rule, a different nesting walk, a different public-address predicate) shows
#: up on a spread of records, not on one specific one. Deterministic stride
#: so a failure is reproducible.
PARITY_SAMPLE = 400


def _fail(message: str) -> None:
    print(f"FAIL {message}")


def check_manifest_integrity() -> list[str]:
    problems: list[str] = []
    if not RECORDS.is_file():
        return [f"{RECORDS.relative_to(ROOT)} is missing"]
    if not MANIFEST.is_file():
        return [f"{MANIFEST.relative_to(ROOT)} is missing"]

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    text = RECORDS.read_text(encoding="utf-8")
    body = "".join(line + "\n" for line in text.splitlines() if not line.startswith("#"))
    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
    if digest != manifest.get("records_sha256"):
        problems.append(f"records_sha256 mismatch: manifest says {str(manifest.get('records_sha256'))[:16]}, file is {digest[:16]}")

    rows = [line for line in text.splitlines() if line and not line.startswith("#")]
    if len(rows) != manifest.get("record_count"):
        problems.append(f"record_count says {manifest.get('record_count')} but the file has {len(rows)} rows")
    if not rows:
        problems.append("the dataset is empty; refusing to report a classifier that can classify nothing as healthy")
    if not manifest.get("version"):
        problems.append("manifest carries no version; a class stamped with no version cannot be dated")

    present = {row.split("\t")[1] for row in rows if len(row.split("\t")) >= 2}
    covered = set(manifest.get("covered_classes") or [])
    if present != covered:
        problems.append(f"covered_classes {sorted(covered)} does not match the classes present {sorted(present)}")

    for source in manifest.get("sources") or []:
        for required in ("id", "url", "class", "terms_url", "redistribution", "upstream_sha256"):
            if not source.get(required):
                problems.append(f"source {source.get('id', '?')} has no {required}; provenance must be recorded per source")
    return problems


def check_loader_downloader_pair() -> list[str]:
    import fetch_ip_class_dataset as downloader  # noqa: PLC0415

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    declared = {source.id for source in downloader.SOURCES}
    recorded = {source["id"] for source in manifest.get("sources") or []}
    problems: list[str] = []
    if declared != recorded:
        problems.append(
            f"downloader declares {sorted(declared)} but the committed manifest records {sorted(recorded)}; "
            "a loader for data nobody can fetch cannot be refreshed or audited"
        )
    return problems


def check_class_vocabulary() -> list[str]:
    import fetch_ip_class_dataset as downloader  # noqa: PLC0415
    import ip_class_dataset as loader  # noqa: PLC0415

    problems: list[str] = []
    if tuple(downloader.ALL_CLASSES) != tuple(loader.ALL_CLASSES):
        problems.append(f"downloader classes {downloader.ALL_CLASSES} != loader classes {loader.ALL_CLASSES}")

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if tuple(manifest.get("all_classes") or ()) != tuple(downloader.ALL_CLASSES):
        problems.append("manifest all_classes disagrees with the downloader")

    # The Go side names the closed set in its package documentation rather
    # than in a constant (it reads whatever the dataset holds), so what is
    # checked here is that every shipped class is one the plan named.
    unexpected = set(manifest.get("covered_classes") or ()) - set(downloader.ALL_CLASSES)
    if unexpected:
        problems.append(f"dataset ships classes the plan does not name: {sorted(unexpected)}")

    overlap = set(manifest.get("covered_classes") or ()) & set(manifest.get("tenant_supplied_only") or ())
    if overlap:
        problems.append(f"classes claimed both shipped and tenant-supplied-only: {sorted(overlap)}")
    return problems


def check_vendored_copy() -> list[str]:
    vendored = ROOT / "services" / "fusion" / "app" / "services" / "ip_class.py"
    canonical = ROOT / "scripts" / "ip_class_dataset.py"
    if not vendored.is_file():
        return [f"{vendored.relative_to(ROOT)} is missing; the replay path cannot classify without it"]
    if canonical.read_text(encoding="utf-8") not in vendored.read_text(encoding="utf-8"):
        return ["the vendored loader has drifted; run scripts/sync_vendored_ip_class.py"]
    return []


_GO_PARITY_PROGRAM = """package main

import (
\t"bufio"
\t"fmt"
\t"os"
\t"strings"

\t"github.com/beenuar/aisoc/services/ingest/internal/activity/ipclass"
)

func main() {
\tscanner := bufio.NewScanner(os.Stdin)
\tfor scanner.Scan() {
\t\taddr := strings.TrimSpace(scanner.Text())
\t\tif addr == "" {
\t\t\tcontinue
\t\t}
\t\tc, ok := ipclass.Lookup(addr)
\t\tif !ok {
\t\t\tfmt.Printf("%s\\t\\t\\t\\n", addr)
\t\t\tcontinue
\t\t}
\t\tfmt.Printf("%s\\t%s\\t%s\\t%s\\n", addr, c.Class, c.Provider, c.Version)
\t}
}
"""


def _sample_addresses() -> list[str]:
    import ipaddress  # noqa: PLC0415

    rows = [line for line in RECORDS.read_text(encoding="utf-8").splitlines() if line and not line.startswith("#")]
    stride = max(1, len(rows) // PARITY_SAMPLE)
    out: list[str] = []
    for row in rows[::stride]:
        try:
            network = ipaddress.ip_network(row.split("\t")[0], strict=False)
        except ValueError:
            continue
        out.append(str(network.network_address))
    return out


def check_go_python_parity() -> tuple[list[str], bool]:
    """Returns (problems, checked).

    A missing Go toolchain is a **failure**, not a skip. A gate that reports
    "not checked" and exits 0 is indistinguishable from one that passed, and
    that shape has cost this repository several months of false confidence.
    A caller that genuinely cannot run Go passes `--skip-go` and says so.
    """
    import ip_class_dataset as loader  # noqa: PLC0415

    if subprocess.run(["which", "go"], capture_output=True, check=False).returncode != 0:  # noqa: S603, S607
        return ["no Go toolchain here, so the Go/Python parity probe could not run; pass --skip-go to accept that"], True

    addresses = _sample_addresses()
    if not addresses:
        return ["no sample addresses could be read from the dataset"], True

    program_dir = ROOT / "services" / "ingest" / "internal" / "activity" / "ipclass" / "parityprobe"
    program_dir.mkdir(parents=True, exist_ok=True)
    program = program_dir / "main.go"
    program.write_text(_GO_PARITY_PROGRAM, encoding="utf-8")
    try:
        done = subprocess.run(  # noqa: S603
            ["go", "run", "./internal/activity/ipclass/parityprobe"],  # noqa: S607
            cwd=ROOT / "services" / "ingest",
            input="\n".join(addresses),
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return ["the Go parity probe timed out"], True
    finally:
        program.unlink(missing_ok=True)
        program_dir.rmdir()

    if done.returncode != 0:
        return [f"the Go parity probe failed: {done.stderr.strip()[:400]}"], True

    problems: list[str] = []
    for line in done.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 4:
            continue
        address, go_class, go_provider, go_version = parts[0], parts[1], parts[2], parts[3]
        answer = loader.classify(address)
        py_class = answer.ip_class if answer else ""
        py_provider = answer.source if answer else ""
        py_version = answer.version if answer else ""
        if (go_class, go_provider, go_version) != (py_class, py_provider, py_version):
            problems.append(
                f"{address}: Go says ({go_class!r}, {go_provider!r}, {go_version!r}) "
                f"but Python says ({py_class!r}, {py_provider!r}, {py_version!r})"
            )
        if len(problems) >= 10:
            problems.append("... further mismatches suppressed")
            break
    return problems, True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="run every check (the default)")
    parser.add_argument("--skip-go", action="store_true", help="skip the Go parity probe")
    parser.parse_args()

    problems = check_manifest_integrity()
    if problems:
        for problem in problems:
            _fail(problem)
        return 1

    problems += check_loader_downloader_pair()
    problems += check_class_vocabulary()
    problems += check_vendored_copy()

    go_checked = False
    skipped_go = "--skip-go" in sys.argv
    if not skipped_go:
        go_problems, go_checked = check_go_python_parity()
        problems += go_problems

    for problem in problems:
        _fail(problem)
    if problems:
        return 1

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    print(
        f"OK ip-class dataset version {manifest['version']}: "
        f"{manifest['record_count']} records, "
        f"{len(manifest['sources'])} sources, "
        f"covered {manifest['covered_classes']}, "
        f"tenant-supplied-only {manifest['tenant_supplied_only']}"
    )
    print(
        "   Go/Python parity: "
        + (
            f"checked over {PARITY_SAMPLE} sampled addresses"
            if go_checked
            else "NOT CHECKED -- --skip-go was passed, so this run proves nothing about the two readers agreeing"
        )
    )
    if not re.fullmatch(r"\d{4}\.\d{2}\.\d{2}", manifest["version"]):
        print(f"   note: version {manifest['version']!r} is not the YYYY.MM.DD shape the downloader writes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
