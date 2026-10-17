#!/usr/bin/env python3
"""Vendor the Semgrep rule packs the ratchet's ceiling was measured with.

Why this exists (issue #1099)
-----------------------------
``security.yml`` pins the semgrep *binary* exactly, because for a ratchet the
scanner version is the behaviour. It then fetched five rule packs from the
registry at scan time — ``p/security-audit``, ``p/owasp-top-ten``,
``p/python``, ``p/typescript``, ``p/react`` — so the ratchet compared today's
tree against whatever those packs contained today. A pinned binary against
unpinned rules is half a pin, and it was measured rather than suspected: two
consecutive runs on one branch read 103/39 then 104/40 while the commits in
between changed **zero scanned files**.

So the packs are vendored. The five YAMLs under ``.security/semgrep/`` are
the rules the scan runs and the rules the ceiling in
``.security/allowlist.yml`` was measured with; ``MANIFEST.sha256`` records a
digest per file, and the combined digest (``--digest``) is pinned in the
allowlist as ``rules_sha256``, which ``check_scanner_ratchet.py`` verifies
the same way it verifies ``measured_with`` — a ceiling is bound to the exact
binary *and* the exact rules that produced it, and moving either is an
explicit re-measure rather than a silent one.

Refreshing is deliberate: run this script with no arguments to re-fetch the
packs, then re-measure the counts and update ``rules_sha256`` and the
ceilings in the same change. ``--check`` only verifies that the committed
files match the manifest — it never touches the network, because a check
that compared against the live registry would fail whenever upstream moves,
which is exactly when the pin is doing its job.

Usage
-----
    python3 scripts/vendor_semgrep_packs.py              # re-fetch (deliberate refresh)
    python3 scripts/vendor_semgrep_packs.py --check      # CI gate: files match manifest
    python3 scripts/vendor_semgrep_packs.py --digest     # print the combined digest
    python3 scripts/vendor_semgrep_packs.py --self-test
"""

from __future__ import annotations

import argparse
import hashlib
import sys
import tempfile
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PACK_DIR = REPO_ROOT / ".security" / "semgrep"
MANIFEST = "MANIFEST.sha256"

#: The registry packs the scan ran before vendoring, in the order the
#: workflow listed them. The registry serves each pack's rules YAML at
#: https://semgrep.dev/c/p/<name>.
PACKS = ("security-audit", "owasp-top-ten", "python", "typescript", "react")

REGISTRY = "https://semgrep.dev/c/p/"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_manifest(pack_dir: Path) -> dict[str, str]:
    """``{filename: sha256}`` from the manifest, comments skipped."""
    out: dict[str, str] = {}
    for line in (pack_dir / MANIFEST).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        digest, name = line.split(None, 1)
        out[name.strip()] = digest.strip()
    return out


def combined_digest(pack_dir: Path) -> str:
    """One digest over every vendored pack, computed from the files.

    sha256 over the sorted ``<name>:<file-sha256>`` lines, so a changed byte
    in any pack, a missing pack, or an extra one all move it. Computed from
    the files rather than the manifest on purpose: the ratchet compares this
    value against the allowlist's ``rules_sha256``, and reading the manifest
    would let an edited pack hide behind a stale manifest line.
    """
    files = sorted(p for p in pack_dir.glob("*.yaml"))
    if not files:
        raise SystemExit(
            f"vendor_semgrep_packs: {pack_dir} holds no *.yaml packs. Finding nothing and "
            "comparing nothing print the same word, so this refuses rather than reporting a digest."
        )
    lines = [f"{p.name}:{_sha256(p.read_bytes())}" for p in files]
    return _sha256("\n".join(lines).encode("ascii"))


def fetch(pack_dir: Path) -> int:
    pack_dir.mkdir(parents=True, exist_ok=True)
    entries: list[str] = []
    for pack in PACKS:
        url = f"{REGISTRY}{pack}"
        with urllib.request.urlopen(url, timeout=120) as resp:  # noqa: S310 — fixed https registry root
            data = resp.read()
        if not data.lstrip().startswith(b"rules:"):
            raise SystemExit(f"vendor_semgrep_packs: {url} did not return a rules YAML (got {data[:40]!r})")
        (pack_dir / f"{pack}.yaml").write_bytes(data)
        entries.append(f"{_sha256(data)}  {pack}.yaml")
        print(f"fetched {pack}.yaml ({len(data)} bytes)")
    header = (
        f"# Vendored semgrep rule packs — fetched {datetime.now(UTC).strftime('%Y-%m-%d')} from {REGISTRY}<name>.\n"
        "# Refresh deliberately with scripts/vendor_semgrep_packs.py, then re-measure the\n"
        "# ceilings and rules_sha256 in .security/allowlist.yml in the same change (issue #1099).\n"
    )
    (pack_dir / MANIFEST).write_text(header + "\n".join(entries) + "\n", encoding="utf-8")
    print(f"wrote {MANIFEST}; combined digest {combined_digest(pack_dir)}")
    return 0


def check(pack_dir: Path) -> int:
    if not (pack_dir / MANIFEST).exists():
        print(
            f"vendor_semgrep_packs: {pack_dir / MANIFEST} is missing — nothing to verify against, which is a failure rather than a pass.",
            file=sys.stderr,
        )
        return 1
    manifest = _read_manifest(pack_dir)
    if not manifest:
        print("vendor_semgrep_packs: the manifest lists no packs; refusing to call that verified.", file=sys.stderr)
        return 1
    problems: list[str] = []
    for name, want in manifest.items():
        path = pack_dir / name
        if not path.exists():
            problems.append(f"{name}: in the manifest but not on disk")
            continue
        got = _sha256(path.read_bytes())
        if got != want:
            problems.append(f"{name}: sha256 {got} != manifest {want}")
    for path in pack_dir.glob("*.yaml"):
        if path.name not in manifest:
            problems.append(f"{path.name}: on disk but not in the manifest")
    if problems:
        print("vendor_semgrep_packs: the vendored packs disagree with the manifest:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        print(
            "A deliberate refresh is scripts/vendor_semgrep_packs.py (then re-measure the ceilings); anything else is corruption.",
            file=sys.stderr,
        )
        return 1
    print(f"vendor_semgrep_packs: OK — {len(manifest)} packs match the manifest; combined digest {combined_digest(pack_dir)}")
    return 0


def self_test() -> int:
    cases: list[tuple[str, bool]] = []
    with tempfile.TemporaryDirectory() as td:
        d = Path(td) / "semgrep"
        d.mkdir()
        (d / "a.yaml").write_bytes(b"rules: []\n")
        (d / "b.yaml").write_bytes(b"rules: [x]\n")
        entries = [f"{_sha256((d / n).read_bytes())}  {n}" for n in ("a.yaml", "b.yaml")]
        (d / MANIFEST).write_text("# t\n" + "\n".join(entries) + "\n")
        cases.append(("an in-sync tree passes", check(d) == 0))
        baseline = combined_digest(d)

        (d / "a.yaml").write_bytes(b"rules: [tampered]\n")
        cases.append(("a changed byte in a pack fails", check(d) != 0))
        cases.append(("and moves the combined digest", combined_digest(d) != baseline))
        (d / "a.yaml").write_bytes(b"rules: []\n")

        (d / "c.yaml").write_bytes(b"rules: []\n")
        cases.append(("a pack the manifest does not list fails", check(d) != 0))
        (d / "c.yaml").unlink()

        (d / "b.yaml").unlink()
        cases.append(("a manifest entry with no file fails", check(d) != 0))

    with tempfile.TemporaryDirectory() as td:
        empty = Path(td) / "semgrep"
        empty.mkdir()
        cases.append(("a directory with no manifest is refused", check(empty) != 0))
        failed_digest = False
        try:
            combined_digest(empty)
        except SystemExit:
            failed_digest = True
        cases.append(("a digest over no packs is refused rather than minted", failed_digest))

    ok = True
    for name, passed in cases:
        print(f"  {'PASS' if passed else 'FAIL'}  {name}")
        ok = ok and passed
    print("vendor_semgrep_packs: self-test " + ("OK" if ok else "FAILED"))
    return 0 if ok else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--check", action="store_true", help="verify the committed packs match the manifest")
    group.add_argument("--digest", action="store_true", help="print the combined digest the allowlist pins")
    group.add_argument("--self-test", action="store_true", help="prove the check can fail")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    if args.check:
        return check(PACK_DIR)
    if args.digest:
        print(combined_digest(PACK_DIR))
        return 0
    return fetch(PACK_DIR)


if __name__ == "__main__":
    raise SystemExit(main())
