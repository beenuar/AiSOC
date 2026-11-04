#!/usr/bin/env python3
"""Carry the upstream ``author:`` onto every vendored SigmaHQ rule.

The importer that produced ``detections/sigma-imports/`` built its provenance
block out of the source repository, the rule's UUID, its upstream path and the
licence, and never read the one field DRL-1.1 actually turns on: who wrote the
rule. This restores it, and — the more durable half — verifies it.

Reproducibility is the point. The attribution is read from SigmaHQ/sigma at the
commit ``tools/detection_import/import_orchestrator.SIGMA_COMMIT`` pins, not
from whatever ``master`` holds today, so re-running this on a different day
produces the same names or says why it cannot. Rules are matched on the Sigma
rule UUID rather than on the file path, because a path is something upstream
reorganises and a UUID is the identity the Sigma project maintains for exactly
this purpose. (Measured at the pinned commit: 3,132 of 3,132 vendored rules
match by UUID, and all 3,132 paths agree as well — but the UUID is the key that
will still be right after an upstream reshuffle.)

A rule whose upstream carries no ``author:`` is recorded as
``(no author recorded upstream)`` rather than being left empty or assigned to
"SigmaHQ". Empty is indistinguishable from the defect this closes, and naming
the organisation is the substitution the licence explicitly does not accept.
No rule in the corpus needs it at the pinned commit; the spelling exists so the
next import does not have to invent one.

Usage:
    python3 scripts/sync_sigma_authors.py            # write authors into the YAML
    python3 scripts/sync_sigma_authors.py --check    # verify against upstream, write nothing
    python3 scripts/sync_sigma_authors.py --self-test
"""

from __future__ import annotations

import argparse
import io
import re
import sys
import tarfile
import urllib.request
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root

ROOT = repo_root()
SIGMA_YAML = ROOT / "detections" / "sigma-imports"
ORCHESTRATOR = ROOT / "tools" / "detection_import" / "import_orchestrator.py"

#: Where a fetched upstream snapshot is cached, so --check does not re-download.
CACHE = ROOT / ".import-cache" / "sigma-authors"

#: The only host this tool reads from. The URL is assembled from this literal
#: prefix plus a 40-character hex commit validated below, and the fetch refuses
#: anything that does not start with it — so the `file://` read semgrep's
#: `dynamic-urllib-use-detected` warns about is not reachable here. The rule
#: still fires on any non-literal argument to `urlopen`; it is counted in
#: `.security/allowlist.yml` rather than suppressed, matching how the other
#: five instances in this repository are handled.
CODELOAD_ROOT = "https://codeload.github.com/SigmaHQ/sigma/tar.gz/"

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")

ABSENT = "(no author recorded upstream)"

_PIN_RE = re.compile(r'^SIGMA_COMMIT\s*=\s*"([0-9a-f]{40})"', re.MULTILINE)


def pinned_commit() -> str:
    """The upstream commit the importer pins, read from the importer."""
    match = _PIN_RE.search(ORCHESTRATOR.read_text(encoding="utf-8"))
    if not match:
        raise SystemExit(f"could not read SIGMA_COMMIT from {ORCHESTRATOR.relative_to(ROOT)}")
    return match.group(1)


def _author_of(doc: dict) -> str:
    """The ``author:`` value, normalised to the string upstream wrote.

    Sigma's schema makes this a string, and in practice it is a comma-separated
    list when a rule has several authors. A handful of rules use a YAML list
    instead; both are preserved as upstream expressed them rather than being
    rewritten into a shape this project invented.
    """
    raw = doc.get("author")
    if raw is None:
        return ""
    if isinstance(raw, (list, tuple)):
        return ", ".join(str(part).strip() for part in raw if str(part).strip())
    return str(raw).strip()


def upstream_authors(commit: str) -> dict[str, str]:
    """``{sigma rule uuid: author string}`` from SigmaHQ/sigma at ``commit``.

    Parsed, not pattern-matched. A first cut read the ``id:`` line with a regex
    anchored on end-of-line and lost ten rules whose id carries a trailing YAML
    comment (``id: 9f50fe98-… # Susp Paths``) — ten rules that would have
    shipped with no attribution while the tool reported success. The upstream
    side is read with the parser; only the write-back is line-based, so the
    vendored files keep their formatting.
    """
    if not _SHA_RE.match(commit):
        raise SystemExit(f"refusing to fetch: {commit!r} is not a 40-character commit sha")
    archive = CACHE / f"{commit}.tar.gz"
    if not archive.exists():
        CACHE.mkdir(parents=True, exist_ok=True)
        url = CODELOAD_ROOT + commit
        if not url.startswith(CODELOAD_ROOT):
            raise SystemExit(f"refusing to fetch outside {CODELOAD_ROOT}: {url}")
        print(f"fetching {url}")
        with urllib.request.urlopen(url, timeout=180) as response:  # noqa: S310 — fixed host, pinned commit
            archive.write_bytes(response.read())

    authors: dict[str, str] = {}
    with tarfile.open(archive, "r:gz") as tar:
        for member in tar.getmembers():
            if not member.isfile() or not member.name.endswith((".yml", ".yaml")):
                continue
            rel = member.name.split("/", 1)[-1]
            if not rel.startswith(("rules/", "rules-")):
                continue
            handle = tar.extractfile(member)
            if handle is None:
                continue
            try:
                doc = yaml.safe_load(io.TextIOWrapper(handle, encoding="utf-8").read())
            except (UnicodeDecodeError, OSError, yaml.YAMLError):
                continue
            if not isinstance(doc, dict):
                continue
            rule_id = str(doc.get("id") or "").strip()
            if not rule_id:
                continue
            authors[rule_id] = _author_of(doc)
    return authors


def _provenance_bounds(lines: list[str]) -> tuple[int, int]:
    """(first, last+1) line indices of the ``provenance:`` block, or (-1, -1)."""
    start = -1
    for index, line in enumerate(lines):
        if line.startswith("provenance:"):
            start = index
            break
    if start < 0:
        return -1, -1
    end = len(lines)
    for index in range(start + 1, len(lines)):
        if lines[index].strip() and lines[index][:1] not in {" ", "\t"}:
            end = index
            break
    return start, end


def _read_field(lines: list[str], start: int, end: int, key: str) -> str | None:
    """A provenance value, parsed as YAML rather than de-quoted by hand.

    Naively stripping quotes was wrong on 90 rules and wrong in the direction
    that matters: authors such as ``Mark Morowczynski '@markmorow'`` are
    written as a correctly escaped YAML scalar, and a reader that strips the
    outer quotes by character returns a truncated string and reports a
    disagreement with upstream that does not exist. A check that cries wolf on
    90 of 3,132 rules is a check nobody will keep running.
    """
    for index in range(start + 1, end):
        stripped = lines[index].strip()
        if not stripped.startswith(f"{key}:"):
            continue
        raw = stripped.partition(":")[2].strip()
        if not raw:
            return ""
        try:
            value = yaml.safe_load(raw)
        except yaml.YAMLError:
            return raw
        return "" if value is None else str(value)
    return None


def _quote(value: str) -> str:
    """YAML-safe single-quoted scalar. Author strings carry commas and @ signs."""
    return "'" + value.replace("'", "''") + "'"


def sync(*, check: bool) -> int:
    commit = pinned_commit()
    print(f"SigmaHQ/sigma pinned at {commit}")
    authors = upstream_authors(commit)
    print(f"upstream rules at that commit: {len(authors):,}")

    files = sorted(SIGMA_YAML.rglob("*.yaml"))
    if not files:
        print(f"FAIL — no vendored rules under {SIGMA_YAML.relative_to(ROOT)}")
        return 1

    written = 0
    agreed = 0
    unmatched: list[str] = []
    disagreed: list[str] = []
    none_upstream = 0

    for path in files:
        text = path.read_text(encoding="utf-8")
        lines = text.splitlines()
        start, end = _provenance_bounds(lines)
        if start < 0:
            unmatched.append(f"{path.relative_to(ROOT)}: no provenance block")
            continue
        source_id = _read_field(lines, start, end, "source_id")
        if not source_id or source_id not in authors:
            unmatched.append(f"{path.relative_to(ROOT)}: upstream id {source_id!r} not at {commit[:9]}")
            continue

        want = authors[source_id] or ABSENT
        if not authors[source_id]:
            none_upstream += 1
        have = _read_field(lines, start, end, "author")

        if have == want:
            agreed += 1
            continue
        if check:
            disagreed.append(f"{path.relative_to(ROOT)}: have {have!r}, upstream has {want!r}")
            continue

        # Insert immediately after `source:` so the block reads
        # "source, author, ..." — publisher then person.
        rendered = f"  author: {_quote(want)}"
        replaced = False
        for index in range(start + 1, end):
            if lines[index].strip().startswith("author:"):
                lines[index] = rendered
                replaced = True
                break
        if not replaced:
            anchor = start
            for index in range(start + 1, end):
                if lines[index].strip().startswith("source:"):
                    anchor = index
                    break
            lines.insert(anchor + 1, rendered)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        written += 1

    print(f"vendored rules: {len(files):,}")
    print(f"  already correct: {agreed:,}")
    if not check:
        print(f"  written:         {written:,}")
    print(f"  upstream credits nobody (recorded as absent): {none_upstream:,}")

    if unmatched:
        print(f"\nFAIL — {len(unmatched):,} vendored rules do not resolve upstream at {commit[:9]}:")
        for line in unmatched[:10]:
            print(f"  {line}")
        return 1
    if disagreed:
        print(f"\nFAIL — {len(disagreed):,} rules disagree with upstream at {commit[:9]}:")
        for line in disagreed[:10]:
            print(f"  {line}")
        if len(disagreed) > 10:
            print(f"  … and {len(disagreed) - 10:,} more")
        return 1

    print(f"\nsync_sigma_authors: OK — every vendored rule matches SigmaHQ/sigma at {commit[:9]}")
    return 0


def _self_test() -> int:
    ok = True

    def case(description: str, passed: bool) -> None:
        nonlocal ok
        ok &= passed
        print(f"  {'PASS' if passed else 'FAIL'}  {description}")

    folded = yaml.safe_load("author: Alice One,\n  Bob Two\nstatus: test\n")
    case("reads a multi-author value folded across lines", _author_of(folded) == "Alice One, Bob Two")

    case("reads a single author", _author_of(yaml.safe_load("author: Tim Shelton\n")) == "Tim Shelton")

    case("reads an author expressed as a YAML list", _author_of({"author": ["A", "B"]}) == "A, B")

    case("reads a missing author as empty", _author_of({"title": "x"}) == "")

    # The divergence that cost ten rules: upstream writes a trailing YAML
    # comment after the id, which an end-of-line-anchored regex does not match.
    commented = yaml.safe_load("title: t\nid: 9f50fe98-fe5c-4a2d-86c7-fad7f63ed622 # Susp Paths\nauthor: N B # note\n")
    case(
        "reads an id and author carrying trailing YAML comments",
        str(commented["id"]) == "9f50fe98-fe5c-4a2d-86c7-fad7f63ed622" and _author_of(commented) == "N B",
    )

    case("quotes an author containing an apostrophe", _quote("D'Arcy") == "'D''Arcy'")
    case("quotes a comma-separated author list", _quote("A, B") == "'A, B'")

    lines = ["id: x", "provenance:", "  source: SigmaHQ/sigma", "  source_id: abc", "notes: y"]
    start, end = _provenance_bounds(lines)
    case(
        "finds the provenance block and stops at the next top-level key",
        (start, end) == (1, 4) and _read_field(lines, start, end, "source_id") == "abc",
    )

    # The round trip has to be lossless for an author carrying quotes, which
    # is where a hand-rolled de-quoter silently truncates.
    tricky = "Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo'"
    round_tripped = ["provenance:", f"  author: {_quote(tricky)}", "x: y"]
    bounds = _provenance_bounds(round_tripped)
    case(
        "round-trips an author containing single quotes without truncating",
        _read_field(round_tripped, bounds[0], bounds[1], "author") == tricky,
    )

    case("reads the pinned commit from the importer", len(pinned_commit()) == 40)

    print()
    print(f"sync_sigma_authors.py: self-test {'OK' if ok else 'FAILED'}")
    return 0 if ok else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify against upstream, write nothing")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return _self_test()
    return sync(check=args.check)


if __name__ == "__main__":
    raise SystemExit(main())
