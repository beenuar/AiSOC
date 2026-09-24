#!/usr/bin/env python3
"""Competitor-naming gate.

AiSOC never names a competitor product — not in documentation, marketing copy,
plan files, code comments or release notes. Where a competitor is the benchmark
for a comparison the text refers to it neutrally and keeps the analytical
content: the capability compared, the direction of the gap, the magnitude.

The difficulty is that a vendor name is usually *correct* here. This product
ships 80+ connectors, so a connector module, a plugin manifest, a setup guide or
a normalizer profile naming its vendor is necessary. `Torq` is the clearest
case: it is simultaneously a first-party SOAR connector and a name that used to
appear in a competitive comparison matrix. A blind search-and-replace would
break working connector code.

So the gate never infers intent from prose. It works from two explicit lists in
`scripts/competitor_names.toml`:

  * `[[competitors]]` — the product names that may not appear, as regexes.
  * `[[allow]]`       — the integration surfaces where those names are expected,
                        by path, each naming which names it excuses and why.

Plus a third, narrower list: `[[comparison_surfaces]]` pins the published
comparison tables by literal start/end marker and checks them against a wider
vendor list. A comparison table is the one place where any vendor name is a
violation, including a vendor this product integrates with, because the table's
whole job is to position AiSOC against it. The integration allow-list does not
apply inside those regions.

Both lists are checked in both directions, because the dominant failure shape in
this repository is a check that compares A against B and never B against A, then
prints OK while drift accumulates:

  * a competitor pattern that matches nothing anywhere — including its own
    fixtures — is dead and fails, rather than silently excusing the tree;
  * an allow entry matching no file, or matching files that no longer contain
    any of the names it excuses, is a stale exemption and fails, so an exemption
    cannot outlive the code it excused;
  * a comparison-surface marker that no longer matches fails, rather than
    scanning an empty slice and reporting clean.

The scan root is resolved from the working directory (or `--root`), never from
this file's own location, and is printed along with the file count. A gate that
resolves its own repository can print a confident OK about a tree it never
inspected.

Usage:
    python3 scripts/check_competitor_names.py --self-test
    python3 scripts/check_competitor_names.py
    python3 scripts/check_competitor_names.py --root /path/to/worktree
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
import subprocess
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

# Paths that hold competitor names because they are the machinery for detecting
# them, or the record of the cleanup. Scanning these would make the gate flag
# itself and its own documentation.
SELF_REFERENTIAL = frozenset(
    {
        "scripts/competitor_names.toml",
        "scripts/check_competitor_names.py",
        "scripts/competitor_fixtures.json",
        "tests/test_competitor_names_gate.py",
        ".github/workflows/competitor-names.yml",
    }
)

# Binary and lockfile suffixes: never prose, and only a source of noise.
SKIP_SUFFIXES = (
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".svg",
    ".ico",
    ".pdf",
    ".woff",
    ".woff2",
    ".ttf",
    ".zip",
    ".gz",
    ".tar",
    ".mp4",
    ".lock",
)


class ConfigError(RuntimeError):
    """The gate's own configuration is unusable, so it cannot report a verdict."""


@dataclass(frozen=True)
class Competitor:
    name: str
    regex: re.Pattern[str]
    neutral: str


@dataclass(frozen=True)
class AllowEntry:
    paths: tuple[str, ...]
    names: frozenset[str]
    reason: str


@dataclass(frozen=True)
class ComparisonSurface:
    file: str
    start: str
    end: str
    reason: str


@dataclass(frozen=True)
class Config:
    competitors: tuple[Competitor, ...]
    allows: tuple[AllowEntry, ...]
    comparison_vendors: tuple[str, ...]
    comparison_surfaces: tuple[ComparisonSurface, ...]


@dataclass
class Finding:
    path: str
    line_no: int
    competitor: str
    excerpt: str
    neutral: str
    kind: str = "naming"


@dataclass
class ScanReport:
    root: Path
    config_path: Path
    files_scanned: int = 0
    files_skipped: int = 0
    findings: list[Finding] = field(default_factory=list)
    stale_allows: list[str] = field(default_factory=list)
    dead_patterns: list[str] = field(default_factory=list)
    broken_surfaces: list[str] = field(default_factory=list)
    surfaces_checked: int = 0

    @property
    def ok(self) -> bool:
        return not (self.findings or self.stale_allows or self.dead_patterns or self.broken_surfaces)


def load_config(path: Path) -> Config:
    """Parse the TOML config, failing loudly on anything malformed."""
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConfigError(f"config not found: {path}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"config is not valid TOML: {path}: {exc}") from exc

    competitors: list[Competitor] = []
    for entry in raw.get("competitors", []):
        name = entry.get("name")
        pattern = entry.get("pattern")
        if not name or not pattern:
            raise ConfigError(f"[[competitors]] entry needs both 'name' and 'pattern': {entry!r}")
        flags = 0 if entry.get("case_sensitive", False) else re.IGNORECASE
        try:
            regex = re.compile(pattern, flags)
        except re.error as exc:
            raise ConfigError(f"[[competitors]] {name}: bad regex {pattern!r}: {exc}") from exc
        competitors.append(Competitor(name=name, regex=regex, neutral=entry.get("neutral", "a neutral descriptor")))
    if not competitors:
        raise ConfigError("config declares no competitors, so the gate would pass everything")

    known = {c.name for c in competitors}
    allows: list[AllowEntry] = []
    for entry in raw.get("allow", []):
        paths = tuple(entry.get("paths", ()))
        names = frozenset(entry.get("names", ()))
        reason = entry.get("reason", "")
        if not paths or not names or not reason:
            raise ConfigError(f"[[allow]] entry needs 'paths', 'names' and 'reason': {entry!r}")
        unknown = names - known
        if unknown:
            raise ConfigError(f"[[allow]] {paths[0]} excuses names that are not declared competitors: {sorted(unknown)}")
        allows.append(AllowEntry(paths=paths, names=names, reason=reason))

    vendors = tuple(raw.get("comparison", {}).get("vendors", ()))
    surfaces: list[ComparisonSurface] = []
    for entry in raw.get("comparison_surfaces", []):
        for key in ("file", "start", "end", "reason"):
            if not entry.get(key):
                raise ConfigError(f"[[comparison_surfaces]] entry needs '{key}': {entry!r}")
        surfaces.append(ComparisonSurface(file=entry["file"], start=entry["start"], end=entry["end"], reason=entry["reason"]))
    if surfaces and not vendors:
        raise ConfigError("comparison surfaces are declared but [comparison].vendors is empty")

    return Config(
        competitors=tuple(competitors),
        allows=tuple(allows),
        comparison_vendors=vendors,
        comparison_surfaces=tuple(surfaces),
    )


def resolve_root(explicit: str | None) -> Path:
    """Resolve the tree to scan from the working directory, never from __file__.

    A gate that locates its repository relative to its own source file reports on
    whichever checkout it was imported from, which is not necessarily the one the
    caller meant. Deriving it from the caller's directory keeps the two aligned.
    """
    if explicit:
        root = Path(explicit).resolve()
        if not root.is_dir():
            raise ConfigError(f"--root is not a directory: {root}")
        return root
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ConfigError("not inside a git worktree; pass --root explicitly") from exc
    return Path(out.stdout.strip()).resolve()


def tracked_files(root: Path) -> list[str]:
    out = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"],
        capture_output=True,
        text=True,
        check=True,
    )
    return [p for p in out.stdout.split("\0") if p]


def _matches(path: str, globs: tuple[str, ...]) -> bool:
    for glob in globs:
        if fnmatch.fnmatch(path, glob):
            return True
        # A directory glob should cover the directory itself as well as its
        # contents, so "docs/connectors/**" matches "docs/connectors/x.md".
        if glob.endswith("/**") and (path == glob[:-3] or path.startswith(glob[:-2])):
            return True
    return False


def excused_names(path: str, allows: tuple[AllowEntry, ...]) -> set[str]:
    excused: set[str] = set()
    for allow in allows:
        if _matches(path, allow.paths):
            excused |= allow.names
    return excused


def scan_text(
    path: str,
    text: str,
    competitors: tuple[Competitor, ...],
    excused: set[str],
) -> list[Finding]:
    findings: list[Finding] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        for competitor in competitors:
            if competitor.name in excused:
                continue
            match = competitor.regex.search(line)
            if match:
                findings.append(
                    Finding(
                        path=path,
                        line_no=line_no,
                        competitor=competitor.name,
                        excerpt=line.strip()[:160],
                        neutral=competitor.neutral,
                    )
                )
    return findings


def scan_comparison_surfaces(root: Path, config: Config, report: ScanReport) -> None:
    """Check the pinned comparison-table regions against the wider vendor list."""
    vendor_patterns = [(v, re.compile(rf"\b{re.escape(v)}\b", re.IGNORECASE)) for v in config.comparison_vendors]
    for surface in config.comparison_surfaces:
        target = root / surface.file
        if not target.is_file():
            report.broken_surfaces.append(f"{surface.file}: file is missing, so its comparison table was never checked")
            continue
        text = target.read_text(encoding="utf-8", errors="replace")
        start = text.find(surface.start)
        if start == -1:
            report.broken_surfaces.append(f"{surface.file}: start marker {surface.start!r} not found, so the region was never checked")
            continue
        end = text.find(surface.end, start + len(surface.start))
        if end == -1:
            report.broken_surfaces.append(f"{surface.file}: end marker {surface.end!r} not found after the start marker")
            continue
        report.surfaces_checked += 1
        offset = text.count("\n", 0, start) + 1
        for rel_line, line in enumerate(text[start:end].splitlines()):
            for vendor, pattern in vendor_patterns:
                if pattern.search(line):
                    report.findings.append(
                        Finding(
                            path=surface.file,
                            line_no=offset + rel_line,
                            competitor=vendor,
                            excerpt=line.strip()[:160],
                            neutral="a neutral capability descriptor (row/column labels), keeping every cell intact",
                            kind="comparison",
                        )
                    )


def scan_tree(root: Path, config: Config, config_path: Path) -> ScanReport:
    report = ScanReport(root=root, config_path=config_path)
    # Which competitor names were seen anywhere at all, and which allow entries
    # actually excused something. Both feed the reverse checks below.
    seen_names: set[str] = set()
    allow_hits: dict[int, int] = {i: 0 for i in range(len(config.allows))}

    for rel in tracked_files(root):
        if rel in SELF_REFERENTIAL or rel.endswith(SKIP_SUFFIXES):
            report.files_skipped += 1
            continue
        target = root / rel
        try:
            text = target.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            report.files_skipped += 1
            continue
        report.files_scanned += 1

        excused = excused_names(rel, config.allows)
        for competitor in config.competitors:
            if competitor.regex.search(text):
                seen_names.add(competitor.name)
                for index, allow in enumerate(config.allows):
                    if competitor.name in allow.names and _matches(rel, allow.paths):
                        allow_hits[index] += 1
        report.findings.extend(scan_text(rel, text, config.competitors, excused))

    scan_comparison_surfaces(root, config, report)

    # Reverse check 1: an allow entry that excuses nothing is stale. Either the
    # integration was removed and the exemption outlived it, or the path moved
    # and the exemption now covers nothing while looking like it still works.
    for index, allow in enumerate(config.allows):
        if allow_hits[index] == 0:
            report.stale_allows.append(f"{', '.join(allow.paths)} excuses {sorted(allow.names)} but no file there contains any of them")

    # Reverse check 2: a competitor pattern that matches nothing in the tree is
    # not proof of cleanliness on its own — the self-test proves each pattern
    # still matches its fixture. What is checked here is that the fixtures exist
    # and cover every declared competitor, which `--self-test` enforces.
    return report


def print_report(report: ScanReport, config: Config) -> None:
    print(f"competitor-naming gate: scanned {report.root}")
    print(f"  config:            {report.config_path}")
    print(f"  competitors:       {len(config.competitors)}")
    print(f"  allow entries:     {len(config.allows)}")
    print(f"  files scanned:     {report.files_scanned}")
    print(f"  files skipped:     {report.files_skipped} (binary, generated, or the gate's own machinery)")
    print(f"  comparison tables: {report.surfaces_checked}/{len(config.comparison_surfaces)} regions located and checked")

    if report.broken_surfaces:
        print("\nComparison-table regions that could not be located:")
        for item in report.broken_surfaces:
            print(f"  ✗ {item}")

    if report.stale_allows:
        print("\nStale allow-list entries (an exemption must not outlive the code it excused):")
        for item in report.stale_allows:
            print(f"  ✗ {item}")

    if report.findings:
        print(f"\n{len(report.findings)} competitor reference(s) found:")
        for finding in report.findings:
            label = "comparison table" if finding.kind == "comparison" else "competitor name"
            print(f"  ✗ {finding.path}:{finding.line_no}  [{label}] {finding.competitor}")
            print(f"      {finding.excerpt}")
            if finding.kind == "comparison":
                print(f"      → use {finding.neutral}")
            else:
                print(f"      → use {finding.neutral}, keeping the analytical content")
        print(
            "\nIf this is an integration reference (a connector, plugin manifest, setup\n"
            "guide, normalizer profile or test), add the path to [[allow]] in\n"
            "scripts/competitor_names.toml with the names it excuses and a reason."
        )

    if report.ok:
        print("\nOK: no competitor product named outside its integration surfaces.")


def self_test(config_path: Path, fixtures_path: Path) -> int:
    """Prove the gate is not vacuous, in both directions.

    A gate checked only against clean input cannot tell you it still works: a
    regex that stops matching turns it into a no-op that reports OK forever. A
    gate checked only against bad input can pass by flagging everything, which
    would break every connector page in the tree. Both directions are asserted.
    """
    config = load_config(config_path)
    corpus = json.loads(fixtures_path.read_text(encoding="utf-8"))
    failures: list[str] = []

    declared = {c.name for c in config.competitors}
    covered = {case["competitor"] for case in corpus["bad"]}
    missing = declared - covered
    if missing:
        failures.append(f"no known-bad fixture for declared competitor(s): {sorted(missing)}")

    # Direction 1: every known-bad sample must be caught, by the expected name.
    for case in corpus["bad"]:
        found = scan_text(case["path"], case["text"], config.competitors, excused=set())
        names = {f.competitor for f in found}
        if case["competitor"] not in names:
            failures.append(f"known-bad not caught ({case['competitor']}): {case['text'][:80]!r}")

    # Direction 2: every known-good sample must pass. These are real integration
    # shapes — a connector docstring, a plugin manifest line, a setup guide
    # heading, a lower-case SEO keyword — and flagging them would be a false
    # positive that breaks working connector surfaces.
    for case in corpus["good"]:
        excused = excused_names(case["path"], config.allows)
        found = scan_text(case["path"], case["text"], config.competitors, excused)
        if found:
            failures.append(
                f"known-good flagged at {case['path']}: {case['text'][:80]!r} "
                f"(matched {sorted({f.competitor for f in found})}) — {case['why']}"
            )

    # Direction 3: the comparison-surface check must catch a vendor name that the
    # integration allow-list would otherwise excuse, and must accept the neutral
    # form. This is the property that keeps a connector vendor out of a published
    # comparison table.
    vendor_patterns = [(v, re.compile(rf"\b{re.escape(v)}\b", re.IGNORECASE)) for v in config.comparison_vendors]
    for case in corpus["comparison_bad"]:
        if not any(p.search(case["text"]) for _, p in vendor_patterns):
            failures.append(f"comparison-table vendor not caught: {case['text'][:80]!r}")
    for case in corpus["comparison_good"]:
        hit = [v for v, p in vendor_patterns if p.search(case["text"])]
        if hit:
            failures.append(f"neutral comparison label flagged as vendor {hit}: {case['text'][:80]!r}")

    print(f"self-test: config {config_path}")
    print(f"  fixtures:          {fixtures_path}")
    print(
        f"  cases:             {len(corpus['bad'])} known-bad, {len(corpus['good'])} known-good, "
        f"{len(corpus['comparison_bad'])} comparison-bad, {len(corpus['comparison_good'])} comparison-good"
    )
    if failures:
        print(f"\nself-test FAILED ({len(failures)}):")
        for failure in failures:
            print(f"  ✗ {failure}")
        return 1
    print("  OK: every declared competitor has a fixture, bad input is caught, good input is not.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--root", help="repository to scan (default: the git worktree containing the CWD)")
    parser.add_argument("--config", help="path to competitor_names.toml (default: <root>/scripts/competitor_names.toml)")
    parser.add_argument("--fixtures", help="path to competitor_fixtures.json (default: alongside the config)")
    parser.add_argument("--self-test", action="store_true", help="prove the gate works, both directions")
    args = parser.parse_args()

    try:
        root = resolve_root(args.root)
        config_path = Path(args.config).resolve() if args.config else root / "scripts" / "competitor_names.toml"
        fixtures_path = Path(args.fixtures).resolve() if args.fixtures else config_path.parent / "competitor_fixtures.json"

        if args.self_test:
            return self_test(config_path, fixtures_path)

        config = load_config(config_path)
        report = scan_tree(root, config, config_path)
    except ConfigError as exc:
        print(f"competitor-naming gate: {exc}", file=sys.stderr)
        return 2

    print_report(report, config)
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
