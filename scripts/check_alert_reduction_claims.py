#!/usr/bin/env python3
"""A retracted benchmark figure must stay retracted on every surface that quotes it.

Why this exists
---------------
``apps/docs/docs/benchmark.md`` withdrew the 75.3 % alert-reduction claim: the
harness that produced it groups on four tiers of ``(rule_id, host, user)``,
while the shipping ``RawAlert.correlation_key()`` groups on
``{tenant}:{entity}:{tactic}``. It does not merely re-implement fusion's
grouping, it implements **different** grouping, so the number describes an
algorithm the product does not run.

The retraction reached exactly one of the three surfaces carrying the claim.

  * ``BenchmarkResults.tsx`` kept rendering a green **"Real measurement"**
    badge on ``0.753`` with a blurb asserting the harness used the production
    grouping rules, "same logic" — the precise sentence ``benchmark.md``
    exists to withdraw.
  * ``benchmarks/alert-reduction.md`` called the harness a "faithful in-harness
    re-implementation of the production Tier 1 / Tier 2 / Tier 3 grouping
    rules" and headlined 75.3 %. It is ``sidebar_position: 1``, so it was the
    first benchmark page a reader opened.
  * ``ComparisonTable.tsx`` qualified the figure as "measured on fixed noisy
    stream" — a qualifier, but not the one that matters.

A correction that lands on one surface and not the others is not a
correction; it is a repository that contradicts itself and cites whichever
page the reader happened to open. Prose cannot be generated the way a count
can, so the invariant is gated instead:

1. No published surface may assert the legacy harness runs the production
   grouping logic.
2. Any surface quoting the legacy figure must carry the retraction with it.
3. Surfaces must agree on the figure that *does* describe the product.

Usage
-----
    python3 scripts/check_alert_reduction_claims.py
    python3 scripts/check_alert_reduction_claims.py --check      # same, explicit
    python3 scripts/check_alert_reduction_claims.py --self-test
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

# `scripts/` is on sys.path when this file is run as a program, but not when a
# test loads it by path with importlib. gate_toolkit sits beside it either way.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_main

REPO_ROOT = repo_root()

#: Surfaces a reader can reach: the docs portal, the marketing/console UI, and
#: the governance documents at the root. Deliberately not `services/` — a test
#: docstring explaining the defect must be free to describe it.
SCAN_ROOTS: tuple[tuple[Path, tuple[str, ...]], ...] = (
    (REPO_ROOT / "apps" / "docs" / "docs", ("*.md", "*.mdx")),
    (REPO_ROOT / "apps" / "web" / "src", ("*.tsx", "*.ts")),
    (REPO_ROOT / "docs" / "audit", ("*.md",)),
)

#: Root-level documents that publish claims.
SCAN_FILES: tuple[Path, ...] = (
    REPO_ROOT / "README.md",
    REPO_ROOT / "ROADMAP.md",
    REPO_ROOT / "RELEASES.md",
)

#: Where the real figure is pinned, beside the measurement that produces it.
REAL_MEASUREMENT = REPO_ROOT / "services" / "fusion" / "tests" / "test_alert_reduction_real.py"
_PINNED = re.compile(r"^PUBLISHED_REDUCTION_PCT\s*=\s*(?P<pct>\d+(?:\.\d+)?)\s*$", re.MULTILINE)

#: The legacy figure, in every spelling a surface has used for it.
LEGACY_FIGURE = re.compile(r"\b75\.3\s*%|\b0\.753\b")


def published_reduction_pct() -> float:
    """The real figure, read from the test that measures it.

    Not a literal here. A gate that carries its own copy of the number it is
    policing cannot detect the number changing — it can only detect surfaces
    disagreeing with the gate, which is the circularity this repository has
    been bitten by before.
    """
    if not REAL_MEASUREMENT.is_file():
        raise SystemExit(f"{Path(sys.argv[0]).name}: {REAL_MEASUREMENT} missing — nothing pins the published figure")
    match = _PINNED.search(REAL_MEASUREMENT.read_text(encoding="utf-8"))
    if match is None:
        raise SystemExit(f"{Path(sys.argv[0]).name}: no PUBLISHED_REDUCTION_PCT in {REAL_MEASUREMENT.relative_to(REPO_ROOT)}")
    return float(match.group("pct"))


def real_figure_pattern(pct: float) -> re.Pattern[str]:
    """Match the pinned figure in both spellings surfaces use: `33.3 %`, `0.333`."""
    as_pct = f"{pct:g}".replace(".", r"\.")
    as_ratio = f"{pct / 100:g}".replace(".", r"\.")
    return re.compile(rf"\b{as_pct}\s*%|\b{as_ratio}\b")


#: Surfaces that publish the real figure in prose. Explicit, like
#: ``COUNT_BEARING_FILES`` in ``generate_connector_count.py``: when the
#: measurement moves, each of these has to move with it, and naming them is
#: what makes that a red build rather than a silent contradiction.
FIGURE_BEARING_SURFACES: tuple[Path, ...] = (
    REPO_ROOT / "apps" / "docs" / "docs" / "benchmark.md",
    REPO_ROOT / "apps" / "docs" / "docs" / "benchmarks" / "alert-reduction.md",
    REPO_ROOT / "apps" / "web" / "src" / "components" / "benchmark" / "ComparisonTable.tsx",
)

#: Any one of these, in the same file, counts as carrying the retraction.
#: Several spellings because the surfaces legitimately differ in register: a
#: claim-to-gate matrix row is terser than a benchmark page.
RETRACTION_MARKERS: tuple[re.Pattern[str], ...] = (
    re.compile(r"does not describe this product", re.IGNORECASE),
    re.compile(r"not describing this product", re.IGNORECASE),
    re.compile(r"\blegacy suite\b", re.IGNORECASE),
    re.compile(r"correlation_key", re.IGNORECASE),
)

#: A paragraph carrying one of these is *reporting* the withdrawn claim, not
#: making it. Documenting a retraction necessarily quotes the wording being
#: retracted, and a gate that cannot tell those apart forces the correction to
#: be written in circumlocutions.
NEGATION_MARKERS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bwas wrong\b", re.IGNORECASE),
    re.compile(r"\blong described\b", re.IGNORECASE),
    re.compile(r"\bretract", re.IGNORECASE),
    re.compile(r"\bwithdraw", re.IGNORECASE),
    re.compile(r"\b(is|was) not one\b", re.IGNORECASE),
    re.compile(r"\bnot a faithful\b", re.IGNORECASE),
)

#: Assertions that the legacy harness is equivalent to what ships. Each one
#: was live in the tree when this gate was written.
BANNED_CLAIMS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"faithful[\s\-]+(in[\s\-]harness[\s\-]+)?re[\s\-]?implementation", re.IGNORECASE),
        'calls the legacy harness a "faithful re-implementation" of production grouping',
    ),
    (
        re.compile(r"grouping rules\s*[-—,]\s*same logic", re.IGNORECASE),
        'asserts the harness runs the "same logic" as the production grouping rules',
    ),
    (
        re.compile(r"same Tier 1\s*/\s*2\s*/\s*3 algorithm shipped", re.IGNORECASE),
        "claims the harness is the algorithm shipped in services/fusion",
    ),
)

#: The "Real measurement" label attached to the legacy suite, in the four
#: shapes it took: a section heading, a table row, a glossary entry, and a
#: badge on a console panel. None of these quotes 75.3 % or uses the word
#: "faithful", so the checks above saw nothing wrong with any of them — the
#: claim was carried entirely by the label. Matched within one paragraph so
#: an unrelated "Real measurement" elsewhere on the same page (the wet-eval
#: latency and token rows genuinely are measurements) is not swept up.
_MEASUREMENT_LABEL = re.compile(r"Real measurement", re.IGNORECASE)
_LEGACY_SUBJECT = re.compile(r"`?alert_reduction`?|alert[- ]reduction|alert reduction", re.IGNORECASE)
_PRODUCT_LOGIC = re.compile(r"correlation_key|product logic", re.IGNORECASE)

#: The alert-reduction suite card must not be badged as a real measurement.
#: Matched structurally rather than by prose: the badge is chosen by a `kind`
#: field inside the `alert_reduction` block of `SUITE_META`.
_SUITE_META_ALERT_REDUCTION = re.compile(
    r"alert_reduction:\s*\{(?P<body>.*?)\n\s{2}\},",
    re.DOTALL,
)


def _enclosing_paragraph(text: str, index: int) -> str:
    """The blank-line-delimited block containing ``index``."""
    start = text.rfind("\n\n", 0, index)
    end = text.find("\n\n", index)
    return text[(0 if start < 0 else start) : (len(text) if end < 0 else end)]


def _iter_surfaces() -> list[Path]:
    """Every published file this gate renders a verdict about."""
    found: list[Path] = []
    for root, globs in SCAN_ROOTS:
        if not root.is_dir():
            continue
        for pattern in globs:
            found.extend(p for p in root.rglob(pattern) if "node_modules" not in p.parts)
    found.extend(p for p in SCAN_FILES if p.is_file())
    return sorted(set(found))


def violations(files: dict[Path, str], pct: float, *, whole_tree: bool = False) -> list[str]:
    """Every finding, as a rendered line. Pure, so the self-test can drive it.

    ``whole_tree`` enables the checks that are only meaningful over a complete
    scan — chiefly "a surface that must publish the figure is absent". Without
    it the self-test's injected snippets would trip that check and every case
    would report a finding regardless of what it was testing, which is a
    self-test that passes because it is broken.
    """
    found: list[str] = []
    real_figure = real_figure_pattern(pct)
    required = {p.relative_to(REPO_ROOT) for p in FIGURE_BEARING_SURFACES}
    seen_bearing: set[Path] = set()

    for path, text in sorted(files.items()):
        rel = path.relative_to(REPO_ROOT) if path.is_absolute() else path

        for pattern, description in BANNED_CLAIMS:
            for match in pattern.finditer(text):
                if any(n.search(_enclosing_paragraph(text, match.start())) for n in NEGATION_MARKERS):
                    continue
                line = text[: match.start()].count("\n") + 1
                found.append(f"{rel}:{line}: {description} — {match.group(0)!r}")

        legacy = LEGACY_FIGURE.search(text)
        if legacy and not (real_figure.search(text) or any(m.search(text) for m in RETRACTION_MARKERS)):
            line = text[: legacy.start()].count("\n") + 1
            found.append(
                f"{rel}:{line}: quotes the legacy 75.3% alert-reduction figure without the retraction. "
                "Say that it describes a four-tier scheme the product does not run, and point at the "
                f"{pct:g}% measured against RawAlert.correlation_key()."
            )

        if rel in required:
            seen_bearing.add(rel)
            if not real_figure.search(text):
                found.append(
                    f"{rel}: publishes the alert-reduction figure but does not quote {pct:g}%, which is what "
                    "PUBLISHED_REDUCTION_PCT in services/fusion/tests/test_alert_reduction_real.py measures."
                )

        for match in _MEASUREMENT_LABEL.finditer(text):
            para = _enclosing_paragraph(text, match.start())
            if not _LEGACY_SUBJECT.search(para):
                continue
            # The real-key measurement is a measurement, and says so.
            if _PRODUCT_LOGIC.search(para) or any(n.search(para) for n in NEGATION_MARKERS):
                continue
            line = text[: match.start()].count("\n") + 1
            found.append(
                f'{rel}:{line}: labels the legacy alert-reduction suite a "Real measurement". '
                "It groups on four tiers of (rule_id, host, user); the product groups on "
                "{tenant}:{entity}:{tactic}."
            )

        block = _SUITE_META_ALERT_REDUCTION.search(text)
        if block and re.search(r"kind:\s*'measurement'", block.group("body")):
            line = text[: block.start()].count("\n") + 1
            found.append(
                f"{rel}:{line}: the alert_reduction suite is declared kind: 'measurement', which renders a "
                '"Real measurement" badge on a figure that describes an algorithm this product does not run.'
            )

    if whole_tree:
        for missing in sorted(required - seen_bearing):
            found.append(f"{missing}: named in FIGURE_BEARING_SURFACES but not present — remove it or restore the page")

    return found


def check() -> int:
    surfaces = _iter_surfaces()
    if not surfaces:
        print(
            f"{Path(sys.argv[0]).name}: found no published surfaces under {REPO_ROOT} — refusing to report a clean tree it never opened",
            file=sys.stderr,
        )
        return 2

    pct = published_reduction_pct()
    files = {p: p.read_text(encoding="utf-8", errors="replace") for p in surfaces}
    quoting = sum(1 for text in files.values() if LEGACY_FIGURE.search(text))
    found = violations(files, pct, whole_tree=True)

    print(
        f"alert-reduction claims: scanned {len(files)} published surfaces, "
        f"{quoting} quote the legacy figure; the measured figure is {pct:g}%"
    )
    if found:
        print("\nthe 75.3% alert-reduction figure was retracted; these surfaces still assert it:", file=sys.stderr)
        for line in found:
            print(f"  - {line}", file=sys.stderr)
        print(
            "\nSee apps/docs/docs/benchmark.md#why-there-are-two-alert-reduction-numbers for the wording to reuse.",
            file=sys.stderr,
        )
        return 1

    print("OK: every surface quoting the legacy figure carries the retraction.")
    return 0


def _self_test() -> int:
    """Prove the gate detects each claim it forbids, on injected text."""
    pct = published_reduction_pct()
    real = f"{pct:g}%"
    fake = Path("apps/docs/docs/injected.md")

    cases: list[tuple[str, str]] = [
        (
            "flags a bare legacy figure with no retraction",
            "The harness reports a 75.3 % reduction ratio on a noisy stream.",
        ),
        (
            'flags a "faithful re-implementation" claim',
            f"The code under test is a faithful in-harness re-implementation of the production rules. {real}",
        ),
        (
            'flags a "same logic" claim',
            f"fed into the production Tier 1 / 2 / 3 grouping rules — same logic, no DB-backed dedup. {real}",
        ),
        (
            'flags a "Real measurement" label on the legacy suite',
            "| `alert_reduction` | Real measurement | 1 000-alert noisy stream |",
        ),
        (
            "flags a Real measurement badge beside an alert-reduction heading",
            "<h3>Alert reduction (75.3%)</h3>\n<span>Real measurement</span>\nlegacy suite, 33.3%",
        ),
        (
            "flags kind: 'measurement' on the alert_reduction suite card",
            "const SUITE_META = {\n"
            "  alert_reduction: {\n"
            "    id: 'alert_reduction',\n"
            "    kind: 'measurement',\n"
            f"    blurb: 'see the {real} legacy suite note',\n"
            "  },\n"
            "};\n",
        ),
    ]
    extra = [(name, bool(violations({fake: text}, pct))) for name, text in cases]

    # A surface on the bearing list that quotes the *old* figure after the
    # measurement moved. This is the case the previous design could not see,
    # because the gate carried its own copy of the number.
    extra.append(
        (
            "flags a bearing surface left on a superseded figure",
            bool(
                violations(
                    {FIGURE_BEARING_SURFACES[0]: f"reduction is {pct + 1:g}% — legacy suite retained"},
                    pct,
                )
            ),
        )
    )
    extra.append(
        (
            "passes the retracted wording benchmark.md already uses",
            not violations(
                {
                    fake: (
                        "| Alert reduction (legacy suite) | 75.3 % | A four-tier scheme implemented inside "
                        "the test. Retained for continuity; does not describe this product. The real "
                        f"correlation_key() measurement reports {real}."
                    )
                },
                pct,
            ),
        )
    )
    extra.append(("passes the tree as committed", check() == 0))

    return self_test_main(Path(__file__).name, ["--check"], extra)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Render the verdict (the default).")
    parser.add_argument("--self-test", action="store_true", help="Prove this gate detects the drift it claims to.")
    args = parser.parse_args(argv)
    return _self_test() if args.self_test else check()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
