#!/usr/bin/env python3
"""Generate ``apps/web/src/fonts/fonts.css`` from the vendored font manifest.

This is the offline half of the self-hosted font setup. ``fetch_web_fonts.py``
talks to Google and produces ``manifest.json`` plus the woff2 payload; this
script turns that manifest into the stylesheet the console actually loads, and
in ``--check`` mode it is the CI gate that keeps the three in agreement.

It exists because ``next/font/google`` used to do all of this during
``next build`` — against the network. The output here reproduces what that
loader emitted, deliberately and verifiably:

* one ``@font-face`` per subset per weight per style, carrying the same
  ``unicode-range`` Google serves, so a page with Cyrillic or Vietnamese text
  still gets the real face rather than silently dropping to the fallback;
* a size-adjusted ``<Family> Fallback`` face per family, using the exact
  override metrics ``next/font``'s own table holds for that family, so the
  pre-swap paint occupies the same space and there is no new layout shift;
* a CSS custom property per family whose value is
  ``'<Family>', '<Family> Fallback'`` — the same two-entry list
  ``postcss-next-font`` built, which the Tailwind ``fontFamily`` stacks in
  ``tailwind.config.ts`` then extend with ``system-ui`` and friends.

Usage::

    python3 scripts/generate_web_font_css.py            # write fonts.css
    python3 scripts/generate_web_font_css.py --check    # CI gate, no network
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import tempfile
from pathlib import Path

# `scripts/` is on sys.path when this file is run as a program, but not when a
# test loads it by path with importlib. gate_toolkit sits beside it either way.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_main  # noqa: E402 - needs the sys.path line above

REPO_ROOT = repo_root()
WEB = REPO_ROOT / "apps" / "web"
FONT_PAYLOAD_DIR = WEB / "public" / "fonts"
MANIFEST = WEB / "src" / "fonts" / "manifest.json"
STYLESHEET = WEB / "src" / "fonts" / "fonts.css"
PRELOADS_TS = WEB / "src" / "fonts" / "preloads.ts"

# Public URL prefix the stylesheet and the preload tags both use. `public/` is
# served from the root, and there is no basePath/assetPrefix in next.config.js.
PUBLIC_PREFIX = "/fonts"

# Exactly what `getFallbackFontOverrideMetrics(family)` returns from
# `next/dist/compiled/@next/font/dist/google` for these five families. Copied
# in rather than computed so the generated fallback faces are identical to the
# ones `next/font/google` emitted before the switch; `check_web_fonts` in the
# web test suite pins the resulting CSS.
FALLBACK_METRICS: dict[str, dict[str, str]] = {
    "inter": {
        "fallbackFont": "Arial",
        "ascentOverride": "90.44%",
        "descentOverride": "22.52%",
        "lineGapOverride": "0.00%",
        "sizeAdjust": "107.12%",
    },
    "jetbrains-mono": {
        "fallbackFont": "Arial",
        "ascentOverride": "75.79%",
        "descentOverride": "22.29%",
        "lineGapOverride": "0.00%",
        "sizeAdjust": "134.59%",
    },
    "dm-serif-display": {
        "fallbackFont": "Times New Roman",
        "ascentOverride": "94.37%",
        "descentOverride": "30.51%",
        "lineGapOverride": "0.00%",
        "sizeAdjust": "109.78%",
    },
    "poppins": {
        "fallbackFont": "Arial",
        "ascentOverride": "93.62%",
        "descentOverride": "31.21%",
        "lineGapOverride": "8.92%",
        "sizeAdjust": "112.16%",
    },
    "source-code-pro": {
        "fallbackFont": "Arial",
        "ascentOverride": "73.11%",
        "descentOverride": "20.28%",
        "lineGapOverride": "0.00%",
        "sizeAdjust": "134.59%",
    },
}

# The CSS custom property each family is exposed under, and the class that
# declares it. The property names are the ones `tailwind.config.ts` already
# reads; changing one here without changing it there silently drops the face.
#
# `scope` mirrors the import graph the `next/font` call sites had: the console
# chrome only ever loaded Inter and JetBrains Mono, and the three VelvetEdge
# faces were imported by the marketing routes alone.
VARIABLES: dict[str, tuple[str, str]] = {
    "inter": ("--font-inter", "console"),
    "jetbrains-mono": ("--font-mono", "console"),
    "dm-serif-display": ("--font-velvet-display", "velvet"),
    "poppins": ("--font-velvet-body", "velvet"),
    "source-code-pro": ("--font-velvet-mono", "velvet"),
}

# Which faces carried `preload: true`. JetBrains Mono and Source Code Pro were
# both declared `preload: false` because they are used in code blocks rather
# than on every page, and preloading them produced "preloaded but not used"
# console warnings. Only the latin subset was ever preloaded — `subsets:
# ['latin']` is what selected it.
PRELOADED = {"inter", "dm-serif-display", "poppins"}
PRELOAD_SUBSET = "latin"

HEADER = """/*
 * Self-hosted webfaces for the console and the marketing surfaces.
 *
 * GENERATED by scripts/generate_web_font_css.py from
 * src/fonts/manifest.json — do not edit by hand. Refresh the payload with
 * scripts/fetch_web_fonts.py, then re-run the generator.
 *
 * These five families used to be loaded through `next/font/google`, which
 * resolves a font by fetching from fonts.googleapis.com and fonts.gstatic.com
 * *during `next build`*. That made every build — CI, the production image,
 * a contributor's laptop — depend on a third party being reachable and on its
 * response not changing. Both failed: an unreachable Google fails the build
 * with `Can't resolve '@vercel/turbopack-next/internal/font/google/font'`,
 * and in Nov 2026 Google began serving one shared variable file for the two
 * Source Code Pro weights this app asks for, which Turbopack cannot resolve
 * either — reddening `main` with no commit having touched the web app.
 *
 * The faces, weights, styles, unicode-ranges and fallback metrics below are
 * the ones `next/font/google` produced; see the generator for how each is
 * derived.
 */
"""


def _families(manifest: dict) -> dict:
    families = manifest.get("families")
    if not isinstance(families, dict) or not families:
        raise SystemExit(f"{MANIFEST} has no families")
    return families


def render(manifest: dict) -> str:
    """Build the stylesheet text from a manifest."""
    families = _families(manifest)
    out: list[str] = [HEADER]

    for slug, family in families.items():
        css_name = family["cssName"]
        out.append(f"/* ─── {css_name} ─── */")
        for face in family["faces"]:
            out.append(
                "@font-face {\n"
                f"  font-family: '{css_name}';\n"
                f"  font-style: {face['style']};\n"
                f"  font-weight: {face['weight']};\n"
                "  font-display: swap;\n"
                f"  src: url('{PUBLIC_PREFIX}/{face['file']}') format('woff2');\n"
                f"  unicode-range: {face['unicodeRange']};\n"
                "}"
            )

        metrics = FALLBACK_METRICS[slug]
        out.append(
            "@font-face {\n"
            f"  font-family: '{css_name} Fallback';\n"
            f'  src: local("{metrics["fallbackFont"]}");\n'
            f"  ascent-override: {metrics['ascentOverride']};\n"
            f"  descent-override: {metrics['descentOverride']};\n"
            f"  line-gap-override: {metrics['lineGapOverride']};\n"
            f"  size-adjust: {metrics['sizeAdjust']};\n"
            "}"
        )
        out.append("")

    # One class per scope rather than `:root`, so the VelvetEdge properties stay
    # confined to the marketing routes exactly as the old import graph confined
    # them. The class names are what `layout.tsx` and `marketing-fonts.ts`
    # apply.
    for scope, label in (("console", "Console chrome"), ("velvet", "VelvetEdge marketing")):
        decls = [
            f"  {prop}: '{families[slug]['cssName']}', '{families[slug]['cssName']} Fallback';"
            for slug, (prop, slug_scope) in VARIABLES.items()
            if slug_scope == scope
        ]
        out.append(f"/* {label} custom properties */")
        out.append(f".font-{scope}-vars {{\n" + "\n".join(decls) + "\n}")
        out.append("")

    return "\n".join(out).rstrip() + "\n"


def preload_hrefs(manifest: dict, scope: str) -> list[str]:
    """Public URLs that carried `preload: true` on the latin subset."""
    families = _families(manifest)
    hrefs: list[str] = []
    for slug, (_prop, slug_scope) in VARIABLES.items():
        if slug_scope != scope or slug not in PRELOADED:
            continue
        for face in families[slug]["faces"]:
            if face["subset"] == PRELOAD_SUBSET:
                href = f"{PUBLIC_PREFIX}/{face['file']}"
                if href not in hrefs:
                    hrefs.append(href)
    return hrefs


def render_preloads(manifest: dict) -> str:
    """Emit the preload URL lists as TypeScript so they cannot drift."""

    def literal(scope: str) -> str:
        hrefs = preload_hrefs(manifest, scope)
        return "\n".join(f"  '{href}'," for href in hrefs)

    return (
        "// GENERATED by scripts/generate_web_font_css.py — do not edit by hand.\n"
        "//\n"
        '// `next/font/google` used to emit a <link rel="preload"> for every font\n'
        "// file whose subset appeared in the call's `subsets` option, on the routes\n"
        "// that imported the face. These lists reproduce that set exactly: the latin\n"
        "// subset of the faces that were declared `preload: true`. JetBrains Mono and\n"
        "// Source Code Pro are absent because both set `preload: false` — they are\n"
        "// used in code blocks rather than on every page, and preloading them\n"
        "// produced 'preloaded but not used' warnings.\n"
        "\n"
        "/** Preloaded by the root layout — the console chrome loads Inter everywhere. */\n"
        f"export const CONSOLE_FONT_PRELOADS: readonly string[] = [\n{literal('console')}\n];\n"
        "\n"
        "/** Preloaded by the marketing surfaces only, matching the old import graph. */\n"
        f"export const VELVET_FONT_PRELOADS: readonly string[] = [\n{literal('velvet')}\n];\n"
    )


def verify_payload(manifest: dict) -> list[str]:
    """Every file the manifest names must exist and be a real woff2."""
    problems: list[str] = []
    referenced: set[str] = set()
    for slug, family in _families(manifest).items():
        if slug not in FALLBACK_METRICS:
            problems.append(f"{slug}: no fallback metrics declared in the generator")
        if slug not in VARIABLES:
            problems.append(f"{slug}: no CSS custom property declared in the generator")
        for face in family["faces"]:
            name = face["file"]
            referenced.add(name)
            path = FONT_PAYLOAD_DIR / name
            if not path.exists():
                problems.append(f"{slug}: manifest names {name}, which is not in public/fonts")
                continue
            payload = path.read_bytes()
            if payload[:4] != b"wOF2":
                problems.append(f"{name} is not a woff2 file")
            # The filename carries the first 8 hex of the payload's sha256.
            # A file swapped without regenerating the manifest fails here.
            expected = hashlib.sha256(payload).hexdigest()[:8]
            if f"-{expected}.woff2" not in name:
                problems.append(f"{name} does not match its own content hash ({expected})")

    on_disk = {p.name for p in FONT_PAYLOAD_DIR.glob("*.woff2")}
    for orphan in sorted(on_disk - referenced):
        problems.append(f"{orphan} is in public/fonts but no manifest face references it")
    return problems


def _injected_cases() -> list[tuple[str, bool]]:
    """Prove the comparisons still fire, by breaking each one on purpose.

    "Refuses an empty tree" says the gate fails closed; it says nothing about
    whether it can still see drift in a tree that *does* have content. Each
    case below perturbs exactly one thing a real refresh could get wrong and
    requires the gate to notice.
    """
    global FONT_PAYLOAD_DIR  # noqa: PLW0603 - restored in the `finally` below
    manifest = json.loads(MANIFEST.read_text())
    first = next(iter(manifest["families"].values()))
    sample = first["faces"][0]
    real_dir = FONT_PAYLOAD_DIR
    cases: list[tuple[str, bool]] = []

    drifted = json.loads(MANIFEST.read_text())
    next(iter(drifted["families"].values()))["faces"][0]["unicodeRange"] = "U+0041"
    cases.append(("a changed unicode-range in the manifest changes the generated stylesheet", render(drifted) != render(manifest)))

    try:
        with tempfile.TemporaryDirectory() as tmp:
            scratch = Path(tmp)
            for woff2 in real_dir.glob("*.woff2"):
                shutil.copy2(woff2, scratch / woff2.name)
            FONT_PAYLOAD_DIR = scratch

            cases.append(("an untouched payload reports no problems", verify_payload(manifest) == []))

            (scratch / sample["file"]).unlink()
            cases.append(("a manifest face naming a missing file is refused", verify_payload(manifest) != []))

            # Right name, wrong bytes — the case a swapped font would produce.
            (scratch / sample["file"]).write_bytes(b"wOF2" + b"\x00" * 64)
            problems = verify_payload(manifest)
            cases.append(
                (
                    "a woff2 whose bytes no longer match its filename hash is refused",
                    any("content hash" in p for p in problems),
                )
            )

            shutil.copy2(real_dir / sample["file"], scratch / sample["file"])
            (scratch / "orphan-latin-00000000.woff2").write_bytes(b"wOF2")
            cases.append(
                (
                    "a woff2 on disk that no manifest face references is refused",
                    any("orphan" in p for p in verify_payload(manifest)),
                )
            )
    finally:
        FONT_PAYLOAD_DIR = real_dir

    return cases


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail if fonts.css is stale or the vendored payload disagrees with the manifest.",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Prove this gate still detects drift, then exit.",
    )
    args = parser.parse_args()

    if args.self_test:
        return self_test_main("generate_web_font_css.py", ["--check"], extra=_injected_cases())

    if not MANIFEST.exists():
        print(f"Missing {MANIFEST.relative_to(REPO_ROOT)} — run scripts/fetch_web_fonts.py")
        return 1
    manifest = json.loads(MANIFEST.read_text())

    problems = verify_payload(manifest)
    expected_css = render(manifest)
    expected_preloads = render_preloads(manifest)

    if args.check:
        for path, expected in ((STYLESHEET, expected_css), (PRELOADS_TS, expected_preloads)):
            name = path.name
            if not path.exists():
                problems.append(f"{name} is missing")
            elif path.read_text() != expected:
                problems.append(f"{name} is stale (regenerate with scripts/generate_web_font_css.py)")
        if problems:
            print("Self-hosted font check FAILED:")
            for problem in problems:
                print(f"  - {problem}")
            return 1
        faces = sum(len(f["faces"]) for f in _families(manifest).values())
        files = len(list(FONT_PAYLOAD_DIR.glob("*.woff2")))
        print(f"OK — {files} vendored woff2 files, {faces} @font-face declarations, fonts.css current.")
        return 0

    if problems:
        print("Refusing to generate — the vendored payload is inconsistent:")
        for problem in problems:
            print(f"  - {problem}")
        return 1

    STYLESHEET.write_text(expected_css)
    PRELOADS_TS.write_text(expected_preloads)
    print(f"Wrote {STYLESHEET.relative_to(REPO_ROOT)} and {PRELOADS_TS.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
