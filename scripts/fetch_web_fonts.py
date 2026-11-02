#!/usr/bin/env python3
"""Download the web console's webfonts from Google Fonts into the repository.

``apps/web`` used to load its five faces through ``next/font/google``, which
resolves them **at compile time**: every ``next build`` issued a request to
``fonts.googleapis.com`` for the stylesheet and one to ``fonts.gstatic.com``
per font file.  That made the build depend on a third party being both
reachable *and* unchanged, and both halves bit us:

* unreachable — a build on a runner with no egress to Google fails with
  ``Module not found: Can't resolve
  '@vercel/turbopack-next/internal/font/google/font'``, which reads like a bad
  import and is a network error;
* changed — Google moved Source Code Pro from v30 to v32 and began serving a
  single variable file for the two weights ``apps/web`` asks for, so the two
  ``@font-face`` blocks pointed at one URL.  Turbopack cannot resolve a font
  file referenced twice and failed the same way, on a tree nobody had touched.

So the fonts are vendored and loaded with ``next/font/local``.  This script is
how they were produced and how they are refreshed; ``check_web_fonts.py`` is
the gate that keeps the vendored set and the TypeScript declarations honest,
and it runs offline so refreshing is a deliberate act rather than a build-time
accident.

Usage::

    python3 scripts/fetch_web_fonts.py            # refresh apps/web/src/fonts
    python3 scripts/fetch_web_fonts.py --check    # fail if a refresh would change anything

The request is byte-for-byte the one ``next/font/google`` would have made: the
URLs below are what ``getGoogleFontsUrl()`` builds for the options each face is
declared with, and the user agent is the one
``next/dist/compiled/@next/font/dist/google/fetch-resource.js`` sends in order
to be served ``woff2`` rather than ``ttf``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
import tempfile
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import TypedDict

# `scripts/` is on sys.path when this file is run as a program, but not when a
# test loads it by path with importlib. gate_toolkit sits beside it either way.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_if_requested  # noqa: E402 - needs the sys.path line above

self_test_if_requested(__file__)

REPO_ROOT = repo_root()
# The woff2 payload is served from `public/` rather than imported through the
# bundler so that the `<link rel="preload">` tags in the layouts can name a
# stable URL. Filenames carry a content hash, which is what makes the
# immutable cache header in `next.config.js` safe.
FONT_DIR = REPO_ROOT / "apps" / "web" / "public" / "fonts"
# The declarations derived from those files live beside the stylesheet they
# generate, under `src/`, so nothing describing the build is served to users.
MANIFEST = REPO_ROOT / "apps" / "web" / "src" / "fonts" / "manifest.json"

# Chrome UA. Google serves `ttf` to clients it does not recognise, so this is
# load-bearing rather than cosmetic — it is what gets us `woff2`.
USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36"

# The only two hosts this script may contact: the stylesheet API and the font
# CDN that stylesheet points at.
ALLOWED_HOSTS = frozenset({"fonts.googleapis.com", "fonts.gstatic.com"})

# An opener carrying *only* the handlers an https GET needs. Both
# `build_opener()` and the default `urlopen` install FileHandler and
# FTPHandler; omitting them means a `file://` or `ftp://` URL arriving in a
# Google response has no handler to serve it and raises, rather than being
# fetched and written into the repository as a font. UnknownHandler is here
# so that refusal is a clean URLError instead of `open()` returning None.
# HTTPHandler is absent too, so plain http cannot be used either.
_OPENER = urllib.request.OpenerDirector()
for _handler in (
    urllib.request.HTTPSHandler(),
    urllib.request.HTTPRedirectHandler(),
    urllib.request.HTTPErrorProcessor(),
    urllib.request.UnknownHandler(),
):
    _OPENER.add_handler(_handler)


class RemoteFace(TypedDict):
    """One `@font-face` block as Google's stylesheet describes it."""

    subset: str
    weight: str
    style: str
    unicodeRange: str
    url: str


class VendoredFace(TypedDict):
    """The same face once its file is vendored — `url` becomes `file`."""

    file: str
    subset: str
    weight: str
    style: str
    unicodeRange: str


class FamilyRecord(TypedDict):
    cssName: str
    googleQuery: str
    faces: list[VendoredFace]


class Manifest(TypedDict):
    _comment: str
    families: dict[str, FamilyRecord]


@dataclass(frozen=True)
class Family:
    """One font family, and the Google query the old call site resolved to."""

    # Slug used for the vendored filenames and the manifest key.
    slug: str
    # Family name as it appears in the stylesheet Google returns.
    css_name: str
    # The `family=` value `getGoogleFontsUrl()` builds for this face's options.
    query: str


FAMILIES = (
    # `Inter({ subsets: ['latin'] })` — no weight given, so the variable axis.
    Family("inter", "Inter", "Inter:wght@100..900"),
    # `JetBrains_Mono({ subsets: ['latin'] })` — likewise variable.
    Family("jetbrains-mono", "JetBrains Mono", "JetBrains+Mono:wght@100..800"),
    # `DM_Serif_Display({ weight: '400', style: ['normal', 'italic'] })`.
    Family("dm-serif-display", "DM Serif Display", "DM+Serif+Display:ital,wght@0,400;1,400"),
    # `Poppins({ weight: ['300', '400', '500', '600', '700'] })` — static cuts.
    Family("poppins", "Poppins", "Poppins:wght@300;400;500;600;700"),
    # `Source_Code_Pro({ weight: ['400', '500'] })` — the face that broke.
    Family("source-code-pro", "Source Code Pro", "Source+Code+Pro:wght@400;500"),
)

# `@font-face` blocks in a Google stylesheet are preceded by a comment naming
# the subset they cover. That comment is the only place the subset name appears,
# so it is parsed rather than inferred from the unicode-range.
_FACE_RE = re.compile(
    r"/\*\s*(?P<subset>[a-z0-9-]+)\s*\*/\s*@font-face\s*\{(?P<body>[^}]*)\}",
    re.IGNORECASE,
)


def _declaration(body: str, prop: str) -> str:
    match = re.search(rf"\b{re.escape(prop)}\s*:\s*(?P<value>[^;]+);", body)
    if match is None:
        raise SystemExit(f"Google stylesheet has a @font-face with no `{prop}`:\n{body}")
    return match.group("value").strip()


def _get(url: str) -> bytes:
    """Fetch `url`, which must be https on one of the two Google font hosts.

    The font-file URLs are read out of a stylesheet Google returns, so they
    are attacker-influenced in principle. `urllib` honours `file://`, which
    would turn an odd response into "read a local file and commit it as a
    font", so the opener below is built with no file, ftp or plain-http
    handler at all — those schemes are not merely rejected, they are
    unrepresentable. The host allowlist is the second, legible layer.
    """
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS:
        raise SystemExit(f"Refusing to fetch {url!r}: not https on {sorted(ALLOWED_HOSTS)}")
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with _OPENER.open(request, timeout=30) as response:
        return response.read()


def fetch_family(family: Family) -> list[RemoteFace]:
    """Return one record per `@font-face` Google serves for `family`."""
    url = f"https://fonts.googleapis.com/css2?family={family.query}&display=swap"
    css = _get(url).decode("utf-8")

    faces: list[RemoteFace] = []
    for match in _FACE_RE.finditer(css):
        body = match.group("body")
        src = _declaration(body, "src")
        href = re.search(r"url\((?P<href>https://[^)]+)\)", src)
        if href is None:
            raise SystemExit(f"@font-face src is not a remote url: {src}")
        faces.append(
            {
                "subset": match.group("subset"),
                "weight": _declaration(body, "font-weight"),
                "style": _declaration(body, "font-style"),
                "unicodeRange": _declaration(body, "unicode-range"),
                "url": href.group("href"),
            }
        )

    if not faces:
        raise SystemExit(f"No @font-face blocks found for {family.css_name} at {url}")
    return faces


def build(destination: Path) -> Manifest:
    """Download every face into `destination` and return the manifest."""
    destination.mkdir(parents=True, exist_ok=True)
    manifest: Manifest = {
        "_comment": (
            "Generated by scripts/fetch_web_fonts.py. Vendored so `next build` "
            "never contacts Google. Refresh with that script, never by hand."
        ),
        "families": {},
    }

    for family in FAMILIES:
        faces = fetch_family(family)
        # Google serves one *variable* file per subset, so the same URL is
        # reused across the weights that file covers. Download each distinct
        # URL once and let several faces point at the same vendored file —
        # exactly the sharing that Turbopack could not resolve remotely.
        by_url: dict[str, str] = {}
        records: list[VendoredFace] = []
        for face in faces:
            url = face["url"]
            if url not in by_url:
                payload = _get(url)
                if payload[:4] != b"wOF2":
                    raise SystemExit(f"{url} did not return a woff2 file")
                digest = hashlib.sha256(payload).hexdigest()
                name = f"{family.slug}-{face['subset']}-{digest[:8]}.woff2"
                (destination / name).write_bytes(payload)
                by_url[url] = name
            records.append(
                {
                    "file": by_url[url],
                    "subset": face["subset"],
                    "weight": face["weight"],
                    "style": face["style"],
                    "unicodeRange": face["unicodeRange"],
                }
            )
        manifest["families"][family.slug] = {
            "cssName": family.css_name,
            "googleQuery": family.query,
            "faces": records,
        }

    return manifest


def _written_state(directory: Path) -> dict[str, str]:
    """Map every vendored file to its sha256, for comparing two directories."""
    return {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(directory.glob("*.woff2"))}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Download into a temporary directory and report whether the vendored set is stale. Requires network.",
    )
    args = parser.parse_args()

    if args.check:
        with tempfile.TemporaryDirectory() as tmp:
            scratch = Path(tmp)
            fresh = build(scratch)
            stale = []
            if _written_state(scratch) != _written_state(FONT_DIR):
                stale.append("font files differ")
            if not MANIFEST.exists():
                stale.append("manifest.json is missing")
            elif json.loads(MANIFEST.read_text()) != fresh:
                stale.append("manifest.json differs")
            if stale:
                print("Vendored fonts are stale: " + "; ".join(stale))
                print("Refresh with: python3 scripts/fetch_web_fonts.py")
                return 1
        print("Vendored fonts match Google Fonts.")
        return 0

    # Write into a scratch directory first so a failed download cannot leave
    # the tree with half a font set.
    with tempfile.TemporaryDirectory() as tmp:
        scratch = Path(tmp)
        manifest = build(scratch)
        if FONT_DIR.exists():
            for stale_file in FONT_DIR.glob("*.woff2"):
                stale_file.unlink()
        FONT_DIR.mkdir(parents=True, exist_ok=True)
        for produced in sorted(scratch.glob("*.woff2")):
            shutil.copy2(produced, FONT_DIR / produced.name)
    MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n")

    total = sum(len(f["faces"]) for f in manifest["families"].values())
    files = len(list(FONT_DIR.glob("*.woff2")))
    print(f"Vendored {files} woff2 files covering {total} @font-face declarations.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
