#!/usr/bin/env python3
"""Render AiSOC white-paper markdown files to PDF.

Phase 4.3 update: the script now discovers every markdown file under
``apps/web/content/papers/`` and renders each one to
``apps/web/public/papers/<slug>.pdf``. This is what the CI papers
workflow drives.

Backwards-compatible CLI: passing ``--input`` / ``--output`` still
renders a single paper at an explicit path so the local dev workflow
documented in ``apps/web/public/papers/README.md`` keeps working.

It uses the WeasyPrint stack already required by the executive-digest
PDF in ``services/api/app/services/digest_pdf.py`` plus a ``markdown``
package for HTML conversion. Both are pure-Python installs on top of
native libs (Pango / Cairo / GLib) that are pinned in
``services/api/Dockerfile`` and in the ``papers`` CI workflow.

If WeasyPrint is not available (typical for a CI runner without the
native stack) the script exits with code 2 and a clear message so
callers can fall back to shipping the markdown unrendered.

This script is deliberately dependency-light. It does not introduce a
new heavy dependency (e.g. puppeteer / headless Chromium); WeasyPrint
is already part of the AiSOC build profile for the API service.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tempfile
from pathlib import Path

# `scripts/` is on sys.path when this file is run as a program, but not when a
# sibling imports it.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_main  # noqa: E402

REPO_ROOT = repo_root()
DEFAULT_SRC_DIR = REPO_ROOT / "apps" / "web" / "content" / "papers"
DEFAULT_OUT_DIR = REPO_ROOT / "apps" / "web" / "public" / "papers"

# Records the digest of each markdown source at the moment its PDF was
# rendered, so `--check` can tell a stale PDF from a current one.
#
# The digest is taken over the *source markdown*, never the rendered PDF.
# WeasyPrint stamps a creation timestamp into its output and glyph metrics
# depend on which fonts the host happens to have installed, so two correct
# renders of one source do not produce equal bytes. A PDF byte comparison
# would therefore fail for reasons that have nothing to do with staleness.
MANIFEST_PATH = DEFAULT_OUT_DIR / "render-manifest.json"

PRINT_CSS = """
@page {
    size: A4;
    margin: 22mm 18mm 22mm 18mm;
    @bottom-center {
        content: counter(page) " / " counter(pages);
        font-family: "Inter", "Helvetica Neue", Arial, sans-serif;
        font-size: 9pt;
        color: #6b7280;
    }
    @top-right {
        content: string(paper-title);
        font-family: "Inter", "Helvetica Neue", Arial, sans-serif;
        font-size: 8pt;
        color: #9ca3af;
    }
}

html, body {
    font-family: "Inter", "Helvetica Neue", Arial, sans-serif;
    font-size: 10.5pt;
    line-height: 1.55;
    color: #111827;
}

h1 {
    font-size: 22pt;
    margin: 0 0 0.4em 0;
    color: #0f172a;
    page-break-before: auto;
    string-set: paper-title content();
}
h2 {
    font-size: 15pt;
    margin: 1.6em 0 0.4em 0;
    color: #0f172a;
    page-break-after: avoid;
}
h3 {
    font-size: 12pt;
    margin: 1.2em 0 0.3em 0;
    color: #1f2937;
    page-break-after: avoid;
}

p { margin: 0 0 0.7em 0; }

code, pre {
    font-family: "JetBrains Mono", "Menlo", "Consolas", monospace;
    font-size: 9pt;
    background: #f1f5f9;
    color: #0f172a;
}
code { padding: 0 2px; }
pre {
    padding: 10px 12px;
    border-radius: 4px;
    overflow-x: auto;
    page-break-inside: avoid;
}

blockquote {
    border-left: 3px solid #94a3b8;
    margin: 0.6em 0;
    padding: 0.2em 0 0.2em 0.8em;
    color: #334155;
    font-style: italic;
}

table {
    border-collapse: collapse;
    width: 100%;
    margin: 0.6em 0;
    font-size: 9.5pt;
    page-break-inside: avoid;
}
th, td {
    border: 1px solid #cbd5e1;
    padding: 5px 7px;
    text-align: left;
    vertical-align: top;
}
th { background: #e2e8f0; }

a { color: #1d4ed8; text-decoration: none; }
a:hover { text-decoration: underline; }

hr {
    border: none;
    border-top: 1px solid #cbd5e1;
    margin: 1em 0;
}

ul, ol { margin: 0.2em 0 0.7em 1.4em; padding: 0; }
li { margin: 0.2em 0; }
"""

COVER_HTML = """
<div style="page-break-after: always;">
  <div style="margin-top: 60mm; text-align: center;">
    <div style="font-size: 32pt; font-weight: 700; color: #0f172a;">
      {title}
    </div>
    <div style="margin-top: 12mm; font-size: 13pt; color: #475569;">
      {subtitle}
    </div>
    <div style="margin-top: 18mm; font-size: 10pt; color: #64748b;">
      AiSOC project · {version} · Released {date}
    </div>
    <div style="margin-top: 4mm; font-size: 10pt; color: #94a3b8;">
      MIT licensed · github.com/beenuar/AiSOC
    </div>
  </div>
</div>
"""


def _strip_frontmatter(source: str) -> tuple[dict[str, str], str]:
    """Return (metadata, body) after stripping YAML frontmatter."""
    if not source.startswith("---"):
        return {}, source
    parts = source.split("---", 2)
    if len(parts) < 3:
        return {}, source
    raw_meta, body = parts[1], parts[2]
    meta: dict[str, str] = {}
    for line in raw_meta.strip().splitlines():
        if ":" in line and not line.startswith(" "):
            key, _, value = line.partition(":")
            meta[key.strip()] = value.strip().strip('"').strip("'")
    return meta, body.lstrip("\n")


def _render_one(markdown_path: Path, output_path: Path) -> None:
    try:
        import markdown as md  # type: ignore[import-untyped]
    except ImportError as exc:
        print(
            "[render_white_paper] ERROR: the `markdown` package is required. "
            "Install with `pip install markdown weasyprint` or run inside the "
            "services/api Dockerfile build profile.",
            file=sys.stderr,
        )
        raise SystemExit(2) from exc

    try:
        from weasyprint import CSS, HTML  # type: ignore[import-untyped]
    except (ImportError, OSError) as exc:
        print(
            "[render_white_paper] ERROR: WeasyPrint (or its native libs) is "
            "missing. See services/api/Dockerfile for the required apt "
            "packages (libpango, libcairo, libgdk-pixbuf, libffi, libssl). "
            "Install with `pip install weasyprint` once the libs are present.",
            file=sys.stderr,
        )
        raise SystemExit(2) from exc

    source = markdown_path.read_text(encoding="utf-8")
    meta, body = _strip_frontmatter(source)

    rendered_body = md.markdown(
        body,
        extensions=["extra", "tables", "fenced_code", "toc", "sane_lists"],
    )

    cover = COVER_HTML.format(
        title=meta.get("title", markdown_path.stem.replace("-", " ").title()),
        subtitle=meta.get("subtitle", ""),
        version=meta.get("version", "v1.0"),
        date=meta.get("date", ""),
    )
    html = (
        "<!doctype html><html><head><meta charset='utf-8'/>"
        f"<title>{meta.get('title', 'AiSOC White Paper')}</title>"
        "</head><body>"
        f"{cover}"
        f"{rendered_body}"
        "</body></html>"
    )

    # Strip the redundant top-level H1 added by the markdown body so the
    # cover page is the only title surface. We only do this for the
    # first occurrence to avoid wrecking section headings.
    html = re.sub(r"<h1[^>]*>.*?</h1>", "", html, count=1)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    HTML(string=html).write_pdf(
        str(output_path),
        stylesheets=[CSS(string=PRINT_CSS)],
    )
    size = output_path.stat().st_size
    print(
        f"[render_white_paper] wrote {output_path} ({size:,} bytes)",
        file=sys.stderr,
    )


def render(markdown_path: Path, output_path: Path) -> None:
    """Public single-file entrypoint kept for backwards compatibility."""
    _render_one(markdown_path, output_path)


def _discover() -> list[tuple[Path, Path]]:
    """Pair every ``content/papers/*.md`` with its target PDF path."""
    pairs: list[tuple[Path, Path]] = []
    for src in sorted(DEFAULT_SRC_DIR.glob("*.md")):
        if src.name.startswith("_"):
            continue
        pdf = DEFAULT_OUT_DIR / f"{src.stem}.pdf"
        pairs.append((src, pdf))
    return pairs


def _source_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _display(path: Path) -> str:
    """Repository-relative where possible, absolute where not.

    The gate-contract harness and ``--self-test`` both point this script at a
    tree outside ``REPO_ROOT``, where ``relative_to`` raises.
    """
    try:
        return str(path.relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def _read_manifest() -> dict[str, str]:
    if not MANIFEST_PATH.exists():
        return {}
    try:
        loaded = json.loads(MANIFEST_PATH.read_text())
    except json.JSONDecodeError:
        return {}
    sources = loaded.get("sources")
    return sources if isinstance(sources, dict) else {}


def _record_rendered(sources: dict[str, str]) -> None:
    """Merge digests for the papers just rendered into the manifest."""
    merged = {**_read_manifest(), **sources}
    MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST_PATH.write_text(json.dumps({"sources": dict(sorted(merged.items()))}, indent=2) + "\n")


def _render_all() -> None:
    pairs = _discover()
    if not pairs:
        print(
            f"[render_white_paper] no markdown sources found under {DEFAULT_SRC_DIR}",
            file=sys.stderr,
        )
        return
    for src, dst in pairs:
        _render_one(src, dst)
    _record_rendered({src.name: _source_digest(src) for src, _ in pairs})


def _check() -> int:
    """Report papers whose PDF is missing or older than its source.

    Needs no rendering stack, so it runs anywhere python does.
    """
    pairs = _discover()
    if not pairs:
        print(
            f"[render_white_paper] refusing to pass: no markdown sources under {DEFAULT_SRC_DIR}",
            file=sys.stderr,
        )
        return 1

    manifest = _read_manifest()
    problems: list[str] = []

    for src, pdf in pairs:
        if not pdf.exists():
            problems.append(f"{_display(pdf)} does not exist")
            continue
        recorded = manifest.get(src.name)
        if recorded is None:
            problems.append(f"{src.name} has a PDF but no recorded render")
        elif recorded != _source_digest(src):
            problems.append(f"{src.name} changed since its PDF was rendered")

    known = {src.name for src, _ in pairs}
    for orphan in sorted(set(manifest) - known):
        problems.append(f"{orphan} is recorded but its source is gone")

    if problems:
        print("[render_white_paper] rendered PDFs are out of date:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        print(
            "\nRun `make papers` and commit the result. CI cannot refresh them for\n"
            "you: main is branch-protected, so a workflow cannot push to it.",
            file=sys.stderr,
        )
        return 1

    print(f"[render_white_paper] {len(pairs)} paper(s) up to date with their sources")
    return 0


def _injected_defect_cases() -> list[tuple[str, bool]]:
    """Plant each defect ``--check`` claims to catch and require a refusal.

    The control case matters as much as the rest: a gate that refused
    everything would "detect" all four defects and be useless, so a
    well-formed paper is required to pass.
    """
    global DEFAULT_SRC_DIR, DEFAULT_OUT_DIR, MANIFEST_PATH

    def plant(root: Path, *, pdf: bool, recorded: str | None, orphan: bool) -> None:
        # Without this, the assignments below bind locals to `plant` and every
        # case silently grades the real tree instead of the planted one.
        global DEFAULT_SRC_DIR, DEFAULT_OUT_DIR, MANIFEST_PATH

        src_dir, out_dir = root / "content", root / "public"
        src_dir.mkdir(parents=True)
        out_dir.mkdir(parents=True)
        source = src_dir / "paper.md"
        source.write_text("# a paper\n")
        if pdf:
            (out_dir / "paper.pdf").write_bytes(b"%PDF-1.7 not a real render\n")
        entries: dict[str, str] = {}
        if recorded == "match":
            entries["paper.md"] = _source_digest(source)
        elif recorded == "stale":
            entries["paper.md"] = "0" * 64
        if orphan:
            entries["deleted.md"] = "0" * 64
        DEFAULT_SRC_DIR, DEFAULT_OUT_DIR = src_dir, out_dir
        MANIFEST_PATH = out_dir / "render-manifest.json"
        MANIFEST_PATH.write_text(json.dumps({"sources": entries}) + "\n")

    cases: list[tuple[str, dict[str, object], bool]] = [
        ("a paper whose PDF matches its recorded source passes", {"pdf": True, "recorded": "match", "orphan": False}, True),
        ("a source edited since its PDF was rendered is refused", {"pdf": True, "recorded": "stale", "orphan": False}, False),
        ("a source with no PDF at all is refused", {"pdf": False, "recorded": "match", "orphan": False}, False),
        ("a PDF with no recorded render is refused", {"pdf": True, "recorded": None, "orphan": False}, False),
        ("a recorded paper whose source is gone is refused", {"pdf": True, "recorded": "match", "orphan": True}, False),
    ]

    saved = (DEFAULT_SRC_DIR, DEFAULT_OUT_DIR, MANIFEST_PATH)
    results: list[tuple[str, bool]] = []
    try:
        for description, shape, should_pass in cases:
            with tempfile.TemporaryDirectory() as tmp:
                plant(Path(tmp), **shape)  # type: ignore[arg-type]
                results.append((description, (_check() == 0) is should_pass))
    finally:
        DEFAULT_SRC_DIR, DEFAULT_OUT_DIR, MANIFEST_PATH = saved
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        help=("Render a single paper from this markdown path. If omitted, render every paper under apps/web/content/papers/."),
    )
    parser.add_argument(
        "--output",
        help=("Write the rendered PDF to this path. Required when --input is supplied; ignored otherwise."),
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help=("Render every paper under apps/web/content/papers/. Default when neither --input nor --output is supplied."),
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help=("Report papers whose PDF is missing or older than its source. Renders nothing."),
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help=("Prove --check still detects each defect it claims to, then exit. Renders nothing."),
    )
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test_main(Path(__file__).name, ["--check"], extra=_injected_defect_cases())

    if args.check and (args.input or args.output or args.all):
        parser.error("--check renders nothing, so it takes no other arguments")
    if args.input and not args.output:
        parser.error("--output is required when --input is supplied")
    if args.output and not args.input:
        parser.error("--input is required when --output is supplied")

    if args.check:
        return _check()

    if args.input and args.output:
        source = Path(args.input)
        _render_one(source, Path(args.output))
        # Keep the manifest honest when a single paper is rendered in place,
        # so the next --check does not report a paper that was just refreshed.
        if source.resolve().parent == DEFAULT_SRC_DIR:
            _record_rendered({source.name: _source_digest(source)})
    else:
        _render_all()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
