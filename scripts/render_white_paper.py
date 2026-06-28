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
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SRC_DIR = REPO_ROOT / "apps" / "web" / "content" / "papers"
DEFAULT_OUT_DIR = REPO_ROOT / "apps" / "web" / "public" / "papers"

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
    args = parser.parse_args(argv)

    if args.input and not args.output:
        parser.error("--output is required when --input is supplied")
    if args.output and not args.input:
        parser.error("--input is required when --output is supplied")

    if args.input and args.output:
        _render_one(Path(args.input), Path(args.output))
    else:
        _render_all()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
