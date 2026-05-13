# AiSOC public papers

This directory hosts publication-quality PDFs that the AiSOC marketing
site and docs site link to.  Source markdown lives at
`apps/web/content/papers/`; PDFs here are generated artefacts.

## Regenerating the PDFs

PDFs are regenerated from their source markdown via:

```bash
python3 scripts/render_white_paper.py \
  --input  apps/web/content/papers/l0-l4-automation-maturity.md \
  --output apps/web/public/papers/l0-l4-automation-maturity.pdf
```

The script depends on two Python packages — `markdown` and
`weasyprint` — and on the native libs WeasyPrint requires (Pango,
Cairo, GLib, libffi, libssl).  The AiSOC API service image
(`services/api/Dockerfile`) already installs the native libs, so
running the script from the API service container is the easiest path:

```bash
docker compose run --rm api \
  python3 scripts/render_white_paper.py
```

On a developer laptop with Homebrew:

```bash
brew install pango cairo libffi
pip install markdown weasyprint
python3 scripts/render_white_paper.py
```

## Index

| Paper | Source | Status |
|-------|--------|--------|
| `l0-l4-automation-maturity.pdf` | `apps/web/content/papers/l0-l4-automation-maturity.md` | Shipped with v8.0 (T7.2). |

When adding a new paper:

1. Author the markdown at `apps/web/content/papers/<slug>.md`.
2. Add a YAML frontmatter block with `title`, `subtitle`, `author`,
   `date`, and `version` keys (the render script reads these for the
   cover page).
3. Run the render script to produce the PDF.
4. Add an entry to the index table above.
5. Link the PDF from the relevant docs concept page or marketing surface.

Do not commit PDFs without their matching markdown source, and do not
commit markdown without re-rendering the PDF when the content changes.
The hosted PDF is the public artefact; the markdown is the canonical
one.  CI does not yet rebuild PDFs automatically — that is on the v8.x
roadmap.
