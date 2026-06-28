# AiSOC public papers

This directory hosts publication-quality PDFs that the AiSOC marketing
site and docs site link to.  Source markdown lives at
`apps/web/content/papers/`; PDFs here are generated artefacts.

## Regenerating the PDFs

PDFs are regenerated from their source markdown via the top-level
Makefile target (Phase 4.3):

```bash
make papers                       # regenerate every paper
```

The Makefile delegates to `scripts/render_white_paper.py`. You can
still render a single paper with explicit paths if you prefer the
old workflow:

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

Do not commit PDFs without their matching markdown source. CI now
rebuilds PDFs automatically via
[`.github/workflows/papers.yml`](../../../../.github/workflows/papers.yml)
on every push to `main` that touches a paper's markdown source —
**you no longer have to run the renderer locally before opening a
PR**. The workflow:

1. Builds every paper using the same WeasyPrint stack.
2. Uploads the rendered PDFs as a workflow artifact (visible on every
   run — useful for PR preview).
3. On `main` only, commits any changed PDFs back as
   `chore(papers): refresh rendered PDFs from <sha> [skip ci]`.

The hosted PDF is the public artefact; the markdown is the canonical
one.
