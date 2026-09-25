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
3. Run `make papers` to produce the PDF and record its source digest.
4. Commit the markdown, the PDF and `render-manifest.json` together.
5. Add an entry to the index table above.
6. Link the PDF from the relevant docs concept page or marketing surface.

Do not commit PDFs without their matching markdown source.

**Editing a paper's markdown means running `make papers` and committing
the result in the same change.** CI does not refresh PDFs for you. It
once did, pushing a `chore(papers)` commit straight to `main`, but that
stopped working when `main` became branch-protected — the push is
rejected with `GH006`. Opening a pull request instead is not available
either, because this repository has Actions set to read-only permissions
with pull-request creation disabled.

So [`.github/workflows/papers.yml`](../../../../.github/workflows/papers.yml)
reports rather than repairs:

1. Fails if any committed PDF is older than its markdown source, naming
   the papers to re-render.
2. Renders every paper, so a markdown change that breaks rendering fails
   the build rather than shipping a broken PDF.
3. Fails if any source produced no PDF.
4. Uploads the rendered PDFs as an artifact, useful for previewing a PR.

Staleness is judged by comparing each source's SHA-256 against the digest
recorded in `render-manifest.json` when its PDF was last rendered, which
`make papers` updates. PDF bytes are deliberately not compared: WeasyPrint
stamps a creation timestamp into its output and glyph metrics depend on
the host's installed fonts, so two correct renders of the same source are
not byte-identical. Commit `render-manifest.json` alongside the PDF.

The hosted PDF is the public artefact; the markdown is the canonical
one.
