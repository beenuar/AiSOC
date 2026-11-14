# `docs/design/` — landing page kickoff bundle

This folder is the design-team handoff for the AiSOC marketing landing
page on `tryaisoc.com`. Six documents, in order of importance:

1. **`landing-page-brief.md`** — the product brief. Seventeen sections,
   from positioning and personas through information architecture,
   accessibility, performance, and a feature × section content matrix.
   Start here; this is the document the UX designer should treat as
   the source of truth.
2. **`landing-page-content.md`** — drop-in copy for every section in
   §6 of the brief. Headlines, sub-heads, body text, button labels,
   microcopy, FAQ answers, footer links. Paste into Figma; no lorem
   ipsum anywhere.
3. **`landing-page-references.md`** — ten condensed competitive design
   teardowns from adjacent categories (developer tools, open-source
   infrastructure, observability), each tagged with "what to steal"
   and "what to avoid." Per project rule, no SOC-competitor product is
   named.
4. **`landing-page-design-tokens.md`** — copy-paste-ready token spec.
   Surfaces, foregrounds, brand, gradients, type scale, spacing, radius,
   elevation, motion durations / easings, iconography, imagery, banned
   tokens. Resolves every magic number to a Tailwind class or CSS
   variable.
5. **`landing-page-component-recipes.md`** — one recipe per IA section
   (`nav` → `footer`). Names the Aceternity / MagicUI primitives to
   use, the React anatomy to build, the prop tweaks needed, the failure
   modes to handle, and the responsive states.
6. **`landing-page-motion-spec.md`** — the choreography table. Twelve
   distinct micro-animations with trigger, duration, easing, stagger,
   and `prefers-reduced-motion` fallback per row. The single source of
   truth for any motion landing on the page.

## Owner

Prince Sinha · `prince.sinha@cyble.com` · branch `v8.0/agentic-soc-foundation`.

## Status

Draft for design kickoff. Open questions live in `landing-page-brief.md`
§15 — bring answers back before the second design review.

## Out of scope

Logged-in product UI, docs site redesign, deep pricing page, blog
template, status page, customer case-study CMS. See §14 of the brief.
