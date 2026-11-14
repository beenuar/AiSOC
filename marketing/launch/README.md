# AiSOC launch kit

In-repo launch materials so they ship and version with the code. Everything
here is written to two rules:

1. **No superlatives, only sourced claims.** The audience is security
   engineers; overreach burns trust.
2. **Synthetic vs. measured is always labelled.** The `--demo` fixture is a
   deterministic 200-alert synthetic set; substrate metrics come from the
   CI-gated [eval harness](../../apps/docs/docs/benchmark.md). Never present the
   demo's fixture numbers as measured production accuracy.

## Contents

| File | What it is |
|---|---|
| [`show-hn.md`](./show-hn.md) | Show HN post draft, centered on `npx aisoc triage --demo`. |
| [`demo-video-shotlist.md`](./demo-video-shotlist.md) | 90-second demo video shot list. |
| [`product-hunt.md`](./product-hunt.md) | Product Hunt tagline, description, first comment, gallery list. |
| [`blog-outlines.md`](./blog-outlines.md) | Six technical blog outlines, each ending in a reproducible command. |
| [`comparison-dossier.md`](./comparison-dossier.md) | Category-level comparison vs. closed-source AI SOC products (sourced, no vendor names). |
| [`../../docs/press/README.md`](../../docs/press/README.md) | Press kit: boilerplate, logo kit, fast facts. |

## Ground truth for every claim

Before publishing anything here, re-check it against:

- The benchmark page: `apps/docs/docs/benchmark.md` and the public scoreboard
  `apps/docs/docs/benchmark-scoreboard.mdx`.
- The claim-to-gate matrix: `docs/audit/CLAIM_TO_GATE_MATRIX.md` (every product
  claim maps to a CI gate).
- The detection truth table: `docs/detections/truth-table.md` (executable vs.
  quarantined rule counts).

If a claim isn't backed by one of those, cut it or soften it to what is.
