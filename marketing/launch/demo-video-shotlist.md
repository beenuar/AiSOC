# 90-second demo video shot list

Goal: show the wow, then the depth, in 90 seconds. Screen-only, no talking-head
required. Captions on. Each shot is a real command against `main`.

| # | Time | Shot | On screen | Caption |
|---|------|------|-----------|---------|
| 1 | 0:00–0:12 | Cold terminal | `npx aisoc triage --demo` typed and run | "No install. No key. No Docker." |
| 2 | 0:12–0:22 | Verdict table + headline fills in | The table + "triaged 200 alerts: 12 TP, 171 FP suppressed (85.5% noise), 17 need review — in 0.1s" | "A verdict on every alert, in under a second." |
| 3 | 0:22–0:30 | `npx aisoc triage --demo --share` → open the SVG card | The report card | "Share the result — aggregate only, nothing leaks." |
| 4 | 0:30–0:45 | Browser: open a public replay permalink on the local stack, `http://localhost:3000/r/demo-lockbit` (replays are served by the deployment that produced them; there is no hosted public instance) | Animated playback: timeline scrubber, evidence cards, attack graph growing, verdict stamp | "Every agent decision is logged — and replayable." |
| 5 | 0:45–0:58 | Scrub the replay timeline; hover a step to show the rationale | Step rationale + confidence | "Prompt, tool call, evidence, rationale — per step." |
| 6 | 0:58–1:12 | Terminal: `pnpm aisoc:selfplay` (self-play campaign) — sped up | 5-stage attack chain running; detections firing; DAC proposals auto-filed | "It attacks itself nightly and files detections for every miss." |
| 7 | 1:12–1:24 | Browser: the mesh/network stats page | Instances connected, signatures shared, community FP-suppression lift | "Every install makes every other install smarter." |
| 8 | 1:24–1:30 | Repo landing + star button | github.com/beenuar/AiSOC | "MIT. Self-hostable. github.com/beenuar/AiSOC" |

## Production notes

- Record shot 1–3 with `asciinema` or a clean terminal at 16–18pt; the demo is
  deterministic so re-takes are identical.
- Shots 6–7 are recordable: self-play (`pnpm aisoc:selfplay`) and the mesh
  service (`services/mesh/`) have both merged. This note used to say they were
  pending.
- Keep total assets under `apps/web/public/demo/`; the README hero references
  `demo/hero.gif` + the `.mp4`.
- No fabricated dashboards — every screen must be a real run.
