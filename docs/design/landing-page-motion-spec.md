# AiSOC landing page — motion spec

> Companion to `landing-page-component-recipes.md` and
> `landing-page-design-tokens.md` §7. Twelve micro-animations across
> the page. Every duration / easing resolves to a token from the
> design-tokens doc — no inline `cubic-bezier()`, no inline `ms`.

---

## 1. Choreography table

The canonical source for **what animates, when, how long, and what
reduced-motion does instead.** Each row is one PR-sized unit.

| ID                          | Where                                        | Trigger             | Enter dur          | Enter easing  | Exit dur     | Exit easing      | Stagger        | Reduced-motion fallback                       | Purpose                                                         |
|-----------------------------|----------------------------------------------|---------------------|--------------------|---------------|--------------|------------------|----------------|----------------------------------------------|-----------------------------------------------------------------|
| `hero-h1-reveal`            | `hero`                                       | mount               | `slow` 800         | `out-expo`    | —            | —                | 30 / word      | **instant** — opacity 1, no transform         | Sets page pace; H1 earns scale by entering with intent.         |
| `hero-bg-grid`              | `hero`                                       | mount loop          | `bg-loop` 30000    | `linear-loop` | —            | —                | —              | **static** — render grid frame once           | Living signal under page that never pulls focus.                |
| `hero-spotlight-pulse`      | `hero`                                       | mount loop          | `hero-loop` 8000   | `out-expo`    | —            | —                | —              | **static** — spotlight at 60%, no breathe     | Soft "page is alive" cue without a video.                       |
| `hero-cta-shimmer`          | `hero`, `final-cta`                          | hover               | `medium` 400       | `in-out-quad` | `fast` 150   | `in-out-quad`    | —              | **none** — solid `brand-500`, no sheen        | Reward intent on conversion target without animating pre-hover. |
| `pillar-card-stagger`       | `pillars`                                    | scroll-into-view    | `medium` 400       | `out-quart`   | —            | —                | 80 / card      | **instant** — cards opacity 1, no translate   | Eye absorbs four claims one at a time.                          |
| `pillar-card-glow`          | `pillars` (P2)                               | hover               | `base` 250         | `in-out-quad` | `fast` 150   | `in-out-quad`    | —              | **none** — static `border-brand-500/30`       | Marks P2 differentiation without a "look at me" loop.           |
| `connector-marquee`         | `connectors`, `proof-strip`                  | mount loop          | `marquee` 20000–60000 | `linear-loop` | —         | —                | —              | **static row** — 18 logos in 5-col grid       | Gives the `CONNECTOR_COUNT` chip (84 connectors) sensory weight; static art still works.   |
| `agent-beam`                | `solution`, `hero` visual                    | scroll + loop       | `beam` 1500        | custom `cubic-bezier(0.65,0,0.35,1)` | `slow` 800 | `in-out-quad` | —     | **static path** full-length, single colour    | Four-agent topology as a sequence, not an org chart.            |
| `number-ticker-benchmark`   | `benchmark`, `nav`, `pillars`, `open-source` | scroll-into-view    | `slow` 800–`beam` 1500 | `out-expo` | —          | —                | 200 / tile     | **final value** rendered directly             | Earns the metric; reduced-motion shows destination directly.    |
| `accordion-toggle`          | `faq`                                        | click               | `base` 250 open / `fast` 150 close | `in-out-quad` | `fast` 150 | `in-out-quad` | —     | **instant** — open / close, no slide          | Familiar affordance; small motion confirms click.               |
| `final-cta-wave`            | `final-cta`                                  | mount loop          | `bg-loop` 30000    | `linear-loop` | —            | —                | —              | **static gradient** — `landing.gradient.cta`  | Closes page with calm motion; static gradient carries energy.   |
| `card-hover-lift`           | `pillars`, `deploy`, `pricing-teaser`, `features-*` | hover        | `base` 250         | `in-out-quad` | `fast` 150   | `in-out-quad`    | —              | **none** — colour shift only, no translate    | Card invites click without behaving like a button.              |

---

## 2. Notes

- **`hero-h1-reveal`.** Text Generate Effect with `filter={false}` — at 56–64 px, blur reads as a mistake. 30 ms / word ≈ "spoken," not "typed." Total ≈ 920 ms — inside the 1.2 s LCP budget on a wired laptop.
- **`hero-bg-grid` + `hero-spotlight-pulse`.** Coprime periods (30 s / 8 s) so the visual never lands on a frame the eye has cached.
- **`hero-cta-shimmer`.** Hover-gated — never on mount (would compete with the H1 reveal). Loops indefinitely on hover (the cursor is the user's commitment).
- **`pillar-card-stagger`.** Single intersection-observer fire at 30% viewport. 80 ms × 4 = 320 ms cascade. If a fifth pillar lands later, drop to 60 ms so total cascade stays under 400 ms.
- **`agent-beam`.** Most important motion. Draws once on scroll (1.5 s, custom curve settling into the final node), then loops every 6 s, fading just-drawn path to 30% before re-drawing. Reinforces "Respond is the terminus." Static SVG path is the default render, so the section never breaks.
- **`connector-marquee`.** Two rows at 60 s / 75 s. Hover pauses both — losing both rows together stops the cursor-boundary stutter.
- **`number-ticker-benchmark`.** 200 ms gap between tiles. Tile 2 is a string ("Sub-minute"), no ticker. Numeric tiles use `out-expo` so count settles on target, no overshoot.
- **`accordion-toggle`.** Asymmetric: open 250 ms, close 150 ms. Close-faster feels in-control; open-slower lets content reveal readably.
- **`final-cta-wave`.** Pick one of Wavy Background or Background Boxes in recipes — do not stack. Both reduce to the same fallback.
- **`card-hover-lift`.** 2 px translate-Y + swap `landing.shadow.1` → `.2`. Reduced-motion drops translate, keeps shadow swap + icon-colour shift.

---

## 3. `prefers-reduced-motion` policy

The global rule in `globals.css` clamps every animation to 0.01 ms.
On top, **per-section JS gates** check
`window.matchMedia('(prefers-reduced-motion: reduce)').matches` and
skip mounting:

- All Marquee → static grid.
- All Number Ticker → final value.
- All Animated Beam → static SVG path.
- All Border Beam → static border.
- All Wavy Background / Background Boxes / Particles → static gradient or solid surface.

Subagent F lifts the check into a single `useReducedMotion()` hook
from framer-motion (existing dep). Every animated component reads
the hook and self-disables.

---

## 4. Animation budget

| Metric                                          | Budget               |
|-------------------------------------------------|----------------------|
| Animations mounted on initial paint (`hero`)    | ≤ 3                  |
| Animations mounted before LCP fires             | ≤ 3                  |
| Total animations on the page                    | ≤ 12                 |
| Total motion JS (gzip, lazy-loaded)             | ≤ 35 KB              |
| Frame budget per active animation               | ≤ 4 ms / 60 Hz frame |
| Loops that run infinitely                       | 5 (`hero-bg-grid`, `hero-spotlight-pulse`, `connector-marquee`, `agent-beam`, `final-cta-wave`) |
| Reduced-motion fallback coverage                | 12 / 12 (100%)       |

A thirteenth animation is gated on this table — propose here first.

---

## 5. Hand-off checklist

Before opening the implementation PR for a given section:

1. Every animation maps to a row above.
2. Every duration / easing literal resolves to a `landing.duration.*` / `landing.ease.*` token.
3. Page rendered under `prefers-reduced-motion: reduce` shows the listed fallback.
4. `useReducedMotion()` is the single source of truth — no per-component `matchMedia()`.
5. Section animations fit under 4 ms / frame on a 4-year-old MacBook.

---

*End of motion spec. Hold this table next to brief §6 (IA) and the
recipes doc's primitive list while implementing.*
