# AiSOC landing page — design tokens

> Companion to `landing-page-brief.md` §7. Copy-paste-ready token spec
> for the frontend engineer implementing
> `apps/web/src/app/(marketing)/page.tsx`. Every value resolves to a
> Tailwind class or CSS variable — no magic numbers in component code.

---

## 1. Source of truth

`apps/web/src/app/globals.css` and `apps/web/tailwind.config.ts` are
authoritative. Conflicts resolve in favour of existing tokens unless
explicitly overridden below.

| Layer                | Behaviour                                                              |
|----------------------|------------------------------------------------------------------------|
| Existing CSS vars    | Reuse verbatim (`--surface-base`, `--fg-primary`, …).                  |
| Existing Tailwind    | Reuse `brand.*`, `surface.*`, `fg.*`, `severity.*`. Do not redefine.   |
| New marketing tokens | Add under `landing.*` namespace. Never collide.                        |
| Severity tokens      | Off-limits to marketing copy. Product screenshots only.                |

**Explicit overrides (this doc wins):**

1. New gradient pairs `landing.gradient.{hero,pillars,cta}`.
2. New elevation scale `landing.shadow.{1..4}` — additive.
3. New motion tokens `landing.duration.*`, `landing.ease.*`, `landing.stagger.cards`.
4. Light-mode landing deferred to v1.1; route is dark-locked
   (`<html data-theme="dark">`, matching `apps/web/src/app/page.tsx`).

---

## 2. Color tokens

### 2.1 Surface scale (dark — locked v1)

| Token              | Hex / value              | OKLCH                    | Use                                |
|--------------------|--------------------------|--------------------------|------------------------------------|
| `surface.base`     | `#0a0d14`                | `oklch(0.169 0.013 252)` | Page bg. Deepest surface.          |
| `surface.subtle`   | `#0d1119`                | `oklch(0.184 0.013 252)` | `proof-strip`, `footer`, pricing.  |
| `surface.raised`   | `#11151f`                | `oklch(0.211 0.013 252)` | Section bg one notch above base.   |
| `surface.card`     | `#141926`                | `oklch(0.235 0.018 252)` | Pillar / deploy cards, tiles.      |
| `surface.hover`    | `#1a2030`                | `oklch(0.276 0.020 252)` | Hovered card, focused row.         |
| `surface.border`   | `rgba(148,163,184,0.12)` | —                        | 1 px hairlines.                    |
| `surface.divider`  | `rgba(148,163,184,0.08)` | —                        | Section dividers.                  |

Description: `surface.base` is a near-black with a subtle blue tint
(~1.3% chroma at hue 252) — graphite on OLED, deep-navy on backlit
IPS. Each step adds ~3% lightness for elevation legibility without
hard shadows.

### 2.2 Foreground scale (dark)

| Token         | Hex       | OKLCH                    | Use                              |
|---------------|-----------|--------------------------|----------------------------------|
| `fg.primary`  | `#e2e8f0` | `oklch(0.910 0.013 247)` | H1, H2, H3, CTA labels.          |
| `fg.secondary`| `#cbd5e1` | `oklch(0.844 0.018 245)` | Paragraph copy, sub-heads.       |
| `fg.muted`    | `#9ca3af` | `oklch(0.708 0.013 264)` | Captions, eyebrows, FAQ teasers. |
| `fg.subtle`   | `#6b7280` | `oklch(0.537 0.013 264)` | Timestamps, helper text.         |
| `fg.inverse`  | `#0f172a` | `oklch(0.214 0.030 270)` | Text on light buttons (rare).    |

### 2.3 Brand, accent, status

| Token                  | Hex       | Source                         | Use                                          |
|------------------------|-----------|--------------------------------|----------------------------------------------|
| `brand.300`            | `#93c5fd` | existing                       | Active text, eyebrows, badges, link hover.   |
| `brand.400`            | `#60a5fa` | existing                       | Secondary CTA bg, focus glow.                |
| `brand.500`            | `#3b82f6` | existing                       | Primary CTA, focus ring.                     |
| `brand.600`            | `#2563eb` | existing                       | CTA hover / pressed.                         |
| `brand.700`            | `#1d4ed8` | existing                       | CTA active, code keyword colour.             |
| `brand.900`            | `#1e3a8a` | existing                       | Background accents, gradient end-stops.      |
| `landing.accent.ember` | `#f97316` | new                            | Pillar P3 ring; "auditable" only.            |
| `landing.accent.violet`| `#8b5cf6` | new                            | Pillar P2 ring; graph-native moments.        |
| `landing.success`      | `#22c55e` | existing (`status.live`)       | Air-gap "no outbound" badge.                 |
| `landing.warning`      | `#f59e0b` | existing (`status.warn`)       | "Coming soon" chips.                         |
| `landing.destructive`  | `#ef4444` | existing (`severity.critical`) | Form-error UI only.                          |

`severity.{critical,high,medium,low,info}` appear only inside product
screenshots.

### 2.4 Gradient pairs

| Token                       | From                    | To                                | Direction        | Use                                  |
|-----------------------------|-------------------------|-----------------------------------|------------------|--------------------------------------|
| `landing.gradient.hero`     | `#1d4ed8` (`brand.700`) | `#0a0d14` (`surface.base`)        | `to bottom right`| Hero mesh fade; demo frame glow.     |
| `landing.gradient.pillars`  | `#3b82f6` (`brand.500`) | `#8b5cf6` (`landing.accent.violet`)| `to right`      | Pillar P2 active border, eyebrow.    |
| `landing.gradient.cta`      | `#3b82f6` (`brand.500`) | `#1d4ed8` (`brand.700`)           | `to bottom right`| Final CTA panel; primary button sheen.|

CSS-variable additions (in `globals.css` under `[data-theme="dark"]`):

```css
--landing-grad-hero: linear-gradient(to bottom right, #1d4ed8 0%, #0a0d14 80%);
--landing-grad-pillars: linear-gradient(to right, #3b82f6 0%, #8b5cf6 100%);
--landing-grad-cta: linear-gradient(to bottom right, #3b82f6 0%, #1d4ed8 100%);
```

### 2.5 Tailwind diff (extension only)

```ts
// theme.extend.colors
landing: { accent: { ember: '#f97316', violet: '#8b5cf6' } },
// theme.extend.backgroundImage
backgroundImage: {
  'landing-grad-hero': 'var(--landing-grad-hero)',
  'landing-grad-pillars': 'var(--landing-grad-pillars)',
  'landing-grad-cta': 'var(--landing-grad-cta)',
},
```

### 2.6 Light-mode equivalents

**Dark-locked v1; light variant deferred** to v1.1.

---

## 3. Type scale

- **Sans:** `var(--font-inter)` (already loaded), variable, weights 400–800.
- **Mono:** `var(--font-mono)` (JetBrains Mono variable subset).

No new fonts.

### 3.1 Scale (4 px base, unitless line-height, em tracking)

| Token         | Size (px) | Line-ht | Tracking | Weight | Use                                |
|---------------|-----------|---------|----------|--------|------------------------------------|
| `display.2xl` | 64 / 56   | 1.05    | -0.02em  | 700    | Hero H1 (laptop+).                 |
| `display.xl`  | 48 / 44   | 1.10    | -0.02em  | 700    | `final-cta` H2; section H2 desktop.|
| `display.lg`  | 40 / 36   | 1.15    | -0.015em | 700    | `solution`/`pillars`/`connectors` H2.|
| `display.md`  | 32 / 30   | 1.20    | -0.01em  | 600    | Sub-section H3; mobile hero H1.    |
| `display.sm`  | 24 / 24   | 1.25    | -0.005em | 600    | Card titles, tile headlines.       |
| `display.xs`  | 20 / 20   | 1.30    | 0        | 600    | Pillar card title, FAQ question.   |
| `body.lg`     | 18 / 18   | 1.55    | 0        | 400    | Hero sub-head, `solution` sub-head.|
| `body.md`     | 16 / 16   | 1.65    | 0        | 400    | Default paragraph copy.            |
| `body.sm`     | 14 / 14   | 1.55    | 0        | 400    | Captions, deploy-card metadata.    |
| `body.xs`     | 12 / 12   | 1.50    | 0.01em   | 500    | Eyebrows, chip labels.             |
| `mono.md`     | 16 / 16   | 1.50    | 0        | 500    | Inline code, big metric mantissa.  |
| `mono.sm`     | 14 / 14   | 1.55    | 0        | 500    | Code blocks, repo card line.       |
| `mono.xs`     | 12 / 12   | 1.50    | 0.01em   | 500    | Number-tile suffix (`%`, `ms`).    |

Numbers always use mono with `font-feature-settings:"tnum" 1`.

### 3.2 Per-section recommendation

| Section          | H tokens                                     | Body |
|------------------|----------------------------------------------|------|
| `hero`           | `display.2xl` (laptop+) → `display.md` (phone)| `body.lg` |
| `proof-strip`    | n/a                                          | `body.xs` (label) |
| `problem`        | `display.lg`                                 | `body.md` |
| `solution`       | `display.lg`                                 | `body.lg` (sub-head) / `body.md` (cards) |
| `demo`           | `display.lg`                                 | `body.md` |
| `pillars`        | `display.lg` (H2) / `display.xs` (card)      | `body.md` |
| `features-*`     | `display.md` (H3) / `display.sm` (tile)      | `body.sm` |
| `connectors`     | `display.lg`                                 | `body.md` |
| `benchmark`      | `display.lg` / `display.xl` mono metric      | `body.md` |
| `deploy`         | `display.lg`                                 | `body.md` |
| `open-source`    | `display.lg`                                 | `body.md` |
| `testimonials`   | `display.lg`                                 | `body.md` |
| `pricing-teaser` | `display.lg`                                 | `body.md` |
| `faq`            | `display.lg` (H2) / `display.xs` (question)  | `body.md` |
| `final-cta`      | `display.xl`                                 | `body.lg` |
| `footer`         | n/a                                          | `body.sm` |

---

## 4. Spacing rhythm

Base unit **4 px** (Tailwind default — do not override).

| Breakpoint | Default `py` | Hero `py` | Final-CTA `py` |
|------------|--------------|-----------|----------------|
| Phone      | `py-16`      | `py-20`   | `py-20`        |
| Tablet     | `py-20`      | `py-28`   | `py-24`        |
| Laptop+    | `py-24`      | `py-32`   | `py-28`        |

| Token                    | Value                                | Use                        |
|--------------------------|--------------------------------------|----------------------------|
| `landing.container.max`  | `max-w-[1200px]`                     | Default sections.          |
| `landing.container.wide` | `max-w-[1320px]`                     | `hero` only.               |
| `landing.container.bleed`| 100% + 24 px gutter                  | `connectors`, `proof-strip`.|
| `landing.gutter.x`       | `px-6` / `px-8` / `px-12` (sm/md/lg) | All.                       |

| Gap     | px | Use                                 |
|---------|----|-------------------------------------|
| `gap.xs`| 8  | Inside chip, button-icon-to-label.  |
| `gap.sm`| 12 | Card title to body.                 |
| `gap.md`| 24 | Card body to footer link, list rows.|
| `gap.lg`| 40 | Heading-stack to first card row.    |
| `gap.xl`| 64 | Hero copy column to visual column.  |
| `gap.2xl`| 96| Section H2 to nested grid (rare).   |

---

## 5. Radius scale

| Token         | Value | Use                                       |
|---------------|-------|-------------------------------------------|
| `radius.xs`   | 4 px  | Chip, severity badge in product screenshot.|
| `radius.sm`   | 6 px  | Inline code, focus-ring offset.           |
| `radius.md`   | 8 px  | Buttons (default), inputs.                |
| `radius.lg`   | 12 px | Pillar / deploy card, feature tile.       |
| `radius.xl`   | 16 px | Hero shell on phone, demo frame.          |
| `radius.2xl`  | 24 px | Hero shell on laptop+, final-CTA panel.   |
| `radius.full` | 9999  | Avatar, GitHub-star chip, pill nav.       |

---

## 6. Elevation / shadow scale

Soft, diffuse — never hard drops. Each = tight ambient + wider diffuse
glow tinted toward `brand.900`.

| Token              | Dark-mode value                                                                | Use                                |
|--------------------|--------------------------------------------------------------------------------|------------------------------------|
| `landing.shadow.1` | `0 1px 0 rgba(255,255,255,0.04) inset, 0 1px 2px rgba(0,0,0,0.4)`              | Default card / tile.               |
| `landing.shadow.2` | `0 1px 0 rgba(255,255,255,0.05) inset, 0 8px 24px -8px rgba(0,0,0,0.55)`        | Hover state pillar / deploy card.  |
| `landing.shadow.3` | `0 1px 0 rgba(255,255,255,0.06) inset, 0 24px 48px -16px rgba(30,58,138,0.45)` | Hero demo frame, sticky nav glass. |
| `landing.shadow.4` | `0 1px 0 rgba(255,255,255,0.06) inset, 0 32px 80px -24px rgba(59,130,246,0.35)` | Final-CTA panel.                   |

Light-mode shadows deferred (see §2.6).

---

## 7. Motion tokens

### 7.1 Easing

| Token                      | Value                                                          |
|----------------------------|----------------------------------------------------------------|
| `landing.ease.out-expo`    | `cubic-bezier(0.16, 1, 0.3, 1)` (default reveal)               |
| `landing.ease.out-quart`   | `cubic-bezier(0.25, 1, 0.5, 1)` (card stagger, list reveal)    |
| `landing.ease.in-out-quad` | `cubic-bezier(0.45, 0, 0.55, 1)` (hover, accordion)            |
| `landing.ease.linear-loop` | `cubic-bezier(0, 0, 1, 1)` (marquee, infinite loops)           |
| `landing.ease.spring-soft` | framer-motion `{type:'spring', stiffness:140, damping:22}`     |

### 7.2 Duration

| Token                       | Value      | Use                              |
|-----------------------------|------------|----------------------------------|
| `landing.duration.instant`  | `0 ms`     | Reduced-motion fallback.         |
| `landing.duration.fast`     | `150 ms`   | Hover bg, focus-ring fade.       |
| `landing.duration.base`     | `250 ms`   | Card hover lift, link colour.    |
| `landing.duration.medium`   | `400 ms`   | Section reveal, accordion open.  |
| `landing.duration.slow`     | `800 ms`   | Hero H1 reveal, big metric tick. |
| `landing.duration.beam`     | `1500 ms`  | Agent-beam path draw.            |
| `landing.duration.marquee`  | `20000 ms` | Connector marquee revolution.    |
| `landing.duration.hero-loop`| `8000 ms`  | Hero spotlight breathe.          |
| `landing.duration.bg-loop`  | `30000 ms` | Background mesh slow drift.      |

### 7.3 Stagger

`landing.stagger.cards = 60 ms` per item, capped at four (`pillars`,
`deploy`, `pricing-teaser`). Larger grids (`features`, `connectors`)
use 80 ms across the first six, then drop to zero.

### 7.4 `prefers-reduced-motion` policy

Loops pause at first frame; reveals swap to opacity 1 + transform 0
instantly; hover affordances keep colour, drop transforms / shadows;
marquees become a static grid; agent-beam becomes a static SVG drawn
full-length. Per-animation table in `landing-page-motion-spec.md`.

---

## 8. Iconography

- **Library:** Lucide (existing dep).
- **Sizes:** `16` (chip / inline), `20` (default body), `24` (card glyph).
- **Stroke:** `1.75 px`. Use `<Icon size={20} strokeWidth={1.75} />`.
- **Colour:** `currentColor`; default `fg.muted`, active card → `brand.300`.
- **Never fill icons inline with body text.**
- **Brand glyphs** at `apps/web/public/glyphs/` (Subagent F creates):
  four-agent nodes, entity-graph mesh, maturity-dial.

---

## 9. Imagery

- **Banned:** Stock photography, shield-on-circuit, glowing brains,
  padlock-on-keyboard, hooded-hacker, isometric server rooms.
- **Allowed (priority):** (1) schematic line-art SVG, (2) real product
  screenshots dark-theme PNG, (3) captured developer photography (no
  faces, low-key) for `open-source` if needed.

| Section                | Ratio  | Pixel target (laptop)    |
|------------------------|--------|--------------------------|
| `hero` visual          | 16:9   | 960 × 540 (SVG preferred)|
| `demo` embed           | 16:9   | 1280 × 720               |
| `pillars` glyph        | 1:1    | 96 × 96                  |
| `features` tile        | 4:3    | 320 × 240                |
| `solution` agent glyph | 1:1    | 64 × 64                  |
| `open-source` repo     | 16:9   | 720 × 405                |
| OG image               | 1.91:1 | 1200 × 630               |

---

## 10. Banned tokens

Not allowed inside any landing component:

1. Inline `#hex` strings — use Tailwind class or CSS var (§2).
2. Inline `px` margins / paddings — use Tailwind utility (§4).
3. Inline `rgba()` shadows — use `landing.shadow.*` (§6).
4. Inline `cubic-bezier()` — use `landing.ease.*` (§7).
5. Tailwind arbitrary values (`text-[14.5px]`, `bg-[#123456]`) outside
   the OG image generator (to add — the only Satori route in the tree today
   is `apps/web/src/app/r/[slug]/opengraph-image.tsx`) (Satori
   demands literal hex).
6. `font-bold` on body copy — body is `400`, headings `600`/`700`.
7. The word `severity` outside product screenshots.

---

*End of tokens. Pair with `landing-page-component-recipes.md` and
`landing-page-motion-spec.md`.*
