# AiSOC landing page — component recipes

> Companion to `landing-page-brief.md` §6 and
> `landing-page-design-tokens.md`. One recipe per IA section, in the
> same order with the same ID. The frontend engineer (Subagent F) reads
> this while implementing the landing page at `apps/web/src/app/page.tsx`.
>
> **Library catalog:**
> - Aceternity UI — `https://ui.aceternity.com/components`
> - MagicUI — `https://magicui.design/docs/components`
>
> Each recipe lists primitives (with prop overrides), custom touches,
> anatomy (sub-components), states, and failure modes.

---

## §1 — `nav` (Sticky nav)

- **Primitives:**
  - Aceternity **Floating Navbar** (`/components/floating-navbar`) — base shell. Override `hideOnScroll={false}`. Glass via `backdrop-blur-md` + `bg-surface-base/70`.
  - MagicUI **Number Ticker** (`/docs/components/number-ticker`) — live GitHub star chip. `value={liveStars}`, `direction="up"`, `delay={0.4}`.
  - MagicUI **Shimmer Button** (`/docs/components/shimmer-button`) — primary CTA. `shimmerColor="var(--color-brand-300)"`, `background="linear-gradient(110deg,var(--color-brand-600) 45%,var(--color-brand-500) 55%)"`.
- **Custom:** Existing `<Wordmark />` from `apps/web/src/components/brand/`. Border-bottom appears via `data-scrolled="true"` set by an `IntersectionObserver` on a hero sentinel.
- **Anatomy:** `LandingNav` → `NavLogo`, `NavLinks`, `NavStarChip`, `NavCtas`, `NavMobileSheet`.
- **States:** Default `bg-surface-base/70`; on-scroll `bg-surface-base/90 border-b-surface-border`. <768 → logo + chip + hamburger. Reduced-motion drops shimmer.
- **Failure:** Star API → static "Star on GitHub" pill. JS off → static `<header>` + anchors. Hamburger fails → `<details>` fallback.

---

## §2 — `hero`

- **Primitives:**
  - Aceternity **Spotlight** (`/components/spotlight`) — corner glow. `fill="var(--color-brand-500)"`, top-right at 40% / 20%.
  - Aceternity **Text Generate Effect** (`/components/text-generate-effect`) — H1. `words="Detect. Triage. Hunt. Respond."`, `duration={0.8}`, `filter={false}` (blur unreadable at 56–64 px).
  - MagicUI **AnimatedGridPattern** (`/docs/components/animated-grid-pattern`) — bg mesh. `numSquares={48}`, `maxOpacity={0.08}`, `duration={3}`, `repeatDelay={1}`. Mask 70%-radius radial fade.
  - MagicUI **Border Beam** (`/docs/components/border-beam`) — frame around hero visual. `size={250}`, `duration={12}`, `colorFrom="#3b82f6"`, `colorTo="#8b5cf6"`.
  - MagicUI **Shimmer Button** — primary CTA (same as nav).
- **Custom:** Right-column visual is a hand-built SVG of the four-agent topology rendered with framer-motion `<motion.path>` (motion spec `agent-beam`). Eyebrow uses `<Eyebrow />` chip with `bg-brand-900/40 text-brand-300 border-brand-500/20`.
- **Anatomy:** `Hero` → `HeroCopy` (eyebrow, H1, sub-head, CTAs, social-proof), `HeroVisual` (SVG topology + Border Beam), `HeroBackground` (Spotlight + AnimatedGridPattern).
- **States:** Visual right at `lg+`, stacked at `<lg`; auto-pauses motion at `<md`. Hover primary CTA shimmer slow-loops; secondary CTA border `surface-border → brand-500`. Reduced-motion: H1 instant; mesh static; Border Beam → 1 px static `brand-500/30`.
- **Failure:** Spotlight fails → inline `radial-gradient`. Mesh fails → flat `bg-surface-base`. SVG fails → `<img src="/og-image.png" />` poster.

---

## §3 — `proof-strip`

- **Primitives:**
  - MagicUI **Marquee** (`/docs/components/marquee`) — logos. `pauseOnHover={true}`, `vertical={false}`, `repeat={4}`, `className="[--duration:40s]"`. L → R.
  - Aceternity **Sparkles** (`/components/sparkles`) — *optional*, soft particles. Skip first ship.
- **Custom:** Logos at `apps/web/public/logos/oss/{langgraph,kafka,neo4j,postgresql,qdrant,ollama}.svg`. Default `fill="currentColor"` + `text-fg-muted`; hover restores per-logo brand colour. Design partners block: 4 placeholder outlines + caption from content doc.
- **Anatomy:** `ProofStrip` → `ProofStripLabel`, `ProofStripLogos` (Marquee), `ProofStripPartners`.
- **States:** Auto-plays; pauses on hover. Phone — two rows. Reduced-motion → static centred 3 × 2 grid.
- **Failure:** Marquee fails → static row. Logo 404 → 24 × 96 px `bg-surface-card` placeholder.

---

## §4 — `problem`

- **Primitives:**
  - Aceternity **Hero Highlight** (`/components/hero-highlight`) — wrap H2 to highlight "drowning". `highlightClassName="bg-brand-500/15 px-2 rounded-md"`.
  - MagicUI **Animated List** (`/docs/components/animated-list`) — three pain bullets, `delay={400}`. Each (icon + headline + body) animates as one unit.
- **Custom:** Three line-art SVGs at `apps/web/public/glyphs/problem-{1,2,3}.svg`, 56 × 56 px, 1.75 px stroke. Stat callouts use `<mark>` styled `text-brand-300 bg-transparent`.
- **Anatomy:** `Problem` → `ProblemHeading`, `ProblemBullets` (Animated List of `ProblemBullet`).
- **States:** 3-column → 1-column at <768. Hover icon → stroke flips `brand.300`. Reduced-motion → flat reveal.
- **Failure:** Hero Highlight fails → flat `bg-brand-500/15` span. Glyph 404 → `<span aria-hidden>•</span>`.

---

## §5 — `solution`

- **Primitives:**
  - MagicUI **Animated Beam** (`/docs/components/animated-beam`) — connect four agent cards L → R (Detect → Triage → Hunt → Respond). Three beams. `duration={3}`, `pathColor="rgba(148,163,184,0.15)"`, `gradientStartColor="#3b82f6"`, `gradientStopColor="#8b5cf6"`, `curvature={-30}`.
  - Aceternity **Bento Grid** (`/components/bento-grid`) — alternate layout for `lg+`. First ship: flat 4-up flex row.
  - Aceternity **Card Hover Effect** (`/components/card-hover-effect`) — agent cards. Override stagger off; hover `bg-brand-500/8` + `border-brand-500/30`.
- **Custom:** 24 × 24 SVG glyph per card at `apps/web/public/glyphs/agents/{detect,triage,hunt,respond}.svg`. Animated Beam parent wraps `forwardRef` divs; Subagent F adds a `<BeamAnchor ref={...} />` helper.
- **Anatomy:** `Solution` → `SolutionHeading`, `SolutionDiagram` (4 × `BeamAnchor` + 3 × `<AnimatedBeam>`), 4 × `SolutionAgentCard`.
- **States:** Beams loop; cards lift `-2 px` with `landing.shadow.2`. <1024 → vertical stack, beams hidden, agent cards 2 × 2 (<768) or stacked (<640). Reduced-motion → beams swap to static SVG.
- **Failure:** Animated Beam fails → static SVG fallback path. Card Hover fails → plain Tailwind transition lift.

---

## §6 — `demo`

- **Primitives:**
  - MagicUI **Border Beam** — frame. `duration={10}`, `colorFrom="#3b82f6"`, `colorTo="#8b5cf6"`, `borderWidth={1.5}`.
  - Aceternity **Container Scroll Animation** (`/components/container-scroll-animation`) — *optional*, tilts demo on scroll. `titleComponent={null}`. Skip first ship if it bloats bundle.
  - Aceternity **Spotlight** — soft glow. Reuse hero with `fill="var(--color-brand-700)"`.
- **Custom:** muted walkthrough video at `apps/web/public/demo/demo.mp4` + fallback. Caption overlay is an absolutely-positioned `<div>`. Lazy-load via `IntersectionObserver` once 30% in viewport. Poster at `apps/web/public/demo/demo-poster.png`. (This bullet previously named `inc-rt-001.mp4`/`.avif`, which were never committed.)
- **Anatomy:** `Demo` → `DemoHeading`, `DemoFrame` (Border Beam wraps `<video>`), `DemoCaptionOverlay`, `DemoCta`.
- **States:** Autoplay muted, loop, inline. Hover → caption + scrub controls. <768 controls always visible. Reduced-motion → freezes on poster, "Play replay" button centred.
- **Failure:** `<video>` fails → poster + "Watch on Vimeo" link. Border Beam fails → static `brand-500/30` border. Vimeo blocked → CTA changes to "Run this yourself."

---

## §7 — `pillars`

- **Primitives:**
  - Aceternity **Glowing Effect** (`/components/glowing-effect`) — wraps each card border. `glow={true}`, `proximity={64}`, `inactiveZone={0.4}`.
  - Aceternity **Bento Grid** — used loosely (flat 2 × 2, equal heights, no skew).
  - MagicUI **Number Ticker** — stat lines. P1 `value={EXECUTABLE_DETECTION_COUNT}` (from `apps/web/src/data/corpusStats.ts`, currently 2511 — do not hard-code it; the literal `6998` sat here while the corpus moved, and `2603` sat here after that), P2 `value={17}`, P3 `value={4}`, P4 `value={6}`.
- **Custom:** 24 × 24 brand glyphs (`open-source`, `graph`, `agentic`, `deploy-anywhere`). Active borders: P2 → `landing.gradient.pillars`, P3 → `landing.accent.ember`, P1 / P4 → `brand-500/30`.
- **Anatomy:** `Pillars` → `PillarsHeading`, `PillarsGrid` (4 × `PillarCard`), each → `PillarIcon`, `PillarTitle`, `PillarBody`, `PillarStat`, `PillarLink`.
- **States:** Default `landing.shadow.1`, `surface-border`. Hover → Glowing Effect on; lift `-2 px`. Focus → existing `:focus-visible` 2 px `brand-500` ring. <768 stacks. Reduced-motion → Glowing `disabled={true}`; lift instant.
- **Failure:** Glowing fails → static `brand-500/20` border. Number Ticker fails → static formatted string.

---

## §8 — `features` (Detect & Investigate · Hunt & Respond · Operate at scale)

Three sub-section bands with anchor IDs `features-detect`,
`features-hunt`, `features-operate`.

- **Primitives:**
  - Aceternity **Tabs** (`/components/tabs`) — *optional*, switch between bands on `lg+`. Safer first ship: render all three sequentially.
  - Aceternity **Card Hover Effect** — 6 tiles per band. Subtle, no scale; bg shift only.
- **Custom:** Tile icons from Lucide (`shield-alert`, `users`, `book-open`, `clock`, `git-branch`, `key-round`, …) sized 24, stroke 1.75. Body links resolve to `apps/docs/` URLs.
- **Anatomy:** `Features` → `FeaturesHeading`, 3 × `FeaturesBand`; each → `FeaturesBandHeading` + `FeaturesGrid` (6 × `FeatureTile`).
- **States:** 3-up at `lg+`, 2-up at `md`, 1-up at `sm`. Hover → `bg-surface-hover`; link icon translates `+2 px` right. Reduced-motion → translation off.
- **Failure:** Lucide import fails → tile renders without icon. Doc link 404 → `cursor-default`, no-op.

---

## §9 — `connectors`

- **Primitives:**
  - MagicUI **Marquee** — two rows, second reversed. `pauseOnHover={true}`, `repeat={3}`, row 1 `[--duration:60s]`, row 2 `[--duration:75s]`.
  - MagicUI **Particles** (`/docs/components/particles`) — *optional*, drift behind logos. Skip if performance budget tightens.
  - Aceternity **Code Block** (`/components/code-block`) — connector callout. `language="python"`, `filename="my_connector.py"`, `highlightLines={[7,8,9,10,11]}`.
- **Custom:** Category chips use existing `<ChipGroup>`; filter is in-page `useState`. Below 640 px, render 18 logos + "See all 69 →" link.
- **Anatomy:** `Connectors` → `ConnectorsHeading`, `ConnectorsCategoryChips`, `ConnectorsMarquee`, `ConnectorsCodeCallout`.
- **States:** Marquees loop; chip filter → `opacity-30` on non-matching logos. Reduced-motion → static 5-col grid (first 30 logos). Phone → chips horizontal-scroll; marquee disabled in favour of 18-logo grid.
- **Failure:** Marquee fails → static grid. Logo 404 → 24 × 96 px placeholder. Code Block fails → plain `<pre>`.

---

## §10 — `benchmark`

- **Primitives:**
  - MagicUI **Number Ticker** — three big numbers. Tile 1 `value={97.0}` `decimalPlaces={1}`; tile 2 literal "Sub-minute"; tile 3 `value={35}`.
  - Aceternity **Lamp Effect** (`/components/lamp-effect`) — *optional* section header. Skip first ship.
  - Aceternity **Animated Tooltip** (`/components/animated-tooltip`) — each tile hovers a tooltip naming the suite (`test_mitre_accuracy`, `wet_eval_target`, `test_substrate_runtime`).
- **Custom:** Each label includes `(substrate)` or `(wet-eval)` per `AGENTS.md`.
- **Anatomy:** `Benchmark` → `BenchmarkHeading`, `BenchmarkTiles` (3 × `BenchmarkTile`), each → `BenchmarkMetric`, `BenchmarkCaption`, `BenchmarkTooltip`.
- **States:** 3-column. Tooltip 200 ms delay. Reduced-motion → final value direct.
- **Failure:** Number Ticker fails → static string. Tooltip fails → label inline below metric.

---

## §11 — `deploy`

- **Primitives:**
  - Aceternity **Card Hover Effect** — three deploy cards. Middle card has `landing.gradient.cta` 8% overlay.
  - Aceternity **Glowing Effect** — middle card only.
  - MagicUI **Border Beam** — middle card border. `duration={14}`, `colorFrom="#3b82f6"`, `colorTo="#8b5cf6"`.
- **Custom:** Card titles carry Lucide icons (`cloud`, `terminal`, `lock`). "Time to live" line uses `mono.sm`.
- **Anatomy:** `Deploy` → `DeployHeading`, `DeployGrid` (3 × `DeployCard`), each → `DeployCardIcon`, `DeployCardTitle`, `DeployCardMeta`, `DeployCardBody`, `DeployCardCta`.
- **States:** Three equal cards; middle brighter. Hover → Glowing on middle; outer cards lift only. <1024 stacks. Reduced-motion → Border Beam static.
- **Failure:** All primitives fail → 1 px `surface-border`; recommended card carries `bg-brand-500/8`.

---

## §12 — `open-source`

- **Primitives:**
  - Aceternity **Code Block** — `git clone … && pnpm aisoc:demo`. `language="bash"`, `filename="terminal"`, `theme="dark"`.
  - MagicUI **Number Ticker** — repo card star count.
  - Aceternity **Sparkles** — *optional* behind H2. Skip if it competes with §3.
- **Custom:** Repo card mirrors GitHub's repo card in `surface-card` with brand-tinted hover. Octocat from `apps/web/public/glyphs/octocat.svg`, brand-tinted via CSS filter.
- **Anatomy:** `OpenSource` → `OpenSourceHeading`, `OpenSourceRepoCard`, `OpenSourceCodeSnippet`, `OpenSourceCtas`.
- **States:** 2-column at `lg+` (repo left, code right); stacks at `md`. Hover repo → border `brand-500/40`. Reduced-motion → Sparkles off, ticker static.
- **Failure:** Star API fails → static "★ Star on GitHub" pill. Code Block fails → `<pre>`. Octocat 404 → SVG placeholder.

---

## §13 — `testimonials`

- **Primitives:**
  - Aceternity **Animated Testimonials** (`/components/animated-testimonials`) — once ≥ 2 published. `autoplay={true}`, `pauseOnHover={true}`.
  - Aceternity **Card Stack** (`/components/card-stack`) — alternative layout; pick whichever performs better in QA.
  - **Empty-state pattern** for v1 (likely first ship): single `surface-card` block with copy from content doc + "Become a reference partner" CTA. **No fake testimonials, no placeholder logos.**
- **Custom:** Industry chip uses existing `<Chip>` with brand-tinted bg.
- **Anatomy:** `Testimonials` → `TestimonialsHeading`, `TestimonialsCarousel` (gated on `published.length >= 2`) **or** `TestimonialsEmptyState`.
- **States:** Carousel autoplays 1 / 6 s; pauses on hover. <768 single card visible, swipe enabled. Reduced-motion → autoplay off, manual arrows visible.
- **Failure:** MDX fetch fails → empty state. Animated Testimonials fails → static `react-snap-carousel` fallback (existing dep).

---

## §14 — `pricing-teaser`

- **Primitives:**
  - Aceternity **Card Hover Effect** — three pricing cards.
  - Aceternity **Glowing Effect** — middle card (Team) only.
  - MagicUI **Border Beam** — middle card border.
- **Custom:** `<TierBadge>` (Free / Managed / Enterprise) top-left; explicit "Includes everything in {previous tier}" line.
- **Anatomy:** `PricingTeaser` → `PricingHeading`, `PricingGrid` (3 × `PricingCard`), each → `PricingTierBadge`, `PricingTitle`, `PricingPrice`, `PricingTagline`, `PricingIncludes`, `PricingCta`.
- **States:** Three equal cards. Hover middle → Glowing on. <1024 stacks. Reduced-motion → Border Beam static.
- **Failure:** All primitives fail → plain border + `bg-brand-500/8` on Team.

---

## §15 — `faq`

- **Primitives:**
  - **Radix Accordion** (to add — there is no `Accordion` component in `apps/web/src` today) — `type="multiple"`, `defaultValue={['faq-q1','faq-q2']}`.
  - Aceternity **Tracing Beam** (`/components/tracing-beam`) — *optional* left-edge beam. Skip first ship.
- **Custom:** Each question carries `id={faq-q{n}}` for analytics. Answers may include `<code>`; respect mono token.
- **Anatomy:** `Faq` → `FaqHeading`, `FaqAccordion` (Radix), each → `FaqQuestion`, `FaqAnswer`.
- **States:** First two open. Click toggles Radix's 200 ms slide. Keyboard `Enter` / `Space` toggles, `Tab` traverses. Reduced-motion → instant open.
- **Failure:** Radix fails → fallback `<details>` with first two `default open`.

---

## §16 — `final-cta`

- **Primitives:**
  - Aceternity **Wavy Background** (`/components/wavy-background`) — full-bleed panel. `colors={["#1d4ed8","#3b82f6","#8b5cf6"]}`, `waveOpacity={0.3}`, `speed="slow"`, `blur={10}`.
  - MagicUI **Shimmer Button** — primary CTA only.
  - Aceternity **Background Boxes** (`/components/background-boxes`) — *alternative*. **Pick one** of Wavy or Boxes; do not stack.
- **Custom:** Microcopy uses `body.sm` + `fg.muted`; `·` separator rendered as `<span aria-hidden>·</span>`.
- **Anatomy:** `FinalCta` → `FinalCtaPanel` (Wavy or Boxes), `FinalCtaHeading`, `FinalCtaButtons`, `FinalCtaMicrocopy`.
- **States:** Wavy animates slowly. Hover primary → shimmer accelerates. <600 buttons stack. Reduced-motion → Wavy frame 0; secondary CTA gains `border-brand-500/40` for balance.
- **Failure:** Wavy fails → static `landing.gradient.cta`. Shimmer Button fails → solid `brand.500`.

---

## §17 — `footer`

- **Primitives:**
  - **No animated primitives.** Footer is intentionally calm.
  - MagicUI **Dot Pattern** (`/docs/components/dot-pattern`) — *optional* dotted bg. `cy={1}`, `cr={1}`, `className="[mask-image:radial-gradient(ellipse_at_top,white,transparent_70%)] opacity-40"`.
- **Custom:** Five-column grid; bottom row carries copyright, social icons (Lucide `github`, `twitter`, custom Discord glyph), language switcher (English-only v1, dropdown disabled).
- **Anatomy:** `Footer` → `FooterColumns` (5 × `FooterColumn`), `FooterBottom` (`FooterCopyright`, `FooterSocial`, `FooterLangSwitcher`, `FooterStatusDot`).
- **States:** Desktop grid, `surface-subtle` bg. Hover link → `text-fg-primary` (was `fg-secondary`). <768 columns collapse into `<details>`. Status dot pulses every 2 s via `.pulse-dot`.
- **Failure:** Dot Pattern fails → flat `bg-surface-subtle`. Status fetch fails → static dot in `status.idle`.

---

*End of recipes. Pair with `landing-page-design-tokens.md` and
`landing-page-motion-spec.md`.*
