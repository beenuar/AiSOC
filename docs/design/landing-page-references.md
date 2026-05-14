# Landing-page design references

> Companion to `landing-page-brief.md` §16. These are condensed teardown
> notes for the UX designer kicking off the AiSOC landing page. Every
> reference below sits in an adjacent category — developer tools,
> open-source infrastructure, observability, DevSecOps — never in
> direct SOC competition. Per `AGENTS.md`, no Security-Operations
> Center competitor product names appear here or anywhere else in the
> repo.

Each entry follows the same shape: **URL** · **what to steal** · **what
to avoid**.

---

## 1. Linear — `https://linear.app`

- **Steal.** The opinionated typographic stack (Inter Display + Inter
  Variable), the resolute single-column hero that lets the H1 carry
  the page, and the way the marketing site exposes product surface
  through tasteful animated screenshots rather than glossy 3D. The
  product-narrative section (one feature, one big picture, one
  paragraph, repeat) is the cleanest pattern in SaaS marketing today.
- **Avoid.** Their gradient-heavy "hero glow" backdrop reads as fashion
  more than substance and would clash with AiSOC's "calm, technical,
  graph-native" tone. Resist the urge to copy their large all-caps
  category labels in body copy — they hurt readability at small
  sizes.

## 2. Vercel — `https://vercel.com`

- **Steal.** The information density of the homepage feature grids
  without ever feeling cramped. The unambiguous primary CTA in the
  navbar that persists through scroll. The way pricing is acknowledged
  on the landing page itself instead of being hidden behind a separate
  marketing funnel. The light/dark theme parity (matters for us
  because of our existing CSS-variable theming).
- **Avoid.** The relentless "we are platform-of-record" framing. AiSOC
  is one tool that does one thing very well — don't position it as a
  platform that eats your entire stack.

## 3. PlanetScale — `https://planetscale.com`

- **Steal.** The benchmark-as-marketing pattern: three giant numbers
  with a one-line caption, then a "read the methodology" link
  directly underneath. This is the gold standard for being honest
  about performance claims without burying them in fine print, and it
  maps directly onto AiSOC's substrate-vs-wet-eval disclosure.
- **Avoid.** Heavy product-isometric illustrations. AiSOC's domain is
  better served by clean line-art schematics of the four-agent
  topology and the entity graph, not stylised isometric servers.

## 4. Supabase — `https://supabase.com`

- **Steal.** The "open-source moment" treatment — a dedicated section
  with the repo card, the star count, the licence callout, and a
  one-command quickstart. This is exactly the affordance our community
  expects, and the existing copy in `apps/web/src/app/(marketing)/page.tsx`
  already gestures toward it. Their "everything is in the box" feature
  matrix is a strong reference for our connectors + marketplace
  section.
- **Avoid.** The "we are the open-source alternative to {hyperscaler}"
  comparison frame. We must not name competitor products anywhere in
  the doc — anchor on the category, not a foil.

## 5. Grafana Labs — `https://grafana.com`

- **Steal.** The way they frame an observability *story* on the
  landing page — what an operator sees, in what order, with which
  signals — rather than a wall of features. The persona-anchored sub-
  navigation ("for developers", "for SREs", "for security") is a
  pattern AiSOC can mirror for L1 analysts vs. SOC managers vs.
  CISOs once we ship the dedicated solution pages.
- **Avoid.** The over-rotated product-mark sprawl across their
  marketing footer. Footer hygiene matters — keep ours to five
  columns, no more.

## 6. Sentry — `https://sentry.io`

- **Steal.** Their commitment to making the live product visible above
  the fold (their hero literally shows the issue list and stack trace
  view). For AiSOC, the equivalent is making the Investigation Ledger
  visible — not a hero animation, but an actual screenshot of a live
  case. Treat the demo embed as the product, not as decoration.
- **Avoid.** Their colour palette skews loud (orange, magenta).
  AiSOC's existing tokens — graphite, near-black, indigo, ember — are
  more disciplined and should not be muddied by louder accents.

## 7. Tailscale — `https://tailscale.com`

- **Steal.** The way they explain a complex networking primitive
  ("identity-aware mesh networking") with a single hand-drawn diagram
  and three short paragraphs. The four-agent topology diagram in our
  solution section deserves the same treatment: a single clear
  schematic, not a sprawling architecture diagram. Their "How it
  works" section is also a clean pattern for the architecture deep-
  dive page that will follow this landing.
- **Avoid.** Their reliance on stock developer photography. We have
  the line-art schematics from `apps/docs/static/img/` — use those
  exclusively. Photography is on the banned list in §7 of the brief.

## 8. Render — `https://render.com`

- **Steal.** The "deploy options" card grid: each card shows the
  deploy path, the time-to-live, the operational model. This is the
  pattern AiSOC's `deploy` section in §6.k already mirrors, but
  Render's execution is the cleanest example to study. Their
  one-click deploy button design (the badge, the gradient, the
  shadow) is also a near-perfect reference for our existing Render
  one-click button shipping from `apps/web/src/app/(marketing)/sovereign/`.
- **Avoid.** Their hero-video autoplay. Heavy autoplaying video kills
  LCP on the mid-range laptops most analysts use. Stick to static
  hero screenshots with motion gated behind `prefers-reduced-motion:
  no-preference`.

## 9. Cloudflare Workers — `https://workers.cloudflare.com`

- **Steal.** Their FAQ pattern (clean accordions, two-sentence answers,
  technical specificity without jargon). For AiSOC, the eight FAQ
  questions in `landing-page-content.md` should follow exactly this
  shape: a tight question, a concrete answer, one repo path link.
  Their navbar treatment of GitHub stars (a small chip with a star
  glyph, count refreshed via a public API) is also a useful pattern
  for our `nav` section.
- **Avoid.** Their tendency to list every adjacent product in the
  hero. AiSOC is one product. The landing page is allowed to focus.

## 10. Hashicorp — `https://www.hashicorp.com`

- **Steal.** The way their marketing site bridges between deeply
  technical product pages and an enterprise-credible top-level
  landing. The corporate-tone-without-corporate-blandness is hard to
  pull off and they consistently do. The way they treat
  open-source-and-enterprise as a single story (rather than two
  separate marketing tracks) is exactly the bridge AiSOC needs to
  build between the GitHub community and the managed waitlist.
- **Avoid.** Their dense navigation mega-menus. AiSOC's nav stays
  to six items, full stop.

---

## Pattern-level takeaways for the designer

1. **Single-column hero, no carousel.** Linear, PlanetScale, Tailscale.
2. **Benchmark numbers earn their own band, with methodology link.**
   PlanetScale.
3. **Open-source treatment is a section, not a footnote.** Supabase.
4. **Product visible above the fold via a real screenshot.** Sentry.
5. **Deploy options as a card grid with time-to-live.** Render.
6. **Persona-anchored sub-navigation for /solutions pages.** Grafana.
7. **FAQ with technical specificity, no marketing fluff.** Cloudflare.
8. **GitHub-star chip in the nav, persistent through scroll.**
   Cloudflare, Supabase.
9. **Theme parity (light / dark) baked into the design system, not
   bolted on.** Vercel.
10. **Schematic diagrams over isometric illustrations.** Tailscale,
    PlanetScale.

---

*End of references. See `landing-page-brief.md` §7 for the
illustration-direction rules these references should support.*
