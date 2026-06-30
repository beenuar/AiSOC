# AiSOC landing page — product brief for UX design kickoff

## 1. Document control

- **Author:** Prince Sinha — `prince.sinha@cyble.com`
- **Date:** 2026-05-14
- **Branch:** `v8.0/agentic-soc-foundation`
- **Audience:** Lead UX designer (and the first illustrator / motion designer
  brought in to support the build).
- **Purpose:** Provide everything needed to design a single marketing
  landing page for AiSOC at `tryaisoc.com`, plus a stripped-back logged-in
  product overview that lives behind the same brand. The designer should
  not have to read the repo to design the page.
- **Deliverable:** Figma file (desktop + tablet + phone artboards) covering
  the IA in §6, applying the visual system in §7, with hand-off-ready
  component states and copy from `landing-page-content.md`.
- **Status:** Draft for design kickoff. Open questions (§15) are intentionally
  unresolved — they're the decisions we want from the designer, not from
  product.
- **Reference repo paths:** every feature claim in this document is cited
  back to a specific path so the designer can verify before drawing.

---

## 2. Product one-liner, elevator pitch, and full positioning statement

### One-liner (the tagline that sits under the wordmark)

> **The open agentic SOC. Detect, triage, hunt, and respond — every step
> auditable.**

### Elevator pitch (three sentences)

AiSOC is an MIT-licensed agentic Security Operations Center that fuses raw
events into incidents, runs four named agents — Detect, Triage, Hunt, and
Respond — against them, and records every prompt, tool call, and rationale
to a replayable Investigation Ledger. It ships with 69 click-and-connect
data sources, 6,998 detection rules, 62 playbook packs, and a public
benchmark harness that gates every PR. You can self-host the whole stack
in five minutes, take it air-gapped on a flag, or join the managed
waitlist at `tryaisoc.com` — same code in every direction.

### Positioning statement (≈ 250 words)

Security teams are drowning in alerts, splitting attention across a SIEM,
an EDR, a cloud security tool, a ticketing system, and a half-broken SOAR
playbook archive. The closed-source AI SOC vendors that promise to solve
this ask you to ship every alert, every audit log, and every analyst
keystroke to a black-box agent you cannot inspect, cannot fork, and cannot
benchmark. That trade — visibility for convenience — does not survive
contact with a procurement team, a regulated industry, or an auditor.

**AiSOC is the open-source answer.** It is a single self-hostable stack
that ingests security events, correlates them in real time, runs four
named agents against the resulting incidents, and surfaces the work in a
SOC console that any analyst can use on their first day. The agent stack
is MIT-licensed. The orchestrator is a ~600-line LangGraph in
`services/agents/`. The detection rule corpus is in `detections/`. The
benchmark harness is in `services/agents/tests/` and gates every pull
request targeting `main`. The vault that holds your connector secrets is
Fernet-encrypted at the application layer (`services/api/.../vault.py`)
with key rotation built in.

We sell **transparency, not magic**. Every claim on this page reduces to a
file path in the repo — the designer should hold every visual to that
standard too. The category we anchor in is the open agentic SOC. We are
not "AI-first" the way a 2024 startup is AI-first; we are open the way
Postgres is open and reproducible the way scientific software is
reproducible.

---

## 3. Target personas

### 3.1 SOC analyst (L1 / L2)

**Persona.** Maya, three years into a tier-1 SOC role, owns the queue on a
2 p.m.–10 p.m. shift and writes most of her notes by copy-pasting between
the SIEM, the EDR, and the ticketing system.

- **Jobs-to-be-done.** (1) Clear the queue without missing the one real
  incident in 200. (2) Hand off a clean note to her tier-2. (3) Stop
  rage-quitting when the SOAR breaks at 3 a.m.
- **Pains today.** Alert volume, context switching, opaque AI verdicts she
  cannot defend in a post-mortem.
- **Desired outcomes.** Auto-close the obvious false-positives, escalate
  the ambiguous ones with a one-paragraph rationale, ask a plain-English
  question and get an answer pinned to evidence.
- **Click triggers.** "See it investigating now" — a moving demo with the
  ledger streaming on the right. The phrase "every step auditable."
- **Bounce triggers.** A pricing table at the top of the page. The word
  "platform." Stock-photo analysts pointing at screens.
- **Technical literacy.** Comfortable in a SIEM query bar, allergic to
  YAML, has never read a LangGraph file but will if someone draws it for
  her.
- **Objections.** "Another AI thing that hallucinates." "My boss will not
  let me fork code." "I do not have time to set this up."

### 3.2 SOC manager / detection engineer

**Persona.** Dev, runs a 12-person detection-engineering pod, owns MTTR
and ATT&CK coverage, sits in the weekly metrics review.

- **Jobs-to-be-done.** (1) Improve coverage without ballooning the rule
  graveyard. (2) Defend the AI investment to the CISO with reproducible
  numbers. (3) Keep his analysts engaged so they do not churn.
- **Pains today.** Vendor benchmarks that cannot be reproduced. Detection
  drift between releases. Connectors that ship and then go silent.
- **Desired outcomes.** A versioned detection-as-code pipeline, a
  benchmark his team can run on a laptop, a ChatOps approval flow that
  the security architect signs off on once.
- **Click triggers.** The phrase "public benchmark methodology." A
  per-template macro chart. A linkable, reproducible scoreboard.
- **Bounce triggers.** Hand-wavy phrases like "AI-native." Marketing math
  ("98 % accurate"). No methodology link.
- **Technical literacy.** Reads Sigma, KQL, ES|QL fluently. Will pull the
  repo and run `pnpm aisoc:demo` before talking to sales.
- **Objections.** "Open source means I am the support team." "Will it run
  air-gapped for our regulated tenant?"

### 3.3 CISO / Director of SecOps

**Persona.** Priya, two years into a Director of SecOps role at a
mid-market regulated business, sits between the board and the floor.

- **Jobs-to-be-done.** (1) Move from L0 (analyst-only) toward L2 (low-risk
  autonomous containment) without owning the next breach headline. (2)
  Pass next quarter's SOC 2 audit with less paper. (3) Reduce the
  attrition tax on her L1 bench.
- **Pains today.** Tool sprawl, vendor lock-in, an autonomous-response
  conversation that her risk committee refuses to bless.
- **Desired outcomes.** A tier dial (L0 → L4) she can present to a risk
  committee. Per-action approval evidence in an immutable audit log. A
  weekly executive PDF she can forward without editing.
- **Click triggers.** "L0–L4 automation maturity." "Replayable audit
  trail." "Run it in your VPC, your air-gap, your private LLM."
- **Bounce triggers.** Anything that implies the agent acts without a
  guardrail. The word "autonomous" without a tier next to it. No
  compliance language on the page at all.
- **Technical literacy.** Reads architecture diagrams, does not write code.
  Will forward the brochure PDF to a procurement deck.
- **Objections.** "How does this stay safe at 3 a.m. on a weekend?"
  "What does my auditor see when an agent disables a user?"

---

## 4. Top user value props (the "why this exists")

Ranked. Five total. Each one cites the shipped feature behind it.

### V1 — Investigate at agent speed, audit at human speed

- **Proof.** A four-agent topology (Detect → Triage → Hunt → Respond) runs
  every incident; every prompt, tool call, and rationale lands in the
  Investigation Ledger and is replayable step-by-step.
- **Repo evidence.** `services/agents/app/agents/__init__.py`,
  `apps/docs/docs/architecture/agents.md`,
  `apps/web/src/components/copilot/InvestigationTimeline.tsx`.
- **Metric to display.** Wet-eval sub-minute p50, sub-2-minute p95
  (target gate — labelled wet-eval per `AGENTS.md`).
- **Persona.** SOC manager primary, analyst secondary.

### V2 — Graph at ingest, not at query time

- **Proof.** v8.0 ships an ingest-side graph writer that builds the
  entity-and-event graph as alerts arrive — not when the analyst clicks
  "show graph." A new `security.graph_updates` Kafka topic fans out
  changes to the realtime layer; effective-permissions and attack-chain
  views are graph queries, not lazy joins.
- **Repo evidence.** `services/ingest/internal/graph/` (writer.go,
  extractor.go, schema.go), `apps/docs/docs/architecture/graph-schema.md`,
  `services/api/app/api/v1/endpoints/effective_permissions.py`.
- **Metric to display.** Substrate p95 graph-freshness target ≤ 2 s
  (substrate, per `AGENTS.md`).
- **Persona.** Detection engineer.

### V3 — A public benchmark you can reproduce in 30 seconds

- **Proof.** 200 synthetic incidents drawn from 55 distinct templates
  plus a 361-event synthetic telemetry corpus across 14 log sources. Five
  pytest suites gate every PR. Per-template macros catch the regression
  the per-case mean hides.
- **Repo evidence.** `apps/docs/docs/benchmark.md`,
  `apps/docs/docs/benchmark-methodology.md`,
  `scripts/run_evals.py`, `services/agents/tests/eval_data/`.
- **Metric to display.** Substrate MITRE-tactic accuracy 97.0 % per-case
  / 96.4 % per-template (substrate self-consistency gate). Wet-eval row
  populated by the weekly job in
  `.github/workflows/wet-eval.yml` once it runs (T5.5).
- **Persona.** Detection engineer primary, CISO secondary.

### V4 — Connect 69 sources in three clicks, MIT-licensed plugin SDK in three languages

- **Proof.** `services/connectors/app/connectors/__init__.py` registers 69
  connector classes spanning EDR / SIEM / cloud / IAM / SaaS / VCS /
  network. Each one renders a schema-driven form, encrypts secrets via
  `CredentialVault`, and starts polling on a per-instance schedule. The
  marketplace ships 7,117 items (6,998 detections, 62 playbook packs, 57
  plugins) per `marketplace/index.json`.
- **Repo evidence.** `services/connectors/app/connectors/`,
  `apps/docs/docs/operations/credentials.md`,
  `packages/plugin-sdk-py/`, `packages/plugin-sdk-go/`,
  `packages/plugin-sdk-ts/`, `marketplace/index.json`.
- **Metric to display.** 69 connectors live, 7 categories, 7,117
  marketplace items.
- **Persona.** Analyst (the click-and-connect promise), detection engineer
  (the SDK promise).

### V5 — Deploy where your data is allowed to live

- **Proof.** Six tested deploy targets: Render (one-click), Fly.io (script),
  Docker Compose (one command), Kubernetes (Helm chart), AWS Terraform,
  Coolify. Plus a documented air-gap overlay with an Ollama sidecar and
  per-tenant BYOK LLM credentials in the encrypted vault.
- **Repo evidence.** `infra/render/`, `infra/fly/`, `infra/helm/`,
  `infra/terraform/`, `infra/compose/docker-compose.airgap.yml`,
  `apps/docs/docs/operations/air-gapped.md`,
  `apps/web/src/app/(marketing)/sovereign/page.tsx`.
- **Metric to display.** Six deploy targets, one air-gap overlay, BYOK in
  every direction.
- **Persona.** CISO primary, detection engineer secondary.

---

## 5. Differentiation pillars

Four pillars. Each has a one-sentence claim and a one-paragraph defence.

### P1 — Open source and transparent

**Claim.** Every line of the agent, every detection rule, every benchmark
number is MIT-licensed and reproducible from a fresh clone.

**Defence.** The agent orchestrator is ~600 lines of LangGraph in
`services/agents/app/orchestrator/`. The detection corpus is YAML under
`detections/` (6,998 rules across cloud, endpoint, identity, network,
application, and data-exfil). The benchmark dataset and harness are in
`services/agents/tests/eval_data/` and `scripts/run_evals.py`. Anyone can
run `python3 scripts/run_evals.py` and reproduce every number on the
benchmark page in roughly 35 ms. There is no private fork, no
hosted-only feature, and no commercial license tier that hides code.

### P2 — Graph-native at ingest

**Claim.** AiSOC builds the entity-and-event graph while the alert is
being normalised, not when an analyst clicks "show graph."

**Defence.** `services/ingest/internal/graph/` writes Neo4j nodes and
edges from raw events using a versioned schema (17 node labels, 14
relationships) published at `schemas/graph-schema.yaml` and the docs
page at `apps/docs/docs/architecture/graph-schema.md`. Failures never
block fusion: the writer drops with a metric and the alert ships through
anyway. A new Kafka topic, `security.graph_updates`, fans out graph
changes to the realtime service so the console can show a live graph
without polling. Configuration snapshots, effective permissions, and
attack-chain timelines all read off this graph.

### P3 — Agentic and auditable

**Claim.** Four named agents do the work; an Investigation Ledger logs
every step so a human can replay the reasoning.

**Defence.** The public agent surface is fixed at four — Detect, Triage,
Hunt, Respond — per `apps/docs/docs/architecture/agents.md`. A test
(`services/agents/tests/test_four_agent_facade.py`) fails CI if a fifth
public agent class is introduced. Every prompt and tool call lands in
the Investigation Ledger, rendered as a replayable timeline in
`apps/web/src/components/copilot/InvestigationTimeline.tsx`. The
LLM-input contract (v8.0 T2.3) wraps tool input/output in a fail-closed
Pydantic validator so silent malformed-prompt bugs cannot reach
production. BYOK per-tenant LLM credentials are encrypted with Fernet
AES-128-CBC + HMAC-SHA256 (`CredentialVault`) and decrypted only at
poll-time.

### P4 — Deploy anywhere, including the no-internet rack

**Claim.** Self-host in five minutes, take it sovereign in an afternoon,
take it air-gapped on a flag.

**Defence.** `pnpm aisoc:demo` brings up the slim stack in ~3.5 minutes
warm. `render.yaml` powers a one-click deploy. `infra/helm/aisoc/` runs
on any Kubernetes. `infra/terraform/` brings up AWS. The air-gapped
overlay at `infra/compose/docker-compose.airgap.yml` ships a pinned Ollama sidecar so
the demo seed runs end-to-end with zero external calls; the
`AISOC_AIRGAPPED=true` flag refuses outbound LLM calls,
threat-intel feeds, and telemetry. Per-tenant LLM credentials in
`TenantLlmCredential` let one tenant talk to OpenAI while the next
talks to a private LiteLLM gateway.

---

## 6. Information architecture for the landing page

Section IDs are the slugs the analytics layer should use for in-page
section tracking.

### 6.a — `nav` (Sticky nav)

- **Purpose:** Persistent wayfinding + always-visible primary CTA.
- **Persona:** All three.
- **Conversion behaviour:** Reduce bounce by keeping the CTA glued to the
  viewport. Open the "Get started" sheet without leaving the page.
- **Content blocks:** Wordmark + mark · Product · Solutions · Connectors
  · Benchmark · Pricing · Docs · GitHub star count chip · Primary CTA
  (Start free) · Secondary CTA (Self-host).
- **Visual treatment:** 64 px tall, glass-blur over hero, brand-tinted
  border-bottom appears on scroll. Star count chip pulls live from
  GitHub API client-side; falls back to a static "Star on GitHub" pill.
- **Responsive:** Collapse to logo + GitHub chip + hamburger below 768 px.

### 6.b — `hero` (Hero)

- **Purpose:** State the value, prove openness in one glance, route to
  one of two paths.
- **Persona:** All three; copy weighted to the analyst.
- **Conversion behaviour:** Primary path → managed waitlist
  (`/waitlist`). Secondary path → GitHub repo. Tertiary path → live
  demo deeplink.
- **Content blocks:** Eyebrow ("Open-source · MIT · self-hostable") ·
  H1 ("Detect. Triage. Hunt. Respond.") · sub-head ·
  Primary CTA ("Start free on managed") ·
  Secondary CTA ("Self-host on GitHub") ·
  Social-proof bar (GitHub stars · 69 connectors · 6 deploy targets) ·
  Visual: animated agent-graph or screencast of `INC-RT-001` ledger.
- **Visual treatment:** Two-column on laptop+. Copy left, graph
  visualisation right. The graph motion is the recurring brand motif —
  see §7.
- **Responsive:** Stack to single column under 1024 px; auto-pause
  motion under 768 px.

### 6.c — `proof-strip` (Logo / social-proof strip)

- **Purpose:** Borrow credibility from the open-source stack we sit on
  and the design partners we have.
- **Persona:** CISO most, manager second.
- **Conversion behaviour:** Bounce reduction; no click target.
- **Content blocks:** "Powered by" label · 6 line-art logos
  (LangGraph · Kafka · Neo4j · PostgreSQL · Qdrant · Ollama) · "Design
  partners" label · 4–6 partner placeholders (TBD) · GitHub stars +
  Discord member count.
- **Visual treatment:** Greyscale logos, hover restores brand colour.
  Background `surface-subtle`.
- **Responsive:** 2 rows on phone, single row on tablet+.

### 6.d — `problem` (Problem framing)

- **Purpose:** Earn permission to keep reading by naming the pain.
- **Persona:** Analyst + manager.
- **Conversion behaviour:** Build empathy; no CTA.
- **Content blocks:** H2 ("Your SOC is drowning in alerts") · three pain
  bullets, each with an attributed stat (sourced; see copy doc).
- **Visual treatment:** Three columns with line-art icons (alert-storm,
  context-switch, blank-dashboard).
- **Responsive:** Stack to one column under 768 px.

### 6.e — `solution` (Solution overview — the four agents)

- **Purpose:** Anchor the buyer on the four-agent mental model.
- **Persona:** All three.
- **Conversion behaviour:** Time-on-page; tertiary CTA → docs page on
  the four agents.
- **Content blocks:** H2 · animated four-agent diagram (Detect → Triage
  → Hunt → Respond) · four cards, each with: agent name · one-line job
  · 3 capabilities · "Runs on" line (BYOK: OpenAI · Anthropic · Ollama
  · Azure · LiteLLM).
- **Visual treatment:** Cards live on the brand gradient. Active card
  scrolls into focus on diagram-step hover.
- **Responsive:** Diagram simplifies to a vertical list under 1024 px;
  cards become a 2×2 grid under 768 px.

### 6.f — `demo` (Live demo / interactive moment)

- **Purpose:** Let the visitor see the product before they click.
- **Persona:** Analyst + manager.
- **Conversion behaviour:** Demo dwell time, then primary CTA.
- **Content blocks:** H2 ("Watch it investigate `INC-RT-001`") · embedded
  ledger-replay (90-second loop, no audio, captions baked in) ·
  scrubber affordance · CTA ("Run this yourself in 5 minutes").
- **Visual treatment:** Bordered laptop-frame mock. Replay autopilots
  until the user clicks scrub.
- **Performance requirement.** ≤ 8 s to first frame. Lazy-load on
  intersection observer. Must work without a sign-in. `prefers-reduced-motion`
  freezes the loop on the first ledger step with a "Play replay" button.
- **Responsive:** Maintain 16:9 ratio. Captions burned in so they
  scale on phone without subtitle tracks.

### 6.g — `pillars` (Differentiation pillars)

- **Purpose:** Hold the four claims from §5 on a single screen.
- **Persona:** Manager + CISO.
- **Conversion behaviour:** Read-through; deep-link to docs for each
  pillar.
- **Content blocks:** Four cards (P1–P4) · each card: icon · headline ·
  body (≤ 30 words) · "Read more" link · a single supporting metric
  pulled from the repo.
- **Visual treatment:** 2×2 grid on laptop+, single column on phone.
  Hover lifts the card 2 px. Brand-accent border on the active card.
- **Responsive:** Cards stack at 768 px.

### 6.h — `features` (Feature deep-dive grids — three sub-sections)

- **Purpose:** Cover the breadth of what shipped without overwhelming.
- **Persona:** Manager + analyst.
- **Sub-sections:**
  - **Detect & Investigate.** 6 tiles: fusion engine · entity-risk RBA ·
    native detections · investigation ledger · attack-chain timeline ·
    effective permissions.
  - **Hunt & Respond.** 6 tiles: NL hunt at `/hunt` · Hunt-as-Code YAML
    · response planner · ChatOps approvals · L0–L4 maturity dial ·
    SOAR exec.
  - **Operate at scale.** 6 tiles: 69 connectors · marketplace · plugin
    SDKs (Py/TS/Go) · MCP server · Cursor extension · cost telemetry.
- **Visual treatment:** Each tile: icon · 1-line headline · 1-sentence
  body · doc link. Background `surface-card`.
- **Responsive:** 3-up on laptop+, 2-up on tablet, 1-up on phone.

### 6.i — `connectors` (Connectors + Marketplace)

- **Purpose:** Show the breadth and the SDK ramp.
- **Persona:** Manager primary.
- **Conversion behaviour:** Click through to the marketplace; encourage
  SDK contribution.
- **Content blocks:** H2 ("69 connectors, 6,998 detections, 62 playbook
  packs") · category chips (EDR, SIEM, Cloud, IAM, SaaS, VCS, Network) ·
  marquee or grid of connector logos · "Build your own in 50 lines" code
  callout linking to `packages/plugin-sdk-py/`.
- **Visual treatment:** Logo grid with subtle reveal on scroll. Each
  category chip is a filter (no full page reload).
- **Responsive:** 5-column on laptop+, 3-column on tablet, 2-column on
  phone. Marquee disables under `prefers-reduced-motion`.

### 6.j — `benchmark` (Benchmark band)

- **Purpose:** Anchor the buyer on reproducible numbers; differentiate
  on transparency.
- **Persona:** Manager + CISO.
- **Conversion behaviour:** Click through to `/benchmark`. Build trust.
- **Content blocks:** H2 ("Benchmarked, not vibes") · three big numbers
  (each labelled `substrate` or `wet-eval` per `AGENTS.md`) · short
  paragraph linking to methodology · CTA ("Read the methodology" + "Open
  scoreboard").
- **Visual treatment:** Numbers in mono, captions in sans. Each metric
  carries a tooltip with the underlying suite name.
- **Responsive:** 3 numbers stack on phone.

### 6.k — `deploy` (Deployment options)

- **Purpose:** Answer "where can I run this?" before the procurement
  conversation starts.
- **Persona:** CISO primary, manager secondary.
- **Conversion behaviour:** Route to managed waitlist OR self-host docs
  OR sovereign page.
- **Content blocks:** H2 · three cards: **Managed** (waitlist · cloud
  LLMs · EU/US/India) · **Self-host** (Render · Fly.io · Helm · AWS) ·
  **Sovereign / air-gap** (Ollama sidecar · BYO LLM endpoint · single
  tenant). Each card lists deploy time, cost shape, LLM options.
- **Visual treatment:** Three cards, equal weight. Middle card carries a
  subtle brand glow as the default recommendation.
- **Responsive:** Stack to single column under 1024 px.

### 6.l — `open-source` (Open source moment)

- **Purpose:** Reinforce the open promise and recruit contributors.
- **Persona:** Detection engineer primary.
- **Conversion behaviour:** GitHub star, repo clone, contributing PR.
- **Content blocks:** H2 ("MIT-licensed. Every rule public. Every
  benchmark reproducible.") · GitHub repo card with live star count · CTA
  ("Star on GitHub") · secondary CTA ("Read CONTRIBUTING.md") · code
  snippet showing `pnpm aisoc:demo`.
- **Visual treatment:** Brand-coloured GitHub octocat mark + repo card.
  Code snippet uses `JetBrains Mono` per §7.
- **Responsive:** Code snippet horizontal-scrolls under 600 px.

### 6.m — `testimonials` (Testimonials / case studies)

- **Purpose:** Soft proof for buyers who still want to see another logo.
- **Persona:** CISO primary.
- **Conversion behaviour:** Click into a customer story.
- **Content blocks:** H2 · 2–4 quote cards pulled from
  `apps/web/content/customers/*.mdx`. Each card: industry chip · headline
  · one-sentence quote · attributed name + title · before-after metric
  · "Read case study" link. **Placeholder treatment** for empty state
  (no published studies yet) — show a "Be the first reference" CTA.
- **Visual treatment:** Quote cards with brand-tinted accent on the
  quotation glyph. Industry chip carries the brand-tinted background.
- **Responsive:** Carousel under 768 px.

### 6.n — `pricing-teaser` (Pricing teaser)

- **Purpose:** Surface the three tiers without sending the buyer to a
  full pricing page from the landing.
- **Persona:** CISO + manager.
- **Conversion behaviour:** Click through to `/pricing` (future page) or
  managed waitlist.
- **Content blocks:** H2 · three cards: **Community** (free, MIT,
  self-host) · **Team** (managed, support SLA, BYOK) · **Enterprise**
  (sovereign, air-gap, named contact). One-line value each. "See full
  pricing →" link.
- **Visual treatment:** Three cards, equal weight; Team is the default
  with a soft glow.
- **Responsive:** Stack to single column under 1024 px.

### 6.o — `faq` (FAQ)

- **Purpose:** Pre-empt the eight questions every prospect asks.
- **Persona:** All three.
- **Conversion behaviour:** Reduce hand-holding load on the sales team.
- **Content blocks:** 8 questions (see copy doc). Accordion. First two
  open by default.
- **Visual treatment:** Restrained, neutral. No drop shadows.
- **Responsive:** Native; the accordion respects keyboard nav (`Enter` /
  `Space` to toggle).

### 6.p — `final-cta` (Final CTA band)

- **Purpose:** Last chance to convert.
- **Persona:** All three.
- **Conversion behaviour:** Two routes — managed waitlist OR GitHub.
- **Content blocks:** H2 ("Ship the SOC you wish you had.") · sub-head ·
  Primary CTA ("Try managed") · Secondary CTA ("Self-host on GitHub") ·
  small line: "MIT-licensed · No credit card · Air-gap on a flag."
- **Visual treatment:** Full-bleed brand-gradient panel, contrast-checked.
- **Responsive:** Stack CTAs under 600 px.

### 6.q — `footer` (Footer)

- **Purpose:** Wayfinding to everything not on the landing.
- **Persona:** All three.
- **Conversion behaviour:** Discovery.
- **Content blocks:** Five columns: **Product** · **Resources** ·
  **Company** · **Legal** · **Status & GitHub**. Bottom row: copyright,
  social, language switcher, system status dot.
- **Visual treatment:** `surface-subtle` background. Brand-tinted links
  on hover only.
- **Responsive:** Collapse columns to an accordion under 768 px.

---

## 7. Brand and visual direction

### Colour

We anchor on the brand ramp already defined in
`apps/web/tailwind.config.ts`:

| Token       | Hex      | Use                                |
|-------------|----------|------------------------------------|
| `brand-500` | `#3b82f6` | Primary CTA, brand-accent          |
| `brand-600` | `#2563eb` | CTA hover / pressed                |
| `brand-300` | `#93c5fd` | Active text, eyebrows, badges      |
| `brand-200` | `#bfdbfe` | Soft chip text                     |
| `brand-900` | `#1e3a8a` | Background accents on dark        |

Surface and foreground tokens are CSS-variable-driven (see
`apps/web/src/app/globals.css`); the landing page is dark-locked
(`data-theme="dark"`) per the existing `apps/web/src/app/page.tsx`. Use
`surface-base #0a0d14`, `surface-card #141926`, `fg-primary #e2e8f0`,
`fg-muted #9ca3af`. Severity tokens (`critical #ef4444`, `high #f97316`,
`medium #eab308`, `low #3b82f6`, `info #22c55e`) appear only inside
product screenshots — they are not part of the marketing palette.

### Typography

- **Sans:** Inter (already loaded as `var(--font-inter)` in the web app).
- **Mono:** JetBrains Mono (already used for code blocks per
  `globals.css`).
- **Hero scale.** 56 px / 60 px (laptop), 40 px / 44 px (tablet),
  32 px / 36 px (phone). Hand-set tracking on the hero only.
- **Body scale.** 16 px / 28 px default, 14 px / 22 px on captions.
- **Number scale.** All metrics in `JetBrains Mono`, tabular-figures.

### Tone

Technical, confident, never breathless. Read the existing marketing
voice in `apps/web/src/app/(marketing)/sovereign/page.tsx` and
`apps/web/src/app/(marketing)/customers/page.tsx`. Sentences are short.
Verbs are concrete. Numbers are cited. No hype clichés (see §8 banned
phrases).

### Motion

- **Calm and purposeful.** Animations are there to direct attention, not
  decorate.
- **`prefers-reduced-motion`** must freeze every loop and replace
  parallax with static art.
- **Durations.** 180–240 ms for micro-interactions; 400–600 ms for
  section reveals; 8 s max for any hero loop, with a hard pause at the
  end frame so the loop never feels frantic.
- **Easing.** Lean on `cubic-bezier(0.16, 1, 0.3, 1)` (the "ease-out
  expo" we already use in console transitions).

### Illustration

- **Line-art schematics over stock photography.** The brand is the
  agent-graph: nodes, edges, and the moving signal between them. Reuse
  this motif across at least four sections (hero, solution, connectors,
  benchmark).
- **No stock-photo analysts.** No glowing brains. No padlock-on-circuit
  imagery.
- **Brand glyphs.** Build a 24-icon line-art set (1.5 px stroke, square
  cap, brand-300 default, brand-500 active). Re-use across features and
  the FAQ.

### Photography

- **Allowed.** Hands on a real keyboard with a real terminal in focus,
  shot at desk height in low-key lighting. Captured, not stock.
- **Disallowed.** Generic SOC stock, "shield over earth," "hooded
  hacker," any face-forward portrait we have not licensed individually.

---

## 8. Copywriting principles and banned phrases

### Voice rules

- **One claim per sentence.** Stack short sentences instead of compound
  ones.
- **Cite or cut.** Every metric earns a tooltip or a methodology link.
- **Active voice.** "AiSOC fuses raw events," not "raw events are fused."
- **Pronouns.** We refer to AiSOC as "AiSOC" or "we." The reader is
  "you" (second person), never "users."
- **Sentence length.** Median ≤ 18 words. Hard cap 28.
- **Headlines.** Verb-first or product-name-first. No questions in
  H1/H2.
- **Microcopy.** Button labels are imperative two-word phrases when
  possible (`Start free`, `Read methodology`).
- **No fragments masquerading as full thoughts.** No "Security. Faster."

### Banned phrases

- "Revolutionary"
- "Game-changing"
- "Next-generation"
- "Synergy"
- "Leverage" (as a verb — use `use`)
- "Unleash"
- "Empower"
- "Disrupt"
- "AI-native" / "AI-first"
- "World-class"
- "Cutting-edge"
- "Reimagine"

If a sentence still reads as marketing-speak after deleting the banned
word, rewrite it.

---

## 9. CTAs and conversion model

### Primary CTA — copy variants

1. **Start free on managed** (default)
2. **Join the managed waitlist**
3. **Try it free**

### Secondary CTA — copy variants

1. **Self-host on GitHub** (default)
2. **Clone the repo**
3. **Run it locally in 5 minutes**

### Tertiary CTA — docs / repo

1. **Read the docs**
2. **Read the benchmark methodology**

### Waitlist form behaviour

Mirror the form already on `/waitlist` (`apps/web/src/app/(marketing)/waitlist/page.tsx`):
five fields — email, company, role, current SOC stack (multi-select with
16 options), motivation. Inline validation only on blur. Success state
swaps the form for a thank-you panel with a calendar-booking link.
Submission endpoint `POST /api/v1/waitlist/signup` is already shipped by
Subagent B; do not redesign the field set without product sign-off.

### Event taxonomy (analytics-friendly hit-target names)

Designers should label every CTA and every section with the slug
analytics expects. Section slugs follow §6 IDs verbatim
(`nav`, `hero`, `proof-strip`, `problem`, `solution`, `demo`, `pillars`,
`features-detect`, `features-hunt`, `features-operate`, `connectors`,
`benchmark`, `deploy`, `open-source`, `testimonials`,
`pricing-teaser`, `faq`, `final-cta`, `footer`).

Primary CTA names: `cta-start-managed-{section}`, secondary CTA names:
`cta-self-host-{section}`. FAQ items: `faq-q1`…`faq-q8`.

---

## 10. SEO and metadata

- **Title (≤ 60 chars):** `AiSOC — The open agentic SOC`
- **Description (≤ 155 chars):** `Open-source MIT-licensed agentic SOC.
  Four named agents. 69 connectors. Public benchmark. Self-host in 5
  minutes or join the managed waitlist.`
- **OG image direction.** 1200×630. Dark surface. Wordmark top-left.
  Centred phrase "Detect. Triage. Hunt. Respond." in white. Brand-500
  gradient bar across the bottom. Repo URL bottom-right in mono.
- **Slugs.** `/` (landing). Internal anchors per §6 IDs.
- **Structured data.** `SoftwareApplication` schema with
  `applicationCategory: SecurityApplication`, `operatingSystem:
  Linux/macOS/Kubernetes`, `offers: free`, `softwareVersion: 7.3.1`.
  `FAQPage` schema generated from the FAQ accordion.
- **Target keywords.** `open source AI SOC`, `agentic security
  operations center`, `self-hosted SIEM alternative`,
  `MIT-licensed SOC`, `LangGraph security agent`, `air-gapped SOC`. No
  competitor names per `AGENTS.md`.

---

## 11. Accessibility requirements

- **WCAG 2.2 AA** is the floor, gated by the axe-core CI test at
  `apps/web/src/test/a11y.test.tsx` per `AGENTS.md`. Every new component
  must pass before merge.
- **Keyboard nav order** follows visual order: nav → hero CTAs → demo
  scrubber → pillar cards → feature tiles → connector filters →
  benchmark CTA → deploy cards → open-source CTA → testimonial carousel
  → pricing cards → FAQ items → final CTA → footer.
- **`prefers-reduced-motion`** disables every loop, swaps the hero
  animation for a static frame, and replaces the diagram step
  highlighting with a static state.
- **Colour contrast.** Body copy ≥ 7:1 against `surface-base` (AAA).
  CTAs ≥ 4.5:1 (AA). Severity chips inside product screenshots are
  decorative; never sole carriers of meaning.
- **Target hit area.** 44 × 44 px minimum for any interactive element on
  touch. Buttons keep 48 × 48 px target in copy mocks.
- **Focus ring.** 2 px `brand-500` outside ring with 2 px offset, per
  the rule already in `globals.css` (`:focus-visible`).

---

## 12. Performance budget

- **LCP.** ≤ 2.0 s on a mid-range 4G phone, ≤ 1.2 s on a wired laptop.
- **TTI.** ≤ 3.5 s on 4G phone.
- **JS bundle.** ≤ 110 KB gzipped above the fold; lazy-load the demo
  embed, the testimonials carousel, and the FAQ accordion below the
  fold.
- **Image budget.** Hero illustration ≤ 80 KB (SVG or pre-baked AVIF).
  Total image weight above the fold ≤ 150 KB.
- **Font budget.** Inter and JetBrains Mono variable subsets, preloaded;
  ≤ 90 KB combined.
- **Canary integration.** The existing `pnpm canary` deploy guard
  watches LCP and console errors post-deploy; the design must not
  introduce a layout that breaks the canary thresholds.

---

## 13. Responsive breakpoints

The web app uses Tailwind defaults; respect them: `sm 640`, `md 768`,
`lg 1024`, `xl 1280`, `2xl 1536`. For this brief, treat the four
breakpoints as:

- **Phone** (`< 640 px`)
- **Tablet** (`640–1024 px`)
- **Laptop** (`1024–1440 px`)
- **Desktop** (`> 1440 px`)

Per-section responsive notes are already embedded in §6. The two cases
that need extra care:

- The four-agent diagram in §6.e must remain legible at 360 px. Step
  labels collapse to two-letter glyphs (D · T · H · R) below 640 px.
- The connector grid in §6.i must not flash a single-column list of 69
  logos on phone; show 18 logos plus a "See all 69" link.

---

## 14. Out of scope

The following are **not** part of this landing-page design effort:

- The logged-in product UI (`/dashboard`, `/alerts`, `/cases`,
  `/investigate`, `/hunt`, `/playbooks`, etc.) — those live in
  `apps/web/src/app/(app)/` and have a separate design system.
- The Docusaurus docs site (`apps/docs/`) — owned by a different
  workstream.
- The full pricing page (we ship a teaser; the full page is a follow-on).
- The blog (`/blog`) — already exists at
  `apps/web/src/app/(marketing)/blog/page.tsx`.
- The status page (`status.tryaisoc.com`) — third-party service.
- The Cursor extension marketplace listing (`services/mcp/cursor-extension/`)
  — separate visual asset, separate cadence.
- Hiring / about pages — not committed to a date.

---

## 15. Open questions for the design team

These are the calls we want the designer to make and bring back. Bring
opinions, not just options.

1. **Hero visual.** Lottie animation of the agent graph, a 90-second
   muted screencast of `INC-RT-001`, or a static SVG with subtle
   parallax? Pick one and defend the trade-off against the ≤ 8 s
   first-frame budget in §12.
2. **Demo embed treatment.** Picture-in-picture window vs. full-bleed
   browser-frame mock vs. minimal "terminal" treatment for the
   `pnpm aisoc:demo` flow?
3. **Four-agent diagram style.** Pipeline left-to-right, radial hub,
   stepped vertical, or "stage cards on a track"?
4. **Connector grid.** Marquee that animates on scroll, a static
   alphabetical grid, or a category-filtered grid (default: EDR)?
5. **Benchmark band.** Three big numbers in mono, a single illustrative
   chart, or a small interactive scoreboard widget?
6. **Pricing card hierarchy.** Should "Team (managed)" be visually
   recommended, or should we leave the three tiers visually equal and
   let the buyer self-select?
7. **Testimonial empty state.** Empty until a real customer ships, or
   a "design partners" placeholder card pattern?
8. **Light-mode story.** Does the landing stay dark-locked
   (matches `apps/web/src/app/page.tsx` today) or do we ship a
   light-mode variant for daytime laptop reading?
9. **OG image.** Static export of the hero with the wordmark and tagline,
   or a per-section dynamic OG image (one per anchor) when shared deep?
10. **GitHub star chip.** Live API call client-side (cost: a network
    request) or static pill that links to the repo (cost: one less
    proof point)?
11. **Final CTA band layout.** Two-CTA split with equal weight, or
    stacked with the managed CTA larger?
12. **Iconography vendor.** Build a 24-icon line-art set in-house, or
    license a Lucide / Phosphor subset and brand-tint it?

---

## 16. Appendix A — competitive design references

We deliberately study companies in adjacent open-source, developer-tool,
and observability categories — never SOC competitors. The point is to
borrow patterns that earn trust without leaning on hype.

1. **Supabase** — `supabase.com`. Steal: code-first hero with a working
   snippet, transparent pricing teaser, calm dark-mode default. Avoid:
   their sometimes-busy three-column section layouts.
2. **Vercel** — `vercel.com`. Steal: typographic hero discipline, motion
   that respects `prefers-reduced-motion`. Avoid: their dense
   logo-strip pattern on small viewports.
3. **Linear** — `linear.app`. Steal: micro-interactions that reward
   reading, dense-yet-calm information density. Avoid: heavy custom
   shaders that bloat first paint.
4. **Stripe Docs** — `stripe.com/docs`. Steal: the "claim → code → run"
   rhythm; mono-numerics for prices and rate limits. Avoid: their
   in-page nav becomes complex above 1440 px.
5. **Grafana Labs** — `grafana.com`. Steal: open-source + commercial
   tier coexistence without confusion. Avoid: their "products" mega-nav
   creates a wayfinding tax.
6. **Datadog Open Source** — `datadoghq.com/open-source`. Steal:
   benchmark page anatomy and the "reproduce these numbers" rhythm.
   Avoid: marketing claims without methodology links.
7. **PostHog** — `posthog.com`. Steal: a developer-first voice that
   still converts; the "self-host vs. cloud" comparison pattern. Avoid:
   their FAQ length tends to overwhelm.
8. **Cal.com** — `cal.com`. Steal: an open-source proof bar (stars,
   contributors, license badge) right under the hero. Avoid: emoji-heavy
   microcopy.
9. **Resend** — `resend.com`. Steal: hero scale, restrained colour,
   one-CTA discipline. Avoid: a hero loop that runs forever (drains
   battery on phones).
10. **Hashicorp** — `hashicorp.com`. Steal: deploy-target matrix layout
    we want to mimic for §6.k. Avoid: their pricing-page navigation
    pattern leaks into the marketing nav.

Condensed teardown lives at `docs/design/landing-page-references.md`.

---

## 17. Appendix B — content matrix (shipped features by section)

| Feature                                | Repo path / service                                                                          | Persona served      | Value prop bucket   | Landing section(s)            | Status        |
|----------------------------------------|----------------------------------------------------------------------------------------------|---------------------|---------------------|-------------------------------|---------------|
| Four-agent topology                    | `services/agents/app/agents/__init__.py` · `apps/docs/docs/architecture/agents.md`            | Analyst, manager    | V1 (audit-speed)    | hero, solution, pillars (P3)  | Shipped       |
| Investigation Ledger                   | `apps/web/src/components/copilot/InvestigationTimeline.tsx`                                   | Analyst, CISO       | V1                  | demo, features-detect, pillars (P3) | Shipped |
| Ingest-side graph writer               | `services/ingest/internal/graph/`                                                            | Detection engineer  | V2 (graph-native)   | features-detect, pillars (P2) | Coming (v8.0 T1.1 scaffold) |
| Graph schema v1.0                      | `schemas/graph-schema.yaml` · `apps/docs/docs/architecture/graph-schema.md`                  | Detection engineer  | V2                  | pillars (P2)                  | Shipped       |
| Effective Permissions resolver         | `apps/web/src/components/graph/` (Subagent C)                                                | Detection engineer  | V2                  | features-detect               | In flight (T3.2) |
| Attack-chain timeline                  | `services/api/.../endpoints/attack_chain.py`                                                 | Manager             | V1                  | features-detect               | In flight (T3.3) |
| NL hunt surface (`/hunt`)              | `apps/web/src/app/(app)/hunt/` · `services/api/app/api/v1/endpoints/hunts.py`                | Manager, analyst    | V1                  | features-hunt                 | Shipped       |
| Hunt-as-Code (YAML hunts)              | `hunts/` · `services/agents/app/hunt/`                                                       | Detection engineer  | V1                  | features-hunt                 | Shipped       |
| Public eval harness (5 suites)         | `services/agents/tests/` · `scripts/run_evals.py`                                            | Manager             | V3 (benchmark)      | benchmark, pillars (P1)       | Shipped       |
| Public scoreboard page                 | `apps/docs/docs/benchmark-scoreboard.mdx`                                                    | Manager             | V3                  | benchmark                     | Shipped (T5.4 wip) |
| Weekly wet-eval CI                     | `.github/workflows/wet-eval.yml`                                                             | Manager             | V3                  | benchmark                     | Shipped (T5.5 wip) |
| LLM input contract (fail-closed)       | `services/agents/.../llm_input_contract.py` (T2.3)                                           | CISO                | V1, P3              | pillars (P3)                  | Shipped (T2.3 wip) |
| Pre-fetched ContextBundle              | `services/agents/.../context_bundle.py` (T2.1)                                               | Manager             | V1                  | features-hunt                 | Shipped (T2.1 wip) |
| 69 click-and-connect connectors        | `services/connectors/app/connectors/__init__.py`                                             | Analyst, manager    | V4                  | connectors, features-operate  | Shipped       |
| Marketplace (7,117 items)              | `marketplace/index.json` · `scripts/build_marketplace.py`                                    | Detection engineer  | V4                  | connectors                    | Shipped       |
| Credential vault (Fernet + HMAC)       | `services/api/app/services/vault.py` · `apps/docs/docs/operations/credentials.md`            | CISO                | V4, P3              | deploy, pillars (P3)          | Shipped       |
| Plugin SDKs (Python, TypeScript, Go)   | `packages/plugin-sdk-py/` · `packages/plugin-sdk-ts/` · `packages/plugin-sdk-go/`            | Detection engineer  | V4                  | features-operate              | Shipped       |
| MCP server (13 tools)                  | `services/mcp/`                                                                              | Detection engineer  | V4                  | features-operate              | Shipped       |
| Cursor extension                       | `services/mcp/cursor-extension/` (T7.1)                                                      | Detection engineer  | V4                  | features-operate              | Shipped (scaffold) |
| Render one-click deploy                | `render.yaml` · `infra/render/`                                                              | Analyst, manager    | V5 (deploy)         | deploy                        | Shipped       |
| Fly.io deploy script                   | `infra/fly/`                                                                                 | Manager             | V5                  | deploy                        | Shipped       |
| Helm chart                             | `infra/helm/aisoc/`                                                                          | CISO                | V5                  | deploy                        | Shipped       |
| Terraform (AWS, GCP, BYOC)             | `infra/terraform/`                                                                           | CISO                | V5                  | deploy                        | Shipped       |
| Air-gap overlay (Ollama sidecar)       | `infra/compose/docker-compose.airgap.yml` · `apps/docs/docs/operations/air-gapped.md`        | CISO                | V5, P4              | deploy, pillars (P4)          | Shipped       |
| BYOK per-tenant LLM credentials        | `services/api/app/models/tenant_llm.py` · `apps/web/src/components/settings/SettingsView.tsx`| CISO                | V5, P3              | deploy, pillars (P3)          | Shipped       |
| L0–L4 maturity dial                    | `services/actions/app/services/maturity.py` · `apps/docs/docs/concepts/automation-maturity.md`| CISO                | V1, P3              | features-hunt, pillars (P3)   | Shipped       |
| ChatOps approvals (Block Kit / Adaptive Cards) | `services/slack-bot/` · `services/notifications/.../adaptive_cards.py`                | Analyst, manager    | V1                  | features-hunt                 | Shipped (T3.6 wip) |
| Executive digest PDF                   | `services/api/app/services/digest_pdf.py`                                                    | CISO                | V1                  | (out of scope for landing)    | Shipped       |
| Customers index + MDX pages            | `apps/web/src/app/(marketing)/customers/`                                                    | CISO                | —                   | testimonials                  | Shipped       |
| Sovereign one-pager                    | `apps/web/src/app/(marketing)/sovereign/page.tsx`                                            | CISO                | V5                  | deploy                        | Shipped       |
| Waitlist page                          | `apps/web/src/app/(marketing)/waitlist/page.tsx`                                             | Manager, CISO       | —                   | nav, hero, final-cta          | Shipped (Subagent B) |
| Blog                                   | `apps/web/src/app/(marketing)/blog/`                                                         | All                 | —                   | footer                        | Shipped       |

The companion file `docs/design/landing-page-content.md` carries
ready-to-set copy for every section above. Designers should drop that
copy in verbatim; product owns the words, design owns the layout.

---

*End of brief. Open questions in §15 are the next call to make.*
