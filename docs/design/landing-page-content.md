# AiSOC landing page — ready-to-set copy

> Companion to `landing-page-brief.md`. Every string below is drop-in
> ready. Section IDs match §6 of the brief.

---

## `nav` — Sticky nav

- **Wordmark:** `AiSOC`
- **Nav items (left → right):** `Product` · `Solutions` · `Connectors` ·
  `Benchmark` · `Pricing` · `Docs`
- **GitHub chip:** `★ {count} on GitHub` (fall-back: `Star on GitHub`)
- **Primary CTA:** `Start free`
- **Secondary CTA:** `Self-host`

---

## `hero` — Hero

- **Eyebrow:** `Open-source · MIT · self-hostable`
- **H1:** `Detect. Triage. Hunt. Respond.`
- **Sub-head:**
  `AiSOC is the open agentic Security Operations Center. Four named
  agents investigate every incident end-to-end, and every prompt, tool
  call, and rationale lands in a replayable ledger. Self-host in five
  minutes, take it air-gapped on a flag, or join the managed waitlist.`
- **Primary CTA:** `Start free on managed`
- **Secondary CTA:** `Self-host on GitHub`
- **Tertiary link (under CTAs):** `Watch a 90-second investigation →`
- **Social-proof bar (three chips):**
  - `69 connectors · EDR · SIEM · cloud · IAM · SaaS · VCS · network`
  - `6,998 detections · 62 playbook packs · 57 plugins`
  - `Self-host · Render · Fly.io · Helm · Terraform · air-gap`

---

## `proof-strip` — Logo / social-proof strip

- **Label:** `Built on the open-source stack you already trust`
- **Logos (line-art):** LangGraph · Apache Kafka · Neo4j · PostgreSQL ·
  Qdrant · Ollama
- **Sub-label:** `Design partners`
- **Placeholder treatment:** 4 grey-tinted partner outlines with the
  caption `Reference partners onboarding through Q2 2026`.

---

## `problem` — Problem framing

- **Eyebrow:** `Why we built this`
- **H2:** `Your SOC is drowning in alerts.`
- **Sub-head:**
  `Three problems compound every shift. AiSOC was built to dissolve
  them, not paper over them.`
- **Pain bullets:**
  1. **Headline:** `Alert volume is up. Headcount is not.`
     **Body:** `A typical mid-market SOC sees more alerts in a single
     shift than an analyst can read end-to-end, and the AI tools that
     promise to triage them ship as black boxes you cannot audit.`
  2. **Headline:** `Context lives in eight tabs.`
     **Body:** `SIEM, EDR, cloud console, ticketing, chat, identity
     provider, on-call, runbook. Every alert is the same context-switch
     tax.`
  3. **Headline:** `You cannot defend a verdict you cannot read.`
     **Body:** `When an autonomous tool closes an alert, your analyst,
     your manager, and your auditor all need to know exactly why. Most
     vendors do not show the rationale.`

---

## `solution` — Solution overview (four agents)

- **Eyebrow:** `Four agents, one workflow`
- **H2:** `One agent for each stage of an incident.`
- **Sub-head:**
  `AiSOC ships exactly four named agents — Detect, Triage, Hunt, and
  Respond. Each one has a fixed job, a published capability list, and
  a replayable audit trail. Sub-agents (phishing, identity, cloud,
  insider) are capabilities of Triage, never separate brands.`

- **Card — Detect**
  - **Job:** `Fuse raw signals into incidents.`
  - **Capabilities:** `fusion · entity-risk (RBA) · native detections`
  - **Runs on:** `Deterministic · no LLM required`
- **Card — Triage**
  - **Job:** `Decide what matters and how urgent.`
  - **Capabilities:** `LLM auto-triage · phishing · identity · cloud ·
    insider`
  - **Runs on:** `OpenAI · Anthropic · Azure · Bedrock · Ollama · BYO
    endpoint`
- **Card — Hunt**
  - **Job:** `Ask new questions across the data.`
  - **Capabilities:** `NL → ES|QL · KQL · SPL · scheduled YAML hunts`
  - **Runs on:** `Cloud LLM or local model`
- **Card — Respond**
  - **Job:** `Plan containment, gate execution, approve via ChatOps.`
  - **Capabilities:** `response planner · SOAR exec · approvals`
  - **Runs on:** `L0–L4 maturity dial, dry-run by default`

---

## `demo` — Live demo

- **Eyebrow:** `See it work`
- **H2:** `Watch AiSOC investigate a live ransomware incident.`
- **Sub-head:**
  `INC-RT-001 is a LockBit 3.0 case that ships with every install. The
  ledger streams every prompt, tool call, and decision the agent made.
  Scrub the timeline, pause on any step, fork the rationale into a
  ticket.`
- **Frame caption (overlaid bottom-left):** `INC-RT-001 · LockBit 3.0 ·
  step 14 of 32`
- **Primary CTA (under demo):** `Run this yourself in 5 minutes`
- **Secondary link:** `Read the architecture →`

---

## `pillars` — Differentiation pillars

- **Eyebrow:** `What makes AiSOC different`
- **H2:** `Four promises we hold ourselves to.`

- **Card P1 — Open source and transparent**
  - **Body:** `MIT-licensed agent, public detection corpus, reproducible
    benchmark — every claim on this page maps to a file in the repo.`
  - **Stat:** `6,998 public detection rules`
  - **Link:** `Read the LICENSE →`
- **Card P2 — Graph-native at ingest**
  - **Body:** `The entity graph is written while events are normalised,
    not when an analyst clicks "show graph." Schema v1.0 is published.`
  - **Stat:** `17 node labels · 14 relationships`
  - **Link:** `Read the graph schema →`
- **Card P3 — Agentic and auditable**
  - **Body:** `Four named agents. Every prompt, tool call, and decision
    is logged. The LLM-input contract fails closed on malformed prompts.`
  - **Stat:** `4 agents · 100% audited`
  - **Link:** `Read the agent contract →`
- **Card P4 — Deploy anywhere**
  - **Body:** `Render, Fly.io, Kubernetes, AWS, your air-gapped rack —
    same code path. BYOK LLM credentials in the encrypted vault.`
  - **Stat:** `6 deploy targets · 1 air-gap overlay`
  - **Link:** `Read the deployment guide →`

---

## `features` — Feature deep-dive grids

### Detect & Investigate (6 tiles)

1. **Fusion engine.** `Real-time dedup, ML scoring, per-alert confidence.`
2. **Entity-risk rollup (RBA).** `Time-decayed risk per user, host, IP,
   domain — 50:1 alert-to-incident.`
3. **Native detections.** `6,998 YAML rules across cloud, endpoint,
   identity, network, application, and data-exfil.`
4. **Investigation Ledger.** `Replayable, step-by-step record of every
   agent decision per case.`
5. **Attack-chain timeline.** `Cytoscape over the Neo4j subgraph — see
   the path, not just the alerts.`
6. **Effective permissions.** `What a principal can actually do across
   AWS, Azure, GCP, Okta, Google Workspace.`

### Hunt & Respond (6 tiles)

1. **NL hunt at `/hunt`.** `Ask in English. Get ES|QL, KQL, and SPL back.`
2. **Hunt-as-Code (YAML).** `Hypothesis-driven, MITRE-tagged hunts on a
   cron.`
3. **Response planner.** `Containment → eradication → recovery, dry-run
   by default.`
4. **ChatOps approvals.** `Slack Block Kit + Teams Adaptive Cards, HMAC
   signed.`
5. **L0–L4 maturity dial.** `One per-tenant setting governs every
   action class. Auditable.`
6. **SOAR exec.** `Blast-radius gated playbook execution with full
   rollback.`

### Operate at scale (6 tiles)

1. **69 click-and-connect connectors.** `EDR · SIEM · cloud · IAM ·
   SaaS · VCS · network.`
2. **Marketplace.** `7,117 community items — detections, playbooks,
   plugins.`
3. **Plugin SDKs.** `Python, TypeScript, Go — build a connector in 50
   lines.`
4. **MCP server.** `Use AiSOC from Claude, Cursor, Continue, Cody — 11
   tools.`
5. **Cursor extension.** `Investigate alerts without leaving your
   editor.`
6. **Cost telemetry.** `Per-call tokens and USD captured in the run
   ledger.`

---

## `connectors` — Connectors + Marketplace

- **Eyebrow:** `Plug in everything`
- **H2:** `69 connectors. 6,998 detections. 62 playbook packs.`
- **Sub-head:**
  `Every connector renders a schema-driven form, encrypts its secrets at
  the application layer, and starts polling on a per-instance schedule.
  When the catalogue doesn't have what you need, write your own — the
  plugin SDKs are MIT and the marketplace ships your manifest on the
  next index build.`
- **Category chips:** `EDR` `SIEM` `Cloud` `IAM` `SaaS` `VCS` `Network`
- **Grid label:** `A small sample`
- **Code callout headline:** `Write a connector in 50 lines.`
- **Code callout body:**
  ```python
  from app.connectors.base import BaseConnector, ConnectorSchema, Field

  class MyConnector(BaseConnector):
      connector_id = "my-saas"
      connector_category = "saas"

      @classmethod
      def schema(cls) -> ConnectorSchema:
          return ConnectorSchema(
              name=cls.connector_id,
              label="My SaaS",
              category=cls.connector_category,
              fields=[
                  Field("api_url", "text", required=True),
                  Field("api_token", "secret", required=True, secret=True),
              ],
              default_poll_interval_seconds=300,
          )
  ```
- **Code callout CTA:** `Read the connector SDK →`

---

## `benchmark` — Benchmark band

- **Eyebrow:** `Reproducible by anyone`
- **H2:** `Benchmarked, not vibes.`
- **Sub-head:**
  `Five pytest suites gate every PR. 200 synthetic incidents drawn from
  55 templates plus a 361-event telemetry corpus across 14 log sources.
  Per-template macros catch the regression the per-case mean hides.
  Every figure is labelled — substrate (gated per-PR) or wet-eval
  (weekly job).`
- **Number tile 1.**
  - **Metric:** `97.0%`
  - **Caption:** `MITRE-tactic accuracy (substrate · per-case)`
- **Number tile 2.**
  - **Metric:** `Sub-minute p50`
  - **Caption:** `End-to-end investigation latency (wet-eval target)`
- **Number tile 3.**
  - **Metric:** `35 ms`
  - **Caption:** `Full substrate suite runtime on a laptop`
- **Primary CTA:** `Read the methodology`
- **Secondary CTA:** `Open the public scoreboard`

---

## `deploy` — Deployment options

- **Eyebrow:** `Run AiSOC where your data is allowed to live`
- **H2:** `Three deploy paths. Same code.`

- **Card — Managed (waitlist)**
  - **Title:** `Managed`
  - **Time to live:** `Same day — once seats open`
  - **LLM:** `Cloud APIs · BYO endpoint`
  - **Residency:** `EU · US · India`
  - **Body:** `We host it. You log in. SOC 2 and GDPR are on the
    roadmap. Join the waitlist for early access.`
  - **CTA:** `Join the waitlist`
- **Card — Self-host (recommended)**
  - **Title:** `Self-host`
  - **Time to live:** `Five minutes (warm Docker)`
  - **LLM:** `Cloud APIs · local Ollama · BYO`
  - **Residency:** `Operator-defined`
  - **Body:** `Render one-click, Docker Compose, Fly.io, Helm, AWS
    Terraform — pick any. The slim demo stack ships pre-seeded with a
    LockBit case mid-investigation.`
  - **CTA:** `Self-host on GitHub`
- **Card — Sovereign / air-gap**
  - **Title:** `Sovereign / air-gap`
  - **Time to live:** `An afternoon`
  - **LLM:** `Local Ollama · BYO LiteLLM`
  - **Residency:** `Operator-defined`
  - **Body:** `Set AISOC_AIRGAPPED=true and the platform refuses every
    outbound call. The Ollama sidecar ships a pinned local model so the
    demo seed runs end-to-end with zero external calls.`
  - **CTA:** `Read the air-gap guide`

---

## `open-source` — Open source moment

- **Eyebrow:** `MIT all the way down`
- **H2:** `Every detection rule public. Every benchmark reproducible.`
- **Sub-head:**
  `Fork the agent, fork the rules, fork the harness. We measure ourselves
  on the same metrics we publish, and we ship the dataset that produced
  them. There is no private fork.`
- **Repo card label:** `github.com/beenuar/AiSOC`
- **Repo card body:** `★ {star count} · MIT · TypeScript / Python / Go`
- **Primary CTA:** `Star on GitHub`
- **Secondary CTA:** `Read CONTRIBUTING.md`
- **Code snippet caption:** `Clone, demo, and inspect a live case in
  three commands:`
- **Code snippet:**
  ```bash
  git clone https://github.com/beenuar/AiSOC.git
  cd AiSOC
  pnpm aisoc:demo
  ```

---

## `testimonials` — Testimonials / case studies

- **Eyebrow:** `From the people running it`
- **H2:** `What teams say after their first month.`
- **Empty-state H3 (until a real customer ships):**
  `Be the first reference team.`
- **Empty-state body:**
  `We are onboarding reference partners through Q2 2026. If your team
  ships AiSOC into production, we will publish your case study under
  your byline, with the before/after metrics you choose.`
- **Empty-state CTA:** `Become a reference partner`

> Once `apps/web/content/customers/*.mdx` has at least two published
> studies, swap the empty state for the carousel — each card shows
> industry chip · headline · single-sentence quote · attributed name +
> title · two before/after metrics · link to read the full study.

---

## `pricing-teaser` — Pricing teaser

- **Eyebrow:** `Pricing`
- **H2:** `Free to self-host. Pay only when we host.`
- **Card — Community**
  - **Price:** `Free`
  - **Tagline:** `Self-host the full stack.`
  - **Includes:** `MIT-licensed code · all 69 connectors · marketplace
    · public benchmark harness · community Discord.`
- **Card — Team (managed)**
  - **Price:** `Contact us — waitlist`
  - **Tagline:** `We run it. You log in.`
  - **Includes:** `Everything in Community · managed instance on
    `app.aisoc.dev` · BYOK LLM · email support · SOC 2 (in progress).`
- **Card — Enterprise**
  - **Price:** `Contact us`
  - **Tagline:** `Sovereign, air-gap, or single-tenant in your VPC.`
  - **Includes:** `Everything in Team · sovereign / air-gap deploy ·
    named onboarding · architecture review · 24×7 incident channel.`
- **Footer link:** `See full pricing →`

---

## `faq` — FAQ

1. **Q.** `Is AiSOC really open source?`
   **A.** `Yes — the agent, the connectors, the detection rules, the
   benchmark dataset, and every piece of infrastructure code are
   MIT-licensed. There is no private fork.`
2. **Q.** `What does the agent need to call out to?`
   **A.** `By default the Triage and Hunt agents call an LLM provider
   you configure (OpenAI, Anthropic, Azure, Bedrock, or a private
   LiteLLM gateway). Set AISOC_AIRGAPPED=true and the platform refuses
   every outbound call; an Ollama sidecar runs a local model in-cluster.`
3. **Q.** `Where does my data live?`
   **A.** `Self-host: wherever you point Postgres, ClickHouse, and
   Redis. Managed: EU, US, or India region you pick at signup.
   Sovereign: a single-tenant VPC you control. The connector vault
   encrypts secrets with Fernet AES-128-CBC + HMAC-SHA256.`
4. **Q.** `Can the agent take real-world action without a human?`
   **A.** `Only inside the maturity tier you configure. L0 keeps the
   agent advisory only; L2 (the production default) lets it run
   reversible containment actions; L4 allows whitelisted closed-loop
   actions. Every action class is gated against blast radius.`
5. **Q.** `How is this benchmarked?`
   **A.** `Five pytest suites in services/agents/tests/ run on every
   PR. Three are substrate self-consistency gates; the fourth is a
   real measurement against a fixed 1,000-alert noisy stream; the
   fifth is a coverage gate on the synthetic telemetry corpus. The
   methodology page documents what each suite measures and what it
   does not.`
6. **Q.** `How do connectors work?`
   **A.** `Each connector is a Python class that declares a schema,
   tests its credentials, polls on a schedule, and normalises events
   into OCSF. 69 ship in the box. The plugin SDKs (Python, TypeScript,
   Go) let you author your own in roughly 50 lines.`
7. **Q.** `What runs in production today?`
   **A.** `Beta deployments through reference partners and an internal
   demo on tryaisoc.com. The managed waitlist at app.aisoc.dev is the
   route for hosted customers.`
8. **Q.** `Why not just use an existing AI SOC vendor?`
   **A.** `Use whichever tools fit your risk and procurement model.
   AiSOC's contribution is making the agent itself open, the decisions
   step-by-step auditable, and the benchmark reproducible — three
   guarantees closed-source platforms typically do not offer.`

---

## `final-cta` — Final CTA band

- **H2:** `Ship the SOC you wish you had.`
- **Sub-head:**
  `Either path lands you on a working SOC, not a blank dashboard.`
- **Primary CTA:** `Try managed`
- **Secondary CTA:** `Self-host on GitHub`
- **Microcopy:** `MIT-licensed · No credit card · Air-gap on a flag`

---

## `footer` — Footer

- **Column 1 — Product:**
  `Detect` · `Triage` · `Hunt` · `Respond` · `Connectors` · `Marketplace`
- **Column 2 — Resources:**
  `Docs` · `Architecture` · `Benchmark` · `Blog` · `Changelog` · `Roadmap`
- **Column 3 — Company:**
  `About` · `Sovereign` · `Customers` · `Contact` · `Press`
- **Column 4 — Legal:**
  `License (MIT)` · `Privacy` · `Terms` · `Security`
- **Column 5 — Status & GitHub:**
  `Status page` · `GitHub repo` · `Discord` · `RSS`
- **Bottom row:**
  `© 2024–present AiSOC contributors · MIT-licensed · v7.3.1` ·
  social icons (GitHub, Discord, X) · language switcher (English
  default).

---

*End of copy. Hand over to design with `landing-page-brief.md` for
context.*
