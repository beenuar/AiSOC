# Cyble AiSOC — 12-Month Execution Roadmap

**Version:** 1.1 | **Originally drafted:** April 2026 | **Last updated:** 2026-05-20
**Planning horizon:** May 2026 – April 2027
**Current production version:** v7.3.1 (github.com/beenuar/AiSOC)
**Part of:** [cyble-aisoc-plan.md](../cyble-aisoc-plan.md)

---

## Status Update — 2026-05-20

> **Q1 is complete.** The platform shipped v7.x with Console v1.5, four-agent façade (v8.0 preview), 50-connector catalog, LangGraph investigator, and osquery-TLS. The project is approaching v8.0 and is now mid-Q2 execution.

### What shipped ahead of the Q1 plan
- ✅ Console v1.5: Investigation Rail, Queue, Rule Tuning, Operations Funnel, Critical severity tier, Global time-window selector, Tenant switcher
- ✅ v8.0 four-agent façade: DetectAgent, TriageAgent, HuntAgent, RespondAgent (shipped 2026-05-19)
- ✅ LangGraph investigator (~600-line state machine, shipped 2026-05-19)
- ✅ 50-connector click-and-connect catalog (shipped v7.x)
- ✅ osquery-TLS server + osquery extensions (built-in services)
- ✅ MCP Server: AiSOC tools exposed to Claude Desktop, Cursor, and any MCP-compatible LLM
- ✅ Three-tier agent memory: session / working / institutional
- ✅ L0–L4 automation maturity model (shipped 2026-05-19)
- ✅ SSRF guard on all connectors (2026-05-19)
- ✅ Cross-tenant RBAC CI tests (2026-05-20)

### What is in progress (mid-Q2 as of 2026-05-20)
- 🔄 v8.0 wave-2 connectors: Cloudflare ZT, Sysdig, Vault, Snowflake (fixtures exist, activation in progress)
- 🔄 On-prem / air-gapped LLM support (Ollama + vLLM backends)
- 🔄 SOC 2 Type II audit period
- 🔄 MSSP programme onboarding
- 🔄 FedRAMP boundary documentation

---

## Roadmap Summary

```
MONTH:  1    2    3  │  4    5    6  │  7    8    9  │  10   11   12
        ────────────────────────────────────────────────────────────
        Q1           │  Q2           │  Q3           │  Q4
        FOUNDATION   │  DEPTH        │  RESPONSE     │  SCALE
        ────────────────────────────────────────────────────────────

PLATFORM
        ████ Data Plane ██│                           │               │
        ████ Triager v1 ██│                           │               │
        ████ Console v1  ██│                          │               │
             ◄────── MVP Exit ──────►                 │               │
                          │████ Investigator v1 ██   │               │
                          │████ Threat Graph v1  ██  │               │
                          │████ Hunter v1         █  │               │
                          │         ███ Connector SDK GA             │
                                         │████ Responder v1 ███      │
                                         │████ SOC Mgr Console       │
                                         │████ Custom Actions        │
                                                     │████ Exp-Response Loop
                                                     │████ On-Prem LLM
                                                     │████ Threat Graph v2

INTEGRATIONS
        ████ Tier 1 SIEMs (4) ███│                   │               │
        ████ Tier 1 EDRs (5)  ███│                   │               │
        ████ Tier 1 IDP (3)   ████                   │               │
        ████ Cyble Native     ████                   │               │
                              │████ Tier 2 (NDR, DLP, CASB, PAM)     │
                              │████ Tier 2 Vuln + Firewalls           │
                                              │████ SDK Marketplace ███
                                                     │████ 100+ community connectors

COMPLIANCE
        ████ SOC2 Type I prep ██│                    │               │
                              │████ SOC2 Type II audit period        │
                              │ ████ HIPAA BAA                       │
                                              │████ SOC2 Type II report
                                              │████ ISO 27001 audit
                                                     │████ FedRAMP prep

GTM
        ████ Closed beta (5 accounts) █│            │               │
                              │████ GA + MSSP program               │
                              │████ Integration marketplace v1       │
                                              │█████ New-logo pipeline NA + EU
                                                     │████ RSA 2027 prep
────────────────────────────────────────────────────────────────────────────────
ARR target:  $0 → $1M          $1M → $5M           $5M → $12M      $12M → $20M
```

---

## Q1: Foundation (Months 1–3) — MVP

### Mission
Ship a working Autonomous Tier-1 Triage product that closes 85%+ of simulated alerts with full evidence trails. Get 5 Cyble-attached accounts into production. Prove the core thesis before building depth.

### MVP Exit Criteria (Month 3 gate — all must pass)
- [ ] Triager Agent auto-closes ≥85% of labeled alert test set (1,000 alerts, curated across 4 alert types)
- [ ] False-close rate ≤2% on test set
- [ ] Median triage time ≤2 minutes (P99 ≤5 minutes)
- [ ] Full audit trail present for 100% of cases (tool calls, verdict, confidence, citations)
- [ ] HITL approval functional via Slack and Console (approved actions execute within 60s of click)
- [ ] 5 Tier 1 integrations connected per beta account on average
- [ ] 2+ beta accounts have run ≥100 production alerts each
- [ ] SOC 2 Type I audit engagement started (controls documented)
- [ ] Analyst NPS from beta accounts ≥40

### Engineering deliverables

**Month 1:**
- [ ] Platform infrastructure: EKS cluster, Kafka (MSK), S3 data lake, Elasticsearch hot tier
- [ ] OCSF normalization pipeline (Kafka consumer → schema enforcement → event store)
- [ ] Tool Registry: manifest storage, tenant allowlist enforcement, health monitoring
- [ ] Audit Store: S3 Object Lock setup, session record schema, write path
- [ ] Connector: Splunk Enterprise / Cloud (full Tier 1 capability)
- [ ] Connector: CrowdStrike Falcon (READ + WRITE-SIGNIFICANT with HITL gate)
- [ ] Connector: Okta (READ + WRITE-REVERSIBLE)
- [ ] Connector: Cyble CTI Feed (first-class native tool)
- [ ] Connector: VirusTotal Enterprise (fallback CTI)
- [ ] HITL Gateway: request routing, Slack delivery, Console approval modal

**Month 2:**
- [ ] Triager Agent v1: tool call sequence for Windows Process Anomaly, Identity Anomaly, Network Anomaly, Email Phishing (4 alert types)
- [ ] Evidence grounding check: verdict blocked if any claim lacks tool citation
- [ ] Confidence rubric implementation (evidence weight scoring, not LLM-stated)
- [ ] Analyst Console v1: case queue, evidence panel, HITL approval flow
- [ ] Case object schema: narrative, blast radius placeholder, MITRE ATT&CK placeholder, recommended actions
- [ ] Connector: Microsoft Sentinel (KQL-based query translation)
- [ ] Connector: Okta enhanced (login history, device context)
- [ ] Connector: Cyble Dark Web Monitor (credential exposure, C2 telemetry)
- [ ] Connector: AWS GuardDuty + CloudTrail
- [ ] Connector: Microsoft 365 Defender (email quarantine WRITE-REVERSIBLE)
- [ ] Beta onboarding: environment provisioning, first case simulation, alert library

**Month 3:**
- [ ] Triager Agent v1 tuning: confidence threshold calibration against beta feedback
- [ ] Analyst Console v1: trace view ("why did the agent do that?"), integration health panel
- [ ] Connector: Google Chronicle / SecOps
- [ ] Connector: SentinelOne (READ + WRITE-SIGNIFICANT)
- [ ] Connector: Microsoft Entra ID
- [ ] Connector: Jira Service Management (bidirectional)
- [ ] Connector: Slack (HITL delivery)
- [ ] Connector: Microsoft Teams (HITL delivery)
- [ ] SOC 2 Type I documentation: policies, controls, evidence collection process
- [ ] Alert simulation library v1: 1,000 labeled alerts across 10 alert types
- [ ] Connector SDK alpha: TypeScript, internal use only
- [ ] Performance testing: 10,000 alerts/hour throughput validation

### GTM deliverables

**Month 1:**
- [ ] Internal demo environment (sandbox mode, simulated alerts)
- [ ] Cyble AiSOC product page + waitlist (cyble.com/aisoc)
- [ ] Identify 10 Cyble-attached accounts for closed beta (5 to activate, 5 backup)
- [ ] POV runbook v1: prerequisites, Day 1 checklist, success criteria

**Month 2:**
- [ ] Closed beta kickoff: 3 accounts onboarded
- [ ] POV documentation: integration setup guides (Splunk, CrowdStrike, Okta, Cyble)
- [ ] Beta feedback loop: weekly check-in calls, feedback tracking in Linear

**Month 3:**
- [ ] Remaining 2 beta accounts onboarded
- [ ] First case studies drafted (with beta customer input)
- [ ] Pricing model finalized for GA
- [ ] MSSP partner program designed (terms, revenue share structure, co-branding)

### Headcount (Q1 targets)

| Role | Count | Priority |
|---|---|---|
| Agent Engineering Lead (LLM orchestration, tool grounding, evals) | 1 | Day 1 hire |
| Backend Engineer (data plane, API, connector runtime) | 2 | Day 1 hire |
| Frontend Engineer (Analyst Console) | 1 | Month 1 hire |
| Security Domain Advisor (ex-SOC analyst / threat intel) | 1 | Day 1 hire (part-time or consultant) |
| DevOps / Platform Engineer (EKS, Kafka, observability) | 1 | Month 1 hire |
| Product Manager | 1 | Day 1 (existing Cyble PM or new hire) |
| Solutions Engineer (beta customer support) | 1 | Month 2 hire |

---

## Q2: Depth (Months 4–6) — Investigation + MSSP Launch

### Mission
Add investigation depth to the platform. Launch publicly. Activate MSSP channel. Prove that the Investigator Agent produces case files analysts approve without major changes.

### Q2 Exit Criteria
- [ ] Investigator Agent: ≥80% case approval without major analyst changes (tracked via analyst feedback in Console)
- [ ] <15 minute median investigation time
- [ ] MITRE ATT&CK mapping present in 100% of escalated cases
- [ ] General availability: any account can sign up and be live in <10 minutes
- [ ] Tier 1 integrations complete (all SIEM × EDR × IDP × Cloud × Email × Ticketing × Comms)
- [ ] MSSP partner program active: 5 MSSP partners signed
- [ ] ARR target: $5M (Cyble-attached accounts + MSSP)
- [ ] HIPAA BAA available (healthcare vertical opening)
- [ ] EU data residency live (Frankfurt region)

### Engineering deliverables

**Month 4:**
- [ ] Investigator Agent v1: multi-step investigation plan construction, tool sequence execution
- [ ] Case narrative generation: structured narrative with evidence citations
- [ ] Blast radius assessment: affected assets, lateral movement detection
- [ ] MITRE ATT&CK auto-mapping (technique matching from tool outputs)
- [ ] Threat Graph v1: Neo4j / Neptune, entity schema (user, host, IP, domain, hash, campaign, threat actor)
- [ ] Episodic case memory: Qdrant vector index, similar-case retrieval
- [ ] Connector: Elastic Security / SIEM
- [ ] Connector: Microsoft Defender for Endpoint
- [ ] Connector: Google Cloud Security Command Center

**Month 5:**
- [ ] Investigator Agent v1 tuning: campaign attribution, confidence calibration, dissenting hypotheses generation
- [ ] Case Console updates: blast radius map visualization, ATT&CK tactic chain display, "Ask the agent" panel
- [ ] Analyst feedback loop: case approval, rejection with reason, false-close tagging — feeds back to confidence calibration
- [ ] Hunter Agent v1: Cyble brand intel (typosquatting, fake apps), Cyble ASM (new exposures), proactive case creation
- [ ] Connector: Carbon Black Enterprise
- [ ] Connector: Cortex XDR
- [ ] Connector: Ping Identity
- [ ] Connector: Google Workspace (email security)
- [ ] Connector: ServiceNow ITSM
- [ ] Connector: PagerDuty
- [ ] Connector SDK beta: TypeScript + Python, external developer access (10 MSSP partners)
- [ ] EU data residency: Frankfurt region deployment
- [ ] HIPAA BAA legal documentation, PHI handling review

**Month 6:**
- [ ] Public launch infrastructure: multi-region GA, load tested at 50 concurrent tenants
- [ ] Integration marketplace v1: all Tier 1 connectors published, install flow via Console
- [ ] Connector: Cyble Vuln Intel (CVE-to-asset matching)
- [ ] Connector: Cyble Threat Actor Profiles (APT context for Investigator)
- [ ] Connector: MISP (customer self-hosted)
- [ ] Connector: Abuse.ch / URLhaus / MalwareBazaar
- [ ] SOC 2 Type II audit period begins (6-month observation period)
- [ ] MSSP Console: co-branded view, multi-tenant management, MSSP-tier isolation

### GTM deliverables

**Month 4:**
- [ ] GA announcement strategy: launch blog, product video, demo environment
- [ ] Beta customer case studies published (2+)
- [ ] Pricing page live on cyble.com/aisoc

**Month 5:**
- [ ] General availability launch
- [ ] MSSP partner program go-live: 5 signed MSPs with at least 1 customer each
- [ ] APJ + India sales motion: leveraging Cyble's regional team and relationships
- [ ] Joint webinar with first beta customer: "How we auto-closed 87% of Tier-1 alerts in 30 days"

**Month 6:**
- [ ] Conference presence: Black Hat Asia / AVASEC / local APJ events
- [ ] Analyst relations: Gartner, Forrester briefings scheduled
- [ ] AiSOC product positioned in Cyble's main website nav and category pages
- [ ] MSSP program ARR: first $1M from MSSP channel

---

## Q3: Response (Months 7–9) — SOAR Replacement + SDK GA

### Mission
Ship the Responder Agent. Position the platform as a SOAR replacement. SDK becomes GA and the community connector marketplace grows. SOC2 Type II report issued.

### Q3 Exit Criteria
- [ ] Responder Agent: top 20 response action types functional without playbook authoring
- [ ] 0 DESTRUCTIVE actions executed without multi-person approval in any production tenant
- [ ] Reversibility classification enforced at HITL Gateway (policy-as-code, not prompt)
- [ ] Custom action authoring: natural language → reviewed action spec, end-to-end
- [ ] SOC Manager command center live with queue health, agent-vs-human mix, false-close rate
- [ ] Connector SDK GA: TypeScript + Python, public documentation, community marketplace with 20+ connectors
- [ ] SOC 2 Type II report issued (early in Q3 if 6-month audit period started in Month 6)
- [ ] ARR target: $12M

### Engineering deliverables

**Month 7:**
- [ ] Responder Agent v1: reversibility classification enforcement, action sequencing, edge case reasoning
- [ ] HITL Gateway v2: multi-person approval for DESTRUCTIVE actions, SLA enforcement, on-call escalation
- [ ] Response action library: top 20 actions across EDR, IDP, Firewall, Cloud, Email
- [ ] Pre-execution check: asset criticality validation before every WRITE action
- [ ] Response audit log: every action logged with agent rationale + tool call outputs
- [ ] Connector: Palo Alto NGFW (firewall block/unblock)
- [ ] Connector: Fortinet FortiGate (firewall block)
- [ ] Tier 2 connectors: Darktrace, Tenable.io, Qualys, CyberArk

**Month 8:**
- [ ] Custom action authoring: natural language → action spec → YAML review → version control → deploy
- [ ] Agent A/B harness: route X% of alerts to alternative prompt config, compare distributions
- [ ] Connector SDK GA: full documentation, versioning, public marketplace
- [ ] Marketplace community review SLA: 48 hours
- [ ] SOC Manager command center: queue health, agent-vs-human mix, integration health, false-close rate, Cyble exposure digest
- [ ] Connector: SentinelOne enhanced (network quarantine)
- [ ] Connector: Microsoft Defender for Endpoint enhanced (block hash, isolate machine)
- [ ] Tier 2 connectors: Rapid7, Netskope, CyberArk, BeyondTrust

**Month 9:**
- [ ] Response agent tuning: edge case library, customer-reported exceptions, policy override flows
- [ ] Agent observability: trace view for Responder sessions, action timeline visualization
- [ ] Connector: IBM QRadar (community SDK, MSSP partner authored)
- [ ] Connector: LogRhythm (community SDK)
- [ ] SOC 2 Type II report issued
- [ ] FedRAMP Moderate preparation: readiness assessment, CSP selection, documentation start
- [ ] ISO 27001 audit engagement initiated

### GTM deliverables

**Month 7:**
- [ ] "Replace your SOAR" campaign launch: positioning vs the incumbent no-code SOAR/automation platforms
- [ ] Sales play: "playbook fatigue" — no-code SOAR customer displacement motion
- [ ] Target list: 200 no-code SOAR accounts (via contact data + partner intelligence)

**Month 8:**
- [ ] New-logo pipeline development: North America enterprise (1,000–5,000 employees, no SOAR)
- [ ] Europe pipeline: UK, Germany, Netherlands, Nordics — ISO 27001 compliance angle
- [ ] First Gartner MQ / Cool Vendor inclusion (application submitted)
- [ ] Customer case study: "How Cyble AiSOC replaced our SOAR and cut response time by 80%"

**Month 9:**
- [ ] ARR review: $12M target assessment. Accelerate if behind; assess hiring plan if ahead.
- [ ] Partner channel expansion: VARs and system integrators in North America + Europe
- [ ] SDR / AE team expansion for new-logo motion

---

## Q4: Scale (Months 10–12) — Exposure-to-Response + Platform Scale

### Mission
Complete the Exposure-to-Response loop. Prepare for RSA Conference 2027. Reach $20M ARR. Activate FedRAMP pathway. Make the Threat Graph the compounding flywheel it needs to be.

### Q4 Exit Criteria
- [ ] Exposure-to-Response Loop: dark-web + brand + ASM signals → proactive case → Responder action, end-to-end in production
- [ ] Threat Graph v2: campaign correlation, ATT&CK enrichment, MTTR for repeat patterns ≤60% of first-occurrence
- [ ] On-premises LLM option available (LLaMA 3.3 70B, customer-managed)
- [ ] ISO 27001 certificate issued
- [ ] 5 vertical detection packs published in marketplace
- [ ] ARR target: $20M
- [ ] RSA Conference 2027 presence confirmed + demo ready

### Engineering deliverables

**Month 10:**
- [ ] Exposure-to-Response Loop: Hunter Agent → proactive case → HITL (if needed) → Responder action
- [ ] Cyble feed subscription model: configurable signal types per tenant, alert routing rules
- [ ] Proactive case console view: separate from reactive alert queue, exposure dashboard
- [ ] Threat Graph v2: inter-case entity linking, campaign graph construction, ATT&CK node enrichment
- [ ] Threat Graph query interface (developer): graph traversal API for custom hunter queries
- [ ] Connector: Wiz (CSPM integration for exposure correlation)
- [ ] Connector: Orca Security
- [ ] Vertical pack: FinServ (Sigma rules + detection KB + case templates)
- [ ] Vertical pack: Healthcare (HIPAA breach patterns + medical device anomalies)

**Month 11:**
- [ ] On-premises LLM option: LLaMA 3.3 70B via Ollama, customer-managed deployment, air-gapped compatible
- [ ] Reporter Agent enhanced: executive incident summaries, board-ready language, compliance evidence packages
- [ ] Connector: OT/ICS integration (Claroty or Dragos — community SDK + internal build for manufacturing vertical)
- [ ] Vertical pack: Retail (POS compromise, loyalty fraud)
- [ ] Vertical pack: Manufacturing (IT/OT, ICS protocol)
- [ ] Vertical pack: Public Sector (APT patterns, supply chain)
- [ ] ISO 27001 audit evidence collection complete
- [ ] FedRAMP: documentation package v1, SSP drafted

**Month 12:**
- [ ] Platform hardening: load testing at 200 concurrent tenants, chaos engineering, DR drill
- [ ] ISO 27001 certificate issued (if audit engagement started Month 9)
- [ ] FedRAMP Moderate: ATO package submitted to 3PAO
- [ ] Auto-connector generation from OpenAPI/Swagger specs (early access)
- [ ] RSA Conference 2027 demo build: live platform demonstration, customer stories ready
- [ ] Year 1 retrospective: false-close rate trend, MTTR improvement data, analyst NPS tracking
- [ ] Roadmap v2: Year 2 planning (UEBA, MDR-as-a-service offering, Threat Hunt platform)

### GTM deliverables

**Month 10:**
- [ ] Exposure-to-Response launch: "From dark web to response in under 4 hours" campaign
- [ ] Cyble joint marketing: unified story across CTI + ASM + AiSOC
- [ ] FedRAMP pathway announced: public sector + DOD contractor pipeline activation

**Month 11:**
- [ ] ARR tracking: $20M target in sight
- [ ] Enterprise contract templates: multi-year EAs with outcome-based pricing tiers
- [ ] Partner co-sell: Cyble + top 5 MSSP partners co-selling into enterprise accounts

**Month 12:**
- [ ] RSA Conference 2027: booth + speaking slot + customer story presentations
- [ ] $20M ARR achieved (or tracking clear path to Q1 Year 2)
- [ ] Gartner Magic Quadrant inclusion application (Security Automation / SOC Platforms)
- [ ] Year 2 board deck: platform vision, TAM expansion, Series A/growth round positioning

---

## Engineering Velocity Tracking

### Sprint structure
- 2-week sprints
- Sprint review every other Monday (demos only — working software)
- Roadmap checkpoint: quarterly (CEO + Engineering + Product)
- OKRs set quarterly, reviewed monthly

### Key milestones vs. calendar

| Milestone | Target date | Hard deadline? | Risk |
|---|---|---|---|
| MVP internal demo | Week 6 | No | Triager quality risk |
| First beta account live | Month 2, Week 3 | No | Integration setup time |
| MVP exit criteria met | End of Month 3 | Yes (unblock Q2 scope) | False-close rate calibration |
| Investigator GA | Month 5 | No | Investigation depth quality |
| Public GA launch | Month 6 | Yes (MSSP program depends on it) | Infrastructure readiness |
| SOC 2 Type II report | Month 9 | Yes (blocks enterprise contracts) | Audit engagement timing |
| Responder GA | Month 8 | No | Edge case coverage |
| SDK GA | Month 9 | No (SDK beta available earlier) | Documentation quality |
| ISO 27001 | Month 12 | No (Month 11 would be better) | Audit engagement initiation timing |
| $20M ARR | Month 12 | Target (not hard engineering deadline) | Sales cycle length in NA/EU |

### Engineering team size by quarter

| Quarter | Eng headcount target | Key additions |
|---|---|---|
| Q1 (start) | 7 | Agent Eng Lead, 2 Backend, 1 Frontend, 1 Security Domain, 1 DevOps, 1 PM |
| Q1 (end) | 10 | +1 Backend (integration velocity), +1 Solutions Eng, +1 QA/Eval Engineer |
| Q2 (end) | 15 | +2 Backend, +1 Frontend, +1 Security Research (Cyble team embed), +1 DevOps |
| Q3 (end) | 20 | +2 Backend, +1 Agent Eng (Responder), +1 DevRel (SDK), +1 Security Domain |
| Q4 (end) | 25 | +2 Backend, +1 Agent Eng (Hunter/Graph), +1 Frontend, +1 DevOps/SRE |

---

## ARR Milestone Assumptions

| Quarter end | ARR target | Source |
|---|---|---|
| Q1 | $1M | 5 beta accounts × $200K avg ACV (pilot pricing) |
| Q2 | $5M | 5 beta + 15 GA accounts (Cyble-attached + MSSP first customers) |
| Q3 | $12M | 40 accounts × $300K avg ACV (mix of expansion + new-logo) |
| Q4 | $20M | 60 accounts × $333K avg ACV (expansion + SOAR displacement deals) |

**ACV composition assumptions:**
- Cyble-attached accounts: $150K–$300K ACV (add-on to existing Cyble contracts)
- New-logo enterprise: $300K–$600K ACV (full platform + CTI bundle)
- MSSP per-partner: $100K–$500K depending on customer count under management

---

*See also: [agent-topology.md](../architecture/agent-topology.md) | [integration-matrix.md](../architecture/integration-matrix.md) | [../cyble-aisoc-plan.md](../cyble-aisoc-plan.md)*
