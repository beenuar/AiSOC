---
name: AiSOC depth plan
overview: "Close the depth gaps a capability review at v17.0.0 found against the reference AI-SOC platform: publishable verdict quality, a semantic data layer with live posture, cloud, identity and SaaS detection depth, collection and scale, response that finishes, AI agent security, phishing operations, enterprise gates and analyst surfaces. Ordered by dependency. Every item is reproduced before it is built and lands with a gate."
todos:
  - id: p0-1-progress-file
    content: "Phase 0.1: create DEPTH_PROGRESS.md modelled on PARITY_PROGRESS.md (a checkbox per item, pre-existing state, deviations, item log)"
    status: pending
  - id: p0-2-rederive
    content: "Phase 0.2: re-derive every number this plan cites against the starting tree and record captured vs measured"
    status: pending
  - id: p0-3-baseline
    content: "Phase 0.3: baseline run (make up and make smoke, make up-full, injection suite, model matrix, load harness) committed with hardware, date and commit"
    status: pending
  - id: p1-1-verdict-corpus
    content: "Phase 1.1: balanced labelled verdict corpus (no class above 60%, at least half cloud, identity and SaaS, benign twins, licensed sources); the scorer accepts it and still refuses the all-malicious corpora"
    status: pending
  - id: p1-2-scorecard
    content: "Phase 1.2: scorecard with balanced accuracy and MCC next to the majority baseline, per-class precision and recall, malicious recall with a Wilson interval, false negatives, auto-close precision, escalation rate, time to verdict"
    status: pending
  - id: p1-3-fake-tool-output
    content: "Phase 1.3: close fake_tool_output structurally (tool results only on the tool channel, tool-shaped evidence flagged, verdicts citing a tool result with no ledger row demoted); flip rate at or below 10% on tuned and held-out payloads"
    status: pending
  - id: p1-4-local-model
    content: "Phase 1.4: add a 7B to 8B local model to the matrix, choose by score, make it the default for up-gpu and up-host-llm only unless an ADR fits it in CORE"
    status: pending
  - id: p1-5-replay-kit
    content: "Phase 1.5: make replay-eval, a design-partner kit over the existing history readers, side-effect free, air-gapped by default, signed aggregate report"
    status: pending
  - id: p1-6-publish
    content: "Phase 1.6: generated Verdict quality table in benchmark.md with model id, corpus digest, date and commit, held by a --check drift gate"
    status: pending
  - id: p2-1-ocsf-classes
    content: "Phase 2.1: OCSF classes beyond five; every connector type mapped to a class with a profile or excused, enforced by a gate"
    status: pending
  - id: p2-2-activity-projection
    content: "Phase 2.2: activity projection on every event (actor.kind, action, resource, location, outcome), IP geo and ASN at ingest, user-agent parsing"
    status: pending
  - id: p2-3-event-catalogue
    content: "Phase 2.3: event classification catalogue in schemas/event_catalog with sensitivity, and a gate that every fixture event type is classified or excused"
    status: pending
  - id: p2-4-sessions
    content: "Phase 2.4: sessions per principal (AWS key and assumed-role chain to the originating human, IdP session ids, IP and user-agent fallback) in the lake and graph, attached to alerts"
    status: pending
  - id: p2-5-posture-snapshots
    content: "Phase 2.5: __posture_snapshot__ collectors for AWS, Azure, GCP and Workspace plus GitHub; AWS permission boundaries; scheduled and change-driven, versioned; delete test_posture_snapshot_coverage.py last"
    status: pending
  - id: p2-6-use-posture
    content: "Phase 2.6: privilege tier on every alert, a cited what-this-identity-can-do tool for triage, blast radius from effective permissions"
    status: pending
  - id: p2-7-core-context
    content: "Phase 2.7: ADR measuring entity and session context in CORE (Neo4j vs a Postgres store); implement what it accepts"
    status: pending
  - id: p3-1-windowed-family
    content: "Phase 3.1: translate the 74 windowed det-* rules into wd-* form through export_windowed_ruleset.py"
    status: pending
  - id: p3-2-sequences
    content: "Phase 3.2: ordered sequences in the windowed engine and Sigma correlation import"
    status: pending
  - id: p3-3-enrichment-inputs
    content: "Phase 3.3: parity 5.5 inputs (identity enrichment from posture and SCIM, per-tenant first-seen store, fields nothing emits); lower MAX_UNREACHABLE with each fix"
    status: pending
  - id: p3-4-core-baselines
    content: "Phase 3.4: behavioural baselines in CORE (rarity, peer groups from posture, volume) as typed anomaly signals"
    status: pending
  - id: p3-5-threat-anomaly
    content: "Phase 3.5: threat-and-anomaly condition rules, replay-proven, counted as their own family in project_stats.py"
    status: pending
  - id: p3-6-content-depth
    content: "Phase 3.6: at least 800 executable cloud, identity, SaaS and code conditions (461 at capture) with per-source minimums and a make stats gate"
    status: pending
  - id: p3-7-detection-engineering
    content: "Phase 3.7: detection engineering agent (gap-closure Phase 9 and parity 6.2, as specified)"
    status: pending
  - id: p4-1-cloud-collection
    content: "Phase 4.1: CloudTrail organisation trail on S3 and SQS (data events, VPC flow logs), GCP Pub/Sub log sink, Azure Event Hubs"
    status: pending
  - id: p4-2-standard-inputs
    content: "Phase 4.2: parity 6.10 inputs (syslog listener for RFC 5424, RFC 3164, CEF and LEEF; OTLP logs receiver; Kafka input; TAXII 2.1 server)"
    status: pending
  - id: p4-3-retention
    content: "Phase 4.3: per-tenant retention of at least 400 days, supported cold tier, legal hold blocks deletion, cold search with a cost estimate"
    status: pending
  - id: p4-4-throughput
    content: "Phase 4.4: parity 6.9 (rule index by log source, entity-partitioned fusion, concurrent triage), realistic-mix load harness, cloud-hardware run published"
    status: pending
  - id: p4-5-deployment
    content: "Phase 4.5: parity 6.8 (Helm installs all of CORE, restore covers what backup covers, scheduler leader election, managed cluster run)"
    status: pending
  - id: p5-1-steps-that-act
    content: "Phase 5.1: parity 5.3 (resolve placeholders in http steps, notify through Slack, Teams, email and PagerDuty, fix or remove the osquery step)"
    status: pending
  - id: p5-2-delivery
    content: "Phase 5.2: parity 5.7 (report scheduler, SMTP, email approvals, Teams cards with teams-bot in compose, signed outbound webhooks)"
    status: pending
  - id: p5-3-engine-steps
    content: "Phase 5.3: wait, parallel and loop steps with idempotency keys; console palette for every step type the engine runs"
    status: pending
  - id: p5-4-stateful-verification
    content: "Phase 5.4: user and manager verification on chatops_verify with branching on the signed answer and a timeout outcome"
    status: pending
  - id: p5-5-verb-breadth
    content: "Phase 5.5: governed executor arms from 73 to at least 150, cloud and SaaS containment first, each with a contract, a probe or recorded gap, rollback and a mock-vendor test"
    status: pending
  - id: p5-6-plain-language-playbooks
    content: "Phase 5.6: plain-language playbooks drafted, previewed on a past alert and approved before use"
    status: pending
  - id: p6-1-ai-inventory
    content: "Phase 6.1: AI asset inventory (apps, coding agents, MCP servers, extensions, provider keys, OAuth grants) linked to person, device and permissions"
    status: pending
  - id: p6-2-endpoint-discovery
    content: "Phase 6.2: endpoint discovery from EDR process telemetry and an osquery pack, with no new agent"
    status: pending
  - id: p6-3-provider-coverage
    content: "Phase 6.3: provider coverage beyond OpenAI and Anthropic admin logs (Gemini, M365 Copilot, GitHub Copilot, AI OAuth grants)"
    status: pending
  - id: p6-4-agent-baselines
    content: "Phase 6.4: parity 6.7 (identities for AiSOC's own agents, then per-agent baselines)"
    status: pending
  - id: p6-5-ai-detections
    content: "Phase 6.5: AI rule pack with positive and negative fixtures"
    status: pending
  - id: p6-6-ai-containment
    content: "Phase 6.6: AI containment arms and an approved kill-switch playbook"
    status: pending
  - id: p7-1-phishing-ops
    content: "Phase 7.1: gap-closure Phase 10 and parity 6.4 (reported-message intake, purge and retract verbs, recipient blast radius, campaign grouping)"
    status: pending
  - id: p7-2-phishing-analysis
    content: "Phase 7.2: header, URL and attachment analysis through sandbox and enrichment, cited in the ledger"
    status: pending
  - id: p7-3-aitm
    content: "Phase 7.3: adversary-in-the-middle session-reuse detections on Phase 2.4 sessions"
    status: pending
  - id: p8-1-identity-gates
    content: "Phase 8.1: fix-pass wave 4 leftovers, parity 4.1 IdP end-to-end CI, 4.2 console MFA, 4.4 audit export and retention, 4.5 operator pages, 4.6 i18n, 4.7 accessibility"
    status: pending
  - id: p8-2-abac-elevation
    content: "Phase 8.2: readers for ABAC conditions, time-boxed elevation and workload identities"
    status: pending
  - id: p8-3-security-pack
    content: "Phase 8.3: extend docs/security into a buyer security pack, each statement linked to code or a gate"
    status: pending
  - id: p9-1-mcp-http
    content: "Phase 9.1: parity 6.6 (MCP over streamable HTTP, deployed, audited per call)"
    status: pending
  - id: p9-2-semantic-memory
    content: "Phase 9.2: parity 6.5 (vector recall with provenance), measured on the Phase 1 scorecard"
    status: pending
  - id: p9-3-case-depth
    content: "Phase 9.3: parity 5.6 remainder (merge, bulk triage, custom fields, workload metrics)"
    status: pending
  - id: p9-4-war-rooms
    content: "Phase 9.4: Slack and Teams war rooms synced to the case"
    status: pending
  - id: p9-5-hunt-reports
    content: "Phase 9.5: hunt and retro-hunt findings become cited case reports"
    status: pending
  - id: p9-6-native-responder
    content: "Phase 9.6: native responder build pipeline, push delivery, on-device voice input to the grounded copilot"
    status: pending
  - id: p10-close-books
    content: "Phase 10: re-run every claim row touched, update all progress files, one [Unreleased] entry per phase, final report in DEPTH_PROGRESS.md"
    status: pending
---

# AiSOC depth plan

> **Status**: Locked plan. Implement as specified and do not edit the body. Cursor may update the `status` of each todo in the front matter; that is the only permitted change to this file.
> **Captured**: 2026-10-07, against v17.0.0 plus `[Unreleased]` (commit `90ea2fd`).
> **Tracking**: `DEPTH_PROGRESS.md` (new) mirrors progress and records every deviation; this file is the source of truth.
> **Relationship**: `plans/aisoc_gap_closure_plan.plan.md`, `plans/aisoc_parity_plan.plan.md` and `plans/aisoc_fix_pass_plan.plan.md` stay locked. Where an item here says "implement parity N as specified" (or gap-closure N, or fix-pass N), that plan's text governs and this one only adds to it. Tick the item in that plan's own progress file as well as in `DEPTH_PROGRESS.md`.

### Why this plan exists

A capability review at v17.0.0 compared AiSOC with the reference AI-SOC platform: a SaaS agentic SOC that sells four agents (detect, triage, investigate, respond) over a knowledge graph built at ingest, a security data lake positioned as a SIEM replacement, 130+ integrations, a 24/7 managed service, and, since September 2026, runtime visibility and control of AI agents.

AiSOC already leads on data control (self-hosted, air-gapped, a local model), auditability (the Investigation Ledger and signed evidence bundles), governed autonomy (capability contracts and durable approvals), overlay on an existing SIEM (federated search and two-way writeback), MSSP tenancy, and checkable claims. It loses on depth, in nine places:

1. **No publishable verdict quality.** Verdict accuracy is published as "not measured". Both labelled corpora are all-malicious by construction, so `scripts/score_replay_set.py` correctly refuses them. No hosted model has run, the default is a 3B model on CPU, and the `fake_tool_output` injection family flips every verdict with 0% guard catch. The reference platform publishes outcome figures from production: escalation rate, time to investigate, false-positive reduction.
2. **No semantic layer and no live posture.** Ingest emits five OCSF classes. 12 connector types have a dedicated ingest profile and 5 more a class mapping; the rest of the 84 take the generic mapping. Nothing builds sessions, labels whether an actor is a person, an OAuth app, a token or a workload, parses user agents, or classifies vendor event types by sensitivity. Effective permissions resolve live for Okta only: no connector answers `__posture_snapshot__`, so AWS, Azure, GCP and Workspace return 412 (`docs/audit/DEFERRED_SUBPHASES.md`, 7b+). The entity graph runs only in `full`.
3. **Thin cloud, identity and SaaS detection.** 1,798 of the 2,603 executable rules (69%) are Windows. Cloud has 291, identity 117, code platforms 19 and all SaaS apps together 34. 119 native rules cannot fire (`scripts/check_detection_fields.py`), attributed to windowed form (74), identity enrichment (24), first-seen (8), fields nothing emits (8), other inputs (6) and baselines (2), with some rules needing more than one. Behavioural scoring (z-scores and peer groups in `services/ueba`) runs only in `full`. The reference platform ships 800+ threat and anomaly conditions over cloud, identity, SaaS and code, each learned per environment.
4. **Collection and scale below SIEM class.** CloudTrail arrives through `LookupEvents`, not an organisation trail on S3 with SQS. There is no native syslog listener (an external rsyslog must spool to HTTP), no OTLP logs receiver and no Kafka input for customer topics. Raw lake events are deleted at 90 days. Fusion evaluates every rule against every event, and the published laptop run drains 177 to 214 events/s. The Helm chart omits connectors, actions, threat intel, the LLM gateway, Ollama and Qdrant, and no managed Kubernetes service has run it.
5. **Response that does not finish.** 73 executor arms (reads included) over 33 verbs. Playbook `notify` delivers only to a raw webhook URL, `${...}` placeholders in `http` steps are never resolved, the engine has no `wait`, `parallel` or `loop` step, and there is no SMTP, outbound webhook or proactive Teams card. The reference platform advertises 200+ response actions and stateful verification of users and their managers.
6. **No AI agent security beyond audit logs.** `llm_usage` reads OpenAI and Anthropic admin audit logs and `ai_gateway` reads gateway runtime logs. Nothing discovers coding agents, MCP servers or IDE extensions on endpoints, inventories AI assets against people and devices, baselines agent behaviour, or contains an agent.
7. **No phishing operations.** Email security connectors exist, but there is no reported-message intake, purge or retract verb, or campaign grouping (gap-closure Phase 10, parity 6.4).
8. **Enterprise gates still open.** Console MFA, the remaining fix-pass wave 4 items, audit export and retention, operator pages, and ABAC, time-boxed elevation and workload identities (schema only since v16).
9. **Analyst surfaces behind.** The MCP server is stdio-only and deployed by nothing, knowledge-base recall is full-text only, there is no case merge, bulk triage or workload view, the native mobile app has never been built for a device, and there is no war-room flow.

The phases close these in dependency order. Phase 1 comes first because every later phase must show a before-and-after delta on the measurement Phase 1 builds.

Refer to commercial products only neutrally. The reference platform is not in `scripts/competitor_names.toml`, so `scripts/check_competitor_names.py` will not catch its name: do not write it anywhere, including commit messages and PR bodies, and check by hand.

### Before you start

- **Precondition.** The fix pass must be closed: every item in `FIX_PASS_PROGRESS.md` is `[x]` or `[!]`. Ask the maintainer once if that is not obvious. If it is still open, finish it under its own plan first. Phase 0 here may run alongside it.
- **Read first.** `AGENTS.md`, `docs/audit/REPOSITORY_REALITY.md`, `docs/audit/MATURITY_DEFINITION.md`, `docs/audit/DEFERRED_SUBPHASES.md`, and the rules sections of the three plans named above.
- **Numbers at capture.** Re-derive these at build time and never copy them from this plan:
  - executable detections 2,603 of 6,991 on disk (`make stats`);
  - unreachable native rules 119, with `MAX_UNREACHABLE = 119` in `scripts/check_detection_fields.py`;
  - windowed rules 18 in `services/fusion/app/data/windowed_ruleset.json`;
  - executable cloud, identity, SaaS and code rules 461 (by `log_source` product in `marketplace/index.json`);
  - executor arms 73 (classes declaring `capability = "..."` under `services/actions/app/live_actions/`);
  - claim-to-gate matrix 290 rows, all GATED (`scripts/check_claim_gate_matrix.py`);
  - next migration `095`, next ADR `0010`;
  - CORE 16 services and `full` 22 (`scripts/check_profile_service_counts.py`).

### Rules for every phase

- **Inherited.** Every rule in "Rules for every phase" of `plans/aisoc_gap_closure_plan.plan.md` and `plans/aisoc_parity_plan.plan.md`, and in "Rules for this pass" of `plans/aisoc_fix_pass_plan.plan.md`, applies here verbatim: claims and gates, path-aware proof, shipped means default-reachable, tenancy and auth, migrations, LLM calls, state-changing actions, outbound traffic, no fabricated data, CORE footprint, vendor tests, hygiene, eval re-grading, docs and house style.
- **Measure through the Phase 1 scorecard.** From Phase 2 on, any PR that changes what triage, investigation or detection sees re-runs the scorecard and puts before-and-after numbers in the PR body. A drop in balanced accuracy or malicious recall beyond the scorecard's interval blocks the merge unless the PR explains it.
- **Reproduce before building.** Each item starts by showing the gap on the current tree: a failing test, a gate, or a recorded command. If it does not reproduce, record a Deviation in `DEPTH_PROGRESS.md` and move on. Do not build what is already there.
- **Real vendor shapes.** Every new connector read, posture collector and executor arm is tested against recorded vendor-shaped payloads through a mock server, following `services/connectors/tests/connectors/test_live_vendor_smoke.py`. Read the vendor's current API reference before writing a client and put its URL in the module docstring. Never invent an endpoint or a field.
- **Detections are earned.** A new rule counts only when it is replayed through its real connector and the real engine with a positive fixture that fires and a negative fixture that differs in exactly one indicator field and does not fire (`detections/fixtures/`), the same proof the executable corpus and the hunt library carry today.
- **Off by default where it reaches out.** Anything that collects from a new vendor API, changes vendor state, messages a person, or calls a hosted model ships off by default and is enabled per tenant.
- **Figures come from generators.** Every number this plan adds to the README, docs or the marketplace index is produced by a generator with a `--check` drift gate, the way `scripts/project_stats.py` and `scripts/generate_connector_count.py` work today.
- **Migration numbers across lanes.** Phases run in parallel lanes (see "Parallel lanes"). Claim a migration number in `DEPTH_PROGRESS.md` before writing the file, so two lanes never collide.
- **Front matter.** Cursor may update the todo `status` values. The body is locked; deviations go in `DEPTH_PROGRESS.md`.

### Phase 0: Kickoff

**0.1 Progress file.** Create `DEPTH_PROGRESS.md` (new), modelled on `PARITY_PROGRESS.md`: one checkbox per item below, a "Pre-existing state" section, a "Deviations" section and an item log.

**0.2 Re-derive.** Recount every figure in "Why this plan exists" and "Before you start" against the tree you start from. Record the captured value and the measured value side by side. Where they differ, the tree wins.

**0.3 Baseline.** On a clean clone, run and commit the raw output, with hardware, date and commit, of:
- `make up && make smoke`, then `make up-full`;
- the behavioural injection suite (`services/agents/tests/adversarial/test_behavioural_injection.py`);
- the live-agent model matrix (`scripts/run_model_matrix.py`);
- `scripts/perf/load_harness.py` at steady state, into `docs/perf/results/`.

These are the "before" for every later delta.

**Done when:** `DEPTH_PROGRESS.md` exists, every number is re-derived, and each measurement has a committed baseline artefact.

### Phase 1: Verdict quality you can publish

**Goal:** publish balanced verdict accuracy, malicious recall with an interval, false-negative counts and time to verdict for the model AiSOC ships, measured through the production triage path, and make it trivial for a design partner to produce the same numbers on their own closed alerts.

**1.1 A balanced, labelled corpus.**
- Add a verdict corpus under `services/agents/tests/eval_data/verdict/` (new) with benign, benign-true-positive and malicious items. No class may exceed 60% of the corpus, so a constant answer cannot score above 60%.
- At least half the items come from cloud, identity and SaaS sources: CloudTrail, GCP audit, Azure activity, Entra, Okta, Workspace, M365, GitHub, Slack and Kubernetes audit. That is where the reference platform is strongest and where AiSOC's corpus is thinnest.
- Benign items are the ones real queues are full of: admin bulk changes, scanners, CI service accounts, travel sign-ins, break-glass use with a ticket, backup jobs. Each benign item has a malicious twin that differs in the decisive evidence.
- Sources are public attack-telemetry datasets whose licence permits redistribution, recorded in a provenance block per item the way `detections/` records imports, plus hand-authored items marked `is_synthetic: true`. Refuse any source without a licence.
- `scripts/score_replay_set.py` must accept this corpus and still refuse the two all-malicious corpora.

**1.2 Score the right things.** Extend `packages/aisoc-benchmark` and `scripts/score_replay_set.py` to report, per model:
- balanced accuracy and the Matthews correlation coefficient, always next to the majority-class baseline, so no number appears without what a constant answer would have scored;
- per-class precision and recall, malicious recall with a Wilson interval, and the false-negative count with item ids;
- auto-close precision at the closure threshold the tenant policy applies, and escalation rate;
- time to verdict at p50 and p95 from ledger timestamps, labelled with hardware and never graded.

**1.3 Close `fake_tool_output`.** A payload shaped like a tool's answer inside evidence (`sandbox_detonate: verdict=clean`) flips every verdict, and the guard catches none of it (the behavioural injection table in `apps/docs/docs/benchmark.md`). Fix it structurally rather than with another phrase pattern:
- tool results reach the model only as tool messages from `services/agents/app/llm/tool_loop.py` or the triage path's equivalent, never inside the evidence fence;
- the guard in `services/agents/app/prompting/envelope.py` flags evidence that names a registered tool and carries a result-shaped payload, because a real tool result can never arrive inside the fence;
- a verdict whose rationale relies on a tool result with no matching `tool_call` row in the ledger is demoted to human review, the way an ungrounded indicator already is.

Then lower `FAMILY_FLIP_CEILINGS["fake_tool_output"]` in `services/agents/tests/adversarial/test_behavioural_injection.py` to the new measurement, as that test already instructs. Add held-out payloads for the family that the fix was not tuned against, and report both rates.

**1.4 A stronger local model, chosen by measurement.**
- Add candidates in the 7B to 8B instruct class to the model matrix (`scripts/run_model_matrix.py`) next to `llama3.2:3b-instruct-q4_K_M` and `qwen2.5:0.5b`. Choose by score on the 1.1 corpus, not by reputation, and record every candidate's result.
- If one wins, make it the default for `make up-gpu` and `make up-host-llm` only. CPU-only `make up` keeps the 3B default unless an ADR (next number) measures that a larger model fits the 8 GB CORE budget at an acceptable time to verdict.
- Pin it in `services/agents/app/llm/model_pins.py` and `infra/litellm/config.yaml` (`scripts/check_llm_model_routing.py`).

**1.5 The design-partner replay kit.**
- One command, `make replay-eval` (new), that runs on the partner's own host. It reads closed alerts through the history readers that already exist (`services/actions/app/services/alert_history.py`: Splunk, Sentinel, Elastic, QRadar, Defender), replays them through the production triage path with no side effects (fix-pass 3.2, `services/agents/app/replay/runner.py`), and writes a signed report in the evidence-bundle format.
- The report holds aggregate scores by default. Item-level detail stays on the partner's host unless they export it, and a redaction pass runs before any export.
- It runs fully air-gapped on the local model. A hosted model is used only with the partner's own key and an explicit flag.
- Document it in `apps/docs/docs/evaluation/replay.md` as the design-partner path.

**1.6 Publish.** `apps/docs/docs/benchmark.md` gets a "Verdict quality" table generated from the committed scorecard artefact, with model id, corpus digest, date and commit on every row, and a `--check` drift gate. Hosted models read "not measured" until the maintainer funds a key.

**Done when:**
- the scorecard publishes balanced accuracy, malicious recall with its interval and false negatives for the shipped default model and at least one larger local model, on a corpus the scorer accepts;
- the `fake_tool_output` flip rate is at or below 10% on both tuned and held-out payloads, and the ceiling records the new figure;
- `make replay-eval` runs end to end against mocked Splunk and Sentinel history readers and writes a report that verifies.

### Phase 2: A semantic layer and live posture

**Goal:** every event the platform keeps says who acted and what kind of actor it was, what they did, to which resource, from where, with what outcome and how sensitive that is. Events are grouped into sessions, and every identity carries its effective privileges from a live, versioned posture snapshot. Phases 3, 6 and 7 build on this.

**2.1 OCSF classes beyond five.**
- Ingest emits Security Finding, Vulnerability Finding, Authentication, Network Activity and API Activity today (`services/ingest/internal/normalizer/normalizer.go`). Add at least Process Activity, File System Activity, DNS Activity, HTTP Activity, Email Activity, Account Change, User Access Management, Group Management, Web Resources Activity and Datastore Activity.
- Check every class uid and attribute against the OCSF version the tree targets (1.9.0) before using it.
- Map every connector type to a class through a profile, or record in the profile table why it stays generic. A new gate fails on a connector type with neither.
- This implements the "OCSF normalization beyond five classes" part of parity 6.10.

**2.2 The activity projection.** On every normalized event, populate one canonical projection, carried into the lake (new columns through a lake migration next to `services/api/clickhouse/001_init.sql`) and into the graph (`services/ingest/internal/graph/schema.go`):
- `actor`, with `actor.kind` in `human | service_account | oauth_app | api_token | workload | ai_agent | unknown`. This is the field that separates a person from the app or token acting for them. Derive it per source from the vendor's own identity-type, token-type and client fields, and never guess: what cannot be derived stays `unknown`.
- `action` (a normalized verb), `resource` (type, id, owner), `location` (IP, ASN, geography, device) and `outcome`.
- Geography, ASN and reputation for every public IP at ingest, from the enrichment already in the tree, cached.
- User-agent parsing into client family and version (CLI, SDK, browser, infrastructure-as-code tool, known offensive tooling), in Go inside ingest. Keep the raw string.

**2.3 An event classification catalogue.**
- `schemas/event_catalog/<source>.yaml` (new) maps each vendor event type to a normalized action, a sensitivity (`info | low | medium | high | critical`) and an optional ATT&CK hint.
- Start with every event type that appears in the fixtures of the cloud, identity and SaaS connectors named in 1.1.
- Ingest reads it at boot. A gate fails when a fixture's event type is neither classified nor listed as deliberately unclassified, so the catalogue grows with the connectors.

**2.4 Sessions.**
- Group events by principal into sessions using the strongest key each source offers: the AWS access key id and assumed-role session, stitched back to the originating human through `sourceIdentity` or the role session name where present; IdP session ids from Okta and Entra; session or token ids from Workspace and M365; and IP plus user agent within an idle gap as the fallback.
- Store sessions in a lake table and as `Session` nodes in the graph, with duration, event count, highest sensitivity and the mix of actor kinds.
- Fusion attaches the session id and summary to every alert, so triage and the investigation rail can show what else the session did.

**2.5 Posture snapshots for AWS, Azure, GCP and Workspace.** Close 7b+ in `docs/audit/DEFERRED_SUBPHASES.md`.
- Each provider's connector answers the `__posture_snapshot__` sentinel through `get_resource_config` with the reconciled snapshot its resolver in `services/api/app/services/effective_permissions/` already consumes:
  - AWS: identity and resource policies, groups, roles and trust policies, SCPs and permission boundaries across the organisation;
  - Azure: role definitions and assignments, Entra directory roles and eligible assignments;
  - GCP: IAM bindings across the resource hierarchy and organisation policy constraints;
  - Workspace: admin roles and privileges, and OAuth grants per user.
- Model permission boundaries in `services/api/app/services/effective_permissions/aws.py`, which today notes that it does not and may over-permit.
- Add GitHub (organisation, team and repository roles). Okta stays as it is.
- Collect daily and on change: an IAM-changing event seen at ingest refreshes that principal. Store each snapshot versioned with `valid_from` and `valid_to`, and document the read-only credentials per provider under `apps/docs/docs/connectors/`.
- Delete `services/api/tests/test_posture_snapshot_coverage.py` last, as that file asks.

**2.6 Use the posture everywhere.**
- Fusion attaches the actor's privilege tier, from the snapshot valid at event time, to every alert. Prioritisation already reads identity privilege (v16) and must read this.
- Triage and investigation get a "what this identity can do" tool whose result is cited in the ledger.
- Graph blast radius uses effective permissions, not group membership alone.

**2.7 Entity context in CORE.** ADR-0007 kept the lake and the graph in `full`. Write an ADR (next number) that measures two options against the 8 GB CORE budget: Neo4j in CORE, and a Postgres-backed entity and session store for CORE with Neo4j kept for `full`. Implement only what the ADR accepts, so alerts on a CORE install carry session, actor-kind and privilege context.

**Done when:**
- a CloudTrail assumed-role chain fixture resolves to one session attributed to the originating human, with `actor.kind` set on every event;
- AWS, Azure, GCP and Workspace effective-permission calls return 200 against mocked vendor APIs, and `services/api/tests/test_posture_snapshot_coverage.py` is gone;
- a gate reports the number of connector types on the generic mapping, and it is lower than at capture;
- the Phase 1 scorecard shows the delta, on cloud and identity items, of giving triage session and privilege context.

### Phase 3: Detection depth for cloud, identity and SaaS

**Goal:** the rules that cannot fire can fire, behaviour is baselined in CORE, and cloud, identity, SaaS and code sources carry content at the depth the reference platform ships, every rule proven by replay.

**3.1 Translate the windowed family.** The windowed engine exists (`services/fusion/app/services/windowed_detection.py`, 18 `wd-*` rules loaded from `services/fusion/app/data/windowed_ruleset.json`), but none of the 74 `det-*` rules that need a window has been translated, which is why the unreachable count never moved (the comment in `scripts/check_detection_fields.py` explains this). Author a `wd-*` rule for each through `scripts/export_windowed_ruleset.py`, and retire or link the `det-*` original.

**3.2 Sequences and Sigma correlations.**
- Add ordered sequences to the windowed engine: A then B by the same entity within a window, ordered by event time with the existing watermark.
- Import Sigma correlation rules (at least event count, value count, temporal and ordered temporal) into windowed form through the Sigma compiler path (`scripts/compile_sigma_ruleset.py`), refusing rather than approximating what does not translate. This completes the "Sigma correlation rule types in fusion" part of parity 6.10.

**3.3 Enrichment inputs.** Implement parity 5.5 as specified for the inputs still missing:
- identity enrichment (24 rules) from the Phase 2.5 posture and SCIM attributes;
- first-seen and age (8 rules) from a per-tenant first-seen store keyed by principal and attribute (country, ASN, device, client family, OAuth app, action, resource), in Redis with a lake backstop;
- the fields nothing emits (8): build them where cheap, otherwise quarantine with a reason.

Lower `MAX_UNREACHABLE` in the same PR as each fix.

**3.4 Baselines in CORE.** Behavioural scoring needs the `full`-profile UEBA service today. Move its scoring core into fusion as a module, or add UEBA to CORE behind an ADR that measures it, so CORE has:
- per-principal rarity of normalized actions, resources, client families and locations;
- peer-group deviation for principals that share a role or group in the posture snapshot;
- volume anomalies per principal and per OAuth app.

Each anomaly is a typed signal, not an alert on its own.

**3.5 Threat and anomaly conditions.** Pair anomaly signals with threat conditions into rules, for example a first-seen country with an MFA factor reset, or a rare client family with access-key creation. They are ordinary rules that read baseline fields, so they carry the same replay proof. Count them as their own family in `scripts/project_stats.py`.

**3.6 Content depth.** Raise executable cloud, identity, SaaS and code conditions (native rules, windowed rules and threat-and-anomaly conditions together) from 461 at capture to at least 800, counted by a new `make stats` line held by a `--check` gate. Minimums, by `log_source` product:
- every SaaS source with a connector (Workspace, M365, Slack, Salesforce, Snowflake, Box, Dropbox, 1Password, Atlassian, Zoom, ServiceNow) has at least 20;
- GitHub and GitLab together have at least 40, covering token abuse, workflow tampering, secret exposure and session hijack;
- AWS and GCP each have at least 120, Azure including Entra at least 150, Kubernetes at least 60 and Okta at least 60.

Each rule follows the native path: YAML under `detections/<category>/`, the spec in `scripts/detection_specs*.py`, exported by `scripts/export_detection_ruleset.py`, with positive and negative fixtures. ATT&CK coverage stays computed from executable rules only.

**3.7 Detection engineering agent.** Implement gap-closure Phase 9 as specified (parity 6.2): per-tenant coverage gaps against the connected sources, drafted rules as DRAFT proposals with fixtures and a replay backtest, and nothing promoted without a separate approver.

**Done when:**
- `scripts/check_detection_fields.py` reports fewer than 20 unreachable rules, each with a reason;
- a CORE install fires a threat-and-anomaly rule on a replayed fixture with no `full` service running;
- `make stats` reports at least 800 cloud, identity, SaaS and code conditions and the gate holds it;
- the Phase 1 scorecard shows malicious recall on cloud and identity items before and after.

### Phase 4: Collection and scale

**Goal:** collect cloud and SaaS telemetry the way production estates emit it, keep it as long as the tenant needs, and measure throughput on cloud hardware.

**4.1 Cloud-native collection.**
- AWS: an organisation trail on S3 with SQS notifications, including data events and VPC flow logs from S3, with checkpointing and backpressure. Keep `LookupEvents` (`services/connectors/app/connectors/aws_cloudtrail.py`) for small accounts.
- GCP: a Pub/Sub subscription on a log sink.
- Azure: Event Hubs for Entra sign-in and audit logs and the Activity log.
- Each is a connector capability with recorded vendor-shaped tests and a setup guide.

**4.2 Standard inputs.** Implement the rest of parity 6.10 as specified: a syslog listener for RFC 5424, RFC 3164, CEF and LEEF in `services/ingest`, an OTLP logs receiver, a Kafka input for customer topics, and a TAXII 2.1 server backed by the tenant IOC store.

**4.3 Retention the tenant chooses.**
- A per-tenant retention setting drives the lake TTL instead of the fixed 90 days in `services/api/clickhouse/001_init.sql`. Allow at least 400 days.
- Turn the opt-in tiering in `services/api/clickhouse/tiering/` into a supported `full` default with an S3-compatible cold volume, and make legal hold (v16) block deletion.
- A query over cold data through `/lake/sql` or a hunt reports an estimated cost and a progress state instead of timing out silently.

**4.4 Throughput.** Implement parity 6.9 as specified: rules indexed by log source, fusion consumers partitioned by entity with ordering per entity, concurrent triage consumers and lag-based autoscaling hints. Extend `scripts/perf/load_harness.py` with a realistic mix in which most events do not alert, and publish runs on stated cloud hardware in `apps/docs/docs/operations/performance.md`, labelled "not an SLO". Aim for a sustained 5,000 events/s through detection at p95 under 2 seconds on one documented instance size, and publish whatever is measured.

**4.5 Deployment completeness.** Implement parity 6.8 as specified: Helm renders and installs every CORE service (`infra/helm/aisoc/values.yaml` omits connectors, actions, threat intel, the LLM gateway, Ollama and Qdrant today), restore covers every component backup covers, the connector scheduler uses leader election, and one managed Kubernetes run is recorded once the maintainer provides a cluster.

**Done when:**
- a CloudTrail organisation-trail fixture on S3 and SQS and a syslog source each reach an alert through `make smoke`;
- a tenant with 400-day retention keeps a row past day 90, and a tenant on legal hold cannot lose one;
- the performance page shows a cloud-hardware run of the realistic mix;
- `helm install` brings up all of CORE on kind.

### Phase 5: Response that finishes

**Goal:** every shipped playbook can run to completion, the verbs cover cloud and SaaS containment, and verifying the affected user and their manager is a stateful workflow.

**5.1 Steps that act.** Implement parity 5.3 as specified: resolve `${...}` placeholders in `http` steps from connector instances and the vault through the SSRF guard, make `notify` deliver through the configured Slack, Teams, email and PagerDuty destinations (`_handle_notify` in `services/agents/app/playbook/engine.py` delivers only to a raw webhook today), and fix or remove the osquery step.

**5.2 Delivery.** Implement parity 5.7 as specified: the report scheduler (`services/api/app/api/v1/endpoints/reports.py`), SMTP delivery, the email-approval sender (`services/api/app/services/email_approval.py`), proactive Teams approval cards with `services/teams-bot` deployed in compose, and signed outbound event webhooks with retries and a dead-letter view.

**5.3 Engine steps.** Add `wait` (a timer or a callback, on the durable pause the `approval` step already uses), `parallel` with a join, and bounded `loop`, each with an idempotency key per step. Widen the console palette to every step type the engine runs, held by `scripts/check_playbook_schema_parity.py`.

**5.4 Stateful verification.** Build on `chatops_verify`:
- ask the affected user, then their manager (from SCIM or IdP data), over Slack, Teams or email;
- branch the playbook on the signed answer, with a timeout outcome;
- keep the contract's caution: never sent automatically on a confirmed true positive, and auto-sent only for alert classes a tenant opts into.

**5.5 Verb breadth.** Raise executor arms from 73 to at least 150, putting first the cloud and SaaS containment the reference platform automates, where the vendor's API allows it:
- AWS: deactivate an access key, revoke active role sessions with a deny on token issue time, quarantine an instance;
- GCP and Azure: disable a service account or its key, disable a service principal, revoke refresh tokens;
- Workspace and M365: suspend or sign out a user, revoke an OAuth grant, revoke app passwords;
- GitHub: remove an organisation member, delete a deploy key, disable a workflow;
- Slack, Salesforce, Snowflake and 1Password: deactivate or freeze a user and revoke their tokens;
- connected secure web gateways: block a URL or domain.

Each arm has a capability contract, a verification probe or a recorded verification gap, rollback where the vendor allows it, and a mock-vendor test (`scripts/check_action_contract.py`). An arm-count line in `make stats` holds the figure.

**5.6 Plain-language playbooks.** The natural-language playbook drafter produces a schema-valid playbook, previews it against a chosen past alert, and lands it as a draft that needs approval. Every response step in it is graded at dispatch like any other.

**Done when:**
- every pack playbook under `playbooks/` runs to completion in preview against mocked vendors, gated per playbook;
- a verification playbook asks a user and then a manager, waits, branches on a signed answer, and contains on "no" after approval;
- the arm-count gate reads at least 150.

### Phase 6: AI agent security

**Goal:** inventory every AI app, coding agent, MCP server, IDE extension, model-provider key and AI OAuth grant against the person, device and permissions behind it; baseline agent behaviour; detect misuse; contain it.

**6.1 Inventory.** New tenant-scoped tables (next migration, row-level security per the inherited rules) and graph nodes for AI apps, coding agents, MCP servers, IDE extensions, provider keys and OAuth grants, each linked to a person, a device and the effective permissions from Phase 2.5. A console page lists them with first seen, last seen and risk.

**6.2 Endpoint discovery without a new agent.**
- From EDR process telemetry normalized in 2.1 (CrowdStrike, Defender, SentinelOne, and osquery through FleetDM and osctrl): known coding-agent processes, MCP server processes and the configuration files that popular MCP clients read.
- An osquery pack, under `services/osquery-extensions` or alongside the existing packs, for MCP client configuration files and IDE extension directories.
- Record what each source can and cannot see.

**6.3 Provider coverage.** Extend `llm_usage` beyond OpenAI and Anthropic admin audit logs: Workspace audit events for Gemini, M365 audit records for Copilot interactions, GitHub audit events for Copilot, OAuth grants to AI apps from Workspace token audit and Entra consent events, and usage APIs where a provider offers one. Verify every endpoint against the provider's current reference first.

**6.4 Agent identity and baselines.** Implement parity 6.7 as specified: AiSOC's own agents get identities with short-lived credentials and least-privilege tool scopes, then per-agent baselines (tools, resources, volume, token spend, hours) from `packages/aisoc-ai-sdk` telemetry, gateway logs and provider usage, through the Phase 3.4 baseline module.

**6.5 Detections.** An AI rule pack with fixtures: a provider key created or used from a new ASN, an agent invoking a new high-risk tool, an MCP server from an unvetted source, a coding agent started with its permission prompts disabled, bulk data access by an OAuth AI app, a rise in guardrail violations, and token-spend anomalies.

**6.6 Containment.** Executor arms with contracts: revoke a provider API key, revoke an AI OAuth grant, block a key at a supported gateway, and kill the agent process through the existing EDR `kill_process`. Compose them into one agent kill-switch playbook that requires approval.

**Done when:**
- a fixture estate with one coding agent, one MCP server and one provider key shows all three on the inventory page, linked to the right person and device;
- an anomalous-agent fixture raises an alert, and the kill-switch playbook runs end to end in preview.

### Phase 7: Phishing operations

**Goal:** reported phish goes from intake to purge with a governed blast radius.

**7.1 Intake to purge.** Implement gap-closure Phase 10 and parity 6.4 as specified: reported-message intake (an M365 report mailbox through Graph, Workspace user reports, and the existing `email_inbox` connector), purge and retract verbs with capability contracts for M365 and Workspace, a blast radius scaled by recipient count, and campaign grouping.

**7.2 Analysis.** Headers, sender authentication results, URLs and attachments go through the existing sandbox providers (`services/api/app/services/sandbox/`) and enrichment, cited in the ledger.

**7.3 Adversary-in-the-middle.** A detection family on Phase 2.4 sessions: the same session or token used from a new ASN or client family shortly after an MFA-satisfied sign-in, plus the link from a reported message whose URL precedes that sign-in.

**Done when:** a reported-message fixture is grouped into a campaign and purged in preview across its recipients at the contract's approval tier, and a matching AiTM sign-in fixture fires.

### Phase 8: Enterprise gates

**8.1 Identity and administration.** Finish fix-pass wave 4 (4.1 to 4.6) if Phase 0 found any of it open. Then implement, as specified: parity 4.1's end-to-end CI against a containerised IdP for OIDC and SAML; 4.2 console MFA (TOTP with recovery codes and WebAuthn, enforced per role and per tenant); 4.4 starting from the existing `apps/web/src/components/audit/AuditLogView.tsx`, adding export and an enforced retention job; 4.5 operator pages and opt-in limit enforcement in `services/api/app/services/entitlements.py`; 4.6 internationalisation; and 4.7 accessibility on the remaining core views.

**8.2 ABAC, elevation and workload identities.** Give readers to the tables v16 created as schema only: attribute conditions evaluated inside the single permission path (`scripts/check_one_permission_model.py`), time-boxed elevation with approval and automatic expiry, and workload identities for service-to-service calls. Record any change to an authorization outcome under `### BREAKING`.

**8.3 Buyer security pack.** Extend `docs/security/` into a set a reviewer can use: architecture and data-flow diagrams, the existing threat models, data handling per deployment mode, subprocessors for the hosted service, and answers to a standard security questionnaire. Every statement links to the code or gate that makes it true.

**Done when:** a CI test signs in through OIDC and SAML with MFA enforced for the role, an elevation expires on schedule, and the security pack passes the competitor-name and comment-path gates.

### Phase 9: Analyst surfaces

**9.1 MCP over the network.** Implement parity 6.6 as specified: streamable HTTP for `services/mcp/src/server.ts`, deployed in compose and Helm, scoped keys, tools enabled per tenant, an audit row per call, and approval on destructive tools.

**9.2 Semantic memory.** Implement parity 6.5 as specified: vector recall on Qdrant for past cases, runbooks and institutional memory (`services/api/app/api/v1/endpoints/knowledge_base.py` is full-text only today), with provenance and conflict review. Measure it on the Phase 1 scorecard.

**9.3 Case depth.** Implement the open half of parity 5.6: alert and case merge, bulk triage in both route and UI, tenant custom fields, and per-analyst workload metrics.

**9.4 War rooms.** One action opens a Slack or Teams channel for a case, invites the assignees, posts the timeline and verdicts as they change, and syncs decisions back to the case, built on `services/slack-bot` and `services/teams-bot`.

**9.5 Hunt to report.** A natural-language hunt or a retro-hunt that finds something produces a case report (what, how, where, when) with ledger citations, exportable as PDF through the existing report path.

**9.6 Native responder.** Build `apps/mobile` for a device through a CI pipeline, deliver push through APNs and FCM once the maintainer provides credentials, and add voice input that converts speech to text on the device and sends the text to the grounded copilot. No audio leaves the device.

**Done when:** an MCP client over HTTP runs a hunt with an audit row per call, two alerts merge into one case with their history kept, and a war-room channel mirrors a case's timeline.

### Phase 10: Close the books

- Re-run every claim row this plan touched, and confirm each names a gate that drives the production path on the profile it states.
- Update `GAP_CLOSURE_PROGRESS.md`, `PARITY_PROGRESS.md` and `FIX_PASS_PROGRESS.md` for every item implemented here by reference.
- One `[Unreleased]` entry per phase in `CHANGELOG.md`, in the house style: the gap, how it was measured, and the gate that keeps it closed.
- A final report in `DEPTH_PROGRESS.md`: each "Done when" with its evidence, and each item left open with its reason.

### Parallel lanes

- **Lane A, first:** Phase 0, then Phase 1.
- **Lane B:** Phase 2, then Phase 3. Starts once Phase 1.2 can score.
- **Lane C:** Phase 5. Independent of Lane B; starts after Phase 0.
- **Lane D:** 4.2, 4.3 and 4.5 after Phase 0; 4.1 and 4.4 after 2.1.
- **Lane E:** Phase 8. Independent.
- **Later:** Phase 6 after 2.5, 3.4 and 5.5. Phase 7 after 2.4 and 5.1. Phase 9 any time after Phase 1, with 9.2 measured on its scorecard. Phase 10 last.

### Maintainer-only items (record as [!], do not attempt)

- Fund hosted-model keys so Phase 1 reports hosted rows (fix-pass M2).
- Sign at least two design partners to run `make replay-eval` and consent to publishing aggregates.
- Provide a managed Kubernetes cluster and cloud hardware for 4.4 and 4.5 (fix-pass M3).
- Provide cloud and SaaS test tenants (an AWS organisation, Azure, GCP, Workspace, M365, GitHub, Slack) so each posture collector and executor arm is verified once against the real vendor.
- Apple and Google developer accounts and push credentials for 9.6.
- Commission an external penetration test, and SOC 2 Type II or ISO 27001 for the hosted service.
- Decide whether to offer a managed human-review service on top of the platform. Nothing in this plan depends on it.
- Add a second maintainer with merge rights.
- Publish the npm and PyPI packages and the MCP server package.
