---
name: AiSOC depth plan, wave 2
overview: "Close what a capability review at v21.0.0 still found missing against the reference AI-SOC platform: identity context that changes verdicts (effective permissions in triage, access right-sizing, HR and device context, per-token baselines), detection depth for cloud, identity, SaaS and code, cross-source attack stories, triage that earns trust, hunting from a report, response that finishes in cloud and SaaS, AI agent security, coverage breadth and a voice responder that can act. Every item is reproduced before it is built, lands with a gate, and moves a published measurement or says it did not."
todos:
  - id: p0-1-progress
    content: "Phase 0.1: create DEPTH2_PROGRESS.md modelled on DEPTH_PROGRESS.md (checkbox per item, pre-existing state, deviations, item log, migration and ADR number claims)"
    status: pending
  - id: p0-2-rederive
    content: "Phase 0.2: re-derive every figure in 'Before you start' against the starting tree; record captured vs measured; the tree wins"
    status: pending
  - id: p0-3-baseline
    content: "Phase 0.3: baseline artefacts (verdict scorecard, alert-reduction suite, arm count, cloud/identity/SaaS/code condition count, make smoke) committed with hardware, date and commit"
    status: pending
  - id: p0-4-siem-adr
    content: "Phase 0.4: ADR deciding whether AiSOC takes on SIEM-replacement scope; README's 'not a drop-in SIEM replacement' stays true unless the ADR is accepted and built"
    status: pending
  - id: p1-1-effective-permissions-everywhere
    content: "Phase 1.1: depth 2.6 as specified, plus runtime-usage overlay, computed can-escalate / data-access / third-party / cross-account tags, and the AWS policy semantics the resolver does not yet model"
    status: completed
  - id: p1-2-access-review
    content: "Phase 1.2: access review and right-sizing (granted vs used over a window, best-fit role, humans holding long-lived keys, outside collaborators with admin) as read-only findings and a review page"
    status: completed
  - id: p1-3-hr-device-context
    content: "Phase 1.3: HR connectors (Workday, BambooHR, Rippling) and MDM connectors (Intune, Kandji, Jamf promoted from plugin) feeding employment status, manager, tenure, device owner and compliance into the identity graph and triage"
    status: pending
  - id: p1-4-sub-principal-baselines
    content: "Phase 1.4: baselines per sub-principal (OAuth app, token, service account, AI agent acting for a human); GitHub tokens joined to scopes and classified by cadence"
    status: completed
  - id: p1-5-change-before-alert
    content: "Phase 1.5: a cited 'what changed before this alert' tool over versioned posture and audit events (role, policy, OAuth consent, MFA, sharing)"
    status: completed
  - id: p1-6-anonymizer-classes
    content: "Phase 1.6: VPN, Tor, proxy and hosting-provider classes stamped at ingest from a pinned local dataset with its version recorded"
    status: in_progress
  - id: p2-1-content-depth
    content: "Phase 2.1: depth 3.6 as specified (at least 800 executable cloud, identity, SaaS and code conditions) with the scenario families listed in this plan"
    status: pending
  - id: p2-2-long-horizon
    content: "Phase 2.2: long-horizon identity attack detection (days to weeks, per account) on the baseline store, not the windowed engine"
    status: pending
  - id: p2-3-weak-signal-aggregation
    content: "Phase 2.3: weak-signal aggregation per session, principal and window into one finding that lists its contributing signals, threshold calibrated on the corpus"
    status: pending
  - id: p2-4-api-behaviour
    content: "Phase 2.4: API behaviour from proxy, gateway and WAF logs (path templating, per-endpoint parameter and status profiles, unknown-parameter and enumeration signals)"
    status: pending
  - id: p2-5-detection-engineering-agent
    content: "Phase 2.5: depth 3.7 as specified (gap-closure Phase 9): coverage gaps, DRAFT rule proposals with fixtures and replay backtest, separate approver"
    status: pending
  - id: p3-1-identity-resolution
    content: "Phase 3.1: identity resolution across IdP, EDR device user, proxy user, cloud principal, code platform login and Workspace, with confidence and evidence"
    status: completed
  - id: p3-2-attack-stories
    content: "Phase 3.2: cross-source attack stories linked by resolved identity, session, role chain and shared indicator, with story-level severity and a ledger reason for any escalation"
    status: pending
  - id: p3-3-root-cause-dedup
    content: "Phase 3.3: collapse vendor repeats and same-root-cause alerts across vendors into one finding, originals kept, measured on purity and reduction"
    status: pending
  - id: p4-1-hosted-models
    content: "Phase 4.1: hosted and larger models in the verdict matrix once a funded key exists; rows stay 'not measured' until then"
    status: pending
  - id: p4-2-reviewer-pass
    content: "Phase 4.2: a separate reviewer pass over the decision contract that can escalate or demote, measured on balanced accuracy and auto-close precision"
    status: pending
  - id: p4-3-questions-and-rules
    content: "Phase 4.3: per-alert-type triage questions and plain-language business-context rules compiled to the existing rule schema with a preview"
    status: pending
  - id: p4-4-precedent-and-retriage
    content: "Phase 4.4: similarity-matched analyst precedent cited in triage, and re-triage of open alerts when correlated evidence arrives, each verified first"
    status: pending
  - id: p4-5-vendor-evidence
    content: "Phase 4.5: vendor-alert triage pulls the vendor's own evidence through read verbs into the ledger"
    status: pending
  - id: p4-6-outcomes
    content: "Phase 4.6: outcome evidence from make replay-eval on a design partner's closed alerts: false-positive reduction and time to verdict with denominators, or 'not measured'"
    status: pending
  - id: p5-1-hunt-from-report
    content: "Phase 5.1: hunt from a report URL or pasted text: extract indicators and techniques, draft a closed-schema hunt, refine in conversation, run across the lake and federated SIEMs, open a case"
    status: pending
  - id: p5-2-standing-hunts
    content: "Phase 5.2: extend the hunt scheduler to the lake and federated backends with an emailed PDF, and link hunts into the existing detection-proposal flow"
    status: pending
  - id: p5-3-explorer
    content: "Phase 5.3: Data Explorer shows the query it ran, cross-filters, per-entity views, CSV export and pivot to the graph"
    status: pending
  - id: p5-4-software-inventory
    content: "Phase 5.4: software inventory for supply-chain hunts from code-platform SBOM APIs and osquery package tables"
    status: pending
  - id: p5-5-retro-hunt-scale
    content: "Phase 5.5: measure and publish retro-hunt sweep time and lake cost over at least one million indicators"
    status: pending
  - id: p6-1-verb-breadth
    content: "Phase 6.1: depth 5.5 as specified (at least 150 arms, cloud and SaaS containment first)"
    status: pending
  - id: p6-2-plain-language-playbooks
    content: "Phase 6.2: depth 5.6 as specified, plus a bounded 'ask the model' step type that branches on a schema-valid answer and cannot act"
    status: pending
  - id: p6-3-time-gates-timeouts
    content: "Phase 6.3: business-hours conditions in approval rules and declared timeout outcomes (pause, rollback, or a named limited containment)"
    status: pending
  - id: p6-4-ticket-sync
    content: "Phase 6.4: verify Jira and ServiceNow two-way sync end to end; finish whichever direction is missing"
    status: pending
  - id: p7-1-provider-coverage
    content: "Phase 7.1: depth 6.3 as specified, plus enterprise chat compliance logs stored as labels and bounded snippets only"
    status: pending
  - id: p7-2-hosted-agents-and-skills
    content: "Phase 7.2: hosted-agent inventory through provider admin APIs and a repository scan for agent instruction, skill and MCP config files, both scored by the existing score_risk"
    status: pending
  - id: p7-3-agent-identity
    content: "Phase 7.3: depth 6.4 as specified (parity 6.7)"
    status: pending
  - id: p7-4-ai-rule-pack
    content: "Phase 7.4: depth 6.5 as specified, plus the additional AI detections listed in this plan"
    status: pending
  - id: p7-5-ai-containment
    content: "Phase 7.5: depth 6.6 as specified, plus role demotion, workspace removal and spend caps where the provider API allows"
    status: pending
  - id: p8-1-cnapp-depth
    content: "Phase 8.1: CNAPP connector depth beyond issues (vulnerabilities, configuration findings, secrets, runtime detections) used as triage context"
    status: pending
  - id: p8-2-ndr
    content: "Phase 8.2: NDR connectors (ExtraHop RevealX 360, Corelight) with detections ingested and metadata read verbs for evidence pulls"
    status: pending
  - id: p8-3-enrichment-providers
    content: "Phase 8.3: existing enrichment providers made per-tenant opt-in with vault-held keys, rate limits applied, results cited in the ledger; add the URLScan client and a credential-exposure source"
    status: pending
  - id: p8-4-scale-evidence
    content: "Phase 8.4: first depth plan 4.4 cloud-hardware run and 4.5 managed-cluster run, published or recorded as blocked"
    status: pending
  - id: p9-1-voice-that-acts
    content: "Phase 9.1: build on-device voice input behind the existing voice.ts interface, then read-back and voice approval of a pending response with biometric step-up; no audio leaves the device"
    status: pending
  - id: p9-2-device-evidence
    content: "Phase 9.2: depth 9.6 remainder: a real device runs the voice path and receives a real push once the maintainer provides accounts"
    status: pending
  - id: p9-3-i18n
    content: "Phase 9.3: parity 4.6 internationalisation (pilot locale, RTL, locale formatting, missing-keys gate)"
    status: pending
  - id: p9-4-teams-war-room
    content: "Phase 9.4: depth 9.4 Teams half, once the maintainer registers the Teams app"
    status: pending
  - id: p9-5-operator-pages
    content: "Phase 9.5: parity 4.5 operator pages as specified (first depth plan 8.1 sub-item 4.5)"
    status: pending
  - id: p10-close
    content: "Phase 10: re-run every claim row touched, update progress files, one [Unreleased] entry per phase, final report in DEPTH2_PROGRESS.md"
    status: pending
isProject: false
---

# AiSOC depth plan, wave 2

> **Status**: Locked plan. Implement as specified and do not edit the body. Cursor may update the `status` of each todo in the front matter; that is the only permitted change to this file.
> **Captured**: 2026-10-31, against v21.0.0 (commit `152c6d5`).
> **Tracking**: `DEPTH2_PROGRESS.md` (new) mirrors progress and records every deviation; this file is the source of truth.
> **Relationship**: `plans/aisoc_depth_plan.plan.md`, `plans/aisoc_gap_closure_plan.plan.md`, `plans/aisoc_parity_plan.plan.md` and `plans/aisoc_fix_pass_plan.plan.md` stay locked. Where an item here says "depth N as specified" (or gap-closure N, or parity N), implement that item from that plan exactly, then add only what this plan adds. Open items of the first depth plan that this plan carries are closed in `DEPTH2_PROGRESS.md` and cross-referenced from `DEPTH_PROGRESS.md`; never tick an item in both.

### Why this plan exists

A capability review at v21.0.0 compared AiSOC with the reference AI-SOC platform again: a SaaS agentic SOC selling four agents (detect, triage, investigate, respond) over a knowledge graph built at ingest, a tiered data platform, an agentless AI-security module, a mobile voice app and a managed service on top.

AiSOC leads on data control (self-hosted, air-gapped, a local model), auditability (the Investigation Ledger, signed evidence bundles, provenance on every published number), governed autonomy (capability contracts, durable approvals, default-deny closure) and honest measurement. The first depth plan closed most of its semantic, collection, phishing, governance and analyst-surface items. What remains, measured on the starting tree:

1. **Identity context that does not reach the verdict.** Effective-permission resolvers exist for AWS (SCPs, explicit denies and resource policies; `NotAction`, `NotResource`, most condition operators and session policies are not yet modelled, per the module's own docstring), Azure, GCP, GitHub, Workspace and Okta (`services/api/app/services/effective_permissions/`), but no agent tool under `services/agents/app/tools/` asks "what can this identity do", graph blast radius (`get_blast_radius` in `services/api/app/services/graph_service.py`) is N-hop reachability over any relationship rather than what the identity's effective permissions allow, and depth 2.6 is still open. Nothing compares granted with used permissions. Employee, manager and departure context can be imported into the graph (`services/api/app/services/context_import.py`) and triage reads it when present (`services/agents/app/context/identity.py`), but no connector keeps it current from an HR system, there is no registered MDM connector (Jamf exists only as `plugins/jamf-mdm`), and device compliance reaches no verdict. Baselines are per principal plus a volume baseline per OAuth app (`baseline_oauth_app_volume_z` in `services/fusion/app/services/baselines.py`); tokens and agents acting for a principal have none of their own.
2. **Thin cloud, identity, SaaS and code detection.** Depth 3.6 is open. Across the native and imported compiled rulesets, Google Workspace Apps Script persistence has zero rules, GitHub Actions workflow tampering has no executable rule (the one on disk is quarantined because the audit log carries no file paths), GitHub as a whole has nine executable rules (fourteen on disk), and the imported set covers only Windows, AWS, Azure and Okta. The windowed engine's longest window is one day, so an attack spread over weeks against one account never accumulates.
3. **Correlation that groups less than the reference platform claims and tells no story.** v21 correctly narrowed grouping (33.3% on the production key, 24.5% on a detection-shaped cohort, zero cross-rule merges). `services/fusion/app/services/attack_chain_grouper.py` chains alerts from any source that share a host, user or IP string within an hour, but nothing links them through a resolved identity, a session or a role chain, and nothing scores the chain as a whole. Repeats of one alert fingerprint are collapsed (a 300 s Redis check plus `uq_alerts_tenant_dedup`, migration 120) by discarding them rather than keeping them linked, and different vendors reporting the same root cause are not collapsed at all.
4. **Triage that cannot yet be trusted to close.** The best measured local model reaches 0.357 balanced accuracy against a 0.250 floor; auto-close precision is 0.091 to 0.571; no hosted model has run; there are no per-alert-type questions, no plain-language context rules and no reviewer pass; no outcome (false-positive reduction, time to verdict) has been measured on anyone's real closed alerts.
5. **Hunting that starts from a blank page.** A hypothesis becomes a closed-schema hunt, retro-hunts re-sweep on new intelligence, hunt reports export as PDF, and `services/api/app/workers/hunt_scheduler.py` runs saved hunts on a schedule (off by default, Elasticsearch only, opening a case on a hit). But an analyst cannot hand AiSOC a research report and get a hunt, a scheduled hunt cannot run on the lake or the federated backends or email its results, and no path leads from a hunt into the governed detection-proposal flow (`detection_proposals.py`), which already exists.
6. **Response that stops at endpoints, identity sessions and email.** The live-action capabilities cover hosts, users, sessions, email, network blocks, SIEM and tickets. There is no AWS key or role-session containment, no GCP or Azure service-identity containment, no GitHub, Slack, Salesforce, Snowflake or 1Password containment, and no AI-provider containment. Depth 5.5 and 5.6 are open. `services/actions/app/services/kill_switch.py` is the platform-wide autonomy stop, not an AI-agent kill switch.
7. **AI agent security that sees but cannot act.** The AI estate inventory, endpoint discovery and coding-agent telemetry ingest exist; provider coverage beyond OpenAI and Anthropic admin logs, agent identities and baselines, the AI rule pack and AI containment (depth 6.3 to 6.6) are all open. The inventory (`services/api/app/services/ai_inventory.py`) knows coding agents, IDE extensions, MCP servers and provider keys, each with an exposure score, reasons and a sanctioned state; it has no hosted agents and does not read repository skill, agent-instruction or MCP configuration files.
8. **Coverage gaps where the reference platform builds context.** The CNAPP connector reads issues only (`services/connectors/app/connectors/wiz.py`); there is no NDR connector beyond Zeek/Suricata and Darktrace; `services/enrichment` (in `full` only) fans out to VirusTotal, AbuseIPDB, GreyNoise and commercial feeds and fusion calls it on every alert, but its keys are set per deployment rather than per tenant, URLScan has a config key and no client, its `RATE_LIMIT_*` settings are read and never applied, results are not cited in the ledger, and there is no credential-exposure source.
9. **A responder with a voice interface and no voice.** `apps/mobile/src/lib/voice.ts` defines the recogniser interface and the copilot client, and `scripts/check_no_audio_egress.py` gates it, but no speech-recognition package is installed and no screen imports it; nothing reads answers back, nothing approves a response by voice, no real handset has run the app or received a push, and internationalisation has not started.

The phases close these in dependency order. Phase 1 comes first because identity context is an input to detection (Phase 2), stories (Phase 3) and triage (Phase 4).

Refer to commercial products only neutrally. The reference platform is not in `scripts/competitor_names.toml`, so `scripts/check_competitor_names.py` will not catch its name: do not write it anywhere, including code, docs, commit messages and PR bodies. Vendors AiSOC integrates with (Workday, ExtraHop, Intune and so on) are integration surfaces and follow the existing allow-list rule.

### Before you start

- **Precondition.** The first depth plan's closed items stay closed. Its open items move here: 0.3 (the `make up-full` baseline), 2.6, 3.6, 3.7, the 4.4 cloud-hardware run, the 4.5 managed-cluster run, 5.5, 5.6, 6.3 to 6.6, 8.1's sub-items 4.5 (operator pages) and 4.6 (internationalisation), the 9.4 Teams half, the 9.6 remainder, and its Phase 10. Record the hand-over in both progress files once, at kickoff.
- **Read first.** `AGENTS.md` (its figures table is stale at capture; the generators win), `docs/audit/REPOSITORY_REALITY.md`, `docs/audit/MATURITY_DEFINITION.md`, the "Rules for every phase" sections of the depth, gap-closure and parity plans and "Rules for this pass" of the fix-pass plan, and `DEPTH_PROGRESS.md` (its Deviations section records defects this plan must not reintroduce).
- **Numbers at capture.** Re-derive at build time; never copy them from here:
  - executable detections 2,530 of 7,015 on disk; threat-and-anomaly family 24 (`python3 scripts/project_stats.py`);
  - windowed rules 76, longest window 86,400 s (`services/fusion/app/data/windowed_ruleset.json`);
  - registered connectors 87, connector type ids 98 (`scripts/generate_connector_count.py --check`, `packages/types/src/generated/connector-types.ts`);
  - executor arms 89 over 39 distinct verbs, by the first depth plan's method (classes declaring `capability = "..."` under `services/actions/app/live_actions/`; a looser grep also counts `reverse_capability` arguments and reports 111, which is not the figure); that plan captured 73 and re-derived 74;
  - cloud, identity, SaaS and code conditions: 395 at the first depth plan's re-derivation, about 358 by the same method on this tree (use its 3.6 counting rule and record why it moved);
  - claim-to-gate matrix 334 rows, 329 gated and 5 partial (`scripts/check_claim_gate_matrix.py`);
  - verdict matrix: best balanced accuracy 0.357 against a 0.250 floor, hosted rows *not measured* (`apps/docs/docs/benchmark.md`);
  - alert reduction 33.3% (production key) and 24.5% (detection-shaped cohort, zero cross-rule groups);
  - highest migration at capture 123, highest ADR 0014.

### Rules for every phase

- **Inherited.** Every rule in the "Rules for every phase" sections of the depth, gap-closure and parity plans and in "Rules for this pass" of the fix-pass plan applies verbatim: claims and gates, real transports, negative controls, no fabricated data, "not measured" never `0`, figures from generators.
- **Reproduce before building.** Each item starts by showing the gap on the current tree: a failing test, a gate, or a recorded command. Several gaps in this plan were measured by grep; a grep is a hint, not a reproduction. If an item does not reproduce, record a Deviation in `DEPTH2_PROGRESS.md` with the evidence and move on. Do not build what exists.
- **Measure through the scorecard.** Any PR that changes what triage, investigation, correlation or detection sees re-runs the verdict scorecard and the alert-reduction suite and puts before-and-after numbers in the PR body. A drop in balanced accuracy, malicious recall or grouped purity blocks the merge unless the PR explains it and the maintainer accepts it.
- **Real vendor shapes.** Every new connector read, posture collector, enrichment call and executor arm is tested against recorded vendor-shaped payloads through a mock server, following `services/connectors/tests/connectors/test_live_vendor_smoke.py`. Verify every endpoint, field and scope against the vendor's current public reference before writing it, and fetch every URL you commit (AGENTS.md).
- **Detections are earned.** A rule counts only when replayed through its real connector and the real engine with a positive fixture that fires and a negative fixture that differs in exactly one decisive field and does not fire.
- **Off by default where it reaches out.** Anything that collects from a new vendor API, calls an enrichment provider, changes vendor state, messages a person, fetches a URL or calls a hosted model ships off by default and is enabled per tenant.
- **Read-only before write.** Phases 1.2, 7.2 and 8.x produce findings and context only. Nothing they add may change vendor state; recommendations name the object to change and stop there.
- **Personal data minimisation.** HR, MDM and AI-chat compliance data store the minimum fields each feature uses, are tenant-scoped under RLS, follow the tenant's retention and legal hold, and are covered by the tenant-erasure path (ADR 0014).
- **Tenant and auth gates hold.** Every new route passes `check_route_auth`, `check_route_tenant_scope` and `check_tenant_query_predicates`; every new table gets RLS in its migration.
- **No attribution and no competitor names.** `check_attribution.py` and `check_competitor_names.py` stay green; see "Why this plan exists" for the reference platform.
- **Migration and ADR numbers across lanes.** Claim each number in `DEPTH2_PROGRESS.md` before writing the file.
- **Front matter.** Cursor may update the todo `status` values. The body is locked; deviations go in `DEPTH2_PROGRESS.md`.

### Phase 0: Kickoff

**0.1 Progress file.** Create `DEPTH2_PROGRESS.md` modelled on `DEPTH_PROGRESS.md`: a checkbox per item, "Pre-existing state", "Deviations", "Number claims" and an item log. Record the hand-over of the first depth plan's open items.

**0.2 Re-derive.** Recount every figure in "Before you start" and in "Why this plan exists" against the starting tree. Record captured and measured side by side.

**0.3 Baseline.** Commit raw output with hardware, date and commit: the verdict scorecard (`scripts/run_model_matrix.py --task verdict` on the local models available), the alert-reduction suite (`services/fusion/tests/test_alert_reduction_real.py`), the arm count, the cloud/identity/SaaS/code condition count, `make up && make smoke`, and `make up-full` (the baseline the first depth plan's 0.3 never recorded). These are the "before" for every later delta.

**0.4 SIEM scope decision.** Write an ADR (next number) on whether AiSOC takes on SIEM-replacement scope: compliance search, saved and scheduled searches with export, long-term retention SLAs, and what that costs against the 8 GB CORE budget. Build nothing from it in this plan unless the maintainer accepts it; until then the README line "Not a drop-in SIEM replacement" stays and stays true.

**Done when:** the progress file exists, every number is re-derived, every baseline artefact is committed, and the ADR is merged as Proposed or Accepted.

### Phase 1: Identity context that changes the verdict

**1.1 Effective permissions everywhere.** Implement depth 2.6 as specified (privilege tier from the snapshot valid at event time on every alert; a "what this identity can do" tool for triage and investigation whose result is cited in the ledger; graph blast radius from effective permissions). Then add:
- a runtime-usage overlay: for each principal, which granted actions were exercised in a trailing window, from the lake;
- computed tags on every identity: `can_escalate` (can grant itself or others more access, directly or through a role chain), `data_access` (can read tagged sensitive resources), `third_party` (external or vendor-owned), `cross_account` (reaches another account, project or tenant);
- severity and priority scaling by those tags, through the existing confidence and priority scorers with bounded weights and an explicit `unknown` when no snapshot covers the time;
- the AWS semantics the resolver's docstring lists as not modelled (`NotAction`, `NotResource`, condition operators beyond `StringEquals`/`StringLike`, session policies), each with a fixture that changes an answer, so a "can do" claim is not silently broader or narrower than IAM's.
Do not delete `services/api/tests/test_posture_snapshot_coverage.py`: depth 2.5 turned it into a guard, and `docs/audit/CLAIM_TO_GATE_MATRIX.md` cites it as the gate for a GATED row.

**1.2 Access review and right-sizing.** A read-only access review per principal: what was granted, through which object (group, role, policy, collaborator grant), and whether it was used in the window. Findings for: humans holding long-lived cloud keys; principals with write or admin they never used; outside collaborators with admin on a code platform; dormant admins. For AWS, Okta, Entra, Workspace and GitHub, compute a best-fit role (the smallest built-in or existing custom role that covers every used permission) and name it as a recommendation. Add posture findings that the same review surfaces: code-platform workflows with fork-reachable triggers (such as `pull_request_target`) that can read secrets; organisation members without two-factor authentication; GCP projects in the Apps Script folder whose configuration differs from what the Apps Script service creates (billing linked, extra services enabled); and, once 1.3 lands, movers who kept the access of their previous department. A console page lists findings with the evidence and the object to change. Nothing changes vendor state.

**1.3 HR and device context.** New registered connectors, each with a profile, a mock-vendor test and setup docs, holding only the fields listed:
- HR: Workday, BambooHR, Rippling: employment status, start date, termination or last-day date, manager, department, worker type (employee or contractor). They write through the existing context import path (`context_import.py`: upsert, departures recorded rather than deleted, per-record rejection report) on a schedule, rather than a parallel store.
- MDM: Microsoft Intune and Kandji, and promote `plugins/jamf-mdm` to a registered connector: device owner, compliance state, OS version, encryption, EDR agent health, joined to devices and their owners.
The import path writes to the graph, which is in `full`; make the same context available on a CORE install through the entity store ADR-0010 put in CORE. Extend the identity context triage already reads with tenure, departing within N days, contractor, and the device's compliance, each cited. Add the departing-employee data-movement detections to Phase 2.1's families once this lands.

**1.4 Sub-principal baselines.** Give every actor that acts on a human's behalf its own behavioural baseline: OAuth app (beyond the volume baseline `baselines.py` already keeps), personal access token, service account and AI agent. For GitHub, join the hashed token already used in sessionization (`services/ingest/internal/activity/session.go`) to the token's scopes and owner, and classify each token by cadence as scheduled, scripted or interactive. Signals: a token or app acting outside its own baseline; a scheduled token or bot identity suddenly interactive (new client family, operating system switch, travel); a token used from a new ASN within minutes of creation; a token idle for 60 days or more that reactivates.

**1.5 What changed before this alert.** A triage and investigation tool that returns, for the alert's identities and resources, every change in the N days before the alert: role and group grants, policy edits, OAuth consents, MFA factor changes, sharing changes, key creation. Source it from versioned posture and audit events; cite each change in the ledger.

**1.6 Anonymizer and hosting classes at ingest.** Stamp `vpn`, `tor_exit`, `public_proxy`, `residential_proxy` and `hosting_provider` on public IPs at ingest from a pinned, redistributable local dataset, with its version recorded on the event. Where no redistributable source exists for a class (residential proxies are the likely case), accept a tenant-supplied list instead and say in the docs that the class is otherwise not covered. No per-event network call. Baselines and rules may read the class; the alert shows it with the dataset version.

**Done when:**
- a fixture identity in each of AWS, Okta, Entra, Workspace and GitHub resolves effective permissions from a snapshot, its alerts carry privilege tier and tags, and a triage run cites the tool's answer;
- the access review produces at least one finding of each type against mocked vendors, with a negative control;
- an HR termination fixture changes a triage input and the ledger cites it;
- a GitHub token fixture classified as scheduled raises a signal when it turns interactive from a new ASN, and does not when it does not;
- scorecard and reduction suite re-run, deltas in the PR bodies.

### Phase 2: Detection depth

**2.1 Content depth.** Implement depth 3.6 as specified (at least 800 executable cloud, identity, SaaS and code conditions, per-source minimums, a `make stats` line with a `--check` gate). Within those minimums, cover these scenario families with positive and negative fixtures:
- **Workspace takeover and persistence:** recovery email or phone changed, then the password, within minutes of a risky sign-in; re-authentication from a VPN or hosting exit; OAuth grants of Gmail or Drive scopes to unverified apps; mail forwarding and delegation added; Drive bulk external sharing and bulk downloads; admin role grants; 2-step verification disabled; app passwords created.
- **Apps Script impersonation (GCP audit):** `CreateProject` under the Apps Script system folder by a user principal rather than the Apps Script service account, and `sys-` project ids that the service did not create.
- **Entra and federated identity:** device registration through the authentication broker shortly after a risky sign-in; one session or refresh token used from several countries within minutes, including non-interactive sign-ins (ingest the non-interactive sign-in log if the Entra connector does not); a federated sign-in accepted on another IdP's MFA claim from an unfamiliar network.
- **Code platform compromise:** OAuth or personal-access-token use from a new ASN or client; a token created and used from elsewhere within minutes; bursts of archive downloads or full clones; workflow files changed on a default branch by someone outside its usual editors (the audit log carries no file paths, which is why the rule on disk is quarantined: first collect push events or commit file lists through the GitHub connector, or record that the API cannot supply them); the sequence pull request opened by an unfamiliar identity, then an environment created, then a workflow run; shell-injection strings (`$(`, `${IFS}`, pipe to a shell, `base64 -d`) in pull-request titles, branch names or file names; new self-hosted runners; new deploy keys; new public repositories created by automation that receive encoded or secret-shaped content; organisation member and role changes.
- **Cloud enumeration and abuse:** bursts of `List*`, `Describe*` and `Get*` across many services from one session; log-read reconnaissance (`LookupEvents`, `logging.logEntries.list` and their Azure equivalent) by principals that never read logs; the privilege-write API families (`Attach*Policy`, `Put*Policy`, `CreatePolicyVersion`, `SetDefaultPolicyVersion`, `UpdateAssumeRolePolicy`, `PassRole`, `AddUserToGroup`, `roleAssignments/write`, `setIamPolicy`, custom role creation) from unusual principals; permission-set or cross-account role changes in an organisation's management account; trust-policy drift; root use; generic resource APIs (such as AWS Cloud Control) used by principals that never used them; access keys created for human users; a managed finding (GuardDuty, SCC, Defender for Cloud) on a session that also has identity anomalies.
- **Third-party access:** vendor-owned identities, GitHub Apps and OAuth apps (tagged in 1.1) acting outside their baseline: new scopes, bulk export, interactive use, new geography or ASN.
- **Departing-employee data movement** across Workspace, GitHub and cloud storage, using 1.3's HR dates: clones of repositories outside the user's history, export and sync spikes.
- **Supply chain on endpoints and CI:** package-install hooks spawning shells, credential-file reads, or AI command-line tools run with permission prompts disabled; a process never seen in the tenant packing files into hidden folders; one host reaching an unfamiliar domain, the cloud metadata endpoint and a code host in the same window; secrets pushed to public repositories.
Each family records its ATT&CK techniques; coverage stays computed from executable rules only.

**2.2 Long-horizon identity attacks.** Per-account accumulation over days to weeks on the baseline store (not the windowed engine): distinct source ASNs, countries and IPs of failed and successful authentication against one account, and the ratio's change against the account's own history. A slow distributed attack against one admin account fires; a travelling user with a stable device and successful MFA does not. Thresholds are derived from the corpus and published.

**2.3 Weak-signal aggregation.** Signals that are not alerts on their own (new ASN, ISP, country or client for the account, concurrent activity from two places, sub-principal deviations, anonymizer class, sensitive action, a vendor IdP risk event) accumulate per session, principal and window; several on one session is the canonical case, and one geography or ASN change alone never is. Past a strength threshold they become one finding that lists every contributing signal and its weight. Calibrate the threshold on the verdict corpus plus new benign twins; publish recall and the false-positive count at the chosen threshold.

**2.4 API behaviour from proxy, gateway and WAF logs.** From access logs AiSOC already ingests (WAF and CDN connectors, OTLP and syslog inputs), template request paths (`/api/users/{id}`), learn per-endpoint parameter names, value types and status codes, and raise signals for unknown parameters, type changes on a known parameter, and enumeration across templated identifiers. Off by default per tenant.

**2.5 Detection engineering agent.** Implement depth 3.7 as specified (gap-closure Phase 9, parity 6.2). Coverage gaps are ranked against the tenant's connected sources and the families above; drafts land as DRAFT proposals with fixtures and a replay backtest; nothing is promoted without a separate approver.

**Done when:** the 3.6 gate passes at 800 or more with the per-source minimums; each family above has at least one executable rule with both fixtures; 2.2 and 2.3 have published thresholds with denominators; the agent produces a backtested DRAFT for a seeded gap.

### Phase 3: Stories, not piles

**3.1 Identity resolution.** One person across IdP user, EDR device user, proxy user, cloud principal (including the human behind an assumed-role chain, already sessionized), code platform login and Workspace account. Each link carries its evidence and a confidence; a low-confidence link is shown and never used to merge. Stored in the entity store in CORE and the graph in `full`.

**3.2 Attack stories.** Build on `services/fusion/app/services/attack_chain_grouper.py` rather than beside it. Today it chains on a shared host, user or IP string; extend it to link alerts across sources when they share a resolved identity (3.1), a session, a role chain or a specific indicator within a window, and keep string-only links visibly weaker. A federated sign-in links to the originating IdP session that issued it. A story has its own severity computed from its members and Phase 1 context, and its timeline marks which actions were automated and which interactive for each actor (from 1.4's cadence classes). A member that is benign alone may be escalated by its story, and the ledger records which links did it. Measure on labelled multi-stage scenarios (phish then session reuse then cloud access; token theft then repo clone; departing employee then bulk download): story recall, and purity (no unrelated alert inside a story). v21's narrowing must hold: zero cross-rule merges on the detection-shaped cohort unless a story link justifies them, and each such link is listed.

**3.3 Root-cause dedup.** Same-fingerprint repeats are already collapsed by discarding them (the 300 s Redis check and `uq_alerts_tenant_dedup`). Keep them instead as linked occurrences on the surviving alert (count, first and last seen, the original payload ids), so a vendor repeating a finding 79 times is one alert that says 79. Then collapse findings from different vendors that share a root cause (the same resource, technique and principal reported by SCC, Security Hub, Defender for Cloud or a CNAPP connector) into one finding with every original linked. Publish the reduction this adds, separately labelled from correlation.

**Done when:** story recall and purity are published on the labelled scenarios; the alert-reduction page carries the dedup figure as its own labelled row; the before-and-after scorecard is in the PR.

### Phase 4: Triage that earns trust

**4.1 Hosted and larger models.** When the maintainer funds a key, run the verdict matrix on at least two hosted models and one larger open model through the existing attribution path. Until then the rows stay *not measured* with the one-command reproduction. Do not change the closure posture on the strength of any row.

**4.2 Reviewer pass.** After the decision contract is assembled, a separate pass re-reads it with the evidence and may escalate or demote, never close. Its prompt and output are ledgered. Ship it only if it improves balanced accuracy or auto-close precision on the corpus without lowering malicious recall; otherwise record the measurement and leave it off.

**4.3 Questions and plain-language context rules.** Tenants define questions per alert type ("was this user travelling?", "is this IP a known office?") that triage must answer from evidence or mark unanswerable. Plain-language business-context rules compile into the existing structured business-context rule schema, shown as a preview before saving; the model never receives a tenant's free text as an instruction, and rule ids stay in the injection-scanned channels.

**4.4 Precedent and re-triage.** Verify first, build only what is missing: (a) analyst reclassifications reach triage as cited precedent through similarity (semantic memory with provenance), not only the same signature; (b) an open alert is re-triaged when correlated evidence arrives, and the ledger shows the diff between verdicts.

**4.5 Vendor evidence.** For vendor-originated alerts (GuardDuty, Defender, EDR, NDR), triage pulls the vendor's own evidence through existing or new read verbs (`investigation_reads.py`) and cites it.

**4.6 Outcome evidence.** Run `make replay-eval` with a design partner's closed alerts when one exists. Publish false-positive reduction, escalation rate and time to verdict with denominators and hardware, or *not measured* with the reason.

**Done when:** each shipped change has before-and-after scorecard numbers; anything that did not improve the scorecard is recorded and off.

### Phase 5: Hunting and exploration

**5.1 Hunt from a report.** An analyst pastes text or a URL. A URL is fetched only through the existing SSRF guard, off by default per tenant, size-bounded, and the fetched text goes through the existing prompt-safety path (`services/agents/app/investigator/prompt_sanitizer.py`, `services/api/app/services/llm_safety.py`) as untrusted content. Indicators and techniques are extracted into a reviewable list with their location in the source; the model drafts a hunt in the existing closed schema (values bound as parameters, never query text); the analyst refines it in conversation; it runs across the lake and the federated SIEM backends; results can open a case with the source report attached.

**5.2 Standing hunts.** Extend `services/api/app/workers/hunt_scheduler.py` (scheduled saved hunts, Elasticsearch only today) to run against the lake and the federated backends, and to email the hunt-report PDF that 9.5 already produces through the existing report scheduler. Add the missing link from a hunt to the governed detection-proposal flow that already exists (`detection_proposals.py`: propose, evaluate, backtest, decide, promote), so a hunt can become a DRAFT proposal with its fixtures.

**5.3 An explorer that shows its work.** The Data Explorer shows the exact query it ran for every natural-language question, supports cross-filters by user, host, resource and time, a per-entity view, CSV export, and a pivot from any row into the graph.

**5.4 Software inventory for supply-chain hunts.** Answer "where does package P at version V run" from the code platform's dependency graph (SBOM) APIs through the existing connectors and from osquery package tables, including end-of-life runtimes, so a supply-chain advisory becomes a list of repositories and hosts with evidence.

**5.5 Retro-hunt at scale.** Measure a retro-hunt over a large indicator batch (at least one million indicators) on recorded hardware and publish sweep time and lake cost, or the point where it degrades.

**Done when:** a recorded public report fixture becomes a hunt that finds its seeded indicators in a fixture lake and opens a case; a scheduled hunt produces a PDF against a mail sink; every explorer answer shows its query; a package fixture resolves to repositories and hosts; the retro-hunt scale figure is published with hardware.

### Phase 6: Response that finishes

**6.1 Verb breadth.** Implement depth 5.5 as specified (at least 150 arms; AWS key deactivation and role-session revocation by token issue time and instance quarantine; GCP and Azure service-identity and refresh-token containment; Workspace and M365 OAuth-grant and app-password revocation; GitHub member, deploy key and workflow containment; Slack, Salesforce, Snowflake and 1Password user and token containment; secure web gateway URL and domain blocks). Add GitHub token revocation through the platform's credential-revocation API for a leaked token, and a read verb for secret-scanning alerts on the repositories a compromised token could reach. Each arm has a capability contract, a verification probe or recorded gap, rollback where the vendor allows it, and a mock-vendor test.

**6.2 Plain-language playbooks and a bounded model step.** Implement depth 5.6 as specified. Add one step type that asks the model a bounded question with a schema for the answer and branches on it. It cannot call a verb, its answer is ledgered, and an invalid answer takes the declared fallback branch.

**6.3 Time gates and timeouts.** Approval rules gain business-hours and on-call conditions from the tenant's schedule. Every approval step declares its timeout outcome: stay paused, roll back, or run a named limited containment that is itself a graded verb.

**6.4 Ticket sync.** Verify Jira and ServiceNow two-way sync end to end against mock vendors (case change reaches the ticket; ticket change reaches the case). Finish whichever direction is missing.

**Done when:** the arm-count gate passes at 150 or more, every new arm has its contract test, and a playbook using the bounded step and a timeout outcome runs end to end in preview.

### Phase 7: AI agent security

**7.1 Provider coverage.** Implement depth 6.3 as specified. Add enterprise AI-chat compliance logs where a provider offers a compliance API: store users, roles, projects and audit events, and for content store only classification labels (secrets, personal data, regulated, financial) and a bounded snippet, never full conversations. Off by default.

**7.2 Hosted agents and repository skills.** Inventory hosted agents through provider admin APIs (owner, model, connected tools and connectors) as a new asset kind. Through the code platform connectors, scan repositories for agent instruction files, skill directories and MCP configuration files, and record what tools and servers they reference as assets linked to the repository. Both new kinds go through the existing `score_risk` exposure score and sanctioned state, with their reasons, on the AI estate page; do not add a second scoring path.

**7.3 Agent identity and baselines.** Implement depth 6.4 as specified (parity 6.7).

**7.4 AI rule pack.** Implement depth 6.5 as specified, and add: secrets or personal data labelled in AI chats; an agent process reading browser cookie or credential stores; a skill or MCP server from an unvetted source; a coding agent started with safety controls disabled; write-scope OAuth grants to unsanctioned AI apps; token-spend anomalies per key and per agent.

**7.5 AI containment.** Implement depth 6.6 as specified (provider key revocation, AI OAuth grant revocation, gateway key block, agent process kill, one approved kill-switch playbook). Add role demotion, workspace removal and spend caps where the provider API offers them, each a graded arm with rollback.

**Done when:** each new AI rule has both fixtures; the kill-switch playbook runs end to end in preview against mock providers and requires approval; hosted agents and repository skill files appear on the AI estate page with their exposure score and reasons.

### Phase 8: Coverage breadth

**8.1 CNAPP depth.** Extend the Wiz connector beyond issues to vulnerabilities, configuration findings, secrets and runtime detections where the vendor API offers them, and record the same depth check for the other registered cloud-security connectors (Orca, Prisma Cloud, Lacework, Sysdig). Use the findings as triage context (a finding on the resource the alert touched) rather than as alerts by default.

**8.2 NDR.** New connectors for ExtraHop RevealX 360 and Corelight: detections ingested with their own severity ladder mapped to the five tiers, and read verbs for flow and protocol metadata so Phase 4.5 can pull network evidence.

**8.3 Enrichment per tenant, cited.** `services/enrichment` already fans out to VirusTotal, AbuseIPDB, GreyNoise and commercial feeds with a Redis cache, configured per deployment, and fusion calls it on every alert (`services/fusion/app/services/alert_enricher.py`). Make each provider a per-tenant opt-in with the tenant's own key in the credential vault; apply the `RATE_LIMIT_*` settings it reads and never enforces; make every enrichment result that triage uses a ledger citation with provider and time; add the URLScan client its config already names and one breached-credential exposure source. Never send anything a tenant has not enabled, and say plainly in the docs that enrichment needs the `full` profile.

**8.4 Scale and deployment evidence.** Finish the first depth plan's 4.4 cloud-hardware run and 4.5 managed-cluster run, published with hardware, date and commit, or recorded as blocked with exactly what is needed.

Every connector added in this plan ships with a profile, the rules Phase 2 asks of its source, setup docs and a mock-vendor test. Do not chase a connector count.

**Done when:** each connector passes its live-vendor-smoke-shaped test, and the connector count gate is regenerated, not edited.

### Phase 9: Analyst surfaces

**9.1 Voice that can act.** Voice input does not exist yet: `apps/mobile/src/lib/voice.ts` is an interface and a client with no recogniser behind it and no screen using it. Add an on-device speech recogniser that satisfies that interface (refusing, as the interface already requires, when no offline model is present), a screen that uses it with the transcript shown before sending, then on-device text-to-speech read-back, then approving or rejecting a pending response by voice after on-device biometric step-up, showing the exact action before confirming. No audio leaves the device; extend `scripts/check_no_audio_egress.py` to cover the recogniser package and speech output.

**9.2 Device evidence.** Finish depth 9.6: a real handset runs the voice path and receives a real push once the maintainer provides the Apple and Google accounts and push credentials. Until then the README keeps saying it has not happened.

**9.3 Internationalisation.** Implement parity 4.6 as specified: a pilot locale, RTL, locale-aware formatting and a missing-keys gate. Voice recognition and read-back follow the console locale.

**9.4 Teams war rooms.** Finish depth 9.4's Teams half once the maintainer registers the Teams app.

**9.5 Operator pages.** Implement parity 4.5 as specified (the first depth plan's 8.1 sub-item 4.5); the claim-to-gate matrix row that says they are not built moves to GATED only with its gate.

**Done when:** a voice approval runs end to end on an emulator with step-up and its ledger entry names the approver and channel; the i18n gate is green on the pilot locale; the operator pages' claim row is GATED.

### Phase 10: Close the books

Re-run every claim row touched; regenerate every figure; update `DEPTH2_PROGRESS.md` and the cross-references in `DEPTH_PROGRESS.md`; one `[Unreleased]` CHANGELOG entry per phase in the repository's measured style (what was absent, how it was measured, the gate that keeps it fixed); a final report in `DEPTH2_PROGRESS.md` listing every item as done, deviated or blocked with exactly what is needed. This phase also closes the first depth plan's Phase 10, so `DEPTH_PROGRESS.md` ends with every item done, carried here, or blocked.

### Parallel lanes

- **Lane A (identity):** 1.1, 1.2, 1.4, 1.5, then 3.1.
- **Lane B (sources):** 1.3, 1.6, 8.1, 8.2, 8.3, 8.4.
- **Lane C (detection):** 2.1 to 2.5, starting after 1.3 and 1.6 land for the families that need them.
- **Lane D (response):** 6.1 to 6.4, then 7.5.
- **Lane E (AI security):** 7.1 to 7.4.
- **Lane F (analyst):** 4.x, 5.x, 9.x, with 3.2 and 3.3 after Lane A's 3.1.
Lanes claim migration and ADR numbers in the progress file first. Lanes touching `services/fusion` confidence or priority scoring rebase on each other and combine changes, never take one side.

### Maintainer actions (blocked until provided)

- A funded hosted-model key (4.1).
- A design partner willing to replay closed alerts (4.6).
- Apple and Google developer accounts and push credentials (9.2).
- The Teams app registration (9.4).
- Sandbox tenants or recorded payloads for Workday, BambooHR, Rippling, Intune, Kandji, ExtraHop, Corelight and the CNAPP vendor's newer APIs, where public references are not enough to build the mock.

### Out of scope

A managed detection service, a smartwatch app, store publishing, headline marketing figures that nobody measured, and any change that makes autonomy or closure the default.
