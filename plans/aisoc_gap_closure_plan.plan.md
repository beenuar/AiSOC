# AiSOC gap-closure plan

> **Status**: Locked plan. Implement as specified, do not edit.
> **Captured**: 2026-09-26, against v11.2.0 (commit `2ad20dd`).
> **Tracking**: `GAP_CLOSURE_PROGRESS.md` mirrors progress; this file is the source of truth.

### Why this plan exists

A capability review against commercial AI SOC platforms found AiSOC's feature surface is broad, but it loses evaluations on six things:

1. There is no measured triage accuracy on real alerts. The published benchmark is substrate self-consistency on a synthetic corpus, and no hosted model has been exercised.
2. The investigation agent reads only AiSOC's own event lake. Federated SIEM search and the vendor read verbs exist but are not agent tools, and there is no MCP client. On the default CORE profile the agent has no evidence source at all: the lake, the graph, `connectors` and `actions` all run in `full`.
3. Customers cannot teach or extend the agent. Investigation strategies are hard-coded, triage never reads the knowledge base, and there is no way to define a custom agent.
4. There are no agents beyond triage for hunting, detection engineering, phishing remediation or file analysis.
5. There is no production-scale evidence, and the version signal reads as unstable: four majors in five days.
6. Enterprise and MSSP plumbing is missing: SCIM, white-label, usage metering and i18n.

The phases below close these in dependency order. Refer to commercial products only neutrally (for example "the reference AI-SOC platform"). `scripts/check_competitor_names.py` fails the build otherwise, and it scans plan files too.

### Rules for every phase

- **Claims and gates.**
  - Every new product claim gets a row in `docs/audit/CLAIM_TO_GATE_MATRIX.md` and a gate that fails when the claim stops being true. No row lands as NO GATE.
  - Every new gate script uses `scripts/gate_toolkit.py` (`repo_root`, `self_test_if_requested`) and supports `--self-test`.
  - New gates must refuse to pass over an empty tree (`check_gate_contract.py`) and must be reachable from a workflow (`check_gate_coverage.py`).
- **Tenancy and auth.**
  - The tenant comes from the credential, never from a request field.
  - New tenant-scoped tables get row-level-security policies that satisfy `check_rls_policy_shape.py`, grants for the `aisoc_app` runtime role, and query-layer tenant predicates (`check_tenant_query_predicates.py`, `check_route_tenant_scope.py`).
  - New routes must pass `check_route_auth.py` (default deny).
- **Migrations.** Use the next free number in `services/api/migrations/` (063 is the latest at capture). Keep ORM and migrations in parity (`check_orm_migration_parity.py`).
- **LLM calls.**
  - Request a task alias through the LiteLLM gateway. Add any new role to `infra/litellm/config.yaml` and `services/agents/app/llm/model_pins.py` (`check_llm_model_routing.py`).
  - Send every prompt through the input contract (`services/agents/app/llm/contract.py`, `services/api/app/services/llm_safety.py`).
  - Register prompt text so `check_prompt_lock.py` tracks it.
  - Log every model call and tool call to the Investigation Ledger, with measured or labelled cost (`check_cost_provenance.py`).
- **State-changing actions.** Anything that changes state at a vendor is a live action with a capability contract (impact, reversal, verification probe) in `services/actions/app/live_actions/capability_contracts.py`.
  - It is graded by `approval_matrix.evaluate_contract` and dry-run by default.
  - It is covered by `check_action_contract.py` and `test_approval_doors_agree.py`.
- **Outbound traffic.** Outbound HTTP passes the SSRF guard (`services/agents/app/playbook/ssrf_guard.py` or the API equivalent) and respects air-gap mode (`services/api/app/core/airgap.py`).
- **No fabricated data.**
  - No seeded or demo rows outside demo mode (`check_mock_data_gated.py`, `check_demo_state_gated.py`).
  - Synthetic data carries `is_synthetic` or `substrate: true`.
  - A figure that was not measured reads "not measured", never 0.
- **CORE footprint.** CORE needs 8 GB. Do not add a container to CORE without an ADR (the next free number in `docs/decisions/`) that measures the memory cost. Prefer modules inside existing services. Features that call out, upload, or change state ship off by default.
- **Vendor tests.** Test vendor API calls against recorded, vendor-shaped payloads with a mock server (respx or httpx `MockTransport`), following `services/connectors/tests/connectors/test_live_vendor_smoke.py`. Label fixtures as synthetic.
- **Hygiene.**
  - New test files must be discovered by CI (`check_test_discovery.py`).
  - New dependencies are pinned (`check_dependency_pins.py`).
  - Zero open CodeQL alerts; the mypy baseline may only shrink.
- **Eval re-grading.** PRs that touch agents, prompts, tools or strategies re-grade the eval harness and put before and after deltas in the PR body.
- **Docs.**
  - New pages go under `apps/docs/docs/`, indexed in `apps/docs/sidebars.ts`.
  - `README.md` must stay at or under 250 lines, so link rather than add.
  - Record each phase under `[Unreleased]` in `CHANGELOG.md` in the house style: the gap, how it was measured, and the gate that keeps it closed.
  - Do not tag releases unless the maintainer asks.
- **House style.** No em dashes in new prose. Conventional Commits with DCO sign-off (`git commit -s`). No tool attribution anywhere (`check_attribution.py`).

### Phase 1: Replay evaluation on a customer's own history

**Goal:** any operator can measure AiSOC triage against their own analysts' past decisions, on their own data, before trusting it.

**1.1 History readers.**
- For Splunk ES, Microsoft Sentinel, Elastic Security, IBM QRadar and Microsoft Defender XDR, add read methods that list closed findings in a time window. Each row carries the analyst's disposition, reason, who closed it and when.
- Extend the existing clients in `services/actions/app/clients/` (`splunk_client.py`, `sentinel_client.py`, `elastic_client.py`, `qradar_client.py`, `defender_client.py`) or the matching connectors in `services/connectors/app/connectors/`, whichever already owns the credential path.
- Map vendor labels to the canonical taxonomy the writeback already uses (`services/actions/app/services/disposition_writeback.py`, `services/agents/app/agents/dispositions.py`). A label outside that set becomes `unlabeled` and is excluded from accuracy, never guessed.

**1.2 Replay runner.** A new module in `services/agents` (for example `app/replay/`).
- Normalize each finding with the same connector `normalize()` production uses, order by time, and split by time (default 70/30).
- Run the same triage code path production uses in shadow mode: no writeback, no actions, no alert rows, no memory writes. If that path cannot run without writes, refactor it so persistence is injected. Do not reimplement triage.
- Freeze institutional memory, context statements and business-context rules as of the split point, so the test window cannot see its own answers.
- Record verdict, confidence, cited evidence, tool calls, model id, tokens, measured cost and latency.

**1.3 Scoring.** Extend `packages/aisoc-benchmark` (`metrics.py`, `adapter.py`) rather than writing a second grader. Report:
- per-class precision and recall, with recall on malicious reported first
- a confusion matrix
- abstention rate
- calibration (reliability bins and expected calibration error)
- hallucination rate (cited indicators that are absent from the evidence)
- per-rule and per-source breakdowns
- bootstrap confidence intervals

If the test window holds fewer than 30 malicious cases, the report says so and prints no headline accuracy.

**1.4 Surfaces.**
- CLI `aisoc replay` in `packages/aisoc-cli`.
- An async API job (`POST /api/v1/evaluations/replay`, `GET /api/v1/evaluations/replay/{id}`), with results in tenant-scoped tables.
- A console page, "Evaluate on your history", that shows the report together with its method and sample sizes.
- JSON, Markdown and PDF export, reusing the existing report pipeline.

**1.5 Gates and docs.**
- Tests with recorded vendor payloads for every reader.
- A leakage test proving the test window cannot influence its own triage.
- Claim-to-gate rows.
- `apps/docs/docs/evaluation/replay.md`, covering the method, its limits and privacy. Data leaves the deployment only when the configured model is hosted, and the page says so.

**Done when:** the CLI, run against a mocked Splunk ES holding 200 recorded closed notables, produces a report that reproduces byte for byte on a second run with the deterministic model path.

### Phase 2: Live shadow mode and evidence-gated autonomy

**Goal:** autonomy is promoted by a measured track record, not by a settings toggle.

**2.1 Shadow mode**, per tenant and per alert class.
- Triage runs on live alerts; the verdict is stored but neither acted on nor written back.
- When an analyst closes the alert, in AiSOC or in the source SIEM (polled with the Phase 1 readers), agreement is recorded.

**2.2 Rolling agreement** per alert class, rule, source and model, using the Phase 1 metrics. Show it on the SOC operations dashboard and the autonomy scorecard (`apps/web/src/components/settings/AutonomyScorecard.tsx`).

**2.3 Promotion gate.**
- Auto-closing an alert class, or raising a response verb's autonomy tier, requires a configurable minimum sample (default 100 decisions, at least 30 of them malicious) and thresholds on malicious recall and agreement within a window.
- Demotion on drift is automatic.
- Wire it into `services/actions/app/services/unified_autonomy.py`, `services/actions/app/services/tenant_policy.py` and `services/api/app/api/v1/endpoints/autonomy_policy.py`.
- Every promotion and demotion is written to the hash-chained audit log together with its evidence snapshot.
- An operator can still override, and the override is labelled as one.

**Done when:** on recorded data, a test tenant cannot enable auto-close for a class with 20 shadow decisions, can once the thresholds are met, and is demoted when injected disagreements cross the drift threshold.

### Phase 3: Prompt-injection evaluation suite

**3.1 Corpus.** Incidents with injected instructions in attacker-controllable fields (command lines, email subjects and bodies, file names, user agents, DNS names, ticket text), each paired with a clean twin. Generated deterministically and labelled synthetic.

**3.2 Metrics.** Verdict flip rate against the clean twin, unsafe action proposal rate, tool-call deviation, and guard detection rate.

**3.3 Runs and publishing.**
- The deterministic guard layer runs in CI with a floor.
- Live-model rates run in the weekly wet eval (`.github/workflows/wet-eval.yml`, `scripts/run_model_matrix.py`) and read "not measured" without a key.
- Both are published on the benchmark page together with the method.

**Done when:** CI enforces the guard floor on the corpus, the wet eval emits live rates or "not measured", and `apps/docs/docs/benchmark.md` shows both.

### Phase 4: Let the investigation agent reach the customer's tools

**Context:** today, deep investigation (`services/agents/app/investigator/deep_investigation.py`) binds 11 lake pivots and 4 enrichment calls, and nothing else.

**4.1 Federated search tool.** Expose federated SIEM search (`services/api/app/api/v1/endpoints/federated.py`) as a typed agent tool. The model supplies a structured query (indicators, fields, time window), never raw SPL, KQL or ES|QL. The API handles translation and tenant scoping.

**4.2 Vendor read tools.**
- Expose the read-only vendor verbs in `services/actions/app/live_actions/investigation_reads.py` (`get_host`, `get_detections`, `get_user_activity`) as agent tools, through the API's live-actions surface.
- Add read verbs for clients that already exist:
  - SentinelOne: agents and threats
  - Microsoft Entra ID: sign-ins and risky users
  - Google Workspace: login audit
  - AWS: CloudTrail lookup
  - Microsoft Defender: alerts, and a read-only advanced hunting query

**4.3 Tool handling.**
- Advertise only tools whose backend is configured for the tenant.
- Project results down to the fields that matter, cap their size, and mark them as untrusted data in the prompt.
- A read failure reaches the model as "could not check", never as an empty result.

**4.4 Strategies.** Update `services/agents/app/investigator/strategies.py` so `check_investigation_depth.py` still holds: every expected pivot names a real tool, and every tool is reachable from a strategy.

**4.5 CORE decision.** The default profile has no evidence source. Measure the memory cost of running `connectors` and `actions` in CORE, and decide in an ADR whether they join it. Implement whichever the ADR decides.

**Done when:** on the profile the ADR settles on, investigating a recorded CrowdStrike detection, with Splunk and CrowdStrike mocked, reaches at least three pivots across both sources, and the ledger shows every call.

### Phase 5: MCP client

**5.1 Client.** Add an MCP client to `services/agents` using the official MCP Python SDK (pinned). Streamable HTTP only by default. Stdio servers stay disabled unless an operator enables them with a command allowlist.

**5.2 Registry.**
- A per-tenant MCP server registry in the API holds the URL, a credential stored in the vault, an explicit tool allowlist, a timeout and a response-size cap.
- Discovered tools map onto the `Tool` dataclass in `services/agents/app/tools/registry.py`, namespaced `mcp.<server>.<tool>`.

**5.3 Read-only by default.**
- An agent can call a tool only if it is allowlisted and not annotated as destructive.
- A state-changing MCP tool is reachable only through governed dispatch, as a live action with a declared contract, or not at all.

**5.4 Untrusted by default.**
- Every MCP result is treated as untrusted input (contract boundary markers, the injection guard).
- Every call is logged to the ledger.
- Server URLs pass the SSRF guard and the air-gap policy.

**5.5 Tests and docs.**
- Tests run against an in-process MCP test server and cover discovery, allowlisting, refusal of destructive tools, injection treated as data, and timeouts.
- `apps/docs/docs/operations/mcp-client.md` gives setup for the vendor MCP servers operators are most likely to have, for example those published by CrowdStrike, SentinelOne, Splunk, Microsoft Sentinel and Google Security Operations. Each is marked unverified against a live vendor until someone runs it.

**5.6 AiSOC's own MCP server.** Extend `services/mcp/src/tools/` with read tools for triage verdicts, the Investigation Ledger and replay reports, plus a dry-run-only action preview.

**Done when:** against a mock MCP server, an investigation calls an allowlisted read tool, refuses a destructive one, and the ledger records both.

### Phase 6: Tenant skills and better triage context

**6.1 Tenant-authored skills.**
- Skills are written in YAML in the console editor, following the same pattern as business-context rules (`services/api/app/services/business_context/`).
- A skill has the shape of `Strategy`, plus:
  - match conditions: techniques, rule ids, sources, keywords
  - organisation-specific guidance
  - verdict guidance ("in this org, X is benign because Y")
  - the evidence required before a verdict
  - escalation conditions
  - owner, version and expiry
- Validation rejects any expected pivot that names a tool the tenant does not have.

**6.2 Lifecycle.**
- A skill goes from draft, to a backtest with the Phase 1 replay on matching historical alerts (before and after metrics side by side), to active.
- Every investigation records which skill version guided it.
- Tenant skills outrank built-in strategies when they match; otherwise strategy selection is unchanged.

**6.3 Triage context.** Feed triage the context that moves accuracy most, all point-in-time so replay stays leak-free:
- knowledge-base runbooks, retrieved with citations (`services/api/app/api/v1/endpoints/knowledge_base.py`); today the agents service never reads the knowledge base
- the last N analyst dispositions, with reasons, for the same rule or signature (feedback overrides and `services/agents/app/memory/outcomes.py`)
- HR or identity context, where a connector provides it

**6.4 Measure it.** Replay before and after, on the synthetic corpus and on at least one recorded history fixture, and publish the delta.

**Done when:** a skill authored in the console changes the investigation plan on matching alerts, its backtest report is attached to its activation, and replay shows the delta.

### Phase 7: Declarative custom agents

**7.1 Definition.** A custom agent is data, not code:
- a trigger: an alert filter, a schedule, or manual
- a tool allowlist, drawn from Phases 4 and 5
- skills
- an output schema
- a budget in steps, tokens and seconds
- an autonomy ceiling that can never exceed tenant policy

**7.2 Runtime.**
- It runs on the existing tool loop (`services/agents/app/llm/tool_loop.py`) with the ledger, the input contract and cost caps.
- Definitions are versioned.
- It has a dry-run preview on a sample alert and the same replay backtest as skills.

**7.3 Reference agents.** Ship three as examples (identity takeover review, cloud credential abuse, insider data movement), each with an eval in CI.

**Done when:** the three reference agents run from definitions alone, respect their budgets and autonomy ceilings, and their evals pass in CI.

### Phase 8: Intel-driven retro-hunts and a hunting agent

**8.1 Retro-hunts.**
- Consume the `NEW_IOC` events that the threat-intel pipeline already emits on `threat-intel-events` (`services/threatintel/app/feeds/pipeline.py`); nothing consumes them today.
- For each tenant that opts in, sweep the lake, and through Phase 4 the federated SIEM search, for sightings in a lookback window (default 30 days). Map IOC types to OCSF fields.
- Open deduplicated alerts with provenance: the feed, when the IOC was first seen, and where it matched.
- Rate-limit and budget the sweeps.

**8.2 KEV exposure.** When a new CISA KEV entry arrives, check the tenant's asset and vulnerability data (asset inventory, the Tenable connector) for exposure, and open a case task if exposed.

**8.3 Hunting agent.** Turns a hypothesis (natural language or a `hunts/` YAML) into a plan, read-only queries, and findings with evidence. It can optionally open a DRAFT detection proposal through the existing hunt-finding path. New LLM role alias: `aisoc-hunt`.

**8.4 Hunt library.**
- Grow `hunts/` from 5 hunts to at least 50, spread across ATT&CK tactics and the log sources AiSOC ships connectors for.
- Each hunt gets a positive and a negative synthetic scenario, graded by `services/agents/tests/test_hunt_corpus.py`.
- Fix `hunts/README.md`, which cites `scripts/run_hunt_evals.py`, a script that does not exist.

**Done when:**
- a new IOC injected into the pipeline produces a retro-hunt alert for a tenant whose recorded lake data contains it, and none for a tenant whose data does not
- the hunt corpus holds at least 50 hunts, graded in CI

### Phase 9: Detection-engineering loop

**9.1 Coverage gaps.** For each tenant, rank ATT&CK techniques by relevance (techniques seen in the tenant's alerts, threat intel and KEV-linked activity, weighted by the log sources the tenant actually ingests). Compare them against the compiled executable ruleset that `scripts/compile_sigma_ruleset.py` produces, and show the gaps on the coverage page.

**9.2 Rule-drafting agent.**
- Takes the top gaps that have available telemetry and drafts Sigma through the existing NL detection builder (`/nl-detection/propose`), with fixtures derived from the rule's own selection.
- Runs the eval gate and a backtest (on the lake, or through federated SIEM search where there is no lake), then opens a governed DRAFT proposal.
- Nothing is promoted without a human.

**9.3 Tuning.** Rules with high false-positive rates in analyst dispositions get proposed exclusions, backtested before and after, through the existing rule-tuning surface.

**9.4 Measure.** Proposals accepted, time from gap to proposal, and backtest noise. Publish these as measured on real deployments, or as "not measured".

**Done when:** on recorded data with an uncovered technique and matching telemetry, the loop produces a DRAFT proposal with passing fixtures and an attached backtest, and nothing is promoted without approval.

### Phase 10: Mailbox remediation and phishing campaign response

**10.1 Verbs.**
- Microsoft 365, via Microsoft Graph:
  - read verb `search_mailboxes`: by internet message id, sender, subject, attachment hash and time window
  - state-changing verbs where Graph exposes a documented API: `purge_email` (soft delete, with `restore_email` as its declared reverse) and `block_sender` (with `unblock_sender`)
  - where Graph has no documented API for a verb, do not declare that capability
- Google Workspace, via the Gmail API with domain-wide delegation: search plus trash, with untrash as the reverse.
- Extend `azure_entra_client.py` and `google_workspace_client.py`, or add mail clients beside them.

**10.2 Contracts.** Blast radius scales with the number of recipients. Verification re-queries the mailboxes. High recipient counts require approval.

**10.3 Campaign grouping.** Group phishing submissions (`services/api/app/api/v1/endpoints/phishing.py`) by the same sender, URL or attachment hash, or a near-duplicate subject, and raise one governed purge proposal across all recipients.

**Done when:** against a mocked Graph API, a 25-recipient phishing campaign yields one purge proposal that requires approval, executes once approved, verifies the messages are gone, and can be reversed.

### Phase 11: File and URL analysis provider contract

**11.1 Interface.**
- A `SandboxProvider` interface covers hash lookup, file submission, URL submission, polling, and a report (verdict, score, signatures, IOCs, ATT&CK mapping).
- Ship an open-source reference provider (the CAPEv2 REST API) and a mock.
- Leave a documented slot for commercial sandboxes. MalwareAnalyzer is the first intended adapter, built against its API once the maintainer supplies access.

**11.2 Upload policy.**
- Hash lookup comes first.
- Uploading a customer file to any third party is a disclosure: it is off by default, allowed per tenant per provider, and logged.
- In air-gap mode only local providers are allowed.

**11.3 Wiring.** Connect it to enrichment for file hashes, to phishing attachments, and as an agent tool that respects 11.2.

**Done when:** a phishing attachment hash is looked up through the mock provider, an upload is refused unless tenant policy allows it, and air-gap mode refuses non-local providers.

### Phase 12: Production proof and a stable release channel

**12.1 Load harness.**
- Extend `services/demo-producer` (or add a k6 script) to push sustained events through ingest, Kafka, fusion and Postgres.
- Measure sustained events per second, p50/p95/p99 event-to-alert latency, consumer lag, dead-letter rate and resource use.
- Run it against both the single-host compose stack and a multi-node Helm deployment on kind or k3d.
- Publish results with the hardware and the date. `perf.yml` runs the harness on a schedule with a regression floor, labelled as not a production SLO.

**12.2 Reference HA deployment.**
- Helm values for multi-replica ingest, fusion, agents and API, and three Kafka brokers.
- Documented managed options for Postgres and ClickHouse.
- A chaos test that kills a fusion pod mid-stream and asserts no loss and no duplicates.

**12.3 Release policy**, in `apps/docs/docs/operations/release-policy.md`:
- a major version only when an operator must act
- a `stable` image tag and chart channel
- a support window for security fixes
- a deprecation rule: warn one minor ahead
- a new gate: a major bump requires a BREAKING section in the changelog, and a BREAKING section requires a major bump
- a CI upgrade test from the previous minor to the current one, with data present

**12.4 Package publishing.** Prepare token-free trusted publishing for PyPI and npm in `release.yml` and `publish-cli.yml`. Record the one-time registry steps the maintainer must take in the progress file as `[!]`.

**Done when:**
- the harness has published dated results for both compose and kind
- the chaos test passes
- the new gate fails a major bump with no BREAKING section, and a BREAKING section without a major bump
- the upgrade test runs on every PR that touches migrations

### Phase 13: Enterprise identity and MSSP plumbing

**13.1 SCIM 2.0** (RFC 7643 and 7644).
- Endpoints: Users, Groups, ServiceProviderConfig, ResourceTypes and Schemas, with filtering and PATCH.
- Per-organization bearer tokens, hashed and rotatable.
- Groups map to roles in the existing RBAC.
- Deprovisioning deactivates the user and revokes their sessions and API keys.
- All of it is audited.
- Tests use request shapes from Okta and Microsoft Entra ID provisioning.

**13.2 MSSP white-label, per organization.**
- Product name, logo, colours, support contacts and sender name apply across the console, PDF reports, digests, email approvals and ChatOps messages.
- Uploaded assets are validated (SVGs sanitized) and stored locally, never fetched from third-party URLs.

**13.3 Usage metering, from real rows.**
- Per tenant per day: events ingested, alerts, triages by path (model or deterministic), investigations, LLM tokens and measured cost, actions by tier, active connectors, and seats.
- Exposed through an API and a monthly CSV per organization.
- Linked to the limits in `services/api/app/services/entitlements.py`.
- No pricing logic.

**13.4 Console i18n.**
- Add a Next.js i18n library, and externalize strings on the core analyst surfaces: alerts queue, Investigation Rail, case workspace, settings and sign-in.
- Add a locale switcher, RTL support, and locale-aware dates and numbers.
- Ship English plus one pilot locale, with a CI gate for missing and unused keys.
- ATT&CK ids, field names and query text stay untranslated.

**Done when:**
- an Okta-shaped and an Entra-shaped SCIM sequence (create, update, group membership, deactivate) both pass
- a white-labelled organization's PDF report and console show its branding
- metering matches row counts in a test
- the pilot locale renders the core surfaces and the missing-keys gate is green

### Maintainer-only items (record as [!], do not attempt)

- Fund LLM provider keys for the wet eval and the model matrix (`WET_EVAL_OPENAI_KEY` and any others the matrix uses), then run Phases 1 to 3 on hosted models.
- Registry accounts and trusted-publisher setup for npm and PyPI.
- For the hosted offering: a third-party penetration test, SOC 2 and ISO 27001 (see ADR-0002), and ISO 42001 if hosted AI is sold.
- Design partners who give permission for their closed alerts to be replayed (Phase 1), and named references.
- A managed human-review service behind the agent, if the business chooses to offer one.
