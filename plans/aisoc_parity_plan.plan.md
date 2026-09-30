# AiSOC parity plan

> **Status**: Locked plan. Implement as specified, do not edit.
> **Captured**: 2026-09-30, against v14.0.0 (commit `079fdb6`).
> **Tracking**: `PARITY_PROGRESS.md` mirrors progress; this file is the source of truth.
> **Relationship**: `plans/aisoc_gap_closure_plan.plan.md` stays locked. Where this plan says "implement gap-closure Phase N as specified", that plan's text governs and this one only adds to it.

### Why this plan exists

A capability review at v14.0.0 compared AiSOC with commercial AI SOC platforms and with SIEM, SOAR and XDR suites. It used the criteria buyers now rank highest: proven verdict accuracy on their own alerts (including false negatives), replayable evidence, governed autonomy, integration coverage and time to value, data control, and the security of the agent itself. AiSOC already owns the mechanisms for the top three: replay evaluation over a customer's closed SIEM alerts, the Investigation Ledger, and capability contracts with dry-run defaults. It also leads on checkable claims. It loses evaluations on four things:

1. **No measured result.** No verdict accuracy, false-positive rate or false-negative rate has been measured on the shipped default model (`llama3.2:3b`) or on any hosted model. The only live floor is groundedness over 10 synthetic incidents on `qwen2.5:0.5b`.
2. **Built but dark.** A large share of the product does not run in the default install:
   - the event lake, entity graph, UEBA and enrichment sit in the `full` profile;
   - tenant tuning never reaches the streaming engine;
   - playbooks never trigger from alerts, and their approval step is unimplemented;
   - earned `auto_close` grants and the console's closure thresholds have no reader;
   - the pseudonymizer is on no LLM path;
   - the hunting agent has no caller.
3. **Docs ahead of code.** Twelve documented capabilities go beyond what the code does.
4. **Missing enterprise gates and 2026 agent table stakes.** SSO does not complete a sign-in. The console has no MFA. Custom roles are honoured at 31 permission checks while about 272 read a static role map. There is no hunting, detection-engineering, custom-agent or phishing-operations agent on the default path, no semantic memory, and the MCP server is stdio-only and deployed by nothing.

The common root cause is that the gates certify functions rather than call paths: a claim row can pass on a unit test of a module nothing imports. This plan therefore makes the gates path-aware first. It then wires, governs and measures what already exists, and only then expands.

Refer to commercial products only neutrally, using the phrases in `scripts/competitor_names.toml`. `scripts/check_competitor_names.py` scans every tracked file, including plan files. Nothing scans PR text or commit messages for competitor names, so check those by hand.

### Rules for every phase

- **Inherited rules.** Every rule in "Rules for every phase" of `plans/aisoc_gap_closure_plan.plan.md` applies here verbatim: claims and gates, tenancy and auth, migrations, LLM calls, state-changing actions, outbound traffic, no fabricated data, CORE footprint, vendor tests, hygiene, eval re-grading, docs and house style.
- **Reproduce before fixing.** Each dark, broken or overclaimed item starts with a test, gate or script that fails on the current tree for the reason stated here. If it does not fail, record a Deviation and move on. Do not "fix" what you cannot reproduce.
- **Path-aware proof.**
  - A claim row this plan adds or touches must be gated by a test that drives the production call path: the worker, route or consumer that actually runs in the deployment, not a unit test of an isolated function.
  - Each such row names the profile it holds in (`core` or `full`).
- **Shipped means default-reachable.** A capability counts as shipped only if it runs under `make up` (CORE), or its claim row says `full` and a gate exercises it there. Opt-in flags are fine; flags that nothing reads are not.
- **Retract first, rebuild later.** Phase 1 narrows or removes each overclaim. A claim comes back only with the PR that makes it true, together with its gate.
- **Authorization.**
  - New routes authenticate (`check_route_auth.py`), and every state-changing route authorizes with an existing permission (`check_route_authz.py`).
  - Never write `Annotated[Any, require_permission(...)]` without `Depends`.
  - When a change lowers the number of routes with no authorization decision, lower `MAX_UNAUTHORIZED` in the same PR.
  - Role and scope grants go through `app.core.role_grants`.
- **Tenancy.**
  - The tenant comes from the credential (`user.tenant_id`, `TenantDBSession`). Any `tenant_id` input goes through `scoped_tenant_or_403`.
  - New tables follow `services/api/migrations/069_mcp_servers.sql`: a `tenant_id` NOT NULL foreign key, `ENABLE` and `FORCE ROW LEVEL SECURITY`, the policy shape `check_rls_policy_shape.py` requires, and explicit grants to `aisoc_app` in a guarded `DO` block.
  - Route modules hold no process-global mutable state.
- **Breaking changes.** Accumulate them under `[Unreleased]` with `### BREAKING`, for one planned major. Do not tag, bump `VERSION` or cut releases; the maintainer does that.
- **Numbers drift.** Re-derive these at build time; never copy them from this plan:
  - the next migration number (076 at capture, with duplicate prefixes present);
  - the next ADR number in `docs/decisions/` (0009 at capture);
  - README length (250 lines against a 250-line cap, so link rather than add);
  - ratchet ceilings (route authz 28 and tenant-predicate exceptions 35 at capture).
- **Stale guidance to ignore.**
  - CONTRIBUTING says Python 3.12, but CI and every image use 3.11.
  - CONTRIBUTING shows a four-tier severity sample, but five tiers are required: `info | low | medium | high | critical`.
  - CONTRIBUTING describes hand-written connector docs, but they are generated.
  - Toolchain: Python 3.11, Node 22, pnpm 8.15.1 with `--frozen-lockfile`, and Go as pinned in each `go.mod`.
- **House style everywhere.**
  - No em dashes in code comments, docs, commit messages or PR bodies. Nothing in CI catches this, so check yourself.
  - Conventional Commits with a scope; `!` plus a `BREAKING CHANGE:` footer when breaking; DCO sign-off (`git commit -s`).
  - No tool or assistant attribution in commits, trailers, PR bodies, code or docs.
- **Local checks before every push.**
  - `python3 scripts/check_attribution.py --commits origin/main..HEAD`.
  - These scripts under `scripts/`: `check_competitor_names.py`, `check_gate_coverage.py`, `check_gate_contract.py`, `check_test_discovery.py`, `check_route_auth.py`, `check_route_authz.py`, `check_route_tenant_scope.py`, `check_tenant_query_predicates.py`, `check_rls_policy_shape.py`, `check_orm_migration_parity.py --check` (without `--check` it only advises and always exits 0), `check_claim_gate_matrix.py`, `check_release_policy.py`, `check_comment_paths.py` and `check_mypy_baseline.py`.
  - `ruff format --check .` and `ruff check services/ scripts/ tests/ tools/`.
  - `pytest` from each touched service directory.
  - `make up && make smoke` for anything on the event path.

### Phase 1: Make every claim true on the default path

**Goal:** nothing a buyer reads in the README, docs, trust pages, roadmap or console is contradicted by a proof of value, and the gates would have caught every item in this phase.

**1.1 Retract or narrow the overclaims.** Edit each claim to match what the code does today, and add a tracker line naming the sub-item that will restore it.

| Claim | Where | Action | Restored by |
|---|---|---|---|
| "Hunting agent + 68-hunt library" ready in `full` | `README.md` maturity table | Narrow to what runs | 6.1 |
| Hosted mode pseudonymizes PII before LLM egress by default; matrix row 19, "no data exfiltration" | `docs/trust/data-flows.md`; `docs/audit/CLAIM_TO_GATE_MATRIX.md` row 19 | Retract the default-on statement; re-gate row 19 on a call-path test or downgrade it | 2.4 |
| Session, working and "institutional (PostgreSQL + pgvector, permanent)" memory | `apps/web/src/components/landing/Features.tsx` | Narrow to the reason-coded memory that exists | 6.5 |
| An `auto_close` grant lets the agent close alerts of that class without a human | `apps/docs/docs/operations/shadow-mode.md` | State that grants are recorded but not yet enforced | 2.1 |
| SAML 2.0 and OIDC for major IdPs, IdP group-to-role mapping, `SAML_IDP_METADATA_URL`, TOTP with backup codes and per-role enforcement | `ROADMAP.md`; `apps/docs/docs/operations/security.md` | Move to planned | 4.1, 4.2 |
| SOC 2 Type II evidence dashboard with PDF export; automated evidence across six frameworks including DORA | `ROADMAP.md`; `apps/docs/docs/intro.md` | Narrow to the 24 controls across 5 frameworks the API maps | 1.3 |
| Shift handoff dashboard, EASM risk scoring, MSSP executive dashboard with ARR, team analytics and gamification | `apps/docs/docs/intro.md` | Remove | None |
| "WCAG AA full accessibility pass" | `ROADMAP.md` | Narrow to the components axe covers | 4.7 |
| EU residency via per-tenant routing, `events_dist`, active-active regions, RPO and RTO targets | `docs/operations/multi-region.md` | Label as a design, not implemented | None |
| GCP KMS and Vault Transit "implement the same protocol" | `services/api/app/security/envelope_cipher.py` docstring | Correct to the backends `get_vault` accepts | None |
| Tenant skills are authored "in YAML in the console editor" | `GAP_CLOSURE_PROGRESS.md` | Correct the tracker line | 6.3 |
| ATT&CK coverage of 493 unique techniques | `marketplace/index.json` and the console coverage matrix | Report executable-rule tag coverage only, labelled as tag coverage | 5.5 |

**1.2 Clear the documentation drift.** Where a count is generated, fix the generator, not its output.
- The `playbooks/` README still says 50 playbooks.
- The hunt scheduler's docstring says default-on while its config says off.
- The detection engine's docstring says rules are indexed by product, but it evaluates the whole corpus.
- The auto-triage docstring names a `/triage/stats` route that does not exist.
- `install.sh` prints "Starting the 10-service CORE stack", and `apps/docs/docs/deployment/walkthrough.mdx` says `make up` starts fifteen CORE services. Take the real count from `docker compose config` for the CORE profile.
- The ClickHouse schema comment says "hot tier - 30 days" over a 90-day TTL.
- The upgrade guide covers only v3 to v4; add at least v10 to v14.
- The gap-closure tracker still marks file analysis as blocked, although v12.0.0 shipped the sandbox providers.
- CONTRIBUTING lists Python 3.12 and a four-tier severity sample.

**1.3 Repair the broken console paths.**
- The `/compliance/[framework]` and `/compliance/soc2` pages call routes that do not exist. The calls come from `FrameworkView.tsx`, `ComplianceHeatmap.tsx` and `SOC2View.tsx` in `apps/web/src/components/compliance/`: seven calls to four route shapes, namely `GET /compliance/{framework}` and, under it, `POST .../collect`, `GET .../export` and `GET .../heatmap`.
  - The existing routes (`services/api/app/api/v1/endpoints/compliance.py`) key frameworks as `SOC2`, `PCI-DSS`, `HIPAA`, `ISO27001` and `NIST-CSF`, not the console's slugs.
  - Point the pages at the existing routes with a slug mapping, or build the missing routes with real rows.
  - Never render a placeholder outside demo mode.
- The `/honeytokens` and `/purple-team` pages (`apps/web/src/app/(app)/honeytokens/page.tsx` and `apps/web/src/app/(app)/purple-team/page.tsx`) have no proxy rewrite and send no credentials. Add rewrites in `apps/web/next.config.js` and move the calls onto the typed `request()` client.
- The case page requests a Markdown report from a route that does not exist. Add the `report.md` route (authenticated, authorized and tenant-scoped) or remove the pane.
- `services/agents/app/main.py` registers two handlers for `GET /api/v1/investigations/{run_id}`. The one registered first reads a different store, so console status polling returns 404. Give each handler a distinct path and update the caller.
- Seven functions in the web API client target routes that do not exist and have no callers. Delete them.

**1.4 Make the gates path-aware.** Each new gate follows the gate contract: it uses `gate_toolkit`, has a `--self-test` that injects a violation, fails closed on an empty tree, prints what it scanned, and is wired into a workflow.
- Add `scripts/check_module_reachability.py`. Every module under `services/*/app` and each package's source tree must have a production importer, an entry point, or an allowlist entry with a written reason. The allowlist may only shrink.
- Extend `scripts/check_route_shadowing.py` to catch identical method and path pairs registered by different routers in one app.
- Extend the mock-data and demo-state gates to Python route modules, covering module-level lists or dicts of sample data reachable outside demo mode. Also check that route modules hold no process-global mutable containers. Skip either check if the tree already has it.
- Extend `scripts/check_claim_gate_matrix.py` so every row declares a profile (`core` or `full`) and names its gate test. Fail a row whose gate test imports a module the reachability gate reports as unreachable.
- Add a console route-contract gate so every `fetch()` or `request()` path in `apps/web/src` resolves to a backend route or a Next.js rewrite. None exists at capture: `scripts/check_ledger_replay_contract.py` covers only the ledger routes, and `scripts/check_sdk_surface.py` covers only the SDKs.

**Done when:**
- Every row in 1.1 is narrowed or retracted, with a tracker pointer.
- The console makes no call to a missing route, and a gate enforces it.
- The reachability gate reports zero unexplained modules.
- In `--self-test`, a deliberately orphaned module, a duplicate route pair, a Python demo list and an unprofiled claim row each fail their gate.

### Phase 2: Govern and protect alert closure

**Goal:** the path that closes alerts without a human obeys per-tenant policy, can be stopped instantly, learns only from humans, and never sends unredacted customer data to a hosted model.

**2.1 Per-tenant, per-class closure policy.** Today three things are wrong:
- closure uses one process-wide threshold (`AISOC_AUTO_CLOSE_THRESHOLD`, default 0.85, in `services/agents/app/agents/auto_triage_agent.py`);
- the only grant reader selects `auto_execute` on action verbs (`services/actions/app/services/tenant_policy.py`);
- the console's per-action thresholds are read only by an unused module (`services/agents/app/policy/guardrails.py`).

To fix it:
- Add a tenant-scoped closure policy table with, per alert class, an enabled flag, a threshold and an earned-grant reference. Make the fused-alert worker (`services/agents/app/workers/fused_alert_consumer.py`) read it together with the evidence-gated `auto_close` grants from shadow mode.
- Keep the global env threshold as the fallback, so the change is additive.
- Wire the console threshold editor to the new table. Delete or wire the unused guardrails path; the reachability gate decides which.

**2.2 Kill switch.** Add a database-backed switch, global and per tenant. The triage worker (closure), the actions dispatcher, playbook dispatch and the MCP write tools all check it before acting.
- Provide a console control and an API behind a dedicated permission, audited, with a reason field.
- Tripping the switch stops closure and dispatch within one poll interval, without a restart.
- Add a claim row gated by an end-to-end test.

**2.3 Learn only from humans.** Outcome priors that suppress repeat alerts (`services/agents/app/memory/outcomes.py`) must come from analyst dispositions.
- Write a human-authored prior whenever an analyst disposes an alert.
- Make the suppression lookup read those priors and the analyst override keys (`override:v2:`, `services/api/app/services/override_learning.py`).
- Stop AI-only priors from suppressing anything without analyst corroboration.
- Every prior carries its author, source alert, scope and expiry.

**2.4 Pseudonymize before hosted egress.**
- Route every hosted-model call through the reversible pseudonymizer (`services/agents/app/privacy/redactor.py`) at the LLM contract layer (`services/agents/app/llm/contract.py` and its API equivalent).
- Add a per-tenant setting: on by default for hosted providers, off for local ones. Re-identify the values in the response.
- Add a call-path gate that fails if any hosted call site bypasses the contract, and re-gate claim row 19 on it.

**2.5 One model path for every LLM call.**
- Per-tenant BYOK today wraps only the triage call and explain. Extend it to escalation, copilot, contextual actions, NL query, NL-to-detection and playbook drafting.
- Some API-service features call a hosted provider directly with an OpenAI key: `services/api/app/api/v1/endpoints/nl_query.py`, `detection_loop.py` (which hardcodes a hosted model id) and the ATT&CK embeddings. Move them onto `aisoc-<role>` gateway aliases (`services/api/app/services/model_aliases.py`, `infra/litellm/config.yaml`, `services/agents/app/llm/model_pins.py`), so they work on the local model in CORE and in air-gap mode.

**2.6 Enforced budgets.**
- Replace the per-process, in-memory budget governor (`services/agents/app/core/cost_governor.py`) with a spend window stored in Postgres and shared across replicas and restarts.
- Enforce per-alert token caps and runner tool-call budgets inside the loop (`services/agents/app/graph/runner.py`), not after it.
- An over-budget investigation ends in a labelled "budget exhausted" state that routes to a human, never in a verdict.

**Done when:**
- On recorded data, a tenant with auto-close disabled for a class sees no closure for that class, while another tenant's closures continue.
- The kill switch halts closure and a pending dispatch in an end-to-end test.
- An AI-only prior never suppresses an alert.
- A test that inspects outbound payloads to a mocked hosted provider finds no raw hostname, username, IP, domain or email from the evidence.
- Every LLM call site resolves through a gateway alias, and a gate enforces it.
- A budget breach mid-loop stops the loop.

### Phase 3: Prove verdict quality on the default install

**Goal:** publish verdict accuracy, malicious recall, false-negative counts and injection flip rates for the model AiSOC ships, measured through the production path, with "not measured" everywhere else.

**3.1 Give the default install evidence.** On CORE the investigation agent mostly receives "could not check", because the lake, graph and enrichment run in `full` (`services/agents/app/tools/customer_tools.py`).
- Match the indicators on fused alerts against the tenant's IOC store inside fusion (`services/fusion/app/services/alert_enricher.py`), with IOC expiry and decay.
- Make federated search (`services/connectors/app/federated/`, `services/api/app/api/v1/endpoints/federated.py`) and the configured vendor read verbs default evidence tools whenever a matching connector is enabled.
- Write an ADR (next number) deciding whether a lean event store joins CORE. Measure its memory against CORE's 8 GB budget before deciding, and implement only what the ADR accepts.

**3.2 Accuracy on the shipped model.**
- Point the live-agent eval (`services/agents/tests/eval_data/live_agent_floor.json` and its workflow) at the shipped default model as well as `qwen2.5:0.5b`.
- Report, through `packages/aisoc-benchmark` on labelled replay sets: verdict accuracy, per-class precision and recall, malicious recall with a confidence interval, and false-negative counts. Label synthetic sets as synthetic.
- Publish the results in `apps/docs/docs/benchmark.md` with the model id, dataset, date and commit. Hosted models read "not measured" until the maintainer funds a key.

**3.3 Behavioural injection suite.**
- Implement log-field injection families: instructions planted in usernames, command lines, URLs, email subjects, file paths and process names, plus persona hijack, fake analyst notes and fake tool output.
- Run them as a behavioural suite through the production triage path, reporting verdict flip rate and unsafe-action rate per family next to the existing guard catch rates.
- Fail CI if the flip rate regresses past a recorded floor.

**3.4 Before-and-after measurement.** Implement gap-closure tracker item 6.4 as specified.

**3.5 QA sampling of auto-closed alerts.**
- Send a tenant-configurable sample of auto-closed alerts (default 5 percent) to an analyst review queue.
- Reviewers score each on an open five-part rubric: evidence gathered, reasoning, verdict, response and report quality.
- Disagreements feed 2.3 and appear on the operations dashboard as measured closure accuracy.

**3.6 A grounded copilot.** Give the copilot (`services/agents/app/api/copilot.py`):
- the read tools the investigation agent has;
- the page context the console already sends;
- tenant-scoped persistence;
- citations to ledger entries for every factual claim. An answer with no citation is labelled uncited.

**3.7 Evidence bundles.**
- Export each investigation as a signed, replayable bundle holding the alert, evidence, tool calls, prompts by hash, model id, verdict, confidence, cost provenance and approvals.
- Map agent activity to the OCSF version the tree targets: the `ai_agent` object (added in OCSF 1.9.0), the `ai_operation` profile (added in 1.8.0), and the record-integrity profile for tamper evidence. Check each against the published schema before using it.
- Reports cite the ledger entry behind each finding.

**Done when:**
- `benchmark.md` shows measured accuracy, malicious recall, false-negative counts and flip rates for the shipped model, each with its dataset, date and commit, and "not measured" for anything not run.
- A CORE install investigating a recorded alert, with one mocked SIEM connector, reaches at least two evidence pivots.
- An evidence bundle round-trips through replay byte for byte.

### Phase 4: Enterprise identity and the operator console

**Goal:** an enterprise or MSSP security review passes on identity, access and audit, and operators never need the API for day-to-day administration.

**4.1 SSO end to end.** Today `services/api/app/auth/saml.py` and `oidc.py` put a token in a cookie the API never reads, and it names no local user, tenant or role.
- Declare `python3-saml` as a dependency in every install path.
- Provision users just in time, with tenant binding and IdP group-to-role mapping through `app.core.role_grants`.
- Issue the same bearer token the API already verifies.
- Accept IdP metadata by URL and by file.
- Add an end-to-end CI test against a containerised test IdP (for example Keycloak) for both OIDC and SAML.

**4.2 Console MFA.** Add TOTP with backup codes and WebAuthn for console sign-in, reusing the passkey code in `services/api/app/api/v1/endpoints/passkeys.py`. Support enforcement per role and per tenant, and recovery by an admin with an audit record.

**4.3 Custom roles everywhere.** `require_permission` reads a static map of built-in roles at about 272 call sites (256 dependencies and 16 direct calls), while database custom roles are consulted at 31 (`services/api/app/api/v1/deps.py`).
- Make every check consult the database role model, with a cache that is invalidated on change.
- This changes behaviour, so record it under `### BREAKING`.
- If the security batch already did this, record a Deviation and add only the console role-assignment UI.

**4.4 Audit log for tenant admins.**
- A console audit view scoped to the tenant, with filters and CSV and JSON export.
- An enforced retention job driven by the stored retention setting.
- Export to a configured destination.

**4.5 Operator pages.**
- Console pages for branding, SCIM tokens, retention, organisation members and grants, rule packs and delegations, all of which are API-only today.
- Opt-in enforcement of per-tenant limits, with a clear over-limit state. `services/api/app/services/entitlements.py` reports headroom but enforces nothing.

**4.6 Internationalisation.** Implement gap-closure 13.4 as specified.

**4.7 Accessibility on core views.** Extend axe coverage (`apps/web/src/test/a11y.test.tsx`) to the queue, alert list, case workspace, investigation rail and settings, and fix what it finds. Only then restore an accessibility claim, naming the views covered.

**Done when:**
- A CI test signs in through OIDC and through SAML, lands in the right tenant with the mapped role, and calls an authorized route.
- MFA is enforced for a role that requires it.
- A custom role grants and denies access at a route that used the static map.
- A tenant admin reads and exports their own audit log and cannot read another tenant's.

### Phase 5: Close the response and detection loop

**Goal:** the detections a tenant tunes are the detections that run, and playbooks run from alerts, with human approval wherever the contract requires it.

**5.1 Alert-triggered playbooks.** `find_matching()` (`services/agents/app/playbook/store.py`) has no production caller today. Call it from the fused-alert path behind a setting that ships off. A playbook first runs in preview, with its plan and simulated steps shown on the alert, and then goes live per tenant and per playbook.

**5.2 Approval as a durable pause.** The `approval` step (`services/agents/app/playbook/engine.py`) always fails today, and eight playbooks abort there. Implement it as a persisted pause that:
- resumes from `/approvals/{id}/decide`;
- survives restarts;
- expires with a recorded outcome;
- appears in Slack, the responder app and email approvals.

**5.3 Steps that do something.**
- Resolve `${...}` placeholders in `http` steps from connector instances and the vault, through the SSRF guard. Today 69 such steps are rejected.
- Make `notify` deliver through the configured Slack, Teams, email and PagerDuty destinations. Today 61 such steps deliver nothing.
- Fix or remove the osquery step.
- Ship the 62 pack playbooks and the YAML hunts in the agents image, gated by an image-content check.

**5.4 Tenant tuning inside fusion.** Fusion loads static JSON and never reads tenant tuning (`services/fusion/app/services/detection_engine.py`, `services/api/app/services/rule_tuning.py`), and marketplace install only sets an in-memory flag (`services/api/app/api/v1/endpoints/marketplace.py`).
- Load per-tenant suppressions, thresholds, disables, custom rules and MSSP rule packs into fusion as versioned overlays with hot reload.
- Make marketplace install write rows that fusion reads.
- A tuning change applies to that tenant only and is recorded with its author and reason.

**5.5 Rules that can fire.** 133 of the 833 native rules depend on inputs that do not exist (`scripts/check_detection_fields.py`): a windowed evaluator (74 rules), identity enrichment (24), per-tenant allowlists (15), fields nothing emits (8), first-seen enrichment (8), behavioural baselines (2) and other inputs (6).
- Build the missing inputs where that is cheap; quarantine the rest with a reason, and shrink the ratchet.
- Recompute ATT&CK coverage from executable rules only.

**5.6 Case depth.**
- Alert and case merge. The merge columns in `services/api/app/models/alert.py` have no writer.
- Bulk triage, in both the route and the UI.
- An SLA breach worker that escalates.
- Escalation routing to a tier, queue or on-call schedule. Today "escalate" only raises severity one step (`services/api/app/api/v1/endpoints/alerts.py`).
- Tenant custom fields on cases.
- Per-analyst workload metrics.

**5.7 Delivery.**
- A report scheduler that reads the stored cron and delivers. `services/api/app/api/v1/endpoints/reports.py` leaves generated reports pending.
- SMTP delivery for reports and digests.
- The email-approval sender wired up (`services/api/app/services/email_approval.py`).
- Proactive Teams approval cards. `services/teams-bot` already has the card builder and callback handler; deploy it in compose and post the cards.
- Outbound event webhooks with HMAC signatures, retries and a dead-letter view.

**Done when:**
- A matching alert starts a playbook in preview, which pauses for approval, resumes on the decision and verifies its action.
- A tenant suppression changes fusion output for that tenant only.
- A scheduled report arrives at a mock SMTP server.
- An outbound webhook is signed and retried.

### Phase 6: Agent parity, then platform depth

**Goal:** the agent capabilities buyers treat as table stakes in 2026 run in the default install. Then the platform gains the depth an overlay needs at scale.

**6.1 Hunting.**
- Wire the NL hunting agent (`services/agents/app/hunt/agent.py`) into the console and the MCP server. Today only its test imports it.
- Run the YAML hunt library against federated search or the event store instead of synthetic JSONL (`services/agents/app/hunt/scheduler.py`). Scheduled hunts create alerts through fusion.
- Keep the closed query schema: the model never writes query text.

**6.2 Detection engineering.** Implement gap-closure Phase 9 as specified:
- coverage gaps per tenant;
- drafted rules as governed DRAFT proposals, with fixtures, synthetic events and a backtest through replay;
- nothing promoted without approval.

**6.3 Custom agents.** Implement gap-closure Phase 7 as specified. Add console editors for agent definitions, tenant skills and MCP server registrations, which are API-only today. Each editor has validation, a dry run, and version history with rollback.

**6.4 Phishing operations.** Implement gap-closure Phase 10 as specified:
- reported-phish mailbox intake;
- purge and retract verbs with capability contracts;
- a blast radius scaled by recipient count;
- campaign grouping.

**6.5 Semantic memory with provenance.**
- Add vector recall on Qdrant, which already runs in CORE, for past cases, runbooks and institutional memory. Today `services/api/app/api/v1/endpoints/knowledge_base.py` uses full-text search and tag overlap.
- Every memory item carries an author, source, scope, expiry and state (in use, conflict, not in use). Conflicting items surface for analyst review before use.
- Replay shows the accuracy delta.

**6.6 MCP over the network.** The MCP server (`services/mcp/src/server.ts`) is stdio-only and deployed by nothing. Change that so that it:
- runs over streamable HTTP;
- is deployed in compose and Helm;
- authenticates with scoped API keys;
- enables tools per tenant;
- writes an audit row for every call, reads included;
- marks destructive tools as requiring approval.

**6.7 Agent identity and AI-agent baselines.**
- Give each internal agent its own identity, with short-lived credentials and least-privilege tool scopes, visible in the audit log.
- Then use the AI-agent runtime telemetry that `packages/aisoc-ai-sdk` already emits to build a per-agent behavioural baseline, with anomaly alerts for customers' own AI agents.

**6.8 Deployment completeness.**
- Helm renders and installs every CORE service. Today the chart omits connectors, actions, threat intel, the LLM gateway, Ollama and Qdrant (`infra/helm/aisoc/values.yaml`).
- Restore covers every component that backup covers (`scripts/restore.sh`).
- The connector scheduler uses leader election.
- One run on a managed cloud Kubernetes service is recorded in `docs/perf/`.

**6.9 Scale.**
- Index detection rules by log source, so fusion stops running every rule against every event.
- Concurrent triage consumers, with ordering kept per entity.
- Lag-based autoscaling hints.
- Benchmarks on cloud hardware, with results in `docs/perf/results/` and honest "not an SLO" labels.

**6.10 Collection and standards.**
- A syslog listener (RFC 5424, RFC 3164, CEF and LEEF) in `services/ingest`.
- S3 and queue-based ingestion, for example CloudTrail from S3 and SQS instead of `LookupEvents`.
- An OTLP logs receiver.
- A Kafka input.
- OCSF normalization beyond the five classes ingest emits today.
- Sigma correlation rule types in fusion.
- A real TAXII 2.1 server backed by the tenant IOC store.

**Done when:**
- The locked gap-closure plan's "Done when" criteria for Phases 7, 9 and 10 are met.
- Hunting is reachable from the console and from MCP on CORE.
- MCP over HTTP is deployed, with an audit row per tool call.
- `helm install` brings up all of CORE on kind and on one managed cluster.
- A syslog source reaches an alert through `make smoke`.

### Maintainer-only items (record as [!], do not attempt)

- Fund a hosted-model key so that 3.2 and 3.3 can report hosted results.
- Sign at least one design partner willing to replay closed alerts.
- Publish the npm and PyPI packages and the MCP server package (the names need reserving first).
- Commission an external penetration test, and SOC 2 or ISO 27001 for the hosted service.
- Add a second maintainer with merge rights.
- Decide when to cut the planned major, and the cadence of the stable channel.
