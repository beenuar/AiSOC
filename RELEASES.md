# AiSOC release notes

This file mirrors what used to live in the "What's new" section of [`README.md`](README.md). The complete, machine-readable inventory (with file paths, env-var diffs, and per-release test counts) lives in [`CHANGELOG.md`](CHANGELOG.md).

> **TL;DR for first-time visitors:** AiSOC is on `v10.0.0`, released 2026-09-25 — a release about controls that were written and not reachable. Row-level security covered 92 tables and filtered nothing, because every service connected to Postgres as a superuser; fifty-eight routes carried no authentication at all; UEBA reported healthy and could not write an anomaly; AI triage was wired to a gateway both of its resolvers ignored. **It is a major because upgrading requires action** — services now connect as a DML-only `aisoc_app` role. Every product claim is backed by a failing CI test (claim-to-gate matrix: 143 rows — 135 GATED / 8 PARTIAL / 0 NO GATE). The latest GitHub release with notes and downloads: <https://github.com/beenuar/AiSOC/releases/latest>.

---

## What's new

`VERSION` is `10.0.0`. The **v10.0.0** release (2026-09-25) is an audit of a single shape: a control that exists, is tested, and sits on a path nothing reaches.

**Read the BREAKING section of the changelog before upgrading.** Every deployment must act on one item: services connect to Postgres as a DML-only `aisoc_app` role rather than as the schema owner, which is what makes the row-level-security policies filter. The bundled Postgres provisions it on a fresh volume; an existing volume or a managed database does not.

**v10.0.0 highlights (September 25, 2026)**
- **92 row-level-security policies filtered nothing.** Compose, CI, the Helm chart and the Terraform environment all ran every service as `POSTGRES_USER=aisoc`, which the postgres image creates as a superuser — and a superuser ignores policies even under `FORCE ROW LEVEL SECURITY`. Measured with one alert per tenant and the session bound to tenant A: the old role saw 2 rows, the new role sees 1.
- **Fifty-eight routes across four services carried no authentication at all.** Reproduced rather than inferred: an anonymous caller with no `Authorization` header created a playbook, listed all 64, **executed one**, deleted it, then read copilot conversations and ran a threat hunt. A further thirty routes let the caller name the tenant they were reading.
- **UEBA could never write a baseline or an anomaly, and reported healthy throughout.** Three schema defects on one code path, then a fourth: the baseline updater mutated a dict in place, so SQLAlchemy saw no change and left the column out of every `UPDATE`. Measured on a live stack — 36 events for one entity, all processed without error, the stored baseline frozen at `count: 1`.
- **AI triage could not reach a model, and it was not a missing key.** Compose set `LLM_GATEWAY_URL` on both services; both resolvers had been deliberately written to ignore it, so every `aisoc-<role>` alias went to a provider that cannot resolve one and the caller rendered that as "no LLM available". The gateway also moved from `full` into CORE, so a key now works with no profile change.
- **A new user who followed only the README could not log in** — the seeded address was rejected by the login route's own validator before the password was compared, and the committed hash matched no published credential. `make up` now creates an administrator and prints a generated password once.
- **Costs stopped being invented.** The tracker priced the `aisoc-<role>` *alias* against a table of hosted list prices it does not appear in, so every call fell through a default and a local completion that cost nothing was booked at `$0.000999` — a figure that reached the dashboard, the ledger and the budget circuit breaker. Every cost is now measured, labelled an estimate, or absent.

The full inventory — 188 entries, including what is knowingly still open — lives under `[10.0.0]` in [`CHANGELOG.md`](CHANGELOG.md).

---

## v9.0.0 (2026-09-23)

`VERSION` was `9.0.0`. The **v9.0.0** release (2026-09-23) is ten waves of one audit question: what in this tree exists, is tested, and has no caller?

**v9.0.0 highlights (September 23, 2026)**
- **Approving an action executed nothing.** `decide()` flipped a row, notified the realtime service and returned 200 without ever touching `services/actions`. The other end was missing too — nothing in the repository ever created an approval, so the queue had no producer and was structurally empty on every deployment. A queue with no producer and a queue with no pending work look identical.
- **The confidence x impact approval matrix had zero production callers.** Written, documented, unit-tested and listed in the claim-to-gate matrix as GATED, while `POST /actions` gated on blast radius alone — a property of the verb, so the same answer came back for a 40%-confidence guess and a corroborated finding. Both gates run now and the stricter wins.
- **UEBA never scored a single message.** It consumed a topic nothing in the platform writes, so fusion's UEBA confidence boost — on by default, fully built — could only ever be inert.
- **A plugin could never be rejected for a bad signature.** `_get_registered_pub_key` returned `None` unconditionally, so verification was skipped entirely. The signing path existed end to end, had a CLI command, and was incapable of saying no. There was also no registry allow-list and no digest pinning, both of which the notes claimed existed.
- **The public scoreboard was frozen for ten weeks and every check passed**, because "freshness" meant the accuracy value was current and nothing ever read the row's date.
- **Neither published Go SDK was installable** — wrong case against a case-sensitive VCS path, missing the directory prefix — and **the Helm chart did not render** until dependencies were fetched, which no documentation mentioned.
- **A native responder app**, plus the honest correction that the responder console already existed as a PWA. The native app is a distribution channel; it exists because iOS Web Push requires an installed PWA and has been unreliable even then.

Packaging stops moving the number. It slipped v8.0 to v8.1 to v8.2 for the same reason each time, so the README states a fact rather than a date, and `check_published_packages.py` reads registry state so the claim cannot go stale in either direction.

The full inventory — including what is knowingly still open — lives under `[9.0.0]` in [`CHANGELOG.md`](CHANGELOG.md).

---

## v8.1.1 (2026-09-23)

`VERSION` was `8.1.1`. The **v8.1.1** release (2026-09-23) adds no capability. It exists because an audit of how the repository is adopted — installability, architecture comprehension, data provenance, pipeline connectivity — found the quick start did not start the product.

**v8.1.1 highlights (September 23, 2026)**
- **The documented quick start never ran the product.** `./install.sh` handed off to a nine-service compose file with no ingest service, no fusion service, and `AISOC_DISABLE_KAFKA: true`. Everything visible in the console came from `seed_demo.py` writing fifteen fabricated incidents straight into Postgres, and the installer printed "AiSOC is up and running" because the compose command exited 0. It now runs `make up` — the same CORE stack the README documents and CI tests — then proves the pipeline before claiming success.
- **`make smoke` is the claim.** One real event enters ingest, travels Kafka and fusion, matches a detection, and is read back from the API, with each of the eight stages reporting independently so a break names the boundary. It reaches past nothing: no stubbed Kafka, no inserted alert. CI fails if any stage does, and separately verifies the gate fails when the pipeline is broken.
- **`services/ingest` answered `/health` unconditionally**, so "ingest is healthy" and "every event is being dropped" could both be true at once — exactly the state a broker outage produces. `/readyz` now dials Kafka; verified live at 200 up and 503 down, with a reason and the log command to run.
- **CORE is the default: ten services, roughly 6 GB**, and it is the smallest deployment that turns a real event into a real alert rather than a cut-down toy. ClickHouse, Neo4j, Qdrant, OpenSearch, enrichment and connectors moved to `full`. OpenSearch is started by `full` and read by nothing, and is recorded that way instead of appearing in a diagram.
- **Five surfaces rendered fabricated data outside demo mode** — the MSSP overview, the Copilot's reply on API error, the air-gap status endpoint, an analyst identity in Settings, and the investigation timeline. All are gated now and return honest empties otherwise.
- **Three of the eight publishable packages could not be built.** The v8.1.0 tag surfaced it, which is the credential-gated build design working: an unresolvable workspace dependency for `aisoc` and `@aisoc/mcp`, and a duplicate-path wheel failure for `aisoc-cli`. Both would have blocked the first real publish.

`make doctor`, `docs/audit/REPOSITORY_REALITY.md`, a data-flow rewrite of `docs/architecture/README.md`, and `docs/testing/CLEAN_INSTALL.md` came out of the same pass. The full inventory lives under `[8.1.1]` in [`CHANGELOG.md`](CHANGELOG.md).

---

## v8.1.0 (2026-09-23)

`VERSION` was `8.1.0`. The **v8.1.0** release (2026-09-23) delivers the wave-2 backlog and the defects auditing it surfaced.

**v8.1.0 highlights (September 23, 2026)**
- **A ChatOps approval authorized nobody.** The Slack and Teams bots verified who clicked — Slack signs every interaction payload, Teams payloads carry an HMAC — recorded that person in an audit event, and then called the actions service with no approver. The permission-tier check and separation of duties were both skipped. A bot cannot supply permissions (it knows a Slack user id and has no idea what that person may do in AiSOC), so it now asserts identity only and the actions service maps it through operator configuration. **If you use ChatOps approvals you must populate `AISOC_CHATOPS_APPROVERS` or they will be refused** — that is the intended failure.
- **The signed email-approval fallback linked to a 404.** `approval_url()` pointed at a path no router served, so the documented answer to "Slack is unreachable" failed at the moment it was needed. The route exists, and the recipient is signed into the token, because a bare signed link is a bearer credential that approves as nobody.
- **The API service had no LLM input contract at all.** Seven endpoints POSTed untrusted input straight to a provider, including a submitted email body. The rules are now shared with `services/agents` rather than reimplemented, and the no-bypass gate — which walked the AST for `.ainvoke`/`.astream` and so could not see a raw-HTTP call — has a second half.
- **One `not` rule silently discarded a tenant's entire business-context rule set** at triage, suppressions included, because two evaluators disagreed about whether `not` takes a mapping or a list.
- **A rule id named one rule in the engine and a different one in the catalogue** for 45 network rules, so an analyst looking up an id off an alert read the wrong rule's description and playbook.
- **First-run fixes.** The Codespaces quickstart could never start Docker (capabilities are granted at container creation and cannot be self-granted from an image), and service images were published amd64-only, so Apple Silicon could not pull a single one.

Packaging moves to **v8.2**. The blocker is registry credentials, not code — `release.yml` already builds, packs and would upload all eight packages — and a release cannot schedule an account action by writing a version number.

The full inventory lives under `[8.1.0]` in [`CHANGELOG.md`](CHANGELOG.md).

---

## v8.0.0 (2026-09-22)

`VERSION` was `8.0.0`. The **v8.0.0** release (2026-09-22) is the **Close the loop** release. v8.0 had been reserved for the package-publish milestone; nothing can publish without registry credentials, so the milestone was re-scoped and distribution/packaging moved out. What v8.0 does instead is close the gap between what the codebase contains and what it actually runs.

**v8.0.0 highlights (September 22, 2026)**
- **The finding worth remembering, because it repeated a dozen times:** the mechanism existed, was unit-tested, and had no caller on the path that needed it. A passing test on an uncalled function is indistinguishable from a working feature until someone traces the call graph. `evidence_fingerprint` promised volatile fields were excluded while its only caller hashed the alert row id plus the whole raw event, so no two alerts ever matched and v7.7's repeat-alert suppression could only ever report zero. `PostActionVerifier` had no caller, and its isolation probe returned `bool(device_id)` — it would have certified an uncontained host. The console wrote per-tenant L0–L4 autonomy tiers to Postgres while the dispatcher read one global environment variable. `get_entity_neighbors` accepted a `tenant_id` and never passed it to the driver.
- **Fabricated security data across 24 components.** The `AlertDetailView` catch block rendered a full invented verdict — named IP, C2 domain, "12 additional systems" — as `status: 'completed'`. `/hunt/search` always returned synthetic telemetry behind a green "Live backend" pill. All seeded and mock data is now gated behind demo mode, with honest empty, zero and error states otherwise, enforced by a new `check_mock_data_gated.py` gate.
- **Three services were fully unauthenticated** — `purple-team` (20 routes), `honeytokens` (9) and `ueba` (7) — and so was the live-action router. Default-deny landed on all four.
- **Securing the customer's AI estate** as the flagship capability: a new `ai` connector category, an `ai_gateway` connector, two ingest webhook templates mapping to OCSF `6003` and `2001`, a dependency-free SDK that hashes prompts by default while still reporting which secret shapes they contained, eight executable AI-runtime detections, and AiSOC's own MCP server as the first monitored asset.

The full inventory (every file, env-var, and test count) lives under `[8.0.0]` in [`CHANGELOG.md`](CHANGELOG.md).

---

## v7.7.0 (2026-08-04)

`VERSION` was `7.7.0`. Seven gap-closing waves, each its own PR: detection **backtesting** (`POST /rules/{id}/backtest` replays a candidate rule over real tenant-scoped lake events and reports honest `would_fire` / `hit_rate`); three **detection-authoring modes** (a Python `def rule(event)` framework with a fixture gate, an AI builder that turns natural language into Sigma plus auto-derived fixtures through the eval gate into a governed proposal, and a no-code builder); **invoking-identity least-privilege** scoping for response actions, so the authenticated principal replaces free-text `requested_by` and nobody approves their own action; self-service **data lifecycle** (per-tenant retention, a ReDoS-proof grok transform DSL, runtime custom parsers); an agentless **CSPM** scanner plus compliance auto-evidence and SSRF-guarded destinations; and a customisable **report builder**. Wave 1 wired components that existed but were never connected: auto-triage outcomes persist as per-signature institutional-memory priors, and a repeat alert matching a *trusted* prior benign disposition is auto-resolved without re-triage — human priors trusted immediately, AI priors needing corroboration, a prior true positive never auto-closing. Full inventory under `[7.7.0]` in [`CHANGELOG.md`](CHANGELOG.md).

---

## v7.6.0 (2026-07-13)

`VERSION` was `7.6.0`. The **v7.6.0** release (2026-07-13) is the **Fully-Operational AI-SOC** release — it completes the A1–E1 roadmap that made the platform work end-to-end and pushed it to competitive parity + beyond.

**v7.6.0 highlights (July 13, 2026)**
- **Phase A — the data spine flows.** A ClickHouse lake writer populates `aisoc.raw_events` from the stream (A1); a live detection-evaluation worker runs the 947-rule executable corpus against every event and emits alerts (A2); a cold `docker compose up` now ships connectors + graph-at-ingest by default, proven by an extended integration gate (A3); and the UEBA behavioral model is fused into alert scoring, making the three-model story real (A4).
- **Phase B — autonomous triage + real response.** Every fused alert is auto-triaged off the Kafka stream (copilot/read-only default) (B1); a credential resolver maps connector `auth_config` to executor params and the Phase 9a autonomy `decide()` now governs the live dispatch path, with 10 previously-unregistered vendor adapters wired (B2); rollback makes real reverse vendor calls with post-action verification and durable approval-SLA timers (B3); and Business Context Rules run on the post-fusion → pre-triage hot path (B4).
- **Phase C — parity differentiators.** Advanced Data Explorer (unified NL + SQL over the lake) (C1); Effective-Permissions resolves against a live posture snapshot collected via connector `get_resource_config` (C2); an autopilot/copilot autonomy scorecard defaulting to copilot (C3); and fuse-time attack-chain auto-grouping so related alerts collapse into one ordered incident (C4).
- **Phase D — breadth.** Eight new connectors — IBM QRadar, Exabeam, Securonix, Devo, Netskope, Windows/Sysmon (WEF), Zeek/Suricata NDR, and a generic syslog/CEF listener (D1); an AI/LLM-usage audit connector + eight `llm-*` detections + hot/cold ClickHouse lake tiering (D2); and a live-vendor mock-server smoke suite that exercises each connector's real HTTP client (D3).
- **Phase E — prove it.** The public benchmark scoreboard is now CI-gated against a deterministic live-agent MITRE-accuracy run, closing the last `NO GATE` and ratcheting `MAX_NO_GATE` to 0 (E1).

The full inventory (every file, env-var, and test count) lives under `[7.6.0]` in [`CHANGELOG.md`](CHANGELOG.md). Note that the claim-to-gate figure quoted in the v7.6.0 announcement (33 GATED / 7 PARTIAL) was the count at that time; the matrix has grown since — recount with `python3 scripts/check_claim_gate_matrix.py` rather than reading a number off this line.

---

## v7.5.0 (2026-06-29)

`VERSION` was `7.5.0`. The **v7.5.0** release (2026-06-29) is a v8.0-milestone and trust-readiness release. It tags the `AiSOC missing pieces — Phases 1–5` rollup ([PR #337](https://github.com/beenuar/AiSOC/pull/337); 25 commits, 188 files, +23 743 / -907), the four named v8.0 milestones (T3.7 NL→playbook, T3.8 design system v2 + Storybook, T4 wave-3 marketplace + 6 hardened connectors, T5.3 fidelity loaders), the marketing-shell unification on `tryaisoc.com`, the threat-actor attribution RBAC + port fix, the realtime short-lived-ticket auth, the boundary-aware KB chunker, the Terraform CI workflow + the three missing reusable infra modules (`rds`, `elasticache`, `kafka`), and a large Dependabot + security sweep — every change that landed on `main` since `7.4.0`. The full inventory lives under `[7.5.0]` in [`CHANGELOG.md`](CHANGELOG.md).

**v7.5.0 highlights (June 29, 2026)**
- **AiSOC missing pieces — Phases 1–5 rollup** ([PR #337](https://github.com/beenuar/AiSOC/pull/337)): trust-critical honesty fixes on `/sovereign` + Features + README, CI matrix expanded to 7 previously-untested Python services (~971 new test signals), coverage gates, real SOAR executors for SentinelOne EDR / PAN-OS / FortiGate / Cloudflare WAF + DNS / Splunk ES / Elastic / MDE / Entra ID / Google Workspace, real `CreateTicketExecutor` wired to Jira / ServiceNow / PagerDuty, Azure/GCP/Okta/GWS effective-permissions resolvers, managed-mode auto-provision pipeline (`infra/fly/managed/`), CI-built white-paper PDFs + 90 s Playwright screencast, the deterministic NL → ES|QL / KQL / SPL translator (**81-case eval at 100 % syntactic + 100 % semantic**), real-browser visual regression, a buyer-journey E2E, and four immutable ADRs (`docs/decisions/0001`–`0004`).
- **v8.0 milestones** — T3.7 NL → playbook generator ([#330](https://github.com/beenuar/AiSOC/pull/330)); T3.8 design system v2 + Storybook ([#331](https://github.com/beenuar/AiSOC/pull/331), restored `DraftFromPromptDialog` story in [#335](https://github.com/beenuar/AiSOC/pull/335), Storybook publicDir fix in [#336](https://github.com/beenuar/AiSOC/pull/336)); T4 wave-3 marketplace + 6 hardened connectors ([#333](https://github.com/beenuar/AiSOC/pull/333), wave-1 parity hardening in [#328](https://github.com/beenuar/AiSOC/pull/328)); T5.3 AIT-LDS + MITRE Engenuity fidelity loaders ([#332](https://github.com/beenuar/AiSOC/pull/332)).
- **Threat-actor attribution — port fix + optional RBAC.** The investigation agent's default `AISOC_THREATINTEL_URL` was `http://threatintel:8083`; the service binds **8005** — every `POST /api/v1/actors/attribute` therefore hit a port nothing listens on and silently degraded. Default corrected, docs + `AISOC_ATTRIBUTION_TIMEOUT_SECONDS` aligned, regression test added ([#327](https://github.com/beenuar/AiSOC/pull/327)). Same release ships an opt-in shared-secret gate on `/api/v1/actors/*` ([#329](https://github.com/beenuar/AiSOC/pull/329)): when `AISOC_THREATINTEL_SERVICE_TOKEN` is set, callers must present `Authorization: Bearer <token>` (constant-time compared, `401` on mismatch); when unset, the legacy unauthenticated behaviour is preserved and a startup warning is logged.
- **Marketing-shell unification on `tryaisoc.com`.** Every `/(marketing)` page plus the standalone `/not-found`, `/why-open-source`, and `/benchmark` routes now renders the same `StickyNav` + `sections/Footer` shell; the older simpler `LandingNav.tsx` and `landing/Footer.tsx` were deleted, eleven marketing pages had their per-page nav/footer JSX + imports removed, `(marketing)/layout.tsx` centrally injects the shell, and `StickyNav`'s anchors were absolutised so they resolve identically from the landing page and from any subpage.
- **Knowledge-base ingest — boundary-aware chunking with overlap** ([#321](https://github.com/beenuar/AiSOC/pull/321), closes [#277](https://github.com/beenuar/AiSOC/issues/277)). KB ingestion no longer splits mid-sentence or mid-code-fence; the new chunker prefers paragraph / sentence / code-block boundaries and applies a configurable overlap so retrieval doesn't lose context across chunks.
- **Realtime — WS/SSE authenticated via short-lived tickets** ([#246](https://github.com/beenuar/AiSOC/pull/246), closes [#239](https://github.com/beenuar/AiSOC/issues/239)). The realtime service's WebSocket and SSE endpoints now require a short-lived signed ticket that the API mints for the authenticated session, closing the unauthenticated fan-out surface that lived between `services/realtime` and `apps/web`.
- **Infrastructure — Terraform CI + missing core modules.** A Terraform workflow gates every change to `infra/terraform/**` with `init`/`validate`/`fmt -check` ([#251](https://github.com/beenuar/AiSOC/pull/251)). The three reusable modules the AWS and BYOC references were already importing — `rds`, `elasticache`, `kafka` — are now actually present in `infra/terraform/modules/` ([#252](https://github.com/beenuar/AiSOC/pull/252)) so a fresh `terraform init` against the multi-cloud skeletons no longer errors on missing sources.
- **Dependency & CI maintenance.** ~15 Dependabot landings including `next` 16.2.7 → 16.2.9, `framer-motion` 11 → 12.40.0, `cryptography` updates across services, FastAPI updates in `services/{api,actions,agents}`, `actions/checkout` v6 → v7; `aiohttp` 3.14.1 clears CVE-2026-34993 + CVE-2026-47265 ([#295](https://github.com/beenuar/AiSOC/pull/295)); pnpm audit high/critical findings cleared ([#322](https://github.com/beenuar/AiSOC/pull/322)) so the dep-bump queue could merge; a duplicate `@mdx-js/react` key that was breaking `pnpm install` on fresh clones removed ([#296](https://github.com/beenuar/AiSOC/pull/296)).

**Previously, in v7.4.0 (May 29, 2026)** — security-hardening and platform release that tagged the May 27–29 hardening wave, multi-agent routing, and the multi-cloud infrastructure skeletons that had accumulated on `main` since `7.3.1`. The full inventory lives under `[7.4.0]` in [`CHANGELOG.md`](CHANGELOG.md).
- **Security hardening** — prompt-injection sanitizer wired into the classification agents; cross-tenant isolation enforced on detection-loop suggestions and the compliance / phishing / knowledge-base endpoints; a nightly cross-tenant RBAC regression gate; `cryptography` CVEs cleared and CodeQL quality notes resolved.
- **Multi-agent routing** — `DetectAgent.process` wired to the `FusionEngine` over cross-service HTTP; `/investigate` routed through the `RouterOrchestrator` behind the `ROUTER_INVESTIGATE` flag; a Redis-backed scheduler singleton guard for in-process workers.
- **Multi-cloud infrastructure** — serverless-container Terraform skeletons for GCP (Cloud Run + Cloud SQL + Memorystore) and Azure (Container Apps + PostgreSQL Flexible Server + Cache for Redis), mirroring the AWS/EKS reference file-for-file.
- **Live dashboard & landing** — real `/metrics` data restored on `tryaisoc.com/dashboard`, API/agents machines kept warm so the dashboard no longer 500s, seed timestamps re-anchored so it never goes empty, and the landing CTAs pointed at the live dashboard.
- **Dependency & CI maintenance** — a large Dependabot sweep across the Python, JS, and Go services plus CI stabilization (Ruff cleanup, OpenAPI export permissions, lockfile dedupe).

**Hardening detail folded into v7.4.0 (May 27–28, 2026)**
- **Security Audit green** — `cryptography` floor raised to `44.0.1` to clear CVE-2024-12797 and later 42.x advisories across `services/connectors` and `services/osquery-tls`; advisories without an upstream fix are time-boxed (90-day expiry) in [`scripts/security_audit_ignores.txt`](scripts/security_audit_ignores.txt) ([#229](https://github.com/beenuar/AiSOC/pull/229)).
- **Tenant-isolation fix** — detection-loop suggestion lookups are now scoped to the caller's tenant, closing a cross-tenant read path ([#221](https://github.com/beenuar/AiSOC/pull/221)).
- **Full stack boots clean** — the reserved `window` column is now quoted and `pydantic[email]` ships in the image, so `docker compose` comes up end-to-end without manual patching ([#227](https://github.com/beenuar/AiSOC/pull/227)).
- **OpenAPI auto-export unblocked** — the spec-export CI job now has `contents: write`, so the committed OpenAPI document re-syncs on every merge ([#228](https://github.com/beenuar/AiSOC/pull/228)).
- **CodeQL quality notes cleared** — remaining low-severity CodeQL findings resolved on `main` ([#224](https://github.com/beenuar/AiSOC/pull/224)).
- **Dependency refresh** — `zod` 3 → 4.4.3 ([#225](https://github.com/beenuar/AiSOC/pull/225)), `recharts` 2 → 3.8.1 ([#209](https://github.com/beenuar/AiSOC/pull/209)), plus a Dependabot sweep across `fastapi`, `uvicorn`, `pydantic`, `structlog`, `openai`, `weasyprint`, `strawberry-graphql`, `prometheus-client`, `go-chi`, `turbo`, and `@types/react`.
- **Credits** — new Credits section thanking contributors and security researchers ([#223](https://github.com/beenuar/AiSOC/pull/223)).

**Console workbenches (v1.5 PR-1 → PR-6)** — the SOC operator surface is now a workbench, not a list.
- **Global time-window selector + topbar context** — one selector at the top of the console drives every page (Alerts, Cases, Hunts, Funnel KPIs, Pipeline Health). Persists across reloads, deep-linkable as a URL param.
- **Tenant switcher + role badge** — MSSP operators flip tenants from the topbar; the role badge makes it impossible to confuse a `viewer` session with an `admin` session. New endpoint: `GET /api/v1/tenants/me/identity`.
- **Critical severity tier** — the severity ladder is now `info | low | medium | high | critical`. Vendor-native criticals (Azure 5-tier, GCP SCC, GitHub `critical`, ServiceNow priority 1, GuardDuty ≥ 8.0, AuditD identity-destruction, K8s `cluster-admin`, Tailscale tailnet lockdown) map straight through instead of being collapsed into `high`. Confidence (`alert.confidence`, 0–100, band `low|medium|high`) is now decoupled from severity and emitted by `services/fusion` `ConfidenceScorer`.
- **Operations funnel + pipeline health** — new `/metrics/funnel` and `/health/pipeline` endpoints feed the `FunnelKpiBar` (Detected → Triaged → Investigated → Resolved) and an Efficiency Report so SOC leads can answer "where are we losing time?" without a Grafana detour. Docs: [`apps/docs/docs/console/funnel-kpis.md`](apps/docs/docs/console/funnel-kpis.md).
- **Investigation Rail (W6 / PR-4)** — `/alerts` is now a two-pane workbench with narrative, related entities (`pivotPath` deep links), 6-event mini-timeline, and structured recommended actions. Fusion writes a deterministic correlation narrative at fuse time. Docs: [`apps/docs/docs/console/investigation-rail.md`](apps/docs/docs/console/investigation-rail.md).
- **Investigation Queue workbench (PR-5 / W7)** — `/queue` is the page a Tier-1 analyst lives on: server-anchored SLA countdowns, atomic claim semantics, one-click triage actions. Docs: [`apps/docs/docs/console/queue.md`](apps/docs/docs/console/queue.md).
- **Rule Tuning workbench (PR-6 / W8)** — `/detection/tuning` ranks noisy rules by precision impact and ships one-click suppression + allow-list edits with full audit trail. Docs: [`apps/docs/docs/console/rule-tuning.md`](apps/docs/docs/console/rule-tuning.md).
- **Zero-prerequisite installer** — `install.sh` / `install.ps1` now bootstrap from a clean machine (Docker, Compose, Node, pnpm, Python) with idempotency and a graduated `uninstall.sh`. Documented in [`apps/docs/docs/installation.md`](apps/docs/docs/installation.md), surfaced as **Path 0** in the [quickstart](apps/docs/docs/quickstart.md).

**Architectural foundation (PR [#125](https://github.com/beenuar/AiSOC/pull/125))** — the graph-at-ingest and four-agent groundwork now on `main`.
- **Graph at ingest** — Neo4j entity graph (17 node labels, 14 edge types) written inline with Kafka consumption. Batched UNWIND upserts + fire-and-forget retry queue keep ingest latency budget intact. Schema doc: [`apps/docs/docs/architecture/graph-schema.md`](apps/docs/docs/architecture/graph-schema.md).
- **Four-agent rebrand** — `DetectAgent`, `TriageAgent`, `HuntAgent`, `RespondAgent` are now the public façade; back-compat aliases preserve existing imports. Funnel KPI doc: [`apps/docs/docs/console/funnel-kpis.md`](apps/docs/docs/console/funnel-kpis.md).
- **`/hunt` natural-language surface** — type a hypothesis in English, get ES|QL / SPL / KQL templates back, save and schedule the hunt. HuntAgent never writes raw queries. Saved hunts deep-link into the Investigation Rail via `pivotPath`.
- **Sixteen first-party connectors** — wave-1 (`tines`, `torq`, `falco`, `pagerduty`, `opsgenie`, `confluence_audit`) and wave-2 fixtures (`cloudflare_zt`, `sysdig`, `vault`, `snowflake`). Five severity tiers preserved end-to-end.
- **L0–L4 automation maturity model** — [`apps/docs/docs/concepts/automation-maturity.md`](apps/docs/docs/concepts/automation-maturity.md) plus the marketing surfaces. Ladder: L0 manual → L4 fully autonomous closure with human sign-off.
- **Public weekly benchmark scoreboard** — [`apps/docs/docs/benchmark-scoreboard.mdx`](apps/docs/docs/benchmark-scoreboard.mdx) reads `apps/docs/static/data/scoreboard.json`, refreshed weekly by `.github/workflows/wet-eval.yml`. Substrate rows are visually separated from wet-eval rows — substrate numbers can never be quoted as live agent performance.

**Security & correctness wave** — 12 critical/high CVE-class fixes that landed ahead of v7.4.0. See [`apps/docs/docs/operations/security.md`](apps/docs/docs/operations/security.md) for the full inventory.
- Rule-engine `eval()` RCE eliminated — conditions are parsed to a whitelisted AST in [`services/api/app/services/rules_engine.py`](services/api/app/services/rules_engine.py) ([#116](https://github.com/beenuar/AiSOC/pull/116)).
- `/hunts` and `/cases` tenant isolation enforced at the **query layer** (`WHERE tenant_id = …`), not via RLS alone ([#117](https://github.com/beenuar/AiSOC/pull/117), [#118](https://github.com/beenuar/AiSOC/pull/118)).
- CORS lockdown — a shared `cors.py` is vendored byte-identical into every Python service and refuses to start with `*` + credentials in production ([#119](https://github.com/beenuar/AiSOC/pull/119)).
- Playbook SSRF guard — every outbound `http_request` / `notify` runs through [`services/agents/app/playbook/ssrf_guard.py`](services/agents/app/playbook/ssrf_guard.py) with a cloud-metadata block list ([#120](https://github.com/beenuar/AiSOC/pull/120)).
- Plugin-manager OCI install hardening — signed manifests verified against an allow-list, image digests pinned and re-verified on every load ([#121](https://github.com/beenuar/AiSOC/pull/121)).
- Audit-log integrity (H-4 + M-12) — `actor_ip` spoofing closed via the new `TRUSTED_PROXIES` allow-list, secrets stripped from `changes`, hash-chain tamper-proofing ([#122](https://github.com/beenuar/AiSOC/pull/122)).
- `/alerts/submit` abuse + replay hardening — payload caps (events / per-event bytes / total bytes), `Idempotency-Key` header, recursive `raw_event` redaction, timestamp clamping ([#123](https://github.com/beenuar/AiSOC/pull/123)).
- Pydantic v1 → v2 settings migration ([#124](https://github.com/beenuar/AiSOC/pull/124)), bounded `eval()` + playbook timeouts ([#126](https://github.com/beenuar/AiSOC/pull/126)), one-flag dev-mode (`AISOC_DEV_MODE` — supersedes `DEV_MODE` / `SKIP_AUTH` / `AISOC_DEMO_MODE`, [#127](https://github.com/beenuar/AiSOC/pull/127)), untrusted-enrichment sanitisation before LLM ([#128](https://github.com/beenuar/AiSOC/pull/128)).
- Python CodeQL alert count on `main` driven to zero ([#133](https://github.com/beenuar/AiSOC/pull/133), [#136](https://github.com/beenuar/AiSOC/pull/136), [#137](https://github.com/beenuar/AiSOC/pull/137)); enforced as a CI gate going forward.
- First community contribution merged: [#135](https://github.com/beenuar/AiSOC/pull/135) (UEBA env-var alignment, closes [#134](https://github.com/beenuar/AiSOC/issues/134)). Every UEBA variable accepts both unprefixed (`DATABASE_URL`) and legacy (`UEBA_DATABASE_URL`) forms; unprefixed wins.

**Stage 2 / Stage 3 platform additions** — landed alongside the architectural foundation above.
- **Wazuh Indexer ingest connector** — polls `wazuh-alerts-*` over HTTPX, paginates time-windowed queries, retries on 5xx; collapses Wazuh severity into the AiSOC ladder. Docs: [`apps/docs/docs/connectors/wazuh.md`](apps/docs/docs/connectors/wazuh.md). The connector registry now declares **84 first-party connectors**.
- **auditd `file_tail` connector + `aisoc.rules` profile** — replaces the host-agent dependency for Linux endpoint visibility; 4 new detections pivot on the bundled `aisoc_*` audit keys. Docs: [`apps/docs/docs/connectors/auditd.md`](apps/docs/docs/connectors/auditd.md).
- **Live Actions dispatcher** — generic vendor/capability surface so plugins can register executors against the in-tree taxonomy (`isolate_host`, `disable_user`, `block_ip`, …) without forking. Unknown pairs return a typed `LiveActionResult(FAILED, "executor_not_found")` — never a 500. Docs: [`apps/docs/docs/concepts/live-actions.md`](apps/docs/docs/concepts/live-actions.md).
- **Deterministic NL → ES|QL / KQL / SPL translator** — replaces the template fallback in `/nl_query` with an IR + grammar validator; 50-pair gold eval set scores 100% syntactic, 100% semantic. Air-gapped by default; optional `gpt-4o-mini` enhancement falls back deterministically.
- **STIX → MISP push** — every STIX 2.1 indicator/bundle published through `/api/v1/threatintel/stix/...` can now be mirrored into the configured MISP instance. Air-gap gated, with a `?push_to_misp=true` query param and a dry-run endpoint for air-gapped audits. Docs: [`apps/docs/docs/integrations/misp-push.md`](apps/docs/docs/integrations/misp-push.md).
- **GCP Cloud Run + Cloud SQL Terraform skeleton** — serverless-first BYOC equivalent of the existing AWS module. One `terraform apply` stands AiSOC up on GCP with private-IP networking, Secret Manager, and Artifact Registry. Docs: [`apps/docs/docs/deployment/gcp.md`](apps/docs/docs/deployment/gcp.md).
- **Azure Container Apps + Postgres Flexible Server Terraform skeleton** — file-for-file mirror of the GCP skeleton for teams standardised on Azure. Container Apps for the three customer-visible services, VNet-integrated Postgres 16 + Azure Cache for Redis on private endpoints, Key Vault for secrets, ACR for images, and per-service user-assigned managed identities so each app pulls its own image and reads only its own secrets. Docs: [`apps/docs/docs/deployment/azure.md`](apps/docs/docs/deployment/azure.md).
- **Blameless case post-mortem endpoint** — `GET /api/v1/cases/{case_id}/postmortem?format=json|html` produces a deterministic retrospective covering contributing factors, detection timing/gaps, response phases, blast radius, and action items. Analyst handles are explicitly redacted from the narrative. Docs: [`apps/docs/docs/operations/case-reports.md`](apps/docs/docs/operations/case-reports.md).
- **Per-rule cross-fire FP gate** — `services/agents/tests/test_detection_fp_rate.py` replays every rule's `match_when` against every *other* rule's positive fixture; current corpus 816 native rules, worst FPR 0.49% (5% ceiling). Wired into `scripts/run_evals.py` as `suites.detection_fp_rate`.
- **Operator-facing documentation refresh** — new pages for [notifications](apps/docs/docs/operations/notifications.md), [plugin lifecycle](apps/docs/docs/plugins/lifecycle.md), and [credentials / vault rotation](apps/docs/docs/operations/credentials.md); v2.2 architecture diagram and the corrected **84-connector count** (now including Wazuh Indexer + auditd `file_tail`) rolled through every surface.

The full inventory (with file paths, env-var changes, and test counts) lives in the `[7.4.0]` section of [`CHANGELOG.md`](CHANGELOG.md).


---

## Earlier releases

- **v7.4.0** (2026-05-29) — Security-hardening and platform release. Multi-agent routing, multi-cloud Terraform skeletons (GCP / Azure mirroring AWS), restored live `/metrics` on `tryaisoc.com/dashboard`, large Dependabot + CI maintenance sweep. See [`[7.4.0]`](CHANGELOG.md) in `CHANGELOG.md`.
- **v7.3.1** (2026-05-14) — Smoke-test hotfix: idempotent migrations, new `POST /api/v1/alerts/submit` endpoint that synthesises an `Alert` row directly from a batch of OCSF events.
- **v7.3.0** (2026-05-14) — Founder-flow series (PR1–PR7): the recorded "fresh-clone to first alert" demo now runs verbatim on `main`.
- **v7.2.0** (2026-05-11) — see `CHANGELOG.md`.
- **v7.0 / v7.0.1 / v7.0.2 / v7.0.3** — Buyer-value plan (16 workstreams) plus the endpoint-telemetry wave (osquery + FleetDM + 16 native osquery detections).
- **v6.0 / v6.1** — Investigation Ledger, Ambient Copilot, Responder PWA, public eval harness, MCP server, one-shot demo, autonomous triage agents, EASM, MSSP dashboard.
- **v5.1.0** / **v3.0.0** — Initial foundation work. See `CHANGELOG.md` for the full chronological history.

For machine-readable structure (Keep a Changelog format), always check [`CHANGELOG.md`](CHANGELOG.md). For the GitHub-rendered version of any release with downloads and signed artifacts: <https://github.com/beenuar/AiSOC/releases>.
