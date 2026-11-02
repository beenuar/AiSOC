# AiSOC release notes

This file mirrors what used to live in the "What's new" section of [`README.md`](README.md). The complete, machine-readable inventory (with file paths, env-var diffs, and per-release test counts) lives in [`CHANGELOG.md`](CHANGELOG.md).

> **TL;DR for first-time visitors:** AiSOC is on `v21.0.0`, released 2026-10-31. **The eval-honesty major: the platform's published numbers now carry their own provenance, denominators and safety outcomes — and three communities' requests landed as shipped code in one wave.** Every verdict scorecard records which model *actually served* each call (gateway-verified where the gateway attests it, self-reported where only the response body says so) with an explicit provenance status — a run with missing attribution, zero real calls or a deterministic fallback can no longer be advertised as a named model's performance, and an autonomy measurement that cannot be bound to an attributed call can no longer authorize closures. The replay scorer publishes full-cohort recall (abstentions and failures stay in the malicious denominator), the four closure metrics including contamination, and reliability counts; the model matrix grades the verdict task per model with runtime, sampling and cost recorded, over a deterministic baseline floor (balanced accuracy exactly 0.250 — the number models are read against). Alert reduction now has three labelled figures instead of one flattering one: 75.3% (legacy grouping, not what production runs), 33.3% (the production key), and **24.5% on a detection-shaped cohort after the correlation fix** — a missing identifier now narrows the group instead of widening it (cross-rule merges on that cohort: 36 → 0), proven against live Redis including the creation race. The reflex path reports nine named stages and a decision contract (supporting *and* contradictory evidence, missing prerequisites, escalation reason); retro-hunt gained a rehearsal mode whose mutation boundary is enforced at the write adapter, never the prompt. The same wave shipped the **business-context plan** — tenant rules reach the triage model and impact statements must cite the rules that fired or be dropped and counted; asset criticality orders the queue, weighs fusion confidence (unknown renders *unknown*, never zero-as-evidence) and tighten-only raises approval impact on critical assets — plus the **Agentmetry ingest template** for AI coding-agent telemetry ([discussion #1577](https://github.com/beenuar/AiSOC/discussions/1577): their untested "generic-json should work" claim was verified half-true — events landed but every severity flattened to Unknown — and the bundled template fixes exactly that), and the externally contributed **ack-clock escalation bridge**. **This is the behavior change behind the major:** correlation grouping narrows on missing identifiers (future alerts only; existing incidents untouched), and the evaluation-semantics redefinition means pre-v21 scorecards are not comparable to v21 ones — there is no API break. **3 defects were fixed in this release, 15 across it and the two before** (3 here, 2 in v20.4.0, 10 in v20.3.0 — counting distinct product or CI defects named in each release's Fixed and Security sections, dependency-version advisories excluded). **Neither `stable` channel moves** — v21.0.0 is an application major, and both channel guards hold by design until a deliberate dispatch promotes them. The chart publishes as **`7.14.0`** — an `appVersion`-only move mirroring the app's step, exactly as `7.9.0` shipped the v20 major. Everything below describes v20.4.0 and earlier, which this release does not change.
>
> **Previously:** AiSOC was on `v20.4.0`, released 2026-10-30. **A fix release closing two defects a self-hoster hit the moment they turned SSO on.** Activating SSO OIDC locked the administrator out of their own tenant — 403 on users, investigations and the alert queue all at once (reported in [discussion #1568](https://github.com/beenuar/AiSOC/discussions/1568)). The cause: permissions fall back to the static role map only while a tenant holds zero role *grants*, and the bootstrap admin carries `users.role = 'admin'` with no grant row (it is created after the seed that would have backfilled one). That is harmless until the first SSO sign-in grants the provisioned user a role — which flips the whole tenant to database-backed RBAC, and from that instant the grant-less admin resolves to zero permissions. `bootstrap_admin` now grants the admin its catalog role on every startup, in an isolated session, a no-op when the catalog is unseeded, and **self-healing: a deployment already locked out recovers on the next API restart**. The same report surfaced a second bug: the alert funnel's "events of interest" count queried `aisoc.raw_events.ingested_at`, a column the lake does not have (it has `event_time` and `ingest_time`), so the query failed with ClickHouse `Code: 47` on every call and the console silently served a Postgres estimate; it now reads `ingest_time`, with a test that checks the query's columns against the committed ClickHouse DDL. Both fixes are verified against a real Postgres with the full migration chain — the lockout is reproduced in a test and then shown fixed, and the deprovisioning semantics the resolver relies on are untouched and still separately pinned. **2 defects were fixed in this release, 22 across it and the two before** (2 here, 10 in v20.3.0, 10 in v20.2.1 — counting distinct product or CI defects named in each release's Fixed and Security sections, dependency-version advisories excluded). No breaking changes; **neither `stable` channel moves**. The chart publishes as **`7.13.0`** — an `appVersion`-only move mirrors the app's minor, as `7.10.0`/`7.12.0` did before it. Everything below describes v20.3.0 and earlier, which this release does not change.
>
> **Previously:** AiSOC was on `v20.3.0`, released 2026-10-30. **The community-contributions release: six externally contributed fixes merged in one pass, the console's front door fixed, and the detection corpus made more honest again.** A clean self-hosted install's `/` rendered the project's *marketing page* — neither the dashboard nor the login page an operator expects (reported in discussion #1549); it now redirects to `/login`, which routes onward by itself (first run → setup wizard, signed in → dashboard), and a deployment that *is* the public site opts back in with the runtime `AISOC_MARKETING_HOME`. The `custom` LLM provider's model id no longer has to be typed by hand: **`POST /api/v1/llm/credentials/models` asks any OpenAI-compatible endpoint what chat models it serves** (externally contributed — the exact vendor-neutral gap the #1481 review offered), bounded, SSRF/air-gap-guarded, and the stored key goes only to the stored base URL. An external report that **1 of 12 GitHub detection rules fired on real connector output was substantially correct**: five rules re-claused to GitHub's documented audit vocabulary (the deploy-key rule matched an action that does not exist — deploy keys log as `public_key.create`), five quarantined with recorded reasons, one claim refuted with measurement, a CI gate now replays every GitHub rule through the real connector (11 findings on the pre-fix tree), and the executable count honestly moves **2,535 → 2,530**. Community fixes from [alexmateescu](https://github.com/alexmateescu) close a retry storm (deterministic gateway 400s now dead-letter on first sight; prompt bytes capped at the egress chokepoint with water-filling truncation), a saved connector 422-ing every test-connection once it had polled, fresh chatops deploys crash-looping on a missing sibling mount, playbook agent-events dialling a port realtime never served, and triage verdicts clipped mid-JSON at 512 output tokens (now 2,048, with the reliability harness moving in lockstep — its parity test going red on the one-line bump is the drift guard working). Three dependency advisories cleared (`@hono/node-server` 2.1.5, `decode-uri-component` 0.5.1, archived-SDK `zod` 4.6.6). **10 defects were fixed in this release, 22 across it and the two before** (10 here, 1 in v20.2.1, 11 in v20.2.0 — counting distinct product or CI defects named in each release's Fixed and Security sections, dependency-version advisories excluded). No breaking changes; **neither `stable` channel moves**. The chart publishes as **`7.12.0`** — nothing inside the chart directory moves except `appVersion`, and the chart's step mirrors the app's, exactly as `7.10.0` shipped v20.1.0's minor on an `appVersion`-only change (a chart *patch* is reserved for shipping an app patch, as `7.11.1` did for v20.2.1). Everything below describes v20.2.1 and earlier, which this release does not change.
>
> **Previously:** AiSOC was on `v20.2.1`, released 2026-10-28. **A security release, no breaking changes.** It closes [GHSA-9m2j-23jf-gg3p](https://github.com/beenuar/AiSOC/security/advisories/GHSA-9m2j-23jf-gg3p), a medium-severity denial of service reported by [q7256](https://github.com/q7256): the phishing header analysis scanned a reported message's `From` display name with an unanchored regex, so a long display name containing no address-like substring was re-consumed from every interior position — quadratic, measured at 33 s for 128 KB on maintainer hardware (71 s in the reporter's measurement) — and `POST /api/v1/phishing/reports`, reachable by the default analyst role via `cases:write`, runs that scan synchronously on the event loop, so **one crafted phishing report stalled every other request on the API process**, including unauthenticated health checks. The fix applies two independent bounds: a lookbehind pins each match attempt to the start of a local-part run (interior starts now fail in O(1), match set unchanged), and the display name is analysed on its first kilobyte only (RFC 5322 caps a header line at 998 octets), which also keeps the finding's stored `evidence` out of the megabyte range. 128 KB now completes in 26 ms — ~1,270× faster, and linear. The regression test was demonstrated failing on the pre-fix tree and failing again under a reverted-fix negative control; every other regex in the phishing package was audited for the same class, and the one suspicious-looking sibling was *measured* linear and deliberately left unchanged. **If you run v19.0.0 through v20.2.0 and provision analyst accounts, upgrade.** 1 defect was fixed in this release, 23 across it and the two before (1 here, 11 in v20.2.0, 11 in v20.1.0 — counting distinct product or CI defects named in each release's Fixed and Security sections, dependency-version advisories excluded). The chart publishes as **`7.11.1`**, a patch because only `appVersion` moves. Neither `stable` channel moves. Everything below describes v20.2.0 and earlier, which this release does not change.
>
> **Previously:** AiSOC was on `v20.2.0`, released 2026-10-28. **The first-run-truth release: a fresh Windows install could not boot — and nothing could see it — and the install documentation described a different product; both are fixed, with gates so neither drifts back.** `install.ps1` initialised `.env` with a plain copy of the template, which provisions an environment no real deployment would boot (`ENVIRONMENT=production` with four empty secrets is exactly what `enforce_secure_defaults` refuses), and a Postgres already on 5432 or an Ollama on 11434 — the two conflicts most likely in this audience's environment — ended the install with advice to hand-edit `docker-compose.yml`, while `README.md` promised the opposite. Both paths now run the same generators `make up` runs (`scripts/ensure_env.py`, `scripts/resolve_port_conflicts.py`), a `windows-latest` CI job proves every generated secret lands non-empty, and the installer-parity gate reads the installer's action lines rather than its help text — three of its assertions had been passing on a script that merely *mentioned* the commands. The docs sweep corrected a quickstart advertising a machine 1.5 GB smaller than the measured requirement, an installation page saying "fourteen" CORE containers (sixteen — the number word survived every digit-based check, so the profile-count gate now reads words too), and four surfaces advertising Swagger at an address the production-class stack answers 404 on. The on-ramps consolidated to ones that can prove themselves: `render.yaml` is removed (a paid one-click path to a populated console that cannot answer whether the pipeline works — no ingest, no fusion, Kafka disabled), and the devcontainer attach banner and sandbox README stopped pointing at the demo compose file whose own header says not to evaluate with it. The Jira connector moved to `GET /rest/api/3/search/jql` after Jira Cloud removed the old endpoint (410 Gone on every poll); the nightly reproducible-builds aggregator stopped reading its own matrix's designed skip as lost coverage. The image `stable`-channel guard that had **failed open** across the v19 → v20 application major — a buildx read came back empty, and "empty" was read as "first release" — now reads the registry HTTP API with three states, where a tag that is present but unreadable **blocks** the channel; the channel itself was restored to v19.0.0 by the dispatchable repair workflow, the recorded owner decision. `qs` moves to **6.17.0** via the repo-wide override ([GHSA-6pq8-jhm2-2vcw](https://github.com/advisories/GHSA-6pq8-jhm2-2vcw), medium), and the two unpatchable `deepmerge` alerts (LOW; the latest published release is inside the vulnerable range) are dismissed on recorded evidence — their only dependents are dev/build tooling merging repo-authored configs. **11 defects were fixed in this release, 34 across it and the two before** (11 here, 11 in v20.1.0, 12 in v20.0.0 — counting distinct product or CI defects named in each release's Fixed and Security sections, dependency-version advisories excluded). No breaking changes, and **neither `stable` channel moves**. The chart publishes as **`7.11.0`**. Everything below describes v20.1.0 and earlier, which this release does not change.
>
> **Previously:** AiSOC was on `v20.1.0`, released 2026-10-22. **The harness-honesty release: the measurements and safety nets around the product were made as truthful as the product itself, and one real data-loss defect in every connector's poll loop is closed.** The data-loss fix is externally contributed ([meshreyy](https://github.com/meshreyy)): ingest reports per-event normalization failures as HTTP 200 with accepted/rejected counts, and the connector scheduler advanced its checkpoint on HTTP success alone — so a partially rejected batch moved the cursor past events that were never stored, permanently and silently. The cursor now advances only when every submitted event was accepted; a rejected page is re-fetched on the next overlapping poll and deduplicated by the sink. The live-agent eval was flattering itself two ways — per-incident `asyncio.run` left the model client on a dead event loop so most incidents silently ran heuristics, and failed incidents were dropped from the sample — it now runs one loop per run, scores failures as **0 with the reason recorded**, and the 0.40 groundedness floor was re-derived under the fixed harness (it holds, now 0.04 below the lowest honest run rather than 0.13 below a flattered one). The weekly chaos store-outage legs grade real behaviour instead of artifacts of their own probe contract, which is also why the API gained unauthenticated **`GET /api/v1/health` and `GET /api/v1/health/ready`** probes (database blocks at 503, cache degrades at 200) — the redis and qdrant legs pass end to end; the postgres leg stays red **by design**, naming the services that do not yet export the store keys the contract reads ([#1446](https://github.com/beenuar/AiSOC/issues/1446) stays open). The chart `stable` channel is now guarded by **both version lines** — v20.0.0 (chart 7.9.0, not a chart major) had carried chart `stable` across an application major while every image `stable` tag correctly held at v19 — and a dispatchable repair workflow exists and was used to roll the channel back to 7.8.0, where it stays until a deliberate promotion; **this release moves neither `stable` channel**. `fastapi` moves to 0.146.0 across all 32 declaration sites and 13 locks in one change, the Oct-22 Dependabot waves are folded, and `@vitest/mocker` 4.1.12 closes CVE-2026-112949/112950 in all three npm lockfiles. **11 defects were fixed in this release, 34 across it and the two before** (11 here, 12 in v20.0.0, 11 in v19.0.0 — counting distinct product or CI defects named in each release's Fixed and Security sections, dependency-version advisories excluded). The chart publishes as **`7.10.0`**. Everything below describes v20.0.0 and earlier, which this release does not change.
>
> **Previously:** AiSOC was on `v20.0.0`, released 2026-10-21. **The security-response release: four published advisories, the SSRF guard on every connector egress path, and the dependency queue worked to zero.** Four vulnerability reports were each reproduced against a production-mode stack, fixed, and published as advisories: [GHSA-wwq7-2xvh-qgq6](https://github.com/beenuar/AiSOC/security/advisories/GHSA-wwq7-2xvh-qgq6) (cases GET routes enforced no `cases:read`, so an API key minted with only `alerts:read` could list cases and read their comments, timeline and evidence chain), [GHSA-9mc5-hqgh-j6wf](https://github.com/beenuar/AiSOC/security/advisories/GHSA-9mc5-hqgh-j6wf) (any `cases:write` holder could author a comment the console renders as an unattributed "System note"), [GHSA-898c-wxrw-hx6c](https://github.com/beenuar/AiSOC/security/advisories/GHSA-898c-wxrw-hx6c) (outbound webhooks: registration 500ed against row-level security for every tenant, and destinations were never SSRF-validated), and [GHSA-cq4g-g6wp-4m2w](https://github.com/beenuar/AiSOC/security/advisories/GHSA-cq4g-g6wp-4m2w) (a tenant-controlled connector `base_url` could reach cloud metadata, loopback and internal services from the stateless test route, resource reads and scheduled polls — the guard now sits on every construction path, and the API refuses those destinations before they are stored). **This is the breaking change:** `POST /api/v1/cases/{case_id}/comments` no longer accepts `is_system` in the request body — the server ignores the field rather than refusing the request, so existing clients keep succeeding and only generated SDK request types lose the property; system notes are written by the server itself. Supply-chain pinning tightened in both directions: the semgrep rule packs the scanner ratchet was measured with are vendored into the tree with a rules-digest arm, and the Oct-21 advisory wave (a critical `certifi`, `aiohttp`, `pillow`, the MCP SDK, and the npm floors) is cleared across every lockfile — with one recorded, expiring exception where upstream `fastembed` still caps `pillow` below the fixed version in `services/threatintel`. Four connectors (Lacework, Tines, Datadog, PagerDuty) stopped collapsing their vendor's own top severity into `high`, an OpenCTI feed client validated against a live platform joins threat intel, and the LLM gateway image is pinned to the exact version the stack was measured against after upstream deleted the floating tag it referenced. **39 defects were fixed across this release and the two before it** (12 here, 11 in v19.0.0, 16 in v18.0.0). The chart publishes as **`7.9.0`**. Everything below describes v19.0.0 and earlier, which this release does not change.
>
> **Previously:** AiSOC was on `v19.0.0`, released 2026-10-12. **The release that finished the depth plan's analyst, collection and governance phases.** Nineteen workstreams landed as one verified tree. A session now has **one producer and three stores** that cannot disagree about which session an event belongs to; a real security **posture is collected and versioned** so a detection reads the posture that was true when an event happened; behavioural **baselines moved into CORE** as a fusion module. Collection meets an estate the way it emits — an **OTLP logs receiver, a Kafka input** for customer topics, and a **real TAXII 2.1 server** over the tenant IOC store — and a **cold-tier lake query reports a cost estimate and a progress state** instead of timing out silently. The **Helm chart installs CORE** with exactly one scheduler replica leading through a Postgres lease. A playbook can **ask the person who signed in, then their manager, and branch on the signed answer**; AiSOC's own **MCP server speaks streamable HTTP**, authorized and audited per call; a case opens a **war room** that syncs decisions back; a **hunt that finds something becomes a cited report**; the **responder app is an installable build** with real APNs and FCM delivery. Governance closed the 8.1 clauses: **WebAuthn** as a console second factor enforceable per role, an **enforced audit retention window** that leaves the surviving chain verifiable, **axe accessibility** on the case workspace and alert list, and a tenant's **entitlement limit that can refuse work** when the tenant opts in. **This is the breaking change:** `PATCH /api/v1/alerts/{id}` used to answer **200 while silently dropping** any field outside its five writable ones — a success for a write that did not happen — and now answers **422** naming the field and the route that applies it. If you call that endpoint with `disposition`, `severity`, `confidence` or `snoozed_until`, read the BREAKING section before upgrading. **67 defects were fixed across this release and the two before it** (11 here, 16 in v18.0.0, 40 in v17.1.0), including **tenant deletion**, which had been impossible on any database holding audit rows because the audit immutability trigger refused the cascade its own foreign key declares. The chart publishes as **`7.8.0`**. Everything below describes v18.0.0 and earlier, which this release does not change.
>
> **Previously:** AiSOC was on `v18.0.0`, released 2026-10-09. **The release where the platform learned what it is looking at.** Until now every event from 78 of 87 connector types arrived as a generic OCSF Security Finding, and fusion promotes that class unconditionally — so a permitted DNS lookup, an allowed proxy request and a routine Windows event each became an alert indistinguishable from a real one. Ingest now carries a recorded decision for **every one of the 87 connector types**: the class its stream actually is, or the reason it stays a finding. **This is the breaking change**: `permission_conditions`, `privilege_grants` and `workload_identities` shipped as tables with no reader, and now change authorization outcomes in both directions — a condition that was inert begins denying, and an approved grant that was inert begins conferring. If you wrote rows into those tables directly, read the BREAKING section before upgrading. **Everything else is new capability.** Every event carries an activity projection — who acted, what kind of actor they were, what they did, to which resource, from where, with what outcome — with `actor.kind` derived from each vendor's own documented field rather than guessed. A 44-type event catalogue across ten sources classifies vendor event types by sensitivity, and deliberately changes neither severity nor promotion, so a one-line data edit cannot flood a queue. Detection gained a **72-rule windowed corpus** with ordered and unordered sequences and Sigma correlations: the 74 rules that needed a sliding window are all decided, 50 translated with their thresholds derived from each original's own clauses, 24 refused with a recorded reason. Rules that cannot fire fell from **119 to 2**. Collection now meets an estate the way it actually emits — an organisation CloudTrail over S3 and SQS, GCP Pub/Sub, Azure Event Hubs, and a syslog listener for appliances that speak nothing else. Playbooks gained `wait`, `parallel` and `loop` with idempotency keys, and `notify` and `osquery_live_query` became governed verbs — which is also how we found that every dry run had been reporting a completed send. Retention is the window the tenant chooses up to a 400-day ceiling, and a legal hold now outranks it in the worker rather than only in a function nothing called. Console MFA ships: TOTP against RFC 6238's own vectors, single-use recovery codes, enforceable per tenant. **64 defects were fixed across this release and the two before it** (8 in v17.0.0, 40 in v17.1.0, 16 here). The published executable-rule figure moves **down**, 2,603 to 2,511, and that is the correction rather than a regression: rules that could not fire stopped being counted as capable of it. The chart publishes as **`7.6.0`**. Everything below describes v17.1.0 and earlier, which this release does not change.
>
> **Previously:** AiSOC was on `v17.1.0`, released 2026-10-07. **A security release plus the first community-built console surface; no breaking changes.** It closes **[GHSA-w4r8-969c-67p2](https://github.com/beenuar/AiSOC/security/advisories/GHSA-w4r8-969c-67p2)**, a high-severity audit-trail forgery reported by [cqliuke](https://github.com/cqliuke): the audit middleware decoded the request's Bearer token with signature verification **off** and wrote its claims into the per-tenant tamper-evident audit chain before authentication ran — so an unauthenticated caller with a self-crafted JWT got 401 from the route and still planted any actor and any known tenant id into that tenant's chain. Reproduced against a production-mode stack (forged entry at `chain_index` 0; a no-credential control wrote nothing); the middleware now audits only the verified principal, and a failed authentication writes no row. **If your deployment's audit chain feeds compliance evidence, upgrade** — entries written by unauthenticated requests before this release are indistinguishable from real ones by content alone, so treat chain position and request logs as the tie-breaker. The feature half is the reviewed scope of a community PR by [alexmateescu](https://github.com/alexmateescu): an admin-only **Settings → Users** screen (server-side pagination/search, multi-role assignment with a live effective-permissions preview, enable/disable with session revocation, audited permanent delete guarded against self-delete and last-admin lockout), an editable Roles & Permissions catalog, and a feature-flagged enterprise SSO wave (off by default; JIT lands as `viewer`, admin is unreachable from SSO without an explicit allowlisted group mapping). Migration `091` no longer bulk-seeds a role row into every tenant — the write that could resolve a fresh install's every user, break-glass admin included, to **zero permissions** — and `093` repairs deployments the old seed already touched. Also in: threat-intel enrichment no longer drops WHOIS from non-top-scoring sources and now union-merges DNS records; the grading-integrity gate can no longer lock itself out after a merge burst (it read "no recent successful run" as a stale API read, which its own failures then perpetuated for two days); and the release step that moves the `stable` chart channel ran for the first time ever (`--version` takes a semver constraint, so `--version stable` had failed client-side on every release since the step existed). The chart publishes as **`7.5.0`**. Everything below describes v17.0.0 and earlier, which this release does not change.
>
> **Previously:** AiSOC was on `v17.0.0`, released 2026-10-05. **One breaking change and one number that changes meaning without erroring** — the second is the one to read twice. `POST /api/v1/detection-loop/suggest` and its two `GET /detection-loop/suggestions` reads are removed with their three schemas; no migration is needed because none of them ever worked, since they queried `aisoc_alerts`, `aisoc_detection_rules` and `alerts.evidence`, none of which any migration creates. The governed equivalent is `POST /api/v1/detection-proposals`. The quieter change: **`alerts.total` on `/metrics/dashboard` now counts open work** — `new`, `triaging`, `in_progress` — rather than every alert ever received, and the severity counts beside it are scoped the same way, because the console labels them *Active Alerts* and *Critical — Require immediate action*. A tenant who had resolved everything was still shown their entire historical intake as outstanding, and the number only ever rose. Closed work is now reported separately as `alerts.resolved`. **Every approval was failing**: the dispatch built its principal from two attributes `CurrentUser` has never defined, so the actions service received an empty permission list and refused, while the approval row recorded the decision — the action never ran, for any role, including platform admin. **You can now choose where the model runs**: `make up` is unchanged (CPU, no account, no key), `make up-gpu` layers an NVIDIA device reservation onto the bundled Ollama, and `make up-host-llm` uses an Ollama you already run — the only route to a GPU on Apple Silicon, since Docker Desktop cannot pass Metal into a Linux container. `GET /api/v1/llm/runtime` reports where the model *actually* is by asking Ollama rather than reading the compose file back, because a reservation is a request and a model can still land on the CPU; it answers `unknown` for an idle instance rather than guessing. `POST /api/v1/llm/credentials/test` places one real one-token call, so a revoked key is found at the moment you save it instead of surfacing later as triage quietly falling back. Closed cases can be reopened through `POST /api/v1/cases/{id}/reopen` with a recorded reason; `PATCH` stays forward-only, which is what makes "this case was closed" mean something. Investigations now reason over the alerts' real `raw_event` payloads instead of a restated title, and the groundedness gate covers that path too — refusing to score an empty evidence set rather than demoting everything and appearing to catch hallucination. A period-over-period delta of `-93.75` rendered as `-9375%`; the global time-window selector drove no fetch at all. The chart publishes as **`7.4.0`**. Everything below describes v16.0.1 and earlier, which this release does not change.
>
> **Previously:** AiSOC was on `v16.0.1`, released 2026-10-04. **A security release, no breaking changes.** It closes **GHSA-4gx4-x7gm-4xq8**, a high-severity privilege escalation reported by [HaiND](https://github.com/Haind03): the check that decides whether a caller may *confer* authority read the caller's static role, while the check that admits a caller to the route read its database-resolved permissions. Those are two different answers whenever a tenant uses database-backed RBAC — which is the configuration where it matters, since narrowing an account is what those tables are for. A `tenant_admin` deliberately restricted to `users:write` still carried 28 permissions statically and could grant itself the other 27. **If you use the `roles` and `user_roles` tables to restrict accounts, upgrade.** Deployments with no RBAC rows were never exposed, because the static map was already the correct answer for them. The report named one route; the resolver is shared, so five more had it — authoring a role, re-permissioning one, creating a user, delegating to a child tenant, and minting an API key, that last needing no target user and yielding a durable credential. `scripts/check_role_grant_scope.py` gains a direction that fails CI when a grant is measured against the wrong authority; its previous directions passed on the vulnerable tree because they asked only whether a route *reached* the chokepoint, and all six did. Also raises `serialize-javascript` to `>=7.1.2` and `http-cache-semantics` to `>=4.3.0`. The chart publishes as **`7.3.1`**. Everything below describes v16.0.0 and earlier, which this release does not change.
>
> **Previously:** AiSOC was on `v16.0.0`, released 2026-10-03. **One breaking change:** the `cases` table is gone and its rows live in `aisoc_cases`. Any SQL of your own against `cases` — a Grafana panel, a scheduled export — now fails with "relation does not exist" rather than returning stale rows, which is the intended behaviour. The theme is a single shape repeated seventeen times: **a mechanism that is complete, tested, and has no caller**, so it passes CI forever while doing nothing. SSO could not sign anyone in — `aisoc_sso_connections` was written by nothing, so every SAML and OIDC callback returned 403 on every deployment, while both handlers were fully tested. MTTA published a confident `0.0` because `alerts.first_seen_at` had no writer. The evidence chain an auditor exports was always `[]`. SLA reporting ran 350 lines of correct arithmetic over an empty table. The console's rule-Approve button could not succeed. The live agent evaluation imported a class that exists only in the historical prototype. And the two case tables never synchronised, so **every case an analyst created was invisible to every case metric** — which is the break above. Measured, not asserted: an agent answering "true positive" to everything scored **1.000** on the detection corpus and now scores **0.727**, because the benign class was derived from `response_class == "monitor"` and those incidents are BloodHound enumeration tagged T1087.002. The first live behavioural run published "unsafe action proposal rate 0.0%", which meant the agent proposed no actions at all; it now reports **not measured** and the verdict flip rate is **9.3%** from one manual run of the 200-incident synthetic corpus against a locally-served `llama3.2:3b`, which is not the model a hosted deployment resolves. New: detection lifecycle with rollback and separation of duties, content packs, alert prioritisation, case queues and escalation, legal hold and residency, workload identity and time-boxed elevation, restore paths for Neo4j/Qdrant/Redis, and inbound translation from Splunk SPL, Sentinel KQL and Elastic EQL — on the 2,005 rules bundled here, 1,734 translate and **1,711 of those only partially**. A 22-page technical guide ships as a PDF with real console screenshots. The chart publishes as **`7.3.0`**. Everything below describes v15.1.0 and earlier, which this release does not change.
>
> **Before that:** AiSOC was on `v15.1.0`, released 2026-10-03. **No breaking changes** — two routes are added and none removed, so every generated SDK client keeps working. The theme is the gap between a capability existing and a user reaching it: `v15.0.0` closed thirteen security defects sharing the shape *a control that exists, passes its tests and never runs*, and this release applies the same reading to the product. Playbooks could not act at all — `find_matching()` had no production caller, so no playbook had ever run from an alert, and the `approval` step was documented as a durable pause with nowhere to suspend to. A tenant's detection tuning never reached the streaming engine, so a rule turned off in the console kept firing. Every CloudTrail event collapsed onto a single alert, which a one-event pipeline test cannot reveal. Three things are worth reading before upgrading: **first run changed substantially** (`make up` resolves a port conflict instead of refusing to start, measured at 64 seconds from clone to signed-in console on a host with 5432 and 11434 both taken, and a new tenant lands on a setup wizard), **CloudTrail users will see more alerts**, and **the project-maturity table now means something** — `Stable` has a written definition in `docs/audit/MATURITY_DEFINITION.md` and a gate, and the two rows that claimed CI coverage which existed nowhere were fixed rather than relabelled. New: signed, replayable evidence bundles at `GET /api/v1/investigations/{run_id}/bundle`, byte-identical across exports with prompts as digests and an OCSF 1.9.0 mapping checked against the published schema before use; and a copilot that cites every checkable claim to a ledger entry or labels it **uncited**. On the benchmark page, **verdict accuracy is published as *not measured*, with the reason** — every labelled corpus here is entirely malicious by construction, so an agent answering "true positive" to everything would post 100%, and `scripts/score_replay_set.py` refuses such a corpus with a test asserting this tree's own two are refused. The chart publishes as **`7.2.0`**. Everything below describes v15.0.0 and earlier, which this release does not change.

---

## What's new

`VERSION` is `21.0.0`. The **v21.0.0** release (2026-10-31) is the
eval-honesty major: the platform's published numbers now carry their own
provenance, denominators and safety outcomes. Serving-model attribution flows
from the gateway header (verified) or the response body (self-reported,
credited only when it can witness itself) into every scorecard, ledger
exchange and eligibility decision — a run with missing attribution, zero real
calls or a deterministic fallback cannot be advertised as a named model's
performance, and an autonomy measurement that cannot be bound to an
attributed call cannot authorize closures. The replay scorer publishes
full-cohort recall (abstentions and failures stay in the malicious
denominator), the four closure metrics including contamination, reliability
counts (requested / attempted / completed / failed / unattempted) and
per-severity segments. The correlation engine's **behavior change** is the
reason this is a major: a missing identifier now narrows the group instead of
widening it — alerts with no tactic group per rule, alerts with no
identifiers never cross-rule merge — measured on a detection-shaped cohort as
reduction falling 42.6% → 24.5% while cross-rule merges fell 36 → 0, because
unrelated alerts stopped counting as grouped; the production-key headline
stays 33.3%, and a live-Redis suite (expiry, tenant boundary, restart, the
creation race fixed with `SET NX`) now runs in CI. The reflex path reports
nine named stages and a structured decision contract; retro-hunt gained a
rehearsal mode (`RETRO_HUNT_DRY_RUN`) whose mutation boundary is enforced at
the write adapter; verdict scorecards disclose the model-knowledge limit on
historical claims. The same wave landed the business-context plan (tenant
rules reach the triage model with cited impact statements; asset criticality
orders the queue, weighs confidence and tighten-only raises approval impact),
the Agentmetry ingest template for AI coding-agent telemetry (discussion
#1577 — their untested generic-json claim verified half-true and fixed by the
bundled template), the externally contributed ack-clock escalation bridge,
an annotated unsupported-claim measurement that found and fixed a real
claim-support defect, and the verdict model matrix with a deterministic
baseline floor (balanced accuracy exactly 0.250) against which every model
row is read — rows without a funded run say *not measured* with one-command
reproduction. No API breaks. Neither `stable` channel moves. The chart
publishes as **`7.14.0`**. Everything below describes v20.4.0 and earlier,
which this release does not change.

---

`VERSION` was `20.4.0`. The **v20.4.0** release (2026-10-30) closes two
defects a self-hoster hit when they enabled SSO (discussion #1568).
Activating SSO OIDC locked the administrator out — 403 on users,
investigations and the alert queue — because permissions fall back to
the static role map only while a tenant holds zero role grants, and the
bootstrap admin had no grant row until the first SSO sign-in flipped the
tenant to database-backed RBAC. `bootstrap_admin` now grants the admin
its catalog role on every startup, which also heals an already-locked
deployment on the next restart. The same report surfaced a funnel query
that filtered `aisoc.raw_events` on a non-existent `ingested_at` column,
failing with ClickHouse `Code: 47` every call and silently falling back
to a Postgres estimate; it now reads `ingest_time`. Both are verified
against a real Postgres with the full migration chain. No breaking
changes; neither `stable` channel moves; the chart publishes as
`7.13.0`. 2 defects fixed (22 across this release and the two before
it). See the TL;DR above and the `[20.4.0]` section of
[`CHANGELOG.md`](CHANGELOG.md) for the full inventory.

### Previously: v20.3.0

The **v20.3.0** release (2026-10-30) merges six
externally contributed fixes in one pass and repairs the console's
front door: a self-hosted install's `/` now lands on the console
(redirecting to `/login`, which routes onward — setup wizard on first
run, dashboard when signed in) instead of the project's marketing page,
with `AISOC_MARKETING_HOME` as the runtime opt-in for deployments that
are the public site. The `custom` LLM provider gains model discovery
(`POST /api/v1/llm/credentials/models`, externally contributed):
bounded, guarded, stored-key-scoped-to-stored-URL, and the hand-typed
id remains. The GitHub detection rules were re-claused to the vendor's
documented audit vocabulary after an external report — measured
substantially correct — that almost none fired on real connector
output; a new CI gate replays every GitHub rule through the real
connector, and the executable count honestly moves 2,535 → 2,530.
Community fixes close an inference retry storm (terminal 400s now
dead-letter; prompt bytes capped at egress), a saved-connector 422 on
every test after its first poll, a chatops crash-loop, playbook events
dialling a dead port, and 512-token verdict clipping (now 2,048, the
reliability harness moving in lockstep). Three dependency advisories
cleared. No breaking changes; neither `stable` channel moves; the
chart publishes as `7.12.0`. 10 defects fixed (22 across this release
and the two before it). See the TL;DR above and the `[20.3.0]` section
of [`CHANGELOG.md`](CHANGELOG.md) for the full inventory.

### Previously: v20.2.1

The **v20.2.1** release (2026-10-28) is a
security patch closing
[GHSA-9m2j-23jf-gg3p](https://github.com/beenuar/AiSOC/security/advisories/GHSA-9m2j-23jf-gg3p)
(medium, reported by [q7256](https://github.com/q7256)): a quadratic
regex in the phishing header analysis let one crafted report — a long
`From` display name with no address-like substring, submitted through
`POST /api/v1/phishing/reports` by any holder of `cases:write`, which
the default analyst role has — stall the whole API process for tens of
seconds, because the scan runs synchronously on the event loop. The scan
is now linear (a lookbehind pins match attempts to run starts, with the
match set unchanged) and the display name is capped at 1 KB before
analysis, which also bounds what the impersonation finding stores as
evidence. 128 KB: 33 s → 26 ms. No breaking changes; neither `stable`
channel moves; the chart publishes as `7.11.1` (a patch — only
`appVersion` moves). If you run v19.0.0 – v20.2.0 and provision analyst
accounts, upgrade. See the `[20.2.1]` section of
[`CHANGELOG.md`](CHANGELOG.md) for the full inventory.

### Previously: v20.2.0

The **v20.2.0** release (2026-10-28) makes first
run on Windows real — `install.ps1` generates `.env` secrets with the
same generator `make up` uses instead of copying a template the API
refuses to boot on, resolves port conflicts instead of exiting with
advice to hand-edit `docker-compose.yml`, and a `windows-latest` CI job
proves every generated secret lands non-empty — and corrects install
documentation that described a different product (the measured
8 GB / 20 GB requirements, sixteen CORE containers rather than
"fourteen", and four surfaces advertising a Swagger address `make up`
answers 404 on). The on-ramps consolidate to ones that can prove
themselves: `render.yaml` is removed and the devcontainer and sandbox
README no longer hand off to the demo compose file. The Jira connector
moves to `GET /rest/api/3/search/jql` after Jira Cloud removed its old
search endpoint (410 Gone on every poll); the image `stable`-channel
guard fails closed now (it had carried the channel across the v19 → v20
application major under green runs when a buildx read came back empty);
the nightly reproducible-builds aggregator accepts its matrix's
designed skip. `qs` moves to 6.17.0
([GHSA-6pq8-jhm2-2vcw](https://github.com/advisories/GHSA-6pq8-jhm2-2vcw)),
and the two unpatchable `deepmerge` alerts are dismissed on recorded
evidence (no patched version exists; dev/build-tooling dependents
only). No breaking changes, and **neither `stable` channel moves**.
11 defects were fixed (34 across this release and the two before it).
See the TL;DR above and the `[20.2.0]` section of
[`CHANGELOG.md`](CHANGELOG.md) for the full inventory.

### Previously: v20.1.0

The **v20.1.0** release (2026-10-22) closes a
data-loss defect in every connector's poll loop (an externally
contributed fix: the checkpoint advanced past events ingest rejected,
and now advances only when every submitted event was accepted), makes
the measurement harnesses as honest as what they measure (the live-agent
eval runs one event loop per run and scores failed investigations as 0
with reasons, with the 0.40 groundedness floor re-derived under the
fixed harness; the chaos store-outage legs grade real behaviour, with
the redis and qdrant legs passing end to end and the postgres leg red
by design on #1446), adds unauthenticated liveness and readiness probes
to the API (`GET /api/v1/health`, `GET /api/v1/health/ready` — database
blocks, cache degrades), guards the chart `stable` channel on both
version lines with a dispatchable repair workflow, and moves `fastapi`
to 0.146.0 across every declaration site and lock in one change, with
the Oct-22 Dependabot waves folded and `@vitest/mocker` 4.1.12 closing
CVE-2026-112949/112950. No breaking changes, and neither `stable`
channel moved. 11 defects were fixed (34 across that release and the
two before it).

### Previously: v20.0.0

The **v20.0.0** release (2026-10-21) is the
security-response release: four vulnerability reports reproduced,
fixed and published as advisories (cases read-scope, system-note
spoofing, webhook RLS + SSRF, and the SSRF guard adopted on every
connector egress path), the semgrep rule packs vendored so the scanner
ratchet's ceiling is bound to the exact pack bytes it was measured with,
the Oct-21 dependency-advisory wave cleared across every lockfile with
one recorded expiring exception, four connectors preserving their
vendor's own top severity instead of collapsing it into `high`, a
community-contributed OpenCTI feed client validated against a live
platform, and the LLM gateway image pinned to the exact version the
stack was measured against after upstream deleted the floating tag. It
carries one breaking change: `POST /api/v1/cases/{case_id}/comments` no
longer accepts `is_system` in the request body (the field is ignored,
not refused, so existing requests keep succeeding). 39 defects were
fixed across this release and the two before it (12 here). See the
TL;DR above and the `[20.0.0]` section of
[`CHANGELOG.md`](CHANGELOG.md) for the full inventory.

### Previously: v19.0.0

The **v19.0.0** release (2026-10-12) finished the depth plan's analyst,
collection and governance phases, landing nineteen workstreams as one
verified tree: sessions with one producer and three stores, versioned
security posture read at event time, behavioural baselines in CORE, an
OTLP/Kafka/TAXII collection surface, cost-estimated cold-lake queries, a
Helm chart that installs CORE with one scheduler leading, a verification
playbook that asks the user then their manager, AiSOC's own MCP server
over streamable HTTP, case war rooms, hunt-to-report, an installable
responder app, and the 8.1 governance clauses — WebAuthn, enforced audit
retention, accessibility, and opt-in entitlement limits. It carried one
breaking change: `PATCH /api/v1/alerts/{id}` now answers 422 on a field
it cannot apply instead of 200 on a silent no-op. The chart published as
`7.8.0`.

### Previously: v18.0.0

The **v18.0.0** release (2026-10-09) gave the platform a semantic layer: a
recorded OCSF class decision for every one of the 87 connector types, an
activity projection on every event, a 44-type event catalogue, a 72-rule
windowed detection corpus, cloud-native collection, and console MFA. It
carried one breaking change — three authorization tables that had no reader
began changing outcomes in both directions. The chart published as `7.6.0`.

### Previously: v17.1.0

The **v17.1.0** release (2026-10-07) was a security
release plus the first community-built console surface, with no breaking
changes. The security half closes
[GHSA-w4r8-969c-67p2](https://github.com/beenuar/AiSOC/security/advisories/GHSA-w4r8-969c-67p2)
(High, CWE-347): the audit middleware decoded the request's Bearer token
with signature verification off and wrote its claims into the per-tenant
tamper-evident audit chain before authentication ran, so an unauthenticated
caller could plant any actor and any known tenant id into that tenant's
chain while the route itself answered 401. The middleware now audits only
the verified principal, and a failed authentication writes nothing. The
feature half lands the reviewed scope of a community PR: an admin-only
**Settings → Users** screen with multi-role assignment and a live
effective-permissions preview, an editable Roles & Permissions catalog, and
a feature-flagged enterprise SSO wave that is off by default and JIT-lands
as `viewer`. Migration `091` no longer bulk-seeds a role row into every
tenant (the write that could resolve a fresh install to zero permissions,
break-glass admin included) and `093` repairs deployments the old seed
touched. Enrichment keeps WHOIS from non-top-scoring sources and
union-merges DNS records; the grading-integrity gate no longer locks itself
out after a merge burst; and the `stable` Helm chart channel moved for the
first time ever, because the step that moves it had failed client-side on
every release since it existed. The chart publishes as `7.5.0`.

Before it, the **v17.0.0** release (2026-10-05) removed three
`/detection-loop/suggest*` routes that never worked — they queried three
relations no migration creates, so every caller was already receiving an
error — and changed one number's meaning without erroring, which is the
change to read twice: **`alerts.total` on `/metrics/dashboard` now counts
open work rather than every alert ever received**, with the severity counts
beside it scoped the same way. A panel charting cumulative intake from that
field will drop to the size of your queue; closed work moved to
`alerts.resolved`.

It also fixes an approval path that had never once succeeded — the dispatch
read two attributes the principal class does not define, so the actions
service received an empty permission list and refused while the approval row
recorded the decision — and adds a choice of **where the model runs**:
`make up` unchanged on CPU, `make up-gpu` for an NVIDIA device, or
`make up-host-llm` for an Ollama you already run, which is the only route to a
GPU on Apple Silicon. `GET /api/v1/llm/runtime` reports where the model
actually is by asking Ollama rather than reading the compose file back, and
`POST /api/v1/llm/credentials/test` finds a bad provider key at the moment you
save it. Closed cases can be reopened with a recorded reason. The full entry
is in [`CHANGELOG.md`](CHANGELOG.md).

The **v16.0.1** release (2026-10-04) was a security
release closing one high-severity privilege escalation
(**GHSA-4gx4-x7gm-4xq8**): a grant was measured against the caller's static
role rather than the permissions it was admitted on, so an account narrowed
through the database-backed RBAC tables could confer on itself anything its
unnarrowed role carried. Six routes shared the defect, not the one reported.
Upgrade if you use `roles` and `user_roles` to restrict accounts; a
deployment with no RBAC rows was never exposed. The full entry is in
[`CHANGELOG.md`](CHANGELOG.md).

The **v16.0.0** release (2026-10-03) carried one
breaking change: the `cases` table is gone and its rows live in
`aisoc_cases`, so SQL of your own against the old name now fails loudly
rather than returning stale rows. It closes seventeen defects sharing one
shape — a mechanism that is complete, tested, and has no caller — of which
the most visible is that SAML and OIDC sign-in returned 403 on every
deployment because the connection table had no writer. The full entry is in
[`CHANGELOG.md`](CHANGELOG.md).

The **v15.0.0** release (2026-10-01) is a security
release closing **thirteen defects**, each found by reading the code at
`v14.0.0` and each shipped with a reproduction that fails on the untouched
tree for the stated reason.

The ones with the widest blast radius: an **AI triage could teach the platform
to stop showing an attacker their own alerts** — three AI verdicts at ≥0.90
confidence on one evidence signature auto-closed every later alert sharing it,
and the corroboration threshold was never a mitigation because the attacker
picks how many alerts to send. **Both SSO handlers minted a signed session for
an identity nobody authenticated**, and since `python3-saml` was declared in no
install path, that branch was the *only* reachable path through the SAML
assertion consumer on every deployment. **Six of the seven `mssp_*` tables had
no row-level security**, so the query predicate was the single control between
one MSSP's portfolio and another's. And an operator could **grant a permission
in the console, watch it appear in the UI, and have 275 of 302 routes ignore
it**.

Two are breaking and are tabled in the `### BREAKING` sections of
[`CHANGELOG.md`](CHANGELOG.md): `/api/v1/shifts` is removed and
`/api/v1/threatintel/stix` reads answer 404 outside demo mode; and
`ENVIRONMENT` defaults to `production` on every documented path, which turns
several previously silent warnings into boot refusals. Upgrading is `make up`.

Three findings are worth more than the fixes. **A real database caught what a
static gate could not**: the obvious MSSP policies are mutually recursive and
Postgres answers `infinite recursion detected` on the first `SELECT`, while
`check_rls_policy_shape.py` passed throughout — shape is not liveness.
**Adding one keyword broke four writer signatures and no test failed on the
exception**, because the call sits inside `contextlib.suppress`; what surfaced
was a zero write-count in an unrelated replay test three files away.
And **the first design for database-backed permissions was wrong**: resolving
inside the permission check would have made a transient database fault deny
every request on the platform, so resolution happens at authentication and
fails *open* to the static map, deliberately.

The claim-to-gate matrix is at **255 rows, all GATED**. The chart publishes as
**`7.1.0`**.

`VERSION` was `14.0.0`. The **v14.0.0** release (2026-09-29) closes a HIGH
privilege-escalation advisory by scoping every grant to the granter: no
principal may confer a role, an API-key scope or an organisation membership
beyond what it holds itself, and the two wildcard roles are unreachable from
any API route. Six routes accepted authority from a request body and only one
was reported; `scripts/check_role_grant_scope.py` names all nine handlers when
run against the tree before the fix. The `### BREAKING` section of
[`CHANGELOG.md`](CHANGELOG.md) tables the change per route.

`VERSION` was `13.0.1`. The **v13.0.1** patch (2026-09-29) shipped no application
change at all: it is the tag push that puts the corrected Helm chart into GHCR
as **`6.0.1`**, the first 6.x a user can actually pull. v13.0.0 left the
chart's own `version` at `5.9.2` while moving `appVersion`, and `helm push`
replaces without a word, so that coordinate meant `v12.3.2` or `v13.0.0`
depending on when it was fetched. The correction landed on `main` after the
tag and could not reach the registry from there — `release.yml` gates its
GHCR login, push and resolve steps on `github.event_name == 'push'`, so a
dispatch packages and lints and then stops on purpose. `scripts/check_chart_version.py`
now refuses the whole class before the push rather than after it. Everything
in the rest of this section describes **v13.0.0**, which this patch leaves
untouched.

The **v13.0.0** release (2026-09-29) works the
identity-only route debt down from **103 to 28** across five reviewed changes
by resource area, using only permissions that already existed in
`ROLE_PERMISSIONS`. It is a major because the break is behavioural: several
surfaces move to `settings:write`, which `soc_analyst`, `soc_lead` and
`threat_hunter` do not hold, so this is the first of these three releases where
a principal other than `viewer` loses access. Read the `### BREAKING` section
of [`CHANGELOG.md`](CHANGELOG.md) before upgrading — it names every route, the
permission it now requires, the roles that lose it, and the two ways to restore
access (a role that holds the permission, or the permission added to a custom
role or an API key's `scopes`). Two permission choices were rejected for
causing an outage rather than fixing a hole, and the rejections are pinned by
tests: `rules:write` on the hunt workbench would have locked out
`soc_analyst`, the role the `/hunt` page exists for, and `settings:write` on
`/insider-threat` would have taken watchlisting away from the analysts the
module is for.

**v13.0.0 highlights (September 29, 2026)**
- **75 routes gated, 28 deliberately left.** The remainder is not a backlog
  with no owner: eight SCIM routes authenticate a purpose-bound provisioning
  credential that has no role for `require_permission` to consult, four
  `/mssp/organizations` routes authorize through an organisation owner/admin
  check that a tenant role cannot substitute for, eleven are self-scoped to
  the caller's own row, and the last five carry a stated product question.
  `POST /kb/query` and `POST /community/plugins/{id}/rate` are pinned
  *ungated* by tests, so changing them takes a decision.
- **`POST /mssp/organizations` was an escalation into the part of that module
  that did authorize.** Founding an organisation makes the caller the `owner`
  that `_admin_scope` accepts, and the route was open to any authenticated
  user, so a read-only role could mint itself an administering principal in
  one request. It was found by a structural test asserting no state-changing
  route in the module is unguarded, not by reading the module.
- **Compliance evidence collection and review now take two different
  permissions**, so a `soc_lead` can produce an evidence item and cannot
  accept it. That is a role-level separation and weaker than the person-level
  separation of duties `services/actions` enforces on response approvals —
  migration 013 records `reviewed_by` and no collector column, so there is
  nobody to compare an approver against, and the stronger check is not
  claimed anywhere.
- **314 new tests, per route and in both directions.** Against the pre-fix
  tree the five suites fail 30/49, 35/55, 41/64, 45/65 and 44/68; `services/api`
  goes 3,537 → 3,819 passing with no unrelated test moving.

**v12.3.2 highlights (September 29, 2026)**

The **v12.3.2** release wires eleven
`require_permission` dependencies that FastAPI had been discarding, found
by sweeping the sibling modules for the omission behind
GHSA-wj5c-88hg-5926. The **v12.3.1** release earlier the same day is a
security patch: two reported advisories fixed, no feature change and nothing breaking.
It follows v12.3.0 the same day because a fix that sits on `main` is not a fix
anyone running the published images has.

**v12.3.1 highlights (September 29, 2026)**
- **GHSA-p37g-cjqx-56hq (critical) — SQL injection in the osquery allowlist.**
  A denylist that scanned rendered SQL for `--`, `/*` and `;` had never
  listed `'`. All six templates were injectable, not the one reported, since
  the numeric parameters were never coerced. Parameters now declare a type
  and anything else is refused, not escaped.
- **GHSA-wj5c-88hg-5926 (high) — missing function-level authorization.** Every
  remediation write route authenticated and none authorized, so a `viewer`
  could raise the tenant to L4 and pre-approve a high blast-radius verb. Now
  enforced on all six routes, including one the advisory does not name.
- **The router also committed before serialising**, returning HTTP 500 on a
  write that had already landed — so the regression tests assert the
  transaction did not commit rather than checking a status code.
- **A gate that asks whether a route authorizes**, not merely whether it
  authenticates: 103 of 246 state-changing routes make no authorization
  decision, recorded as a ceiling that can only fall.


**v12.3.0 highlights (September 29, 2026)**
- **Six deferrals closed, one recurring shape.** 8b (every shipped prompt
  registered, 3 -> 22, with the gate failing in both directions), 9b
  (approvals nobody answered now expire, safe default `rejected`), 5b (dead
  letters replayable from the Kafka offset, re-validated by the validator that
  refused them), 10b (the ingest checkpoint is a declared contract rather than
  an optional method 83 of 84 connectors lacked), 6b (a tenant's projected
  storage $/mo beside its LLM $/mo), and 3.5+ (the demo stack has a measured
  budget, 3m06s -> 1m39s).
- **A skipped upload no longer reports as a successful publish**, and
  something finally asks the registry after a release instead of reading the
  workflow's own result.
- **The weekly security digest stopped grading a repository A/100 across
  sources it could not read.** It had headlined an all-clear derived from one
  of three declared sources, and a byte-identical body each week froze
  `updated_at` so six consecutive successful runs looked abandoned.
- **Both grading-integrity controls are required now**, taking branch
  protection to 24 contexts, and deliberately only the two that report on a
  pull request: their two siblings skip there, and a skipped required check
  counts as passing.
- **A marketplace card counting playbooks was labelled Executable** — the
  number was right and the word was wrong, which in this repository means
  something specific.
- **Seventeen dependency updates**, with the SQLAlchemy 2.1.1 bumps checked
  against the greenlet hazard that reddened this repo before, and the `mcp`
  2.0 major refused with the signature diff that shows why.


**v12.2.0 highlights (September 28, 2026)**
- **Four package READMEs told you to install packages that do not exist.** Each
  deferred to `v8.0+`, a release that shipped four major versions ago, so the
  label read as availability. None of the eight first-party packages has ever
  been uploaded — the registries return 404 for all eight — while the release
  workflow's publish jobs report success, because only the upload step is
  credential-gated. A gate now asks the registry instead of trusting the
  workflow.
- **The claim-to-gate matrix is complete**: 238 rows, all GATED, no PARTIAL
  and no NO GATE. Phase 4 stays unchecked, because a funded hosted-model key
  is not something code can supply.
- **Completion bounds now reach the bundled model.** They had been rendered as
  `max_completion_tokens`, which Ollama ignores silently, so every investigator
  call was effectively unbounded — one ran to 40,960 tokens.
- **CI installs each service's committed lock as an exact closure**, so the
  version CI grades is the version the image ships.

The full inventory — 11 entries — lives under `[12.2.0]` in [`CHANGELOG.md`](CHANGELOG.md).

---

## v12.1.0 (2026-09-28)

A security and correctness release: several controls were reading a description of the system rather than the system. Full detail under `[12.1.0]` in [`CHANGELOG.md`](CHANGELOG.md).

---

## v12.0.0 (2026-09-28)

The release where two services stopped serving unauthenticated. Full detail under `[12.0.0]` in [`CHANGELOG.md`](CHANGELOG.md).

---

## v11.2.0 (2026-09-26)

`VERSION` was `11.2.0`. The **v11.2.0** release (2026-09-26) answers a question that had been asked of this repository for months — *why 833 rules and not 5,000?* — and the answer was not a missing feature. (Claim-to-gate matrix at the v11.2.0 cut: 147 rows — 139 GATED / 8 PARTIAL / 0 NO GATE, counted from the table by `scripts/check_claim_gate_matrix.py`, which is the figure to recount rather than to quote.)

**Nothing in this release requires you to act, which is why it is a minor.** There is no configuration change, no migration and no API change. The connector fix only *adds* fields: it lifts the `System` and `EventData` containers into the namespace the matcher already read, and a connector-normalized key still wins on collision. What does change is that 2,603 rules evaluate where 833 did, and 1,687 of the additions are Windows rules that could never fire before — so expect more alerts from the same stream. Every imported rule carries its `upstream_status` onto the alert, so the 125 `experimental` ones can be filtered without disabling the rest.

**What "executable" means, because the whole figure rests on it.** A rule counts only after a vendor-shaped event has been replayed through the **real** connector `normalize()` and the **real** `DetectionEngine` and that rule was observed to produce a hit, with an empty event of the same shape producing nothing. Nothing is inferred from a directory, an `enabled:` key or the shape of a `detection:` block — and notably not from `check_detection_fields.py`, whose own docstring says it over-approximates and that "a false pass is a rule this gate should have caught". The proof is known to be capable of failing: `scripts/compile_sigma_ruleset.py --prove-gate` reverts the connector to its pre-fix behaviour and requires all 1,687 Windows rules to stop firing. **It is a claim about reachability, not about detection.** A rule that fires on a well-formed event of its own log source is reachable; that is not evidence it detects an attack, that it is tuned, or that it will be quiet.

**What is measured, and what is not.** Auto-triage now asks the provider for a JSON object rather than correcting prose afterwards. Measured over 50 alerts from the committed synthetic corpus, through the LiteLLM gateway exactly as production routes, against the bundled `llama3.2:3b-instruct-q4_K_M` at the production `temperature=0.0` / `max_tokens=512`: replies triage could use went from **44 of 50 to 50 of 50**. Every one of the six failures carried a correct verdict and confidence and a malformed `rationale`, and `finish_reason` was `stop` on all 50 calls, so truncation was not involved. The earlier published "7 of 19" does not reproduce and has been replaced everywhere by the repeatable measurement in `scripts/measure_triage_reliability.py`. **The recorded deployment walkthrough predates this fix and shows the old deterministic fallback**, which the walkthrough's own closing card states. **No hosted provider has ever been exercised** — there is still no funded key, and that remains a separate, unmade claim. The npm and PyPI packages are built and packed on every tag and **are still not uploaded**, because no registry credential exists; treat any install command for them as unavailable rather than broken.

**A known licence gap, still open.** The Sigma importer never captured the upstream `author:` field, so DRL-1.1 attribution travels as repository, upstream rule id, upstream path and licence — enough to find a rule, not enough to name who wrote it. The engine builds its attribution sentence from what the provenance block holds, so an alert reads short rather than crediting an author called `""`. Closing it needs a re-import. It is recorded in [the compilation report](docs/detections/sigma-compilation.md) rather than left to be discovered from the JSON.

**v11.2.0 highlights (September 26, 2026)**
- **Windows telemetry was unreachable, and nothing said so.** `CommandLine` appears in 2,173 public Sigma rules and `Image` in 2,300 — the two most-used fields in the corpus — and both resolved to `None` because the engine flattens `raw_event`'s *top level* and a Windows event puts its payload one level below that. The fix belongs in `windows_event.normalize()` rather than the engine, because `System` and `EventData` are names from the Windows event schema and the engine is shared by every connector. All 1,756 committed fixtures were replayed to confirm every existing native rule keeps its verdict, now a standing test rather than a one-off check.
- **1,770 Sigma rules ship and 1,362 are refused, each with a recorded reason.** The two largest: 556 whose log source no connector emits, and 464 whose negation would flip on a missing field — Sigma treats `not filter` as *true* when the field is absent and only `not_in` and `not_contains_any` do that here, so compiling the rest would turn "not this value" into "fires whenever the field is missing". Refusing is the design: a translation that is merely close changes what a rule means.
- **Upstream lifecycle status no longer decides whether an imported rule runs.** The importer had quarantined 2,844 `test` and 211 `experimental` rules on SigmaHQ status, which conflated whether a rule *can execute here* with how confident its authors are in its content. In SigmaHQ, `test` means reviewed and in community use. Fireability gates now; status is carried onto the rule and the alert so it can still be filtered; `deprecated` and `unsupported` are refused outright.
- **All 122 previously phantom-enabled rules are resolved.** 76 were marked enabled while the engine had never heard of them — they counted as shipped coverage and detected nothing. 46 became executable through the compiler; the rest are `enabled: false` with a `quarantine_reason` naming what each would need. `detection_truth_table.py --check` now fails on any such rule.
- **Eight windowed aggregation rules**, taking that family from 10 to 18 — failed-logon volume per host, password spray counted by distinct account rather than by attempt, service-install and scheduled-task bursts, remote-thread fan-out, and per-process DNS fan-out. The quarantine index had been telling contributors to skip this family for a loader that had existed for some time.
- **Four counters were still classifying rules by their directory.** `_quarantine/` stopped meaning "cannot run" when the compiler began translating rules where they sat, so the tools that had not moved to the compiled ruleset reported the old world while printing OK. The validator published "Quarantined: 5937" against a truth table saying 4,213 about the same tree; the coverage page selected from 1,054 candidates out of 2,603 executable rules and listed a category named `_quarantine`; and the marketplace published 7,016 detections against a README and truth table that both say 6,991 — the 25-rule gap being `detections/playbooks/`, which holds response playbooks, not rules. All four now read the compiled ruleset, which is why they agree.

The full inventory lives under `[11.2.0]` in [`CHANGELOG.md`](CHANGELOG.md).

---

## v11.1.0 (2026-09-25)

`VERSION` was `11.1.0`. The **v11.1.0** release (2026-09-25) began as one user's bug report and ended as an audit of everything between this project's build output and the thing a stranger can actually run. (Claim-to-gate matrix at the v11.1.0 cut: 146 rows — 138 GATED / 8 PARTIAL / 0 NO GATE.)

**Nothing in this release requires you to act, which is why it is a minor.** `AISOC_API_URL`, `AISOC_AGENTS_URL` and `AISOC_REALTIME_URL` configure the console at run time and fall back to the addresses that were previously compiled in. `AISOC_CONSOLE_BIND_ADDR` and `AISOC_BIND_ADDR` both default to loopback, so a laptop install still exposes nothing by omission. The only removals are two variables the console never read.

**What is measured, and what is not.** A fresh `make up` runs AI triage against the bundled `llama3.2:3b-instruct-q4_K_M` with no credentials. At the time this shipped the published figure was 7 schema-valid replies in a measured run of 19. **That figure does not reproduce**: re-measured later over 50 alerts through the gateway, on the same model and the same production call, it reads **44 of 50** — see `[11.2.0]` in `CHANGELOG.md` for the method and for the change that took it to 50 of 50. When validation fails, triage falls back to the deterministic path and logs that it did. In the live QA for this release **both** triage runs fell back to that deterministic path — the token counts are real because the model genuinely was called; what failed was the shape of its reply. The recorded walkthrough's closing card states this rather than hiding it. **No hosted provider has ever been exercised** — there is still no funded key, and that remains a separate, unmade claim. The npm and PyPI packages are built and packed on every tag and **are still not uploaded**, because no registry credential exists; treat any install command for them as unavailable rather than broken.

**v11.1.0 highlights (September 25, 2026)**
- **The console's upstream addresses were frozen at image-build time, so a documented variable could not work.** `next build` inlines every `NEXT_PUBLIC_*` value into the JavaScript bundle *and* compiles the destinations returned by `rewrites()` into `routes-manifest.json`. `next start` re-reads the config and logs that it did, which makes this look configurable while production routing is served from the manifest — so a pulled image could only ever talk to the hosts it was built against. It worked on the bundled stack by coincidence, because the baked `http://api:8000` is that service's DNS name on that network. The entrypoint now re-evaluates the real `rewrites()` against the container's environment before the server starts, and an address that is set and cannot be applied stops the container and names itself rather than starting on the built-in defaults.
- **A single-host deployment could not be reached at all.** Every host port published to a literal `127.0.0.1`, so the stack came up healthy and nothing outside the machine could reach it — including the browser it was meant to be used from — and nothing in `.env` could change that. The console gets its own bind knob because same-origin proxying means one port is enough: exposing AiSOC to a LAN no longer means handing out Postgres, Redis, Kafka and Neo4j with the development passwords this repository ships.
- **The console image a self-hoster pulls had fallen two releases behind `main`, and every workflow was green throughout.** `ghcr.io/beenuar/aisoc-web:latest` was built from a commit two releases old and `aisoc-web:v11.0.0` was never pushed at all, while `aisoc-core-api`, `aisoc-fusion` and `aisoc-ingest` all carried that tag. The cause was arm64 cross-building under QEMU: measured from BuildKit's own step timings, emulation cost roughly 7x on a good run and on a bad one did not converge — that release's arm64 `pnpm install` ran **6,358 seconds without finishing**, 56x its normal time, while the amd64 leg of the same build finished in 100s. Both publish workflows now build each architecture on a runner of that architecture and merge the two into a manifest list, and `publish-images.yml` no longer cancels itself mid-publish.
- **A green workflow says a job ran, not that the registry holds anything.** `scripts/check_published_images.py` resolves every image reference in `docker-compose.yml`, the Helm chart and tracked prose the way the tooling that reads them does, then asks GHCR. Against `main` before this change it reported 14 findings. It runs daily and over the output of every publish, so a half-published release now fails the run that half-published it.
- **The Helm chart could never have installed.** Every image tag defaults to `Chart.AppVersion`, which read `5.2.0` — a tag that exists for no image — so a default `helm install` could only reach `ImagePullBackOff` on every pod. The chart also named `ghcr.io/beenuar/aisoc-alert-fusion`, which has never existed, and set no upstream addresses on the web Deployment at all, so every console request in a cluster resolved nowhere and every panel stayed empty. `aisoc-honeytokens`, `aisoc-purple-team` and `aisoc-osquery-tls` are published for the first time in this release.
- **`make up` printed an address the operator could not use, and `make doctor` reported another deployment's health as yours.** `up` printed a hardcoded `http://localhost:3000` while the line two below it printed the configured address, contradicting each other on the one screen where a credential is handed over. `doctor` correctly reported which host port this project published and then probed the canonical one anyway — observed here reporting `ingest-worker ... cannot reach Kafka` while this deployment's own `/readyz` answered 200, because it was probing a different project's containers.
- **A recorded deployment walkthrough, and the written form of it.** Two minutes 57 seconds taking one host from nothing to an AI triage verdict, against the images published on GHCR, signed into at a LAN address rather than `localhost`. Everything in it is real: real images, real CISA KEV feed, real alert, real tokens, demo mode off and nothing seeded. Terminal waits are shortened and a badge says so on screen for the whole of every segment it applies to.

The full inventory — 19 entries — lives under `[11.1.0]` in [`CHANGELOG.md`](CHANGELOG.md).

---

## v11.0.0 (2026-09-25)

`VERSION` was `11.0.0`. The **v11.0.0** release (2026-09-25) is what a first run actually produced. Most of it was found by bringing the stack up from the documented path and photographing the result, and nearly every item passed the existing test suite while failing on a real deployment.

**Read the BREAKING section of the changelog before upgrading.** Two items need action. `POST /v1/ingest` and `POST /v1/ingest/batch` now require a credential and take the tenant from it; previously they read `X-Tenant-ID`, believed it, and wrote alerts into whatever tenant the caller named. And CORE now needs **8 GB of memory and 20 GB of free disk**, up from `~6.5 GB`, because the threat-intelligence feed, its vector store and a local model moved into it.

**What is measured, and what is not.** A fresh `make up` now runs AI triage against the bundled `llama3.2:3b-instruct-q4_K_M` with no credentials. At the time this shipped the published figure was 7 schema-valid replies in a measured run of 19. **That figure does not reproduce**: re-measured later over 50 alerts through the gateway, on the same model and the same production call, it reads **44 of 50** — see `[11.2.0]` in `CHANGELOG.md` for the method and for the change that took it to 50 of 50. When validation fails, triage falls back to the deterministic path and logs that it did. That ratio is published here, in the README and on the architecture page rather than implied away. **No hosted provider has ever been exercised** — there is still no funded key, and that remains a separate, unmade claim. The npm and PyPI packages are built and packed on every tag and **are still not uploaded**, because no registry credential exists; treat any install command for them as unavailable rather than broken.

**v11.0.0 highlights (September 25, 2026)**
- **The ingest API authenticated nothing.** It read `X-Tenant-ID`, believed it, and wrote events for whatever tenant the caller named — so anyone who could reach the port could write alerts into any tenant. The comment in `server.go` asserting the endpoint was "token-authenticated per request" had been false since it was written. It is true now: a minted push token or a service token, with `X-Tenant-ID` intersected against what the credential authorises rather than trusted, and no dev-mode bypass.
- **Following the README broke the credential vault.** `.env.example` shipped a placeholder Fernet key and `cp .env.example .env` is step two of the quick start — but the vault only takes its ephemeral-development path when the key is *empty*, so a placeholder raised and every connector save returned HTTP 500. Not copying the template worked; following the instructions did not, and the failure surfaced minutes later at the connector wizard with nothing linking the two. `make up` now generates real secrets. The `make doctor` check meant to catch shipped placeholders matched neither placeholder the repository shipped.
- **`make up` could not succeed, ever.** Its wait loop scored any exited container as broken, and the one-shot model pull has always exited by the time `docker compose up -d` returns — so the step whose job is to say whether the stack is healthy reported the opposite on a completely healthy stack.
- **CORE had no real data and no AI.** The threat-intelligence service and its vector store lived in a profile nobody starting out runs, while the console shipped a page whose endpoint existed in no profile — the missing feed and a recent fabricated-IOC incident were one hole. A fresh `make up` now holds **1,723 real CISA KEV entries** within a minute of boot with no credentials, and Ollama moved in so triage produces real verdicts with real token counts. Along the way: a daily feed that would not have polled for 24 hours, and every auto-triage run on a default install being dead-lettered by a `NOT NULL` cost column.
- **The marketing site's only picture of the console was invented.** A hand-authored ledger with a named ransomware family, a confidence score, a dollar figure against a named hosted model — none of it labelled a mock, none of it ever having happened. It is replaced by four captures of a running CORE stack, two of them deliberately empty or degraded states. The "design partners" block and a testimonials section advertising a closed window were removed rather than updated, and the footer's hard-coded `v7.3.1` — shipped through seven major releases — now reads the version the release flow bumps.
- **Nothing in the console rendered the AI verdict.** The agents service triages every fused alert and writes the verdict, score and groundedness back onto the row; the API returned all four fields; the client dropped all four. The product's headline capability was producing tokens, cost and a ledger entry that no surface showed.

The full inventory — 83 entries, including what is knowingly still open — lives under `[11.0.0]` in [`CHANGELOG.md`](CHANGELOG.md).

---

## v10.0.0 (2026-09-25)

`VERSION` was `10.0.0`. The **v10.0.0** release (2026-09-25) is an audit of a single shape: a control that exists, is tested, and sits on a path nothing reaches.

**Read the BREAKING section of the changelog before upgrading.** Every deployment must act on one item: services connect to Postgres as a DML-only `aisoc_app` role rather than as the schema owner, which is what makes the row-level-security policies filter. The bundled Postgres provisions it on a fresh volume; an existing volume or a managed database does not.

**v10.0.0 highlights (September 25, 2026)**
- **92 row-level-security policies filtered nothing.** Compose, CI, the Helm chart and the Terraform environment all ran every service as `POSTGRES_USER=aisoc`, which the postgres image creates as a superuser — and a superuser ignores policies even under `FORCE ROW LEVEL SECURITY`. Measured with one alert per tenant and the session bound to tenant A: the old role saw 2 rows, the new role sees 1.
- **Fifty-eight routes across four services carried no authentication at all.** Reproduced rather than inferred: an anonymous caller with no `Authorization` header created a playbook, listed all 64, **executed one**, deleted it, then read copilot conversations and ran a threat hunt. A further thirty routes let the caller name the tenant they were reading.
- **UEBA could never write a baseline or an anomaly, and reported healthy throughout.** Three schema defects on one code path, then a fourth: the baseline updater mutated a dict in place, so SQLAlchemy saw no change and left the column out of every `UPDATE`. Measured on a live stack — 36 events for one entity, all processed without error, the stored baseline frozen at `count: 1`.
- **AI triage could not reach a model, and it was not a missing key.** Compose set `LLM_GATEWAY_URL` on both services; both resolvers had been deliberately written to ignore it, so every `aisoc-<role>` alias went to a provider that cannot resolve one and the caller rendered that as "no LLM available". The gateway also moved from `full` into CORE, so a key now works with no profile change.
- **A new user who followed only the README could not log in** — the seeded address was rejected by the login route's own validator before the password was compared, and the committed hash matched no published credential. `make up` now creates an administrator and prints a generated password once.
- **Costs stopped being invented.** The tracker priced the `aisoc-<role>` *alias* against a table of hosted list prices it does not appear in, so every call fell through a default and a local completion that cost nothing was booked at `$0.000999` — a figure that reached the dashboard, the ledger and the budget circuit breaker. Every cost is now measured, labelled an estimate, or absent.

The full inventory — 188 entries — lives under `[10.0.0]` in [`CHANGELOG.md`](CHANGELOG.md).

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
- Rule-engine `eval()` RCE eliminated — conditions are parsed to a whitelisted AST in [`services/api/app/services/rule_engine.py`](services/api/app/services/rule_engine.py) ([#116](https://github.com/beenuar/AiSOC/pull/116)).
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
- **Wazuh Indexer ingest connector** — polls `wazuh-alerts-*` over HTTPX, paginates time-windowed queries, retries on 5xx; collapses Wazuh severity into the AiSOC ladder. Docs: [`apps/docs/docs/connectors/wazuh.md`](apps/docs/docs/connectors/wazuh.md). The connector registry now declares **91 first-party connectors**.
- **auditd `file_tail` connector + `aisoc.rules` profile** — replaces the host-agent dependency for Linux endpoint visibility; 4 new detections pivot on the bundled `aisoc_*` audit keys. Docs: [`apps/docs/docs/connectors/auditd.md`](apps/docs/docs/connectors/auditd.md).
- **Live Actions dispatcher** — generic vendor/capability surface so plugins can register executors against the in-tree taxonomy (`isolate_host`, `disable_user`, `block_ip`, …) without forking. Unknown pairs return a typed `LiveActionResult(FAILED, "executor_not_found")` — never a 500. Docs: [`apps/docs/docs/concepts/live-actions.md`](apps/docs/docs/concepts/live-actions.md).
- **Deterministic NL → ES|QL / KQL / SPL translator** — replaces the template fallback in `/nl_query` with an IR + grammar validator; 50-pair gold eval set scores 100% syntactic, 100% semantic. Air-gapped by default; optional `gpt-4o-mini` enhancement falls back deterministically.
- **STIX → MISP push** — every STIX 2.1 indicator/bundle published through `/api/v1/threatintel/stix/...` can now be mirrored into the configured MISP instance. Air-gap gated, with a `?push_to_misp=true` query param and a dry-run endpoint for air-gapped audits. Docs: [`apps/docs/docs/integrations/misp-push.md`](apps/docs/docs/integrations/misp-push.md).
- **GCP Cloud Run + Cloud SQL Terraform skeleton** — serverless-first BYOC equivalent of the existing AWS module. One `terraform apply` stands AiSOC up on GCP with private-IP networking, Secret Manager, and Artifact Registry. Docs: [`apps/docs/docs/deployment/gcp.md`](apps/docs/docs/deployment/gcp.md).
- **Azure Container Apps + Postgres Flexible Server Terraform skeleton** — file-for-file mirror of the GCP skeleton for teams standardised on Azure. Container Apps for the three customer-visible services, VNet-integrated Postgres 16 + Azure Cache for Redis on private endpoints, Key Vault for secrets, ACR for images, and per-service user-assigned managed identities so each app pulls its own image and reads only its own secrets. Docs: [`apps/docs/docs/deployment/azure.md`](apps/docs/docs/deployment/azure.md).
- **Blameless case post-mortem endpoint** — `GET /api/v1/cases/{case_id}/postmortem?format=json|html` produces a deterministic retrospective covering contributing factors, detection timing/gaps, response phases, blast radius, and action items. Analyst handles are explicitly redacted from the narrative. Docs: [`apps/docs/docs/operations/case-reports.md`](apps/docs/docs/operations/case-reports.md).
- **Per-rule cross-fire FP gate** — `services/agents/tests/test_detection_fp_rate.py` replays every rule's `match_when` against every *other* rule's positive fixture; current corpus 816 native rules, worst FPR 0.49% (5% ceiling). Wired into `scripts/run_evals.py` as `suites.detection_fp_rate`.
- **Operator-facing documentation refresh** — new pages for [notifications](apps/docs/docs/operations/notifications.md), [plugin lifecycle](apps/docs/docs/plugins/lifecycle.md), and [credentials / vault rotation](apps/docs/docs/operations/credentials.md); v2.2 architecture diagram and the corrected **91-connector count** (now including Wazuh Indexer + auditd `file_tail`) rolled through every surface.

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
